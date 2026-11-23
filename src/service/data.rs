use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{AppAccess, AppData, Tombstone, role};
use crate::repository::apps_data::{self, ListFilters, NewRow, RowUpdate};
use crate::repository::{apps, apps_access};

/// Upper bound on operations in one batch (creates + updates + deletes).
pub const MAX_BATCH_OPS: usize = 1000;
/// `type` is either a legacy plaintext tag or a blind index; neither needs
/// to be long.
const MAX_TYPE_LEN: usize = 256;

/// Active membership, any role. Unknown app/membership is 404, pending 403.
pub async fn require_active(
    executor: impl sqlx::PgExecutor<'_>,
    app_id: Uuid,
    user_id: Uuid,
) -> AppResult<AppAccess> {
    let access = apps_access::find(executor, app_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if access.status != "active" {
        return Err(AppError::Forbidden);
    }
    Ok(access)
}

/// Active membership with write permission (owner or editor). Viewers get
/// 403 — read-only is enforced here, server-side (SPEC.md §5).
pub async fn require_writer(
    executor: impl sqlx::PgExecutor<'_>,
    app_id: Uuid,
    user_id: Uuid,
) -> AppResult<AppAccess> {
    let access = require_active(executor, app_id, user_id).await?;
    if !role::can_write(&access.role) {
        return Err(AppError::Forbidden);
    }
    Ok(access)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OnConflict {
    /// Any already-taken id fails the whole batch with 409 `duplicate_id`.
    Error,
    /// Ids that already exist *in this app* are skipped and reported back —
    /// idempotent imports with deterministic ids. An id taken by another app
    /// still fails.
    Skip,
}

pub struct DeleteItem {
    pub id: Uuid,
    pub expected_version: i64,
}

pub struct Batch {
    /// Required whenever the batch writes ciphertext (creates/updates).
    pub dek_version: Option<i64>,
    pub on_conflict: OnConflict,
    pub create: Vec<NewRow>,
    pub update: Vec<RowUpdate>,
    pub delete: Vec<DeleteItem>,
}

pub struct BatchResult {
    pub created: Vec<AppData>,
    pub skipped: Vec<Uuid>,
    pub updated: Vec<AppData>,
    pub deleted: Vec<Uuid>,
}

fn validate(batch: &Batch) -> AppResult<()> {
    let total = batch.create.len() + batch.update.len() + batch.delete.len();
    if total == 0 {
        return Err(AppError::BadRequest("empty batch".into()));
    }
    if total > MAX_BATCH_OPS {
        return Err(AppError::BadRequest(format!("a batch holds at most {MAX_BATCH_OPS} operations")));
    }
    let mut seen = HashSet::with_capacity(total);
    let ids = batch
        .create
        .iter()
        .map(|c| c.id)
        .chain(batch.update.iter().map(|u| u.id))
        .chain(batch.delete.iter().map(|d| d.id));
    for id in ids {
        if !seen.insert(id) {
            return Err(AppError::BadRequest(format!("id {id} appears more than once in the batch")));
        }
    }
    let check_type = |t: &str| {
        if t.is_empty() || t.len() > MAX_TYPE_LEN {
            Err(AppError::BadRequest(format!("type must be 1..={MAX_TYPE_LEN} bytes")))
        } else {
            Ok(())
        }
    };
    let check_format = |f: i16| {
        if f == 1 || f == 2 {
            Ok(())
        } else {
            Err(AppError::BadRequest("format must be 1 or 2".into()))
        }
    };
    for c in &batch.create {
        check_type(&c.r#type)?;
        check_format(c.format)?;
    }
    for u in &batch.update {
        if let Some(t) = &u.r#type {
            check_type(t)?;
        }
        if let Some(f) = u.format {
            check_format(f)?;
        }
    }
    let writes_ciphertext = !batch.create.is_empty() || !batch.update.is_empty();
    if writes_ciphertext && batch.dek_version.is_none() {
        return Err(AppError::BadRequest("dek_version is required when writing ciphertext".into()));
    }
    Ok(())
}

/// Applies creates, updates and deletes atomically: either every operation
/// lands or none does. Updates and deletes are compare-and-swap on `version`;
/// any mismatch fails the batch with 409 `version_conflict` listing each
/// offending id and its current version (`null` when the row is gone).
pub async fn apply_batch(pool: &PgPool, app_id: Uuid, user_id: Uuid, batch: Batch) -> AppResult<BatchResult> {
    validate(&batch)?;

    let mut tx = pool.begin().await?;
    require_writer(&mut *tx, app_id, user_id).await?;

    let current_dek = apps::lock_dek_version_shared(&mut tx, app_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if batch.dek_version.is_some_and(|v| v != current_dek) {
        return Err(AppError::stale_dek());
    }

    // --- creates ---------------------------------------------------------
    let mut created = Vec::new();
    let mut skipped = Vec::new();
    if !batch.create.is_empty() {
        created = apps_data::insert_many(&mut tx, app_id, &batch.create).await?;
        let inserted: HashSet<Uuid> = created.iter().map(|r| r.id).collect();
        let taken: Vec<Uuid> = batch.create.iter().map(|c| c.id).filter(|id| !inserted.contains(id)).collect();
        if !taken.is_empty() {
            let in_this_app: HashSet<Uuid> = apps_data::existing_ids(&mut tx, app_id, &taken).await?.into_iter().collect();
            let foreign: Vec<Uuid> = taken.iter().copied().filter(|id| !in_this_app.contains(id)).collect();
            if batch.on_conflict == OnConflict::Error || !foreign.is_empty() {
                let ids = if batch.on_conflict == OnConflict::Error { taken } else { foreign };
                return Err(AppError::conflict_with(
                    "duplicate_id",
                    "some ids already exist",
                    json!({ "ids": ids }),
                ));
            }
            skipped = taken;
        }
        let inserted_ids: Vec<Uuid> = inserted.into_iter().collect();
        apps_data::clear_tombstones(&mut tx, app_id, &inserted_ids).await?;
    }

    // --- updates & deletes (compare-and-swap) ------------------------------
    let mut conflicts = Vec::new();
    let mut updated = Vec::with_capacity(batch.update.len());
    for u in &batch.update {
        match apps_data::update_cas(&mut tx, app_id, u).await? {
            Some(row) => updated.push(row),
            None => {
                let current = apps_data::current_version(&mut tx, app_id, u.id).await?;
                conflicts.push(json!({ "id": u.id, "current_version": current }));
            }
        }
    }
    let mut deleted = Vec::with_capacity(batch.delete.len());
    for d in &batch.delete {
        if apps_data::delete_cas(&mut tx, app_id, d.id, d.expected_version).await? {
            deleted.push(d.id);
        } else {
            let current = apps_data::current_version(&mut tx, app_id, d.id).await?;
            conflicts.push(json!({ "id": d.id, "current_version": current }));
        }
    }
    if !conflicts.is_empty() {
        return Err(AppError::conflict_with(
            "version_conflict",
            "some rows changed since they were read; re-read and retry",
            json!({ "conflicts": conflicts }),
        ));
    }

    if !created.is_empty() || !updated.is_empty() || !deleted.is_empty() {
        apps_access::bump_last_edit(&mut tx, app_id, user_id).await?;
    }
    tx.commit().await?;
    Ok(BatchResult { created, skipped, updated, deleted })
}

/// Single-row write helpers map a batch conflict on a row that no longer
/// exists (`current_version: null`) back to a plain 404.
pub fn single_row_error(err: AppError) -> AppError {
    if let AppError::Conflict { code: "version_conflict", details: Some(details), .. } = &err {
        let gone = details["conflicts"]
            .as_array()
            .is_some_and(|c| c.len() == 1 && c[0]["current_version"].is_null());
        if gone {
            return AppError::NotFound;
        }
    }
    err
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Date,
    Edited,
}

pub struct ListParams {
    pub types: Option<Vec<String>>,
    pub format: Option<i16>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub edited_from: Option<DateTime<Utc>>,
    pub edited_to: Option<DateTime<Utc>>,
    pub order: Order,
    pub cursor: Option<(DateTime<Utc>, Uuid)>,
    pub limit: i64,
}

/// What every listing returns besides its rows: the server time read
/// *before* the query (a syncing client's next watermark) and the app's
/// current key epoch (so a reader notices a rotation without writing).
pub struct ListMeta {
    pub server_time: DateTime<Utc>,
    pub dek_version: i64,
}

async fn list_meta(pool: &PgPool, app_id: Uuid) -> AppResult<ListMeta> {
    let dek_version = apps::dek_version(pool, app_id).await?.ok_or(AppError::NotFound)?;
    let server_time = apps_data::server_now(pool).await?;
    Ok(ListMeta { server_time, dek_version })
}

pub async fn list(pool: &PgPool, app_id: Uuid, user_id: Uuid, p: ListParams) -> AppResult<(Vec<AppData>, ListMeta)> {
    require_active(pool, app_id, user_id).await?;
    let meta = list_meta(pool, app_id).await?;

    let filters = ListFilters {
        types: p.types.as_deref(),
        format: p.format,
        date_from: p.date_from,
        date_to: p.date_to,
        edited_from: p.edited_from,
        edited_to: p.edited_to,
        cursor: p.cursor,
        limit: p.limit,
    };
    let rows = match p.order {
        Order::Date => apps_data::list_by_date(pool, app_id, &filters).await?,
        Order::Edited => apps_data::list_by_edited(pool, app_id, &filters).await?,
    };
    Ok((rows, meta))
}

pub async fn list_deleted(
    pool: &PgPool,
    app_id: Uuid,
    user_id: Uuid,
    since: Option<DateTime<Utc>>,
    cursor: Option<(DateTime<Utc>, Uuid)>,
    limit: i64,
) -> AppResult<(Vec<Tombstone>, ListMeta)> {
    require_active(pool, app_id, user_id).await?;
    let meta = list_meta(pool, app_id).await?;
    let rows = apps_data::list_tombstones(pool, app_id, since, cursor, limit).await?;
    Ok((rows, meta))
}
