use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{AppWithAccess, role};
use crate::repository::rotations::{self, StagedRow};
use crate::repository::{apps, apps_access, audit};
use crate::service::data::{require_active, require_writer};

pub async fn create_app(
    pool: &PgPool,
    owner_id: Uuid,
    app_id: Uuid,
    slug: &str,
    encrypted_metadata: &[u8],
    wrapped_dek: &[u8],
) -> AppResult<AppWithAccess> {
    let mut tx = pool.begin().await?;
    let app = apps::create(&mut *tx, app_id, owner_id, slug, encrypted_metadata).await?;
    let access = apps_access::create(&mut tx, app.id, owner_id, wrapped_dek, role::OWNER, "active").await?;
    tx.commit().await?;

    Ok(AppWithAccess {
        app_id: app.id,
        slug: app.slug,
        encrypted_metadata: app.encrypted_metadata,
        metadata_version: app.metadata_version,
        dek_version: app.dek_version,
        role: access.role,
        status: access.status,
        wrapped_dek: access.wrapped_dek,
        last_edit_at: access.last_edit_at,
    })
}

pub async fn list_apps(pool: &PgPool, user_id: Uuid, slug: Option<&str>) -> AppResult<Vec<AppWithAccess>> {
    Ok(apps::list_active_for_user(pool, user_id, slug).await?)
}

pub async fn get_app(pool: &PgPool, app_id: Uuid, user_id: Uuid) -> AppResult<AppWithAccess> {
    let row = apps::find_with_access_for_user(pool, app_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if row.status != "active" {
        return Err(AppError::Forbidden);
    }
    Ok(row)
}

/// Compare-and-swap metadata write by an owner or editor. Returns the new
/// `metadata_version`.
pub async fn patch_metadata(
    pool: &PgPool,
    app_id: Uuid,
    user_id: Uuid,
    encrypted_metadata: &[u8],
    expected_version: i64,
    dek_version: i64,
) -> AppResult<i64> {
    let mut tx = pool.begin().await?;
    require_writer(&mut *tx, app_id, user_id).await?;

    let Some(new_version) =
        apps::update_metadata_cas(&mut tx, app_id, encrypted_metadata, expected_version, dek_version).await?
    else {
        let app = apps::find_by_id(&mut *tx, app_id).await?.ok_or(AppError::NotFound)?;
        if app.dek_version != dek_version {
            return Err(AppError::stale_dek());
        }
        return Err(AppError::conflict_with(
            "version_conflict",
            "metadata changed since it was read; re-read and retry",
            json!({ "current_version": app.metadata_version }),
        ));
    };
    apps_access::bump_last_edit(&mut tx, app_id, user_id).await?;
    tx.commit().await?;
    Ok(new_version)
}

pub async fn delete_app(pool: &PgPool, app_id: Uuid, user_id: Uuid) -> AppResult<()> {
    let app = apps::find_by_id(pool, app_id).await?.ok_or(AppError::NotFound)?;
    if app.owner_id != user_id {
        return Err(AppError::Forbidden);
    }
    apps::delete(pool, app_id).await?;
    audit::log(pool, Some(user_id), "app.delete", Some(app_id), None).await?;
    Ok(())
}

pub async fn leave_app(pool: &PgPool, app_id: Uuid, user_id: Uuid) -> AppResult<()> {
    let access = apps_access::find(pool, app_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if access.role == role::OWNER {
        return Err(AppError::BadRequest(
            "the owner cannot leave; delete the app or rotate access instead".into(),
        ));
    }
    apps_access::remove(pool, app_id, user_id).await?;
    audit::log(pool, Some(user_id), "leave", Some(app_id), None).await?;
    Ok(())
}

// --- staged DEK rotation (SPEC.md §3.1) ------------------------------------

async fn require_owner(pool: &PgPool, app_id: Uuid, user_id: Uuid) -> AppResult<crate::models::App> {
    let app = apps::find_by_id(pool, app_id).await?.ok_or(AppError::NotFound)?;
    if app.owner_id != user_id {
        // Members learn nothing beyond "not yours"; non-members get 404.
        require_active(pool, app_id, user_id).await?;
        return Err(AppError::Forbidden);
    }
    Ok(app)
}

pub struct RotationStarted {
    pub rotation_id: Uuid,
    pub base_dek_version: i64,
    pub started_at: DateTime<Utc>,
}

pub async fn begin_rotation(pool: &PgPool, app_id: Uuid, owner_id: Uuid) -> AppResult<RotationStarted> {
    let app = require_owner(pool, app_id, owner_id).await?;
    let mut tx = pool.begin().await?;
    let rotation = rotations::begin(&mut tx, Uuid::now_v7(), app_id, app.dek_version).await?;
    tx.commit().await?;
    Ok(RotationStarted {
        rotation_id: rotation.id,
        base_dek_version: rotation.base_dek_version,
        started_at: rotation.created_at,
    })
}

async fn find_rotation(
    pool: &PgPool,
    app_id: Uuid,
    rotation_id: Uuid,
) -> AppResult<rotations::Rotation> {
    let rotation = rotations::find(pool, rotation_id).await?.ok_or(AppError::NotFound)?;
    if rotation.app_id != app_id {
        return Err(AppError::NotFound);
    }
    Ok(rotation)
}

pub async fn stage_rotation_rows(
    pool: &PgPool,
    app_id: Uuid,
    owner_id: Uuid,
    rotation_id: Uuid,
    rows: Vec<StagedRow>,
) -> AppResult<()> {
    if rows.len() > crate::service::data::MAX_BATCH_OPS {
        return Err(AppError::BadRequest(format!(
            "stage at most {} rows per request",
            crate::service::data::MAX_BATCH_OPS
        )));
    }
    if rows.iter().any(|r| r.format != 1 && r.format != 2) {
        return Err(AppError::BadRequest("format must be 1 or 2".into()));
    }
    require_owner(pool, app_id, owner_id).await?;
    find_rotation(pool, app_id, rotation_id).await?;
    rotations::stage_rows(pool, rotation_id, &rows).await?;
    Ok(())
}

pub async fn abort_rotation(pool: &PgPool, app_id: Uuid, owner_id: Uuid, rotation_id: Uuid) -> AppResult<()> {
    require_owner(pool, app_id, owner_id).await?;
    find_rotation(pool, app_id, rotation_id).await?;
    rotations::delete(pool, rotation_id).await?;
    Ok(())
}

pub struct RotationCommitted {
    pub metadata_version: i64,
    pub dek_version: i64,
}

/// Swaps every staged row, the new metadata and the re-sealed DEKs in a
/// single transaction. Holds the app row `FOR UPDATE`, which every data and
/// metadata write takes `FOR SHARE`, so no write can interleave. Fails with:
/// - `rotation_incomplete` listing live rows that were created or edited
///   after staging (`missing` / `stale`): stage those and commit again;
/// - `version_conflict` if the metadata moved on: re-encrypt it and retry;
/// - `stale_rotation` if another rotation committed first: start over.
pub async fn commit_rotation(
    pool: &PgPool,
    app_id: Uuid,
    owner_id: Uuid,
    rotation_id: Uuid,
    new_encrypted_metadata: &[u8],
    expected_metadata_version: i64,
    access: Vec<(Uuid, Vec<u8>)>,
) -> AppResult<RotationCommitted> {
    let mut tx = pool.begin().await?;
    let app = apps::lock_for_update(&mut tx, app_id).await?.ok_or(AppError::NotFound)?;
    if app.owner_id != owner_id {
        return Err(AppError::Forbidden);
    }
    let rotation = rotations::find(&mut *tx, rotation_id).await?.ok_or(AppError::NotFound)?;
    if rotation.app_id != app_id {
        return Err(AppError::NotFound);
    }
    if rotation.base_dek_version != app.dek_version {
        return Err(AppError::conflict("stale_rotation", "the app was rotated since this rotation began"));
    }
    if app.metadata_version != expected_metadata_version {
        return Err(AppError::conflict_with(
            "version_conflict",
            "metadata changed during the rotation; re-encrypt it and commit again",
            json!({ "current_version": app.metadata_version }),
        ));
    }

    if !access.iter().any(|(user_id, _)| *user_id == owner_id) {
        return Err(AppError::BadRequest(
            "the access list must include the owner's own re-sealed DEK".into(),
        ));
    }
    // Rotation re-seals for existing members (pending ones included) and
    // drops omitted ones; it never adds members — that goes through the
    // share/accept flow, which requires the recipient's consent.
    let members: HashSet<Uuid> = apps_access::list_for_app(&mut *tx, app_id)
        .await?
        .into_iter()
        .map(|a| a.user_id)
        .collect();
    let mut seen = HashSet::new();
    for (user_id, _) in &access {
        if !members.contains(user_id) {
            return Err(AppError::BadRequest(format!(
                "user {user_id} is not a member of this app; rotation cannot add new members"
            )));
        }
        if !seen.insert(*user_id) {
            return Err(AppError::BadRequest(format!("user {user_id} appears twice in the access list")));
        }
    }

    let mismatches = rotations::mismatches(&mut tx, rotation_id, app_id).await?;
    if !mismatches.is_empty() {
        let missing: Vec<Uuid> = mismatches.iter().filter(|m| m.expected_version.is_none()).map(|m| m.id).collect();
        let stale: Vec<_> = mismatches
            .iter()
            .filter(|m| m.expected_version.is_some())
            .map(|m| json!({ "id": m.id, "current_version": m.version }))
            .collect();
        return Err(AppError::conflict_with(
            "rotation_incomplete",
            "rows changed since they were staged; stage them and commit again",
            json!({ "missing": missing, "stale": stale }),
        ));
    }

    rotations::apply(&mut tx, rotation_id, app_id).await?;
    let (metadata_version, dek_version) = apps::apply_rotation(&mut tx, app_id, new_encrypted_metadata).await?;
    apps_access::apply_rotation(&mut tx, app_id, &access).await?;
    rotations::delete(&mut *tx, rotation_id).await?;
    audit::log(&mut *tx, Some(owner_id), "rotate", Some(app_id), None).await?;
    tx.commit().await?;
    Ok(RotationCommitted { metadata_version, dek_version })
}
