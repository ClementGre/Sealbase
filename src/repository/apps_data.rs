use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{AppData, Tombstone};

pub struct NewRow {
    pub id: Uuid,
    pub r#type: String,
    pub format: i16,
    pub encrypted_json: Vec<u8>,
    pub date: DateTime<Utc>,
}

/// Bulk insert with `ON CONFLICT (id) DO NOTHING`. Returns only the rows that
/// were actually inserted; the caller decides what a skipped id means.
/// `date` is client-supplied (SPEC.md §5); `edited_at` is always server time,
/// so a backdated row still shows up in an `edited_from` sync.
pub async fn insert_many(tx: &mut sqlx::PgConnection, app_id: Uuid, rows: &[NewRow]) -> sqlx::Result<Vec<AppData>> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let types: Vec<String> = rows.iter().map(|r| r.r#type.clone()).collect();
    let formats: Vec<i16> = rows.iter().map(|r| r.format).collect();
    let blobs: Vec<Vec<u8>> = rows.iter().map(|r| r.encrypted_json.clone()).collect();
    let dates: Vec<DateTime<Utc>> = rows.iter().map(|r| r.date).collect();
    sqlx::query_as!(
        AppData,
        r#"
        INSERT INTO apps_data (id, app_id, type, format, encrypted_json, date, edited_at)
        SELECT t.id, $1, t.type, t.format, t.encrypted_json, t.date, now()
        FROM UNNEST($2::uuid[], $3::text[], $4::int2[], $5::bytea[], $6::timestamptz[])
             AS t(id, type, format, encrypted_json, date)
        ON CONFLICT (id) DO NOTHING
        RETURNING id, app_id, type, format, encrypted_json, date, edited_at, version
        "#,
        app_id,
        &ids,
        &types,
        &formats,
        &blobs,
        &dates,
    )
    .fetch_all(tx)
    .await
}

/// Which of `ids` exist in this app (used to tell a same-app duplicate, which
/// `on_conflict: "skip"` tolerates, from an id taken by another app).
pub async fn existing_ids(tx: &mut sqlx::PgConnection, app_id: Uuid, ids: &[Uuid]) -> sqlx::Result<Vec<Uuid>> {
    let rows = sqlx::query!(
        "SELECT id FROM apps_data WHERE app_id = $1 AND id = ANY($2)",
        app_id,
        ids,
    )
    .fetch_all(tx)
    .await?;
    Ok(rows.into_iter().map(|r| r.id).collect())
}

/// A re-created id is alive again: drop its tombstone.
pub async fn clear_tombstones(tx: &mut sqlx::PgConnection, app_id: Uuid, ids: &[Uuid]) -> sqlx::Result<()> {
    sqlx::query!(
        "DELETE FROM apps_data_tombstones WHERE app_id = $1 AND id = ANY($2)",
        app_id,
        ids,
    )
    .execute(tx)
    .await?;
    Ok(())
}

pub struct RowUpdate {
    pub id: Uuid,
    pub expected_version: i64,
    pub encrypted_json: Vec<u8>,
    pub r#type: Option<String>,
    pub format: Option<i16>,
    pub date: Option<DateTime<Utc>>,
}

/// Compare-and-swap update. `None` means either the row doesn't exist or its
/// version moved on; `current_version` tells the two apart.
pub async fn update_cas(tx: &mut sqlx::PgConnection, app_id: Uuid, u: &RowUpdate) -> sqlx::Result<Option<AppData>> {
    sqlx::query_as!(
        AppData,
        r#"
        UPDATE apps_data
        SET encrypted_json = $4,
            type = COALESCE($5, type),
            format = COALESCE($6, format),
            date = COALESCE($7, date),
            version = version + 1,
            edited_at = now()
        WHERE app_id = $1 AND id = $2 AND version = $3
        RETURNING id, app_id, type, format, encrypted_json, date, edited_at, version
        "#,
        app_id,
        u.id,
        u.expected_version,
        u.encrypted_json,
        u.r#type,
        u.format,
        u.date,
    )
    .fetch_optional(tx)
    .await
}

pub async fn current_version(tx: &mut sqlx::PgConnection, app_id: Uuid, id: Uuid) -> sqlx::Result<Option<i64>> {
    let row = sqlx::query!("SELECT version FROM apps_data WHERE app_id = $1 AND id = $2", app_id, id)
        .fetch_optional(tx)
        .await?;
    Ok(row.map(|r| r.version))
}

/// Compare-and-swap delete that leaves a tombstone. Returns false if the row
/// doesn't exist or its version moved on.
pub async fn delete_cas(tx: &mut sqlx::PgConnection, app_id: Uuid, id: Uuid, expected_version: i64) -> sqlx::Result<bool> {
    let deleted = sqlx::query!(
        "DELETE FROM apps_data WHERE app_id = $1 AND id = $2 AND version = $3 RETURNING id",
        app_id,
        id,
        expected_version,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if deleted.is_none() {
        return Ok(false);
    }
    sqlx::query!(
        r#"
        INSERT INTO apps_data_tombstones (app_id, id, deleted_at) VALUES ($1, $2, now())
        ON CONFLICT (app_id, id) DO UPDATE SET deleted_at = now()
        "#,
        app_id,
        id,
    )
    .execute(&mut *tx)
    .await?;
    Ok(true)
}

pub struct ListFilters<'a> {
    pub types: Option<&'a [String]>,
    pub format: Option<i16>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub edited_from: Option<DateTime<Utc>>,
    pub edited_to: Option<DateTime<Utc>>,
    /// Keyset cursor on the active sort key: (date or edited_at, id).
    pub cursor: Option<(DateTime<Utc>, Uuid)>,
    pub limit: i64,
}

/// Rows ordered by `(date, id)` — the natural order for reading.
pub async fn list_by_date(pool: &PgPool, app_id: Uuid, f: &ListFilters<'_>) -> sqlx::Result<Vec<AppData>> {
    let (cursor_key, cursor_id) = split_cursor(f.cursor);
    sqlx::query_as!(
        AppData,
        r#"
        SELECT id, app_id, type, format, encrypted_json, date, edited_at, version
        FROM apps_data
        WHERE app_id = $1
          AND ($2::text[] IS NULL OR type = ANY($2))
          AND ($3::int2 IS NULL OR format = $3)
          AND ($4::timestamptz IS NULL OR date >= $4)
          AND ($5::timestamptz IS NULL OR date <= $5)
          AND ($6::timestamptz IS NULL OR edited_at >= $6)
          AND ($7::timestamptz IS NULL OR edited_at <= $7)
          AND ($8::timestamptz IS NULL OR (date, id) > ($8, $9))
        ORDER BY date, id
        LIMIT $10
        "#,
        app_id,
        f.types,
        f.format,
        f.date_from,
        f.date_to,
        f.edited_from,
        f.edited_to,
        cursor_key,
        cursor_id,
        f.limit,
    )
    .fetch_all(pool)
    .await
}

/// Rows ordered by `(edited_at, id)` — the order an incremental sync walks.
pub async fn list_by_edited(pool: &PgPool, app_id: Uuid, f: &ListFilters<'_>) -> sqlx::Result<Vec<AppData>> {
    let (cursor_key, cursor_id) = split_cursor(f.cursor);
    sqlx::query_as!(
        AppData,
        r#"
        SELECT id, app_id, type, format, encrypted_json, date, edited_at, version
        FROM apps_data
        WHERE app_id = $1
          AND ($2::text[] IS NULL OR type = ANY($2))
          AND ($3::int2 IS NULL OR format = $3)
          AND ($4::timestamptz IS NULL OR date >= $4)
          AND ($5::timestamptz IS NULL OR date <= $5)
          AND ($6::timestamptz IS NULL OR edited_at >= $6)
          AND ($7::timestamptz IS NULL OR edited_at <= $7)
          AND ($8::timestamptz IS NULL OR (edited_at, id) > ($8, $9))
        ORDER BY edited_at, id
        LIMIT $10
        "#,
        app_id,
        f.types,
        f.format,
        f.date_from,
        f.date_to,
        f.edited_from,
        f.edited_to,
        cursor_key,
        cursor_id,
        f.limit,
    )
    .fetch_all(pool)
    .await
}

fn split_cursor(cursor: Option<(DateTime<Utc>, Uuid)>) -> (Option<DateTime<Utc>>, Option<Uuid>) {
    match cursor {
        Some((key, id)) => (Some(key), Some(id)),
        None => (None, None),
    }
}

pub async fn list_tombstones(
    pool: &PgPool,
    app_id: Uuid,
    since: Option<DateTime<Utc>>,
    cursor: Option<(DateTime<Utc>, Uuid)>,
    limit: i64,
) -> sqlx::Result<Vec<Tombstone>> {
    let (cursor_key, cursor_id) = split_cursor(cursor);
    sqlx::query_as!(
        Tombstone,
        r#"
        SELECT id, deleted_at FROM apps_data_tombstones
        WHERE app_id = $1
          AND ($2::timestamptz IS NULL OR deleted_at >= $2)
          AND ($3::timestamptz IS NULL OR (deleted_at, id) > ($3, $4))
        ORDER BY deleted_at, id
        LIMIT $5
        "#,
        app_id,
        since,
        cursor_key,
        cursor_id,
        limit,
    )
    .fetch_all(pool)
    .await
}

pub async fn server_now(pool: &PgPool) -> sqlx::Result<DateTime<Utc>> {
    let row = sqlx::query!(r#"SELECT now() AS "now!""#).fetch_one(pool).await?;
    Ok(row.now)
}
