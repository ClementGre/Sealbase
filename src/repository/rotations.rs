//! Staged DEK rotation (SPEC.md §3.1): `app_rotations` holds the in-flight
//! rotation of an app, `app_rotation_rows` its re-encrypted rows until commit.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub struct Rotation {
    pub id: Uuid,
    pub app_id: Uuid,
    pub base_dek_version: i64,
    pub created_at: DateTime<Utc>,
}

/// Starts a rotation, discarding any previous in-flight one for the app (the
/// owner is the only one who can rotate, so an older one is an abandoned
/// attempt of theirs).
pub async fn begin(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
    app_id: Uuid,
    base_dek_version: i64,
) -> sqlx::Result<Rotation> {
    sqlx::query!("DELETE FROM app_rotations WHERE app_id = $1", app_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query_as!(
        Rotation,
        r#"
        INSERT INTO app_rotations (id, app_id, base_dek_version) VALUES ($1, $2, $3)
        RETURNING id, app_id, base_dek_version, created_at
        "#,
        id,
        app_id,
        base_dek_version,
    )
    .fetch_one(&mut *tx)
    .await
}

pub async fn find(executor: impl sqlx::PgExecutor<'_>, id: Uuid) -> sqlx::Result<Option<Rotation>> {
    sqlx::query_as!(
        Rotation,
        "SELECT id, app_id, base_dek_version, created_at FROM app_rotations WHERE id = $1",
        id,
    )
    .fetch_optional(executor)
    .await
}

pub async fn delete(executor: impl sqlx::PgExecutor<'_>, id: Uuid) -> sqlx::Result<()> {
    sqlx::query!("DELETE FROM app_rotations WHERE id = $1", id)
        .execute(executor)
        .await?;
    Ok(())
}

pub struct StagedRow {
    pub data_id: Uuid,
    pub expected_version: i64,
    pub r#type: String,
    pub format: i16,
    pub encrypted_json: Vec<u8>,
}

/// Upserts a chunk of re-encrypted rows. Re-staging an id overwrites it, which
/// is how a client fixes up rows that changed after it first staged them.
pub async fn stage_rows(pool: &PgPool, rotation_id: Uuid, rows: &[StagedRow]) -> sqlx::Result<()> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.data_id).collect();
    let versions: Vec<i64> = rows.iter().map(|r| r.expected_version).collect();
    let types: Vec<String> = rows.iter().map(|r| r.r#type.clone()).collect();
    let formats: Vec<i16> = rows.iter().map(|r| r.format).collect();
    let blobs: Vec<Vec<u8>> = rows.iter().map(|r| r.encrypted_json.clone()).collect();
    sqlx::query!(
        r#"
        INSERT INTO app_rotation_rows (rotation_id, data_id, expected_version, type, format, encrypted_json)
        SELECT $1, t.data_id, t.expected_version, t.type, t.format, t.encrypted_json
        FROM UNNEST($2::uuid[], $3::int8[], $4::text[], $5::int2[], $6::bytea[])
             AS t(data_id, expected_version, type, format, encrypted_json)
        ON CONFLICT (rotation_id, data_id) DO UPDATE
        SET expected_version = EXCLUDED.expected_version,
            type = EXCLUDED.type,
            format = EXCLUDED.format,
            encrypted_json = EXCLUDED.encrypted_json
        "#,
        rotation_id,
        &ids,
        &versions,
        &types,
        &formats,
        &blobs,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Live rows the staged set doesn't cover: never staged (`expected_version`
/// is `None`, the row was created after staging) or staged at an older
/// version (edited since). Must be empty for a commit to proceed.
pub struct Mismatch {
    pub id: Uuid,
    pub version: i64,
    pub expected_version: Option<i64>,
}

pub async fn mismatches(tx: &mut sqlx::PgConnection, rotation_id: Uuid, app_id: Uuid) -> sqlx::Result<Vec<Mismatch>> {
    sqlx::query_as!(
        Mismatch,
        r#"
        SELECT d.id, d.version, r.expected_version AS "expected_version?"
        FROM apps_data d
        LEFT JOIN app_rotation_rows r ON r.rotation_id = $1 AND r.data_id = d.id
        WHERE d.app_id = $2 AND (r.data_id IS NULL OR r.expected_version <> d.version)
        ORDER BY d.id
        "#,
        rotation_id,
        app_id,
    )
    .fetch_all(tx)
    .await
}

/// Swaps every staged ciphertext into the live table. Staged rows whose live
/// row was deleted meanwhile simply match nothing. `version`/`edited_at` stay
/// as they are: re-encryption is not a content edit (caches key off
/// `dek_version` instead).
pub async fn apply(tx: &mut sqlx::PgConnection, rotation_id: Uuid, app_id: Uuid) -> sqlx::Result<u64> {
    let result = sqlx::query!(
        r#"
        UPDATE apps_data d
        SET encrypted_json = r.encrypted_json, type = r.type, format = r.format
        FROM app_rotation_rows r
        WHERE r.rotation_id = $1 AND d.id = r.data_id AND d.app_id = $2
        "#,
        rotation_id,
        app_id,
    )
    .execute(tx)
    .await?;
    Ok(result.rows_affected())
}
