use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{App, AppWithAccess};

pub async fn create(
    executor: impl sqlx::PgExecutor<'_>,
    id: Uuid,
    owner_id: Uuid,
    slug: &str,
    encrypted_metadata: &[u8],
) -> sqlx::Result<App> {
    sqlx::query_as!(
        App,
        r#"
        INSERT INTO apps (id, owner_id, slug, encrypted_metadata)
        VALUES ($1, $2, $3, $4)
        RETURNING id, owner_id, slug, encrypted_metadata, metadata_version, dek_version, created_at
        "#,
        id,
        owner_id,
        slug,
        encrypted_metadata,
    )
    .fetch_one(executor)
    .await
}

pub async fn find_by_id(executor: impl sqlx::PgExecutor<'_>, id: Uuid) -> sqlx::Result<Option<App>> {
    sqlx::query_as!(
        App,
        r#"
        SELECT id, owner_id, slug, encrypted_metadata, metadata_version, dek_version, created_at
        FROM apps WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(executor)
    .await
}

pub async fn dek_version(executor: impl sqlx::PgExecutor<'_>, id: Uuid) -> sqlx::Result<Option<i64>> {
    let row = sqlx::query!("SELECT dek_version FROM apps WHERE id = $1", id)
        .fetch_optional(executor)
        .await?;
    Ok(row.map(|r| r.dek_version))
}

/// Reads the app's current key epoch under a `FOR SHARE` lock. Every data
/// write takes this lock inside its transaction, and rotation commit takes
/// `FOR UPDATE` on the same row, so a write can never interleave with a
/// rotation: it either lands before (and is caught by the commit's staleness
/// check) or after (and must quote the new `dek_version`).
pub async fn lock_dek_version_shared(tx: &mut sqlx::PgConnection, id: Uuid) -> sqlx::Result<Option<i64>> {
    let row = sqlx::query!("SELECT dek_version FROM apps WHERE id = $1 FOR SHARE", id)
        .fetch_optional(tx)
        .await?;
    Ok(row.map(|r| r.dek_version))
}

/// Same row, exclusive lock: taken by rotation commit.
pub async fn lock_for_update(tx: &mut sqlx::PgConnection, id: Uuid) -> sqlx::Result<Option<App>> {
    sqlx::query_as!(
        App,
        r#"
        SELECT id, owner_id, slug, encrypted_metadata, metadata_version, dek_version, created_at
        FROM apps WHERE id = $1 FOR UPDATE
        "#,
        id,
    )
    .fetch_optional(tx)
    .await
}

/// Compare-and-swap metadata update. Returns the new `metadata_version`, or
/// `None` if `expected_version`/`dek_version` no longer match.
pub async fn update_metadata_cas(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
    encrypted_metadata: &[u8],
    expected_version: i64,
    dek_version: i64,
) -> sqlx::Result<Option<i64>> {
    let row = sqlx::query!(
        r#"
        UPDATE apps SET encrypted_metadata = $2, metadata_version = metadata_version + 1
        WHERE id = $1 AND metadata_version = $3 AND dek_version = $4
        RETURNING metadata_version
        "#,
        id,
        encrypted_metadata,
        expected_version,
        dek_version,
    )
    .fetch_optional(tx)
    .await?;
    Ok(row.map(|r| r.metadata_version))
}

/// Rotation commit: new metadata ciphertext and a new key epoch, in one go.
pub async fn apply_rotation(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
    encrypted_metadata: &[u8],
) -> sqlx::Result<(i64, i64)> {
    let row = sqlx::query!(
        r#"
        UPDATE apps
        SET encrypted_metadata = $2,
            metadata_version = metadata_version + 1,
            dek_version = dek_version + 1
        WHERE id = $1
        RETURNING metadata_version, dek_version
        "#,
        id,
        encrypted_metadata,
    )
    .fetch_one(tx)
    .await?;
    Ok((row.metadata_version, row.dek_version))
}

pub async fn delete(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    sqlx::query!("DELETE FROM apps WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Caller's active memberships joined with apps, optionally filtered by slug.
pub async fn list_active_for_user(
    pool: &PgPool,
    user_id: Uuid,
    slug: Option<&str>,
) -> sqlx::Result<Vec<AppWithAccess>> {
    sqlx::query_as!(
        AppWithAccess,
        r#"
        SELECT a.id AS app_id, a.slug, a.encrypted_metadata, a.metadata_version, a.dek_version,
               aa.role, aa.status, aa.wrapped_dek, aa.last_edit_at
        FROM apps_access aa
        JOIN apps a ON a.id = aa.app_id
        WHERE aa.user_id = $1 AND aa.status = 'active'
          AND ($2::text IS NULL OR a.slug = $2)
        ORDER BY a.created_at
        "#,
        user_id,
        slug,
    )
    .fetch_all(pool)
    .await
}

/// A single app joined with the caller's membership row, any status
/// (service layer decides what pending members may see).
pub async fn find_with_access_for_user(
    pool: &PgPool,
    app_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Option<AppWithAccess>> {
    sqlx::query_as!(
        AppWithAccess,
        r#"
        SELECT a.id AS app_id, a.slug, a.encrypted_metadata, a.metadata_version, a.dek_version,
               aa.role, aa.status, aa.wrapped_dek, aa.last_edit_at
        FROM apps_access aa
        JOIN apps a ON a.id = aa.app_id
        WHERE aa.app_id = $1 AND aa.user_id = $2
        "#,
        app_id,
        user_id,
    )
    .fetch_optional(pool)
    .await
}
