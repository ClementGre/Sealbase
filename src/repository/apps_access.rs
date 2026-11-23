use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{AppAccess, Member};

pub async fn create(
    tx: &mut sqlx::PgConnection,
    app_id: Uuid,
    user_id: Uuid,
    wrapped_dek: &[u8],
    role: &str,
    status: &str,
) -> sqlx::Result<AppAccess> {
    sqlx::query_as!(
        AppAccess,
        r#"
        INSERT INTO apps_access (app_id, user_id, wrapped_dek, role, status)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING app_id, user_id, wrapped_dek, role, status, last_edit_at, created_at
        "#,
        app_id,
        user_id,
        wrapped_dek,
        role,
        status,
    )
    .fetch_one(tx)
    .await
}

pub async fn find(
    executor: impl sqlx::PgExecutor<'_>,
    app_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Option<AppAccess>> {
    sqlx::query_as!(
        AppAccess,
        r#"
        SELECT app_id, user_id, wrapped_dek, role, status, last_edit_at, created_at
        FROM apps_access WHERE app_id = $1 AND user_id = $2
        "#,
        app_id,
        user_id,
    )
    .fetch_optional(executor)
    .await
}

pub async fn list_for_app(executor: impl sqlx::PgExecutor<'_>, app_id: Uuid) -> sqlx::Result<Vec<AppAccess>> {
    sqlx::query_as!(
        AppAccess,
        r#"
        SELECT app_id, user_id, wrapped_dek, role, status, last_edit_at, created_at
        FROM apps_access WHERE app_id = $1
        ORDER BY created_at
        "#,
        app_id,
    )
    .fetch_all(executor)
    .await
}

/// Every membership row of an app joined with the member's username and
/// public key, so the owner can show and re-seal to members without an extra
/// lookup per user.
pub async fn list_members(pool: &PgPool, app_id: Uuid) -> sqlx::Result<Vec<Member>> {
    sqlx::query_as!(
        Member,
        r#"
        SELECT aa.user_id, u.username, u.public_key, aa.role, aa.status, aa.last_edit_at, aa.created_at
        FROM apps_access aa
        JOIN users u ON u.id = aa.user_id
        WHERE aa.app_id = $1
        ORDER BY aa.created_at
        "#,
        app_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn set_role(
    executor: impl sqlx::PgExecutor<'_>,
    app_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> sqlx::Result<Option<AppAccess>> {
    sqlx::query_as!(
        AppAccess,
        r#"
        UPDATE apps_access SET role = $3
        WHERE app_id = $1 AND user_id = $2 AND role <> 'owner'
        RETURNING app_id, user_id, wrapped_dek, role, status, last_edit_at, created_at
        "#,
        app_id,
        user_id,
        role,
    )
    .fetch_optional(executor)
    .await
}

pub struct PendingShare {
    pub app_id: Uuid,
    pub slug: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// Caller's incoming pending shares. `wrapped_dek` is intentionally excluded
/// (SPEC.md §3/§5) — an honest server never hands out the sealed DEK to a
/// recipient who hasn't accepted yet.
pub async fn list_pending_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> sqlx::Result<Vec<PendingShare>> {
    sqlx::query_as!(
        PendingShare,
        r#"
        SELECT aa.app_id, a.slug, aa.role, aa.created_at
        FROM apps_access aa
        JOIN apps a ON a.id = aa.app_id
        WHERE aa.user_id = $1 AND aa.status = 'pending'
        ORDER BY aa.created_at
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn accept(
    executor: impl sqlx::PgExecutor<'_>,
    app_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Option<AppAccess>> {
    sqlx::query_as!(
        AppAccess,
        r#"
        UPDATE apps_access SET status = 'active'
        WHERE app_id = $1 AND user_id = $2 AND status = 'pending'
        RETURNING app_id, user_id, wrapped_dek, role, status, last_edit_at, created_at
        "#,
        app_id,
        user_id,
    )
    .fetch_optional(executor)
    .await
}

pub async fn remove(executor: impl sqlx::PgExecutor<'_>, app_id: Uuid, user_id: Uuid) -> sqlx::Result<()> {
    sqlx::query!(
        "DELETE FROM apps_access WHERE app_id = $1 AND user_id = $2",
        app_id,
        user_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn bump_last_edit(
    tx: &mut sqlx::PgConnection,
    app_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE apps_access SET last_edit_at = now()
        WHERE app_id = $1 AND user_id = $2
        "#,
        app_id,
        user_id,
    )
    .execute(tx)
    .await?;
    Ok(())
}

/// Applies a rotation's access list (SPEC.md §3.1) in place: re-seals the new
/// DEK for every listed member and drops every member not listed. Role,
/// status (pending stays pending) and `last_edit_at` are preserved — rotation
/// changes keys, never permissions.
pub async fn apply_rotation(
    tx: &mut sqlx::PgConnection,
    app_id: Uuid,
    access: &[(Uuid, Vec<u8>)],
) -> sqlx::Result<()> {
    let keep: Vec<Uuid> = access.iter().map(|(id, _)| *id).collect();
    sqlx::query!(
        "DELETE FROM apps_access WHERE app_id = $1 AND NOT (user_id = ANY($2))",
        app_id,
        &keep,
    )
    .execute(&mut *tx)
    .await?;
    for (user_id, wrapped_dek) in access {
        sqlx::query!(
            "UPDATE apps_access SET wrapped_dek = $3 WHERE app_id = $1 AND user_id = $2",
            app_id,
            user_id,
            wrapped_dek,
        )
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}
