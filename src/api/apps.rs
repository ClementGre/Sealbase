use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::bytes::B64;
use crate::api::extractors::AuthUser;
use crate::error::AppResult;
use crate::models::AppWithAccess;
use crate::repository::rotations::StagedRow;
use crate::service::apps as apps_service;
use crate::state::AppState;

#[derive(Serialize)]
pub struct AppResponse {
    pub app_id: Uuid,
    pub slug: String,
    pub encrypted_metadata: B64,
    pub metadata_version: i64,
    pub dek_version: i64,
    pub role: String,
    pub status: String,
    pub wrapped_dek: B64,
    pub last_edit_at: Option<DateTime<Utc>>,
}

impl From<AppWithAccess> for AppResponse {
    fn from(a: AppWithAccess) -> Self {
        AppResponse {
            app_id: a.app_id,
            slug: a.slug,
            encrypted_metadata: a.encrypted_metadata.into(),
            metadata_version: a.metadata_version,
            dek_version: a.dek_version,
            role: a.role,
            status: a.status,
            wrapped_dek: a.wrapped_dek.into(),
            last_edit_at: a.last_edit_at,
        }
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub slug: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<Vec<AppResponse>>> {
    let apps = apps_service::list_apps(state.pool(), auth.user_id, query.slug.as_deref()).await?;
    Ok(Json(apps.into_iter().map(AppResponse::from).collect()))
}

#[derive(Deserialize)]
pub struct CreateAppRequest {
    pub app_id: Uuid,
    pub slug: String,
    pub encrypted_metadata: B64,
    pub wrapped_dek: B64,
}

pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateAppRequest>,
) -> AppResult<(StatusCode, Json<AppResponse>)> {
    let app = apps_service::create_app(
        state.pool(),
        auth.user_id,
        body.app_id,
        &body.slug,
        &body.encrypted_metadata.0,
        &body.wrapped_dek.0,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(app.into())))
}

pub async fn get(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
) -> AppResult<Json<AppResponse>> {
    let app = apps_service::get_app(state.pool(), app_id, auth.user_id).await?;
    Ok(Json(app.into()))
}

#[derive(Deserialize)]
pub struct PatchAppRequest {
    pub encrypted_metadata: B64,
    pub expected_version: i64,
    pub dek_version: i64,
}

#[derive(Serialize)]
pub struct PatchAppResponse {
    pub metadata_version: i64,
}

pub async fn patch(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
    Json(body): Json<PatchAppRequest>,
) -> AppResult<Json<PatchAppResponse>> {
    let metadata_version = apps_service::patch_metadata(
        state.pool(),
        app_id,
        auth.user_id,
        &body.encrypted_metadata.0,
        body.expected_version,
        body.dek_version,
    )
    .await?;
    Ok(Json(PatchAppResponse { metadata_version }))
}

pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    apps_service::delete_app(state.pool(), app_id, auth.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn leave(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    apps_service::leave_app(state.pool(), app_id, auth.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- staged rotation (SPEC.md §3.1) -----------------------------------------

#[derive(Serialize)]
pub struct RotationResponse {
    pub rotation_id: Uuid,
    pub base_dek_version: i64,
    pub started_at: DateTime<Utc>,
}

pub async fn begin_rotation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
) -> AppResult<(StatusCode, Json<RotationResponse>)> {
    let r = apps_service::begin_rotation(state.pool(), app_id, auth.user_id).await?;
    Ok((
        StatusCode::CREATED,
        Json(RotationResponse {
            rotation_id: r.rotation_id,
            base_dek_version: r.base_dek_version,
            started_at: r.started_at,
        }),
    ))
}

#[derive(Deserialize)]
pub struct StagedRowItem {
    pub id: Uuid,
    pub expected_version: i64,
    pub r#type: String,
    pub format: i16,
    pub encrypted_json: B64,
}

#[derive(Deserialize)]
pub struct StageRequest {
    pub rows: Vec<StagedRowItem>,
}

pub async fn stage_rotation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((app_id, rotation_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<StageRequest>,
) -> AppResult<StatusCode> {
    let rows = body
        .rows
        .into_iter()
        .map(|r| StagedRow {
            data_id: r.id,
            expected_version: r.expected_version,
            r#type: r.r#type,
            format: r.format,
            encrypted_json: r.encrypted_json.0,
        })
        .collect();
    apps_service::stage_rotation_rows(state.pool(), app_id, auth.user_id, rotation_id, rows).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct AccessItem {
    pub user_id: Uuid,
    pub wrapped_dek: B64,
}

#[derive(Deserialize)]
pub struct CommitRequest {
    pub encrypted_metadata: B64,
    pub expected_metadata_version: i64,
    /// Every member who keeps access, pending invitees included, each with
    /// the new DEK sealed to them. Members left out are removed.
    pub access: Vec<AccessItem>,
}

#[derive(Serialize)]
pub struct CommitResponse {
    pub metadata_version: i64,
    pub dek_version: i64,
}

pub async fn commit_rotation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((app_id, rotation_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<CommitRequest>,
) -> AppResult<Json<CommitResponse>> {
    let access = body.access.into_iter().map(|a| (a.user_id, a.wrapped_dek.0)).collect();
    let r = apps_service::commit_rotation(
        state.pool(),
        app_id,
        auth.user_id,
        rotation_id,
        &body.encrypted_metadata.0,
        body.expected_metadata_version,
        access,
    )
    .await?;
    Ok(Json(CommitResponse { metadata_version: r.metadata_version, dek_version: r.dek_version }))
}

pub async fn abort_rotation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((app_id, rotation_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    apps_service::abort_rotation(state.pool(), app_id, auth.user_id, rotation_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
