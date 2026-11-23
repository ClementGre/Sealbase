use axum::Json;
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::bytes::B64;
use crate::api::extractors::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::{AppData, Tombstone};
use crate::repository::apps_data::{NewRow, RowUpdate};
use crate::service::data::{self as data_service, Batch, BatchResult, DeleteItem, OnConflict, Order};
use crate::state::AppState;

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 1000;

#[derive(Serialize)]
pub struct DataResponse {
    pub id: Uuid,
    pub r#type: String,
    pub format: i16,
    pub encrypted_json: B64,
    pub date: DateTime<Utc>,
    pub edited_at: DateTime<Utc>,
    pub version: i64,
}

impl From<AppData> for DataResponse {
    fn from(d: AppData) -> Self {
        DataResponse {
            id: d.id,
            r#type: d.r#type,
            format: d.format,
            encrypted_json: d.encrypted_json.into(),
            date: d.date,
            edited_at: d.edited_at,
            version: d.version,
        }
    }
}

// --- request shapes ---------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateItem {
    pub id: Uuid,
    pub r#type: String,
    pub format: i16,
    pub encrypted_json: B64,
    /// Client-controlled, plaintext, queryable (SPEC.md §5).
    pub date: DateTime<Utc>,
}

impl From<CreateItem> for NewRow {
    fn from(c: CreateItem) -> Self {
        NewRow { id: c.id, r#type: c.r#type, format: c.format, encrypted_json: c.encrypted_json.0, date: c.date }
    }
}

#[derive(Deserialize)]
pub struct UpdateItem {
    pub id: Uuid,
    pub expected_version: i64,
    pub encrypted_json: B64,
    /// May change together with the ciphertext (its AAD binds the type), e.g.
    /// when migrating a legacy row to a blind type tag.
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub format: Option<i16>,
    #[serde(default)]
    pub date: Option<DateTime<Utc>>,
}

impl From<UpdateItem> for RowUpdate {
    fn from(u: UpdateItem) -> Self {
        RowUpdate {
            id: u.id,
            expected_version: u.expected_version,
            encrypted_json: u.encrypted_json.0,
            r#type: u.r#type,
            format: u.format,
            date: u.date,
        }
    }
}

#[derive(Deserialize)]
pub struct DeleteRequestItem {
    pub id: Uuid,
    pub expected_version: i64,
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum OnConflictParam {
    #[default]
    Error,
    Skip,
}

#[derive(Deserialize)]
pub struct BatchRequest {
    #[serde(default)]
    pub dek_version: Option<i64>,
    #[serde(default)]
    pub on_conflict: OnConflictParam,
    #[serde(default)]
    pub create: Vec<CreateItem>,
    #[serde(default)]
    pub update: Vec<UpdateItem>,
    #[serde(default)]
    pub delete: Vec<DeleteRequestItem>,
}

#[derive(Serialize)]
pub struct BatchResponse {
    pub created: Vec<DataResponse>,
    pub skipped: Vec<Uuid>,
    pub updated: Vec<DataResponse>,
    pub deleted: Vec<Uuid>,
}

impl From<BatchResult> for BatchResponse {
    fn from(r: BatchResult) -> Self {
        BatchResponse {
            created: r.created.into_iter().map(Into::into).collect(),
            skipped: r.skipped,
            updated: r.updated.into_iter().map(Into::into).collect(),
            deleted: r.deleted,
        }
    }
}

// --- handlers -----------------------------------------------------------

pub async fn batch(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
    Json(body): Json<BatchRequest>,
) -> AppResult<Json<BatchResponse>> {
    let batch = Batch {
        dek_version: body.dek_version,
        on_conflict: match body.on_conflict {
            OnConflictParam::Error => OnConflict::Error,
            OnConflictParam::Skip => OnConflict::Skip,
        },
        create: body.create.into_iter().map(Into::into).collect(),
        update: body.update.into_iter().map(Into::into).collect(),
        delete: body
            .delete
            .into_iter()
            .map(|d| DeleteItem { id: d.id, expected_version: d.expected_version })
            .collect(),
    };
    let result = data_service::apply_batch(state.pool(), app_id, auth.user_id, batch).await?;
    Ok(Json(result.into()))
}

#[derive(Deserialize)]
pub struct CreateRequest {
    #[serde(flatten)]
    pub item: CreateItem,
    pub dek_version: i64,
}

pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
    Json(body): Json<CreateRequest>,
) -> AppResult<(StatusCode, Json<DataResponse>)> {
    let batch = Batch {
        dek_version: Some(body.dek_version),
        on_conflict: OnConflict::Error,
        create: vec![body.item.into()],
        update: vec![],
        delete: vec![],
    };
    let mut result = data_service::apply_batch(state.pool(), app_id, auth.user_id, batch).await?;
    let row = result.created.pop().ok_or_else(|| anyhow::anyhow!("insert returned no row"))?;
    Ok((StatusCode::CREATED, Json(row.into())))
}

#[derive(Deserialize)]
pub struct PatchRequest {
    pub expected_version: i64,
    pub dek_version: i64,
    pub encrypted_json: B64,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub format: Option<i16>,
    #[serde(default)]
    pub date: Option<DateTime<Utc>>,
}

pub async fn patch(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((app_id, data_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<PatchRequest>,
) -> AppResult<Json<DataResponse>> {
    let batch = Batch {
        dek_version: Some(body.dek_version),
        on_conflict: OnConflict::Error,
        create: vec![],
        update: vec![RowUpdate {
            id: data_id,
            expected_version: body.expected_version,
            encrypted_json: body.encrypted_json.0,
            r#type: body.r#type,
            format: body.format,
            date: body.date,
        }],
        delete: vec![],
    };
    let mut result = data_service::apply_batch(state.pool(), app_id, auth.user_id, batch)
        .await
        .map_err(data_service::single_row_error)?;
    let row = result.updated.pop().ok_or_else(|| anyhow::anyhow!("update returned no row"))?;
    Ok(Json(row.into()))
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    pub version: i64,
}

pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((app_id, data_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<DeleteQuery>,
) -> AppResult<StatusCode> {
    let batch = Batch {
        dek_version: None,
        on_conflict: OnConflict::Error,
        create: vec![],
        update: vec![],
        delete: vec![DeleteItem { id: data_id, expected_version: query.version }],
    };
    data_service::apply_batch(state.pool(), app_id, auth.user_id, batch)
        .await
        .map_err(data_service::single_row_error)?;
    Ok(StatusCode::NO_CONTENT)
}

// --- listing ----------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct CursorPayload {
    /// Which sort key the cursor belongs to: "date" or "edited".
    o: String,
    k: DateTime<Utc>,
    id: Uuid,
}

fn order_name(order: Order) -> &'static str {
    match order {
        Order::Date => "date",
        Order::Edited => "edited",
    }
}

fn decode_cursor(cursor: &str, expected_order: &str) -> AppResult<(DateTime<Utc>, Uuid)> {
    let invalid = || AppError::BadRequest("invalid cursor".into());
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| invalid())?;
    let payload: CursorPayload = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if payload.o != expected_order {
        return Err(AppError::BadRequest("cursor belongs to a different order".into()));
    }
    Ok((payload.k, payload.id))
}

fn encode_cursor(order: &str, key: DateTime<Utc>, id: Uuid) -> String {
    let payload = CursorPayload { o: order.to_string(), k: key, id };
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("cursor payload always serializes"))
}

fn parse_time(name: &str, value: &str) -> AppResult<DateTime<Utc>> {
    value
        .parse::<DateTime<Utc>>()
        .map_err(|_| AppError::BadRequest(format!("{name} must be an RFC 3339 timestamp")))
}

/// Query string for `GET /apps/:id/data`. Parsed by hand because `type` may
/// repeat (`?type=a&type=b`), which lets a client query a legacy plaintext
/// type and its blind tag in one go during migration.
#[derive(Default)]
struct ListQuery {
    types: Vec<String>,
    format: Option<i16>,
    date_from: Option<DateTime<Utc>>,
    date_to: Option<DateTime<Utc>>,
    edited_from: Option<DateTime<Utc>>,
    edited_to: Option<DateTime<Utc>>,
    order: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

fn parse_list_query(raw: Option<&str>) -> AppResult<ListQuery> {
    let pairs: Vec<(String, String)> = serde_urlencoded::from_str(raw.unwrap_or(""))
        .map_err(|_| AppError::BadRequest("invalid query string".into()))?;
    let mut q = ListQuery::default();
    for (key, value) in pairs {
        match key.as_str() {
            "type" => q.types.push(value),
            "format" => {
                q.format = Some(value.parse().map_err(|_| AppError::BadRequest("format must be 1 or 2".into()))?)
            }
            "date_from" => q.date_from = Some(parse_time(&key, &value)?),
            "date_to" => q.date_to = Some(parse_time(&key, &value)?),
            "edited_from" => q.edited_from = Some(parse_time(&key, &value)?),
            "edited_to" => q.edited_to = Some(parse_time(&key, &value)?),
            "order" => q.order = Some(value),
            "limit" => q.limit = Some(value.parse().map_err(|_| AppError::BadRequest("invalid limit".into()))?),
            "cursor" => q.cursor = Some(value),
            _ => return Err(AppError::BadRequest(format!("unknown query parameter {key}"))),
        }
    }
    Ok(q)
}

#[derive(Serialize)]
pub struct ListResponse {
    pub data: Vec<DataResponse>,
    pub next_cursor: Option<String>,
    /// Server clock read before the query: the watermark for the next
    /// incremental sync (`edited_from`).
    pub server_time: DateTime<Utc>,
    /// The app's current key epoch; a cached client that sees it change must
    /// reload the app (new DEK) and drop its cached ciphertext.
    pub dek_version: i64,
}

pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
    RawQuery(raw): RawQuery,
) -> AppResult<Json<ListResponse>> {
    let q = parse_list_query(raw.as_deref())?;
    let order = match q.order.as_deref() {
        None | Some("date") => Order::Date,
        Some("edited") => Order::Edited,
        Some(_) => return Err(AppError::BadRequest("order must be 'date' or 'edited'".into())),
    };
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let cursor = q.cursor.as_deref().map(|c| decode_cursor(c, order_name(order))).transpose()?;

    let (rows, meta) = data_service::list(
        state.pool(),
        app_id,
        auth.user_id,
        data_service::ListParams {
            types: (!q.types.is_empty()).then_some(q.types),
            format: q.format,
            date_from: q.date_from,
            date_to: q.date_to,
            edited_from: q.edited_from,
            edited_to: q.edited_to,
            order,
            cursor,
            limit,
        },
    )
    .await?;

    let next_cursor = if rows.len() as i64 == limit {
        rows.last().map(|r| {
            let key = match order {
                Order::Date => r.date,
                Order::Edited => r.edited_at,
            };
            encode_cursor(order_name(order), key, r.id)
        })
    } else {
        None
    };

    Ok(Json(ListResponse {
        data: rows.into_iter().map(DataResponse::from).collect(),
        next_cursor,
        server_time: meta.server_time,
        dek_version: meta.dek_version,
    }))
}

#[derive(Deserialize)]
pub struct DeletedQuery {
    pub since: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
pub struct TombstoneResponse {
    pub id: Uuid,
    pub deleted_at: DateTime<Utc>,
}

impl From<Tombstone> for TombstoneResponse {
    fn from(t: Tombstone) -> Self {
        TombstoneResponse { id: t.id, deleted_at: t.deleted_at }
    }
}

#[derive(Serialize)]
pub struct DeletedResponse {
    pub deleted: Vec<TombstoneResponse>,
    pub next_cursor: Option<String>,
    pub server_time: DateTime<Utc>,
    pub dek_version: i64,
}

/// Ids deleted since `since`, so a cached client can drop them locally.
pub async fn list_deleted(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
    Query(q): Query<DeletedQuery>,
) -> AppResult<Json<DeletedResponse>> {
    let limit = q.limit.unwrap_or(MAX_LIMIT).clamp(1, MAX_LIMIT);
    let cursor = q.cursor.as_deref().map(|c| decode_cursor(c, "deleted")).transpose()?;
    let (rows, meta) =
        data_service::list_deleted(state.pool(), app_id, auth.user_id, q.since, cursor, limit).await?;
    let next_cursor = if rows.len() as i64 == limit {
        rows.last().map(|t| encode_cursor("deleted", t.deleted_at, t.id))
    } else {
        None
    };
    Ok(Json(DeletedResponse {
        deleted: rows.into_iter().map(Into::into).collect(),
        next_cursor,
        server_time: meta.server_time,
        dek_version: meta.dek_version,
    }))
}
