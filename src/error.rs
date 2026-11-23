use axum::{Json, http::StatusCode, response::IntoResponse, response::Response};
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    /// 409 with a machine-readable `code` (e.g. `version_conflict`,
    /// `stale_dek`, `duplicate_id`) and optional structured `details`, so
    /// clients can react without parsing the message.
    #[error("{message}")]
    Conflict {
        code: &'static str,
        message: String,
        details: Option<Value>,
    },
    #[error("too many requests")]
    TooManyRequests,
    #[error(transparent)]
    Database(sqlx::Error),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        AppError::Conflict { code, message: message.into(), details: None }
    }

    pub fn conflict_with(code: &'static str, message: impl Into<String>, details: Value) -> Self {
        AppError::Conflict { code, message: message.into(), details: Some(details) }
    }

    /// The caller's ciphertext was produced under a DEK that has since been
    /// rotated away (SPEC.md §3.1): it must reload the app and retry.
    pub fn stale_dek() -> Self {
        AppError::conflict("stale_dek", "the app's key was rotated; reload the app and retry")
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        // A unique-key violation means a client-generated id is already taken
        // (e.g. a deterministic data id being re-imported). That is the
        // caller's conflict, not a server fault.
        if let sqlx::Error::Database(db) = &err
            && db.code().as_deref() == Some("23505")
        {
            return AppError::conflict("duplicate_id", "a resource with this id already exists");
        }
        AppError::Database(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, json!({ "error": msg })),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, json!({ "error": self.to_string() })),
            AppError::Forbidden => (StatusCode::FORBIDDEN, json!({ "error": self.to_string() })),
            AppError::NotFound => (StatusCode::NOT_FOUND, json!({ "error": self.to_string() })),
            AppError::Conflict { code, message, details } => {
                let mut body = json!({ "error": message, "code": code });
                if let Some(details) = details {
                    body["details"] = details.clone();
                }
                (StatusCode::CONFLICT, body)
            }
            AppError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, json!({ "error": self.to_string() })),
            AppError::Database(err) => {
                tracing::error!(?err, "database error");
                (StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": "internal error" }))
            }
            AppError::Internal(err) => {
                tracing::error!(?err, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": "internal error" }))
            }
        };
        (status, Json(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
