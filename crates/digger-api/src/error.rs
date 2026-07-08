/// Structured error types for the API.
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal error: {0}")]
    InternalError(String),
    #[error("job not found: {0}")]
    JobNotFound(String),
}

impl From<digger_platform::storage::StorageError> for ApiError {
    fn from(e: digger_platform::storage::StorageError) -> Self {
        use digger_platform::storage::ErrorKind;
        match e.kind {
            ErrorKind::NotFound => ApiError::NotFound(e.message),
            _ => ApiError::InternalError(e.message),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::InternalError(msg) => {
                // M1 FIX: Sanitize internal errors — strip file paths and system details
                let safe = sanitize_error_message(&msg);
                (StatusCode::INTERNAL_SERVER_ERROR, safe)
            }
            ApiError::JobNotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };

        let body = serde_json::json!({
            "error": {
                "code": status.canonical_reason().unwrap_or("ERROR").to_uppercase().replace(' ', "_"),
                "message": message,
            }
        });

        (status, axum::Json(body)).into_response()
    }
}

/// M1 FIX: Remove file paths and system details from error messages sent to clients.
fn sanitize_error_message(msg: &str) -> String {
    // Remove anything that looks like a file path (C:\, /home/, /tmp/, etc.)
    let sanitized = msg
        .replace(|c: char| c == '\\' && !msg.starts_with('\\'), "/")
        .split_whitespace()
        .filter(|word| {
            !word.contains(":\\")
                && !word.starts_with("/tmp/")
                && !word.starts_with("/home/")
                && !word.starts_with("/var/")
                && !word.starts_with("/usr/")
                && !word.starts_with("/app/")
                && !word.starts_with(".digger")
                && !word.ends_with(".json")
                && !word.ends_with(".rs")
        })
        .collect::<Vec<_>>()
        .join(" ");

    if sanitized.trim().is_empty() {
        "An internal error occurred".into()
    } else {
        sanitized
    }
}
