use axum::{http::StatusCode, response::IntoResponse};

pub(crate) enum AppError {
    // User is not authorised
    Unauthorised,
    // Post doesn't exist
    PostNotFound(String),
    // Catch-all error, usually used to map to
    Generic(StatusCode, String),
    // Errors with Reqwest
    ReqwestError(reqwest::Error),
    // Errors with Cloudflare Workers
    WorkerError(worker::Error),
}

impl From<reqwest::Error> for AppError {
    fn from(value: reqwest::Error) -> Self {
        AppError::ReqwestError(value)
    }
}

impl From<worker::Error> for AppError {
    fn from(value: worker::Error) -> Self {
        AppError::WorkerError(value)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AppError::Unauthorised => (StatusCode::UNAUTHORIZED, "Unauthorised".to_string()),
            AppError::PostNotFound(slug) => (
                StatusCode::NOT_FOUND,
                format!("Could not find post with slug {slug} in database"),
            ),
            AppError::Generic(status_code, message) => (status_code, message),
            AppError::ReqwestError(error) => {
                if error.is_status() {
                    (error.status().unwrap(), error.to_string())
                } else {
                    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
                }
            }
            AppError::WorkerError(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        }
        .into_response()
    }
}
