use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use std::result::Result;
use tower_service::Service;
use worker::*;

use crate::schema::Comment;

mod schema;

struct AppState {
    env: Env,
}

enum AppError {
    WorkerError(worker::Error),
    PostNotFound(String),
}

impl From<worker::Error> for AppError {
    fn from(value: worker::Error) -> Self {
        AppError::WorkerError(value)
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AppError::WorkerError(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
            AppError::PostNotFound(slug) => (
                StatusCode::NOT_FOUND,
                format!("Could not find post with slug {slug} in database"),
            ),
        }
        .into_response()
    }
}

// Annotation required for D1 (which uses JsFuture) to play nice with Axum
#[send]
async fn get_comments(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Result<axum::Json<Vec<Comment>>, AppError> {
    let d1 = state.env.d1("DB")?;

    // Fetch ID of slug, which we will need for the `Comments` table
    let slug_statement = d1.prepare("SELECT id FROM Posts WHERE name = ?1");
    let slug_query = slug_statement.bind(&[slug.clone().into()])?;
    let slug_result = slug_query.first::<i32>(Some("id")).await?;

    // If ID doesn't exist, raise error
    let Some(id) = slug_result else {
        return Err(AppError::PostNotFound(slug.clone()));
    };

    let comments_statement =
        d1.prepare("SELECT id, username, contents FROM Comments WHERE post_id = ?1");
    let comments_query = comments_statement.bind(&[id.into()])?;
    let comments = comments_query.all().await?.results::<Comment>()?;

    Ok(axum::Json(comments))
}

#[event(fetch, respond_with_errors)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>, worker::Error> {
    console_error_panic_hook::set_once();

    let shared_state = Arc::new(AppState { env });

    let mut router = Router::new()
        .route("/{slug}", get(get_comments))
        .with_state(shared_state);

    Ok(router.call(req).await?)
}
