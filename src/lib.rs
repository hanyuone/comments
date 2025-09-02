use std::sync::Arc;

use axum::{
    extract::{Path, State},
    middleware,
    routing::{delete, get, post},
    Router,
};
use dotenv::dotenv;
use std::result::Result;
use tower_service::Service;
use worker::*;

use crate::{
    auth::{auth_middleware, get_session, login, logout},
    error::AppError,
    schema::{Comment, NewComment, Post},
};

mod auth;
mod error;
mod schema;

struct AppState {
    env: Env,
}

#[send]
async fn get_post(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Result<axum::Json<Post>, AppError> {
    let d1 = state.env.d1("DB")?;

    // Fetch ID of slug, which we will need for the `Comments` table
    let slug_statement = d1.prepare("SELECT id FROM Posts WHERE name = ?1");
    let slug_query = slug_statement.bind(&[slug.clone().into()])?;
    let slug_result = slug_query.first::<i32>(Some("id")).await?;

    // If ID doesn't exist, raise error
    let Some(id) = slug_result else {
        return Err(AppError::PostNotFound(slug.clone()));
    };

    Ok(axum::Json(Post { id }))
}

#[send]
async fn create_post(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Result<(), AppError> {
    let d1 = state.env.d1("DB")?;

    let slug_statement = d1.prepare("INSERT INTO Posts(name) VALUES (?1)");
    let slug_query = slug_statement.bind(&[slug.clone().into()])?;
    slug_query.run().await?;

    Ok(())
}

// Annotation required for D1 (which uses JsFuture) to play nice with Axum
#[send]
async fn get_comments(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
) -> Result<axum::Json<Vec<Comment>>, AppError> {
    let d1 = state.env.d1("DB")?;

    let comments_statement =
        d1.prepare("SELECT id, username, contents FROM Comments WHERE post_id = ?1");
    let comments_query = comments_statement.bind(&[id.into()])?;
    let comments = comments_query.all().await?.results::<Comment>()?;

    Ok(axum::Json(comments))
}

#[send]
async fn create_comment(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
    axum::extract::Json(payload): axum::extract::Json<NewComment>,
) -> Result<(), AppError> {
    let d1 = state.env.d1("DB")?;

    let comments_statement =
        d1.prepare("INSERT INTO Comments(post_id, username, contents) VALUES (?1, ?2, ?3)");
    let comments_query =
        comments_statement.bind(&[id.into(), payload.username.into(), payload.contents.into()])?;
    comments_query.run().await?;

    Ok(())
}

#[event(fetch, respond_with_errors)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>, worker::Error> {
    dotenv().ok();

    console_error_panic_hook::set_once();

    let shared_state = Arc::new(AppState { env });

    let mut router = Router::new()
        // Endpoints requiring login
        .route("/post/{slug}", get(get_post).post(create_post))
        .route("/comment/{id}", get(get_comments).post(create_comment))
        .route_layer(middleware::from_fn_with_state(
            shared_state.clone(),
            auth_middleware,
        ))
        // Authorisation
        .route("/auth/login", post(login))
        .route("/auth/access_token", post(get_session))
        .route("/auth/logout", delete(logout))
        .with_state(shared_state);

    Ok(router.call(req).await?)
}
