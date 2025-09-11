use std::sync::Arc;

use axum::{
    extract::{Path, State},
    middleware,
    routing::{delete, get},
    Extension, Router,
};
use http::StatusCode;
use serde::Deserialize;
use std::result::Result;
use tower_http::cors::CorsLayer;
use tower_service::Service;
use worker::*;

use crate::{
    auth::{auth_middleware, get_session, login, logout},
    error::AppError,
    schema::{Comment, Post, User},
};

mod auth;
mod error;
mod schema;

struct AppState {
    env: Env,
}

#[send]
async fn get_profile(
    State(state): State<Arc<AppState>>,
    Extension(user_id): Extension<i32>,
) -> Result<axum::Json<User>, AppError> {
    let d1 = state.env.d1("DB")?;

    let profile_statement = d1
        .prepare("SELECT * FROM Users WHERE id = ?")
        .bind(&[user_id.into()])?;

    let Some(profile) = profile_statement.first::<User>(None).await? else {
        return Err(AppError::Generic(
            StatusCode::INTERNAL_SERVER_ERROR,
            "User not found".to_string(),
        ));
    };

    Ok(axum::Json(profile))
}

#[send]
async fn get_post(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Result<axum::Json<Post>, AppError> {
    let d1 = state.env.d1("DB")?;

    // Fetch ID of slug, which we will need for the `Comments` table
    let slug_statement = d1.prepare("SELECT * FROM Posts WHERE name = ?1");
    let slug_query = slug_statement.bind(&[slug.clone().into()])?;
    let slug_result = slug_query.first::<Post>(None).await?;

    // If ID doesn't exist, raise error
    let Some(post) = slug_result else {
        return Err(AppError::PostNotFound(slug.clone()));
    };

    Ok(axum::Json(post))
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
    Path(post_id): Path<i32>,
) -> Result<axum::Json<Vec<Comment>>, AppError> {
    let d1 = state.env.d1("DB")?;

    let comments_statement = d1.prepare("SELECT * FROM Comments WHERE post_id = ?1");
    let comments_query = comments_statement.bind(&[post_id.into()])?;
    let comments = comments_query.all().await?.results::<Comment>()?;

    Ok(axum::Json(comments))
}

#[derive(Deserialize)]
pub struct CreateComment {
    pub contents: String,
}

#[send]
async fn create_comment(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<i32>,
    Extension(user_id): Extension<i32>,
    axum::extract::Json(payload): axum::extract::Json<CreateComment>,
) -> Result<(), AppError> {
    let d1 = state.env.d1("DB")?;

    let comments_statement =
        d1.prepare("INSERT INTO Comments(post_id, user_id, contents) VALUES (?1, ?2, ?3)");
    let comments_query =
        comments_statement.bind(&[post_id.into(), user_id.into(), payload.contents.into()])?;
    comments_query.run().await?;

    Ok(())
}

#[event(fetch, respond_with_errors)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>, worker::Error> {
    console_error_panic_hook::set_once();

    let shared_state = Arc::new(AppState { env });

    // CORS support
    let cors_layer = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE])
        .allow_origin(["http://localhost:8080".parse().unwrap()]);

    let mut router = Router::new()
        // Endpoints requiring login
        .route("/profile", get(get_profile))
        .route("/post/{slug}", get(get_post).post(create_post))
        .route("/comment/{id}", get(get_comments).post(create_comment))
        .route_layer(middleware::from_fn_with_state(
            shared_state.clone(),
            auth_middleware,
        ))
        // Authorisation
        .route("/auth/login", get(login))
        .route("/auth/session", get(get_session))
        .route("/auth/logout", delete(logout))
        .layer(cors_layer)
        .with_state(shared_state);

    Ok(router.call(req).await?)
}
