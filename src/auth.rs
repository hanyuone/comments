use std::{env, sync::Arc};

use axum::{
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{AppendHeaders, IntoResponse, Redirect, Response},
};
use axum_extra::extract::Host;
use chrono::Utc;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RequestTokenError, TokenResponse, TokenUrl,
};
use reqwest::{header::AUTHORIZATION, ClientBuilder};
use serde::Deserialize;
use uuid::{NoContext, Timestamp, Uuid};
use worker::send;

use crate::{error::AppError, schema::User, AppState};

fn get_client(
    hostname: String,
) -> BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet> {
    // Environment variables are guaranteed to exist, safe to unwrap
    let client_id = ClientId::new(env::var("GITHUB_CLIENT_ID").unwrap());
    let client_secret = ClientSecret::new(env::var("GITHUB_CLIENT_SECRET").unwrap());

    // GitHub-supplied authorisation/token-distribution URLs
    let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap();
    let token_url =
        TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap();

    // On the client side, redirect back to `/oauth/github`, which will call `/auth/return`
    // to get the access token
    let protocol = if hostname.starts_with("localhost") || hostname.starts_with("127.0.0.1") {
        "http"
    } else {
        "https"
    };

    let redirect_url = RedirectUrl::new(format!("{protocol}//{hostname}/oauth/github")).unwrap();

    let client = BasicClient::new(client_id)
        .set_client_secret(client_secret)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);

    client
}

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let response = next.run(request).await;
    response
}

#[derive(Deserialize)]
pub struct LoginQuery {
    return_url: Option<String>,
}

/// Redirects the user to the GitHub OAuth URL. Access through the endpoint
/// `/auth/login?return_url={}`, where `return_url` is the URL we return to once
/// we get an access token from GitHub.
///
/// # Errors
///
/// This function will return an error if something is wrong with Cloudflare's
/// services.
#[send]
pub async fn login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
    Host(hostname): Host,
) -> Result<Redirect, AppError> {
    let d1 = state.env.d1("DB")?;

    let client = get_client(hostname);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorise_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .url();

    let return_url = query.return_url.unwrap_or("/".to_string());

    // Add information we want to save *between* now and `/auth/access_token` into D1 database,
    // using our unique CSRF token (per-session) as identifier
    let state_statement = d1
        .prepare("INSERT INTO OAuthState(csrf_token, pkce_verifier, return_url) VALUES (?, ?, ?)")
        .bind(&[
            csrf_state.secret().into(),
            pkce_verifier.secret().into(),
            return_url.into(),
        ])?;
    state_statement.run().await?;

    Ok(Redirect::to(authorise_url.as_str()))
}

#[derive(Deserialize)]
pub struct AccessTokenQuery {
    state: String,
    code: String,
}

/// Given a temporary code from GitHub, performs OAuth2 authentication
/// on that code, and returns a user session.
///
/// # Errors
///
/// This function will return an error if:
/// - The user is unauthorised
/// - Something is wrong with Cloudflare's services
/// - Something is wrong with GitHub's OAuth services
#[send]
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AccessTokenQuery>,
    Host(hostname): Host,
) -> Result<impl IntoResponse, AppError> {
    let d1 = state.env.d1("DB")?;

    let client = get_client(hostname);

    // Fetch state left over from `/auth/login`
    let state = CsrfToken::new(query.state);
    let code = AuthorizationCode::new(query.code);

    let fetch_state_statement = d1
        .prepare(
            "DELETE FROM OAuthState WHERE csrf_state = ? RETURNING (pkce_verifier, return_url)",
        )
        .bind(&[state.secret().into()])?;
    let (pkce_verifier, return_url) = fetch_state_statement
        .first::<(String, String)>(None)
        .await?
        .ok_or(AppError::Unauthorised)?;

    let pkce_verifier = PkceCodeVerifier::new(pkce_verifier);

    // Fetch access token from server
    let token_response = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(&oauth2::reqwest::Client::new())
        .await
        .map_err(|e| match e {
            RequestTokenError::ServerResponse(_) => AppError::Unauthorised,
            RequestTokenError::Request(error) => {
                AppError::Generic(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            }
            RequestTokenError::Parse(error, _) => {
                AppError::Generic(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            }
            RequestTokenError::Other(message) => {
                AppError::Generic(StatusCode::INTERNAL_SERVER_ERROR, message)
            }
        })?;

    let access_token = token_response.access_token().secret();

    // Fetch user ID, creating a user if they don't already exist
    let mut headers = HeaderMap::new();
    headers.append(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {access_token}")).unwrap(),
    );

    let client = ClientBuilder::new().default_headers(headers).build()?;
    let user = client
        .get("https://api.github.com/user")
        .send()
        .await?
        .json::<User>()
        .await?;

    let user_statement = d1.prepare("SELECT id FROM Users WHERE username = ?");
    let user_query = user_statement.bind(&[user.username.clone().into()])?;

    let user_id = match user_query.first::<i32>(Some("id")).await? {
        Some(id) => id,
        None => {
            let insert_user_statement = d1
                .prepare("INSERT INTO Users(username, avatar_url) VALUES (?, ?) RETURNING id")
                .bind(&[user.username.into(), user.avatar_url.into()])?;

            insert_user_statement
                .first::<i32>(Some("id"))
                .await?
                .unwrap()
        }
    };

    // Create session from user ID
    let created_at = Utc::now().timestamp();
    let timestamp = Timestamp::from_unix(NoContext, created_at as u64, 0);
    let session_id = Uuid::new_v7(timestamp).to_string();

    let session_statement = d1
        .prepare(
            "INSERT INTO UserSessions(id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&[
            session_id.clone().into(),
            user_id.into(),
            created_at.into(),
            (created_at + 60 * 60 * 24).into(),
        ])?;
    session_statement.run().await?;

    // Set session as cookie
    let headers = AppendHeaders([(
        axum::http::header::SET_COOKIE,
        "session_token=".to_owned() + &session_id + "; path=/; httponly; secure; samesite=strict",
    )]);

    Ok((headers, Redirect::to(&return_url)))
}

pub async fn logout() -> Result<(), AppError> {
    Ok(())
}
