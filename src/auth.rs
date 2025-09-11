use std::sync::Arc;

use axum::{
    extract::{Query, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{Redirect, Response},
};
use axum_extra::extract::{cookie::Cookie, CookieJar, Host};
use http::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RequestTokenError, TokenResponse, TokenUrl,
};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use ureq::Agent;
use uuid::{NoContext, Timestamp, Uuid};
use worker::send;

use crate::{error::AppError, AppState};

fn get_client(
    state: Arc<AppState>,
    hostname: String,
) -> BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet> {
    // Environment variables are guaranteed to exist, safe to unwrap
    let client_id = ClientId::new(state.env.var("GITHUB_CLIENT_ID").unwrap().to_string());
    let client_secret =
        ClientSecret::new(state.env.var("GITHUB_CLIENT_SECRET").unwrap().to_string());

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

    let redirect_url =
        RedirectUrl::new(format!("{}://{}/auth/session", protocol, hostname)).unwrap();

    let client = BasicClient::new(client_id)
        .set_client_secret(client_secret)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);

    client
}

#[derive(Deserialize)]
struct SessionVerifyFields {
    user_id: i32,
    expires_at: String,
}

#[send]
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Fetch session ID
    let headers = request.headers();
    let cookie_jar = CookieJar::from_headers(headers);

    let Some(session_cookie) = cookie_jar.get("session_id") else {
        return Err(AppError::Unauthorised);
    };

    // Check if we have valid session ID (i.e. corresponds to entry in
    // UserSessions table that is not expired)
    let d1 = state.env.d1("DB")?;

    let auth_statement = d1
        .prepare("SELECT (user_id, expires_at) FROM UserSessions WHERE id = ?")
        .bind(&[session_cookie.value().into()])?;

    let Some(session_fields) = auth_statement.first::<SessionVerifyFields>(None).await? else {
        return Err(AppError::Unauthorised);
    };

    // Timestamps stored in database will not be out-of-bounds
    let expires_timestamp = session_fields.expires_at.parse::<i64>().unwrap();
    let expires_at = OffsetDateTime::from_unix_timestamp(expires_timestamp).unwrap();
    if OffsetDateTime::now_utc() >= expires_at {
        return Err(AppError::Unauthorised);
    }

    // Add user ID as Axum extension
    let extensions = request.extensions_mut();
    extensions.insert(session_fields.user_id);

    let response = next.run(request).await;
    Ok(response)
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
    Host(host): Host,
) -> Result<Redirect, AppError> {
    let d1 = state.env.d1("DB")?;

    let client = get_client(state, host);

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

#[derive(Deserialize)]
struct OAuthState {
    pkce_verifier: String,
    return_url: String,
}

#[derive(Deserialize)]
struct GithubUser {
    login: String,
    avatar_url: String,
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
    Host(host): Host,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), AppError> {
    let d1 = state.env.d1("DB")?;

    let client = get_client(state, host);

    // Fetch state left over from `/auth/login`
    let state = CsrfToken::new(query.state);
    let code = AuthorizationCode::new(query.code);

    let fetch_state_statement = d1
        .prepare("DELETE FROM OAuthState WHERE csrf_token = ? RETURNING pkce_verifier, return_url")
        .bind(&[state.secret().into()])?;
    let state = fetch_state_statement
        .first::<OAuthState>(None)
        .await?
        .ok_or(AppError::Unauthorised)?;

    web_sys::console::log_1(&"Retrieved OAuth state data".to_string().into());

    let pkce_verifier = PkceCodeVerifier::new(state.pkce_verifier);

    let http_client: Agent = Agent::config_builder().max_redirects(0).build().into();

    // Fetch access token from server
    let token_response = tokio::task::spawn_blocking(move || {
        client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request(&http_client)
    })
    .await
    .map_err(|e| AppError::Generic(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| match e {
        RequestTokenError::ServerResponse(_) => AppError::Unauthorised,
        RequestTokenError::Request(error) => {
            web_sys::console::log_1(&"Request error".into());
            AppError::Generic(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
        }
        RequestTokenError::Parse(error, bits) => {
            web_sys::console::log_1(&String::from_utf8(bits).unwrap().into());
            AppError::Generic(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
        }
        RequestTokenError::Other(message) => {
            web_sys::console::log_1(&"Other error".into());
            AppError::Generic(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    })?;

    web_sys::console::log_1(&"Fetched access token".to_string().into());
    let access_token = token_response.access_token().secret();

    // Fetch user ID, creating a user if they don't already exist
    let user = ureq::get("https://api.github.com/user")
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {access_token}")).unwrap(),
        )
        .header(
            ACCEPT,
            HeaderValue::from_str("application/vnd.github+json").unwrap(),
        )
        .header(
            "X-Github-Api-Version",
            HeaderValue::from_str("2022-11-28").unwrap(),
        )
        .header(
            USER_AGENT,
            HeaderValue::from_str("hanyuone.live Comments").unwrap(),
        )
        .call()?
        .body_mut()
        .read_json::<GithubUser>()?;

    let user_statement = d1.prepare("SELECT id FROM Users WHERE username = ?");
    let user_query = user_statement.bind(&[user.login.clone().into()])?;

    let user_id = match user_query.first::<i32>(Some("id")).await? {
        Some(id) => id,
        None => {
            let insert_user_statement = d1
                .prepare("INSERT INTO Users(username, avatar_url) VALUES (?, ?) RETURNING id")
                .bind(&[user.login.into(), user.avatar_url.into()])?;

            insert_user_statement
                .first::<i32>(Some("id"))
                .await?
                .unwrap()
        }
    };

    // Create session from user ID
    let created_at = OffsetDateTime::now_utc();
    let expires_at = created_at + Duration::days(1);

    let timestamp = Timestamp::from_unix(NoContext, created_at.unix_timestamp() as u64, 0);
    let session_id = Uuid::new_v7(timestamp).to_string();

    let session_statement = d1
        .prepare(
            "INSERT INTO UserSessions(id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&[
            session_id.clone().into(),
            user_id.into(),
            created_at.unix_timestamp().to_string().into(),
            expires_at.unix_timestamp().to_string().into(),
        ])?;
    session_statement.run().await?;

    // Set session as cookie
    let jar = jar.add(Cookie::build(("session_id", session_id)).expires(expires_at));

    Ok((jar, Redirect::to(&state.return_url)))
}

/// Logs a user out by removing their session cookie.
///
/// # Errors
///
/// This function will return an error if something is wrong with Cloudflare's
/// services.
#[send]
pub async fn logout(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<CookieJar, AppError> {
    // No cookie to remove
    let Some(session_cookie) = jar.get("session_id") else {
        return Ok(jar);
    };

    // Remove session ID from sessions table
    let d1 = state.env.d1("DB")?;
    let session_statement = d1
        .prepare("DELETE FROM UserSessions WHERE session_id = ?")
        .bind(&[session_cookie.value().into()])?;
    session_statement.run().await?;

    // Remove session cookie
    let jar = jar.remove("session_id");
    Ok(jar)
}
