use axum::{extract::Path, routing::get, Router};
use tower_service::Service;
use worker::*;

async fn get_comments(Path(slug): Path<String>) -> String {
    slug
}

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    _env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();

    let mut router = Router::new().route("/{slug}", get(get_comments));
    Ok(router.call(req).await?)
}
