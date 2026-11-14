//! The custom protocol's side of the window: a request from the webview,
//! as `wry` hands it over, goes to the UI's `Router` in this process, and
//! the whole answer comes back. There is no socket anywhere on this path.

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Response, StatusCode, Uri};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

/// The custom protocol's name, as pages are loaded from it
/// (`pathwarden://localhost/`).
pub const SCHEME: &str = "pathwarden";

/// The app's origin in WebView2, with `wry`'s HTTPS mapping of the custom
/// protocol (`pathwarden://` becomes `https://pathwarden.localhost`).
pub const ORIGIN: &str = "https://pathwarden.localhost";

/// The `Host` every request is given, matching [`ORIGIN`].
pub const HOST: &str = "pathwarden.localhost";

/// The largest request body the window accepts. Through a custom protocol
/// the webview hands over a body in one piece, in memory, so large
/// collector files are never uploaded in the window: they are picked with
/// a native dialog and analyzed by path. This only stops a stray upload.
pub const MAX_BODY: usize = 64 << 20;

/// Whether `url` is one of the app's own pages.
pub fn is_internal(url: &str) -> bool {
    url.strip_prefix(ORIGIN)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Turns the webview's request into one for the router: only the path and
/// query are kept, and `Host` is the window's own.
pub fn to_router(req: Request<Vec<u8>>) -> Request<Body> {
    let (mut parts, body) = req.into_parts();
    parts.uri = parts
        .uri
        .path_and_query()
        .and_then(|pq| pq.as_str().parse::<Uri>().ok())
        .unwrap_or_else(|| Uri::from_static("/"));
    parts
        .headers
        .insert(header::HOST, HeaderValue::from_static(HOST));
    Request::from_parts(parts, Body::from(body))
}

/// A JSON error answer, as the UI's own API gives them.
pub fn json_error(status: StatusCode, message: &str) -> Response<Vec<u8>> {
    let mut r = Response::new(
        serde_json::json!({ "error": message })
            .to_string()
            .into_bytes(),
    );
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

/// Serves one request from the webview through `router`.
pub async fn serve(router: Router, req: Request<Vec<u8>>) -> Response<Vec<u8>> {
    if req.body().len() > MAX_BODY {
        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "In the Pathwarden window, choose collector files with the file picker (or drop them on the window) instead of uploading them.",
        );
    }
    let res = match router.oneshot(to_router(req)).await {
        Ok(r) => r,
        Err(never) => match never {},
    };
    let (parts, body) = res.into_parts();
    match body.collect().await {
        Ok(b) => Response::from_parts(parts, b.to_bytes().to_vec()),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The answer was cut short.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::http::Method;
    use pathwarden_ui::server::{router, AppState};
    use pathwarden_ui::workspace::Workspace;

    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn app(name: &str) -> (Router, Dir) {
        let dir =
            std::env::temp_dir().join(format!("pathwarden-desktop-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = AppState::embedded(Workspace::open(&dir).unwrap(), ORIGIN).unwrap();
        (router(Arc::new(state)), Dir(dir))
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// As wry hands it over: the custom-protocol URI, no Host.
    fn webview_get(uri: &str) -> Request<Vec<u8>> {
        Request::get(uri).body(Vec::new()).unwrap()
    }

    #[test]
    fn pages_and_assets_come_through() {
        let (router, _dir) = app("pages");
        let rt = rt();
        for uri in [
            "pathwarden://localhost/",
            "https://pathwarden.localhost/analyze",
            "pathwarden://localhost/static/app.css",
            "pathwarden://localhost/static/app.js",
            "/runs",
        ] {
            let res = rt.block_on(serve(router.clone(), webview_get(uri)));
            assert_eq!(res.status(), StatusCode::OK, "{uri}");
            assert!(res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        }
        let res = rt.block_on(serve(router, webview_get("pathwarden://localhost/nope")));
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn changes_need_the_window_origin() {
        let (router, _dir) = app("origin");
        let rt = rt();
        let delete = |origin: &str| {
            Request::builder()
                .method(Method::DELETE)
                .uri("pathwarden://localhost/api/runs/x")
                .header(header::ORIGIN, origin)
                .body(Vec::new())
                .unwrap()
        };
        let res = rt.block_on(serve(router.clone(), delete("null")));
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let res = rt.block_on(serve(router, delete(ORIGIN)));
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn large_bodies_are_refused() {
        let (router, _dir) = app("large");
        let req = Request::post("pathwarden://localhost/api/analyze")
            .header(header::ORIGIN, ORIGIN)
            .body(vec![0u8; MAX_BODY + 1])
            .unwrap();
        let res = rt().block_on(serve(router, req));
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn internal_urls() {
        assert!(is_internal("https://pathwarden.localhost"));
        assert!(is_internal("https://pathwarden.localhost/runs/x/report"));
        assert!(!is_internal("https://pathwarden.localhost.evil.example/"));
        assert!(!is_internal("http://pathwarden.localhost/"));
        assert!(!is_internal("https://example.com/"));
    }
}
