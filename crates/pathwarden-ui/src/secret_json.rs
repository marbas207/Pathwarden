//! A JSON body extractor for requests that carry a password (collect,
//! retest): like `axum::Json`, but the request body is zeroed once parsed
//! and errors never quote the body. Errors are `{"error": "..."}`, like the
//! rest of the JSON API.
//!
//! Best effort: hyper's receive buffers, and the scratch buffer serde_json
//! uses for strings with escapes, are not reached. The parsed password itself
//! lives in a zeroing `Secret`.

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::DeserializeOwned;
use zeroize::Zeroize;

pub struct SecretJson<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for SecretJson<T> {
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Response> {
        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
        if !is_json {
            return Err(error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Expected request with `Content-Type: application/json`",
            ));
        }
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|e| error(e.status(), &e.body_text()))?;
        let parsed = parse(&body);
        wipe(body);
        parsed
            .map(SecretJson)
            .map_err(|(status, message)| error(status, &message))
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, (StatusCode, String)> {
    serde_json::from_slice(body).map_err(|e| {
        // serde's message can quote the offending value: a password.
        let status = if e.is_data() {
            StatusCode::UNPROCESSABLE_ENTITY
        } else {
            StatusCode::BAD_REQUEST
        };
        let message = format!(
            "invalid request body (line {}, column {})",
            e.line(),
            e.column()
        );
        (status, message)
    })
}

/// Zeroes the body if this is its only reference.
fn wipe(body: Bytes) {
    if let Ok(mut owned) = body.try_into_mut() {
        owned[..].zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[derive(serde::Deserialize, Debug)]
    struct Form {
        #[allow(dead_code)]
        password: u32,
    }

    #[test]
    fn body_is_zeroed_and_errors_do_not_quote_it() {
        let body = Bytes::from(br#"{"password":"hunter2"}"#.to_vec());
        let ptr = body.as_ptr();
        let len = body.len();
        let copy = body.clone();
        // A data error (string, not number) must not echo the value.
        let err = parse::<Form>(&body).unwrap_err();
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!err.1.contains("hunter2"), "{}", err.1);
        drop(copy);
        let mut owned = body.try_into_mut().unwrap();
        assert_eq!(owned.as_ptr(), ptr, "same buffer, not a copy");
        owned[..].zeroize();
        assert!(owned.iter().all(|&b| b == 0) && owned.len() == len);
    }

    #[tokio::test]
    async fn extractor_parses_and_checks_the_content_type() {
        #[derive(serde::Deserialize)]
        struct Ok1 {
            password: String,
        }
        let req = |ct: &str| {
            Request::builder()
                .method("POST")
                .header(header::CONTENT_TYPE, ct)
                .body(Body::from(r#"{"password":"hunter2"}"#))
                .unwrap()
        };
        let SecretJson(form) = SecretJson::<Ok1>::from_request(req("application/json"), &())
            .await
            .map_err(|r| r.status())
            .unwrap();
        assert_eq!(form.password, "hunter2");
        let refused = SecretJson::<Ok1>::from_request(req("text/plain"), &()).await;
        assert_eq!(
            refused.err().map(|r| r.status()),
            Some(StatusCode::UNSUPPORTED_MEDIA_TYPE)
        );
        let bad = SecretJson::<Form>::from_request(req("application/json"), &()).await;
        let resp = bad.err().unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let text = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let text = String::from_utf8_lossy(&text);
        assert!(!text.contains("hunter2"));
        let json: serde_json::Value = serde_json::from_str(&text).expect("a JSON error");
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("invalid request body"));
        // Malformed JSON: a 400, also as `{"error"}`.
        let malformed = Request::builder()
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{not json"))
            .unwrap();
        let resp = SecretJson::<Ok1>::from_request(malformed, &())
            .await
            .err()
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let text = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&text).expect("a JSON error");
        assert!(json["error"].is_string());
    }
}
