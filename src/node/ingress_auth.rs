//! Shared bearer-token gate for the write-surface HTTP ingress endpoints
//! (withdrawal #184, transfer #194).
//!
//! Both endpoints *trigger consensus*, so they are a write surface. They
//! default to disabled and are meant for a loopback/management interface, but
//! when an operator exposes one beyond loopback they can configure a shared
//! token (`bridge.ingress_token`); a request without a matching
//! `Authorization: Bearer <token>` is then refused. With no token configured
//! the gate is a no-op, preserving the historical behaviour.

use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use std::sync::Arc;

/// The optional shared secret an ingress requires. `None` = no auth (only safe
/// on a loopback/management interface); `Some` = every request must present it.
pub type IngressToken = Option<Arc<str>>;

/// Build an [`IngressToken`] from a configured string: an empty string (the
/// default) means no authentication, any other value is the required token.
pub fn token_from_config(configured: &str) -> IngressToken {
    let t = configured.trim();
    if t.is_empty() {
        None
    } else {
        Some(Arc::from(t))
    }
}

/// `Ok` if no token is configured, or the request carries the matching bearer
/// token; otherwise `401`. The token is compared in constant time so it cannot
/// be recovered byte-by-byte through a timing side channel.
pub fn check_bearer(headers: &HeaderMap, token: &IngressToken) -> Result<(), (StatusCode, String)> {
    let Some(expected) = token.as_ref() else {
        return Ok(());
    };
    let presented = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(t) if ct_eq(t.as_bytes(), expected.as_bytes()) => Ok(()),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            "missing or invalid bearer token".to_string(),
        )),
    }
}

/// Constant-time byte-slice equality. The length is not treated as secret (a
/// bearer token's length is low-entropy), but the content comparison does not
/// short-circuit on the first mismatch, so it does not leak the token through
/// per-byte timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(auth: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(a) = auth {
            h.insert(AUTHORIZATION, a.parse().unwrap());
        }
        h
    }

    #[test]
    fn no_token_configured_allows_any_request() {
        let token = token_from_config("");
        assert!(token.is_none());
        assert!(check_bearer(&headers_with(None), &token).is_ok());
        assert!(check_bearer(&headers_with(Some("Bearer whatever")), &token).is_ok());
    }

    #[test]
    fn configured_token_requires_a_matching_bearer() {
        let token = token_from_config("  s3cret  "); // trimmed
        assert_eq!(token.as_deref(), Some("s3cret"));

        // Correct token passes.
        assert!(check_bearer(&headers_with(Some("Bearer s3cret")), &token).is_ok());

        // Missing, wrong, or malformed headers are all 401.
        for bad in [
            None,
            Some("Bearer wrong"),
            Some("s3cret"),
            Some("Basic s3cret"),
        ] {
            let err = check_bearer(&headers_with(bad), &token).unwrap_err();
            assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        }
    }
}
