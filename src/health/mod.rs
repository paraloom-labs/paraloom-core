//! Operational HTTP endpoints: health, readiness, metrics.
//!
//! Separate from the dashboard server because these endpoints are
//! the contract a load balancer or container orchestrator (k8s,
//! systemd, nomad) will hit, not a human looking at the network. The
//! dashboard can lag, restart, or be reskinned without touching this
//! module's interfaces.
//!
//! ## Endpoints
//!
//! - `GET /health` — always returns 200 if the process is alive.
//!   Used as a liveness probe — a 502 here means the process is
//!   stuck or has hung, and the orchestrator should restart it.
//!
//! - `GET /ready` — returns 200 only when the node has finished
//!   start-up, has at least `min_peers_for_ready` peers, and has not
//!   been explicitly marked as draining. Returns 503 with a JSON
//!   body describing which check failed otherwise. Used as a
//!   readiness probe — a 503 here means the orchestrator should not
//!   route traffic but the process is OK; no restart needed.
//!
//! - `GET /metrics` — Prometheus text format. Includes process info
//!   (version, uptime), peer count, and a few placeholder counters
//!   that downstream code can update. Operators scrape this with the
//!   Prometheus scraper for dashboards and alerts.
//!
//! See #67 (the audit follow-up that introduced this module) for the
//! design discussion.

use axum::{
    extract::Extension,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Default minimum peer count required for the readiness probe to
/// return 200. Operators with smaller validator sets (a single-node
/// devnet) should override this via [`HealthServerState::with_min_peers`].
pub const DEFAULT_MIN_PEERS_FOR_READY: usize = 1;

/// Shared state for the operational HTTP server. Cloning is cheap —
/// every field is wrapped in an `Arc` so handlers can read counters
/// without holding the structure.
#[derive(Clone)]
pub struct HealthServerState {
    /// Process start time, for the `uptime_seconds` metric and the
    /// `paraloom_uptime_seconds` Prometheus gauge.
    started_at: Instant,

    /// Whether the node has finished start-up. Defaults to false; the
    /// node binary calls [`HealthServerState::mark_ready`] once
    /// storage is open, the bridge has booted, and consensus is
    /// participating. Setting it back to `false` (e.g. via a
    /// `/admin/drain` endpoint) takes the node out of rotation
    /// without killing the process.
    ready: Arc<AtomicBool>,

    /// Live peer count. Updated by the network layer through
    /// [`HealthServerState::set_peer_count`] every time the swarm
    /// reports a connection event. The readiness probe uses this
    /// directly.
    peer_count: Arc<AtomicUsize>,

    /// Threshold below which `/ready` returns 503 even when
    /// `ready == true`. Configurable so a single-node devnet can run
    /// at `0` while a 7-of-10 mainnet pool can require `7`.
    min_peers_for_ready: usize,
}

impl HealthServerState {
    /// Construct a fresh state with `started_at = now()` and
    /// `peer_count = 0`. The node binary is expected to call
    /// [`mark_ready`] when start-up completes.
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            ready: Arc::new(AtomicBool::new(false)),
            peer_count: Arc::new(AtomicUsize::new(0)),
            min_peers_for_ready: DEFAULT_MIN_PEERS_FOR_READY,
        }
    }

    /// Override the minimum peer count required for readiness.
    pub fn with_min_peers(mut self, min: usize) -> Self {
        self.min_peers_for_ready = min;
        self
    }

    /// Flip the node into "ready to serve" state. Callers should
    /// invoke this after every preflight check has passed.
    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    /// Take the node out of rotation. The process keeps running and
    /// `/health` keeps returning 200; only `/ready` flips to 503.
    pub fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::Release);
    }

    /// Update the live peer count.
    pub fn set_peer_count(&self, count: usize) {
        self.peer_count.store(count, Ordering::Relaxed);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn current_peer_count(&self) -> usize {
        self.peer_count.load(Ordering::Relaxed)
    }

    fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

impl Default for HealthServerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Liveness probe response body. A handful of fields rather than
/// raw `OK` so a misbehaving load balancer that ignores status codes
/// still gets actionable information from the body.
#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
    version: &'static str,
    uptime_seconds: u64,
}

/// Readiness probe response body. Reports each check independently
/// so an operator can see at a glance which one is currently failing.
#[derive(Serialize)]
struct ReadinessBody {
    status: &'static str,
    ready: bool,
    peer_count: usize,
    min_peers_for_ready: usize,
    failed_checks: Vec<&'static str>,
}

async fn health_handler(Extension(state): Extension<HealthServerState>) -> impl IntoResponse {
    let body = HealthBody {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.uptime_seconds(),
    };
    (StatusCode::OK, Json(body))
}

async fn readiness_handler(Extension(state): Extension<HealthServerState>) -> impl IntoResponse {
    let mut failed_checks: Vec<&'static str> = Vec::new();
    let ready_flag = state.is_ready();
    if !ready_flag {
        failed_checks.push("startup_not_complete");
    }
    let peers = state.current_peer_count();
    if peers < state.min_peers_for_ready {
        failed_checks.push("peer_count_below_threshold");
    }

    let status = if failed_checks.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = ReadinessBody {
        status: if failed_checks.is_empty() {
            "ready"
        } else {
            "not_ready"
        },
        ready: ready_flag,
        peer_count: peers,
        min_peers_for_ready: state.min_peers_for_ready,
        failed_checks,
    };
    (status, Json(body))
}

async fn metrics_handler(Extension(state): Extension<HealthServerState>) -> impl IntoResponse {
    let uptime = state.uptime_seconds();
    let peers = state.current_peer_count();
    let ready = if state.is_ready() { 1u8 } else { 0 };
    let body = format!(
        "# HELP paraloom_uptime_seconds Process uptime in seconds.\n\
         # TYPE paraloom_uptime_seconds gauge\n\
         paraloom_uptime_seconds {uptime}\n\
         # HELP paraloom_peer_count Current libp2p peer count.\n\
         # TYPE paraloom_peer_count gauge\n\
         paraloom_peer_count {peers}\n\
         # HELP paraloom_ready 1 if /ready would currently return 200, 0 otherwise.\n\
         # TYPE paraloom_ready gauge\n\
         paraloom_ready {ready}\n\
         # HELP paraloom_build_info Build identification labels (value is always 1).\n\
         # TYPE paraloom_build_info gauge\n\
         paraloom_build_info{{version=\"{version}\"}} 1\n",
        uptime = uptime,
        peers = peers,
        ready = ready,
        version = env!("CARGO_PKG_VERSION"),
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

/// Build the operational endpoint router. Exposed separately so
/// callers can mount it under their own listener if they want.
pub fn router(state: HealthServerState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(readiness_handler))
        .route("/metrics", get(metrics_handler))
        .layer(Extension(state))
}

/// Bind the operational server on `addr` and serve forever.
///
/// Operators typically run this on a separate port from the dashboard
/// (the dashboard might be public-facing while these endpoints stay
/// behind the management interface).
pub async fn serve(
    state: HealthServerState,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!(
        target: "paraloom::health",
        "operational HTTP server listening on http://{}",
        addr
    );
    axum::Server::bind(&addr)
        .serve(router(state).into_make_service())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    /// `/health` always returns 200 with a JSON body that includes
    /// the cargo version. The body is checked with raw bytes since
    /// the response shape is part of the operator-facing contract.
    #[tokio::test]
    async fn health_returns_ok_with_version() {
        let state = HealthServerState::new();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("\"status\":\"ok\""));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
    }

    /// Fresh state is not ready (`mark_ready` not yet called) and
    /// has no peers — both checks fail; readiness must return 503.
    #[tokio::test]
    async fn readiness_503_before_mark_ready() {
        let state = HealthServerState::new().with_min_peers(1);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("startup_not_complete"));
        assert!(text.contains("peer_count_below_threshold"));
    }

    /// After `mark_ready` and enough peers, readiness flips to 200.
    /// Walks the full happy path the load balancer would observe at
    /// node start-up.
    #[tokio::test]
    async fn readiness_200_after_ready_and_peers() {
        let state = HealthServerState::new().with_min_peers(3);
        state.mark_ready();
        state.set_peer_count(5);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// `mark_not_ready` after a previously-ready state must drop the
    /// node out of rotation. Mirrors the drain-then-restart flow an
    /// operator would do for a controlled shutdown.
    #[tokio::test]
    async fn readiness_503_after_drain() {
        let state = HealthServerState::new().with_min_peers(0);
        state.mark_ready();
        state.set_peer_count(5);
        // Initially ready.
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Drain.
        state.mark_not_ready();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Below-threshold peer count fails readiness even when
    /// `mark_ready` has been called. Pins the AND semantics.
    #[tokio::test]
    async fn readiness_503_when_peers_below_threshold() {
        let state = HealthServerState::new().with_min_peers(7);
        state.mark_ready();
        state.set_peer_count(3);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("peer_count_below_threshold"));
        assert!(!text.contains("startup_not_complete"));
    }

    /// `/metrics` is plain text with the Prometheus content type and
    /// every documented gauge present. Pins the contract a Prometheus
    /// scraper relies on.
    #[tokio::test]
    async fn metrics_returns_prometheus_text() {
        let state = HealthServerState::new();
        state.mark_ready();
        state.set_peer_count(4);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("text/plain"),
            "expected Prometheus text content-type, got {}",
            content_type
        );
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("paraloom_uptime_seconds"));
        assert!(text.contains("paraloom_peer_count 4"));
        assert!(text.contains("paraloom_ready 1"));
        assert!(text.contains("paraloom_build_info"));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
    }

    /// Bare construction observes default values — no peers,
    /// not-yet-ready, and the documented default minimum-peers
    /// threshold. Pins the public default contract.
    #[test]
    fn default_state_is_not_ready_with_zero_peers() {
        let state = HealthServerState::new();
        assert!(!state.is_ready());
        assert_eq!(state.current_peer_count(), 0);
        assert_eq!(state.min_peers_for_ready, DEFAULT_MIN_PEERS_FOR_READY);
    }
}
