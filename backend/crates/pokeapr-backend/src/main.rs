use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{env, net::SocketAddr};
use tracing::{error, info, warn};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    webhook_secret: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let webhook_secret =
        env::var("GITHUB_WEBHOOK_SECRET").expect("GITHUB_WEBHOOK_SECRET must be set");

    let port: u16 = env::var("WEBHOOK_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let state = AppState { webhook_secret };

    let app = Router::new()
        .route("/webhook", post(handle_webhook))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, "Starting webhook server");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    // Verify HMAC-SHA256 signature
    let signature = headers
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            warn!("Missing X-Hub-Signature-256 header");
            StatusCode::UNAUTHORIZED
        })?;

    verify_signature(&state.webhook_secret, &body, signature).map_err(|_| {
        warn!("Invalid webhook signature");
        StatusCode::UNAUTHORIZED
    })?;

    // Determine event type
    let event_type = headers
        .get("X-GitHub-Event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    // Parse body into a generic JSON value for now
    let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        error!("Failed to parse JSON body: {e}");
        StatusCode::BAD_REQUEST
    })?;

    log_event(event_type, &payload);

    Ok(StatusCode::OK)
}

/// Verifies the GitHub webhook signature.
///
/// GitHub sends `X-Hub-Signature-256: sha256=<hex>`. We recompute the HMAC-SHA256
/// of the raw body and do a constant-time comparison to prevent timing attacks.
fn verify_signature(secret: &str, body: &[u8], signature: &str) -> Result<(), ()> {
    let hex_digest = signature.strip_prefix("sha256=").ok_or(())?;
    let expected = hex::decode(hex_digest).map_err(|_| ())?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| ())?;
    mac.update(body);
    mac.verify_slice(&expected).map_err(|_| ())
}

fn log_event(event_type: &str, payload: &serde_json::Value) {
    match event_type {
        "pull_request" => {
            let action = payload["action"].as_str().unwrap_or("unknown");
            let number = payload["number"].as_u64().unwrap_or(0);
            let title = payload["pull_request"]["title"]
                .as_str()
                .unwrap_or("unknown");
            let repo = payload["repository"]["full_name"]
                .as_str()
                .unwrap_or("unknown");
            info!(
                event = event_type,
                action,
                pr_number = number,
                title,
                repo,
                "Pull request event"
            );
        }
        "pull_request_review" => {
            let action = payload["action"].as_str().unwrap_or("unknown");
            let pr_number = payload["pull_request"]["number"]
                .as_u64()
                .unwrap_or(0);
            let repo = payload["repository"]["full_name"]
                .as_str()
                .unwrap_or("unknown");
            info!(
                event = event_type,
                action,
                pr_number,
                repo,
                "Pull request review event"
            );
        }
        "pull_request_review_comment" => {
            let action = payload["action"].as_str().unwrap_or("unknown");
            let pr_number = payload["pull_request"]["number"]
                .as_u64()
                .unwrap_or(0);
            let repo = payload["repository"]["full_name"]
                .as_str()
                .unwrap_or("unknown");
            info!(
                event = event_type,
                action,
                pr_number,
                repo,
                "Pull request review comment event"
            );
        }
        other => {
            info!(event = other, "Received unhandled event type");
        }
    }
}
