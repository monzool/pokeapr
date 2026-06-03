use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use chrono::{DateTime, Duration, Utc};
use firestore::{FirestoreDb, FirestoreDbOptions};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{env, net::SocketAddr, pin::Pin};
use tracing::{error, info, warn};

/// A no-op token source for use with the Firestore emulator.
///
/// The emulator accepts any Bearer token without validation; this lets us skip
/// the normal credential look-up that gcloud-sdk performs on startup.
struct EmulatorTokenSource;

impl gcloud_sdk::Source for EmulatorTokenSource {
    fn token<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn std::future::Future<Output = gcloud_sdk::error::Result<gcloud_sdk::Token>> + Send + 'async_trait>>
    where
        Self: 'async_trait,
        'life0: 'async_trait,
    {
        Box::pin(async {
            // The Firestore emulator validates JWT *format* but does NOT verify signatures.
            // Segments (base64url-encoded):
            //   {"alg":"RS256","typ":"JWT"} . {"sub":"emulator","exp":9999999999} . <fake sig>
            const FAKE_JWT: &str = concat!(
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                ".",
                "eyJzdWIiOiJlbXVsYXRvciIsImV4cCI6OTk5OTk5OTk5OX0",
                ".",
                "AAAA"
            );
            Ok(gcloud_sdk::Token::new(
                "Bearer".to_string(),
                gcloud_sdk::SecretValue::from(FAKE_JWT),
                Utc::now() + Duration::hours(24),
            ))
        })
    }
}

type HmacSha256 = Hmac<Sha256>;

const GITHUB_EVENTS_COLLECTION: &str = "github_events";

/// Persisted representation of a GitHub webhook event.
#[derive(Debug, Serialize, Deserialize)]
struct GitHubEventRecord {
    event_type: String,
    action: Option<String>,
    repo: Option<String>,
    author: Option<String>,
    title: Option<String>,
    /// Stored as a native Firestore Timestamp in the database.
    #[serde(with = "firestore::serialize_as_timestamp")]
    timestamp: DateTime<Utc>,
}

#[derive(Clone)]
struct AppState {
    webhook_secret: String,
    db: FirestoreDb,
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

    let project_id =
        env::var("GOOGLE_CLOUD_PROJECT").expect("GOOGLE_CLOUD_PROJECT must be set");

    let port: u16 = env::var("WEBHOOK_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let db = if env::var("FIRESTORE_EMULATOR_HOST").is_ok() {
        info!("FIRESTORE_EMULATOR_HOST set — connecting to emulator with fake token source");
        FirestoreDb::with_options_token_source(
            FirestoreDbOptions::new(project_id.to_string()),
            gcloud_sdk::GCP_DEFAULT_SCOPES.clone(),
            gcloud_sdk::TokenSourceType::ExternalSource(Box::new(EmulatorTokenSource)),
        )
        .await
        .expect("Failed to create Firestore emulator client")
    } else {
        FirestoreDb::new(&project_id)
            .await
            .expect("Failed to create Firestore client")
    };

    let state = AppState { webhook_secret, db };

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

    // Use delivery GUID as the document ID — prevents duplicate writes on retry
    let delivery_id = headers
        .get("X-GitHub-Delivery")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_owned();

    // Parse body into a generic JSON value for now
    let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        error!("Failed to parse JSON body: {e}");
        StatusCode::BAD_REQUEST
    })?;

    log_event(event_type, &payload);

    let record = extract_event_record(event_type, &payload);

    let _: GitHubEventRecord = state
        .db
        .fluent()
        .insert()
        .into(GITHUB_EVENTS_COLLECTION)
        .document_id(&delivery_id)
        .object(&record)
        .execute()
        .await
        .map_err(|e| {
            error!("Failed to write to Firestore: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(
        delivery_id,
        event_type = record.event_type,
        "Event persisted to Firestore"
    );

    Ok(StatusCode::OK)
}

fn extract_event_record(event_type: &str, payload: &serde_json::Value) -> GitHubEventRecord {
    GitHubEventRecord {
        event_type: event_type.to_owned(),
        action: payload["action"].as_str().map(str::to_owned),
        repo: payload["repository"]["full_name"].as_str().map(str::to_owned),
        author: payload["sender"]["login"].as_str().map(str::to_owned),
        title: payload["pull_request"]["title"].as_str().map(str::to_owned),
        timestamp: Utc::now(),
    }
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
            let pr_number = payload["number"].as_u64().unwrap_or(0);
            let title = payload["pull_request"]["title"]
                .as_str()
                .unwrap_or("unknown");
            let repo = payload["repository"]["full_name"]
                .as_str()
                .unwrap_or("unknown");
            info!(
                event = event_type,
                action,
                pr_number,
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
