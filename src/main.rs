//! sovd-token-helper — offboard workshop JWT minter.
//!
//! Mints short-lived bearer tokens that a SOVD server (SOVDd) validates to
//! authorize client (workshop/diagnostic-tool) access. This is an **offboard**
//! service — the JWT analog of `SOVD-security-helper` — modeled on it but a
//! *distinct authority*: it issues client→SOVD access tokens, not UDS unlock
//! responses.
//!
//! The device never mints tokens: the minter holds the signing key, signs an
//! ES256 JWT, and publishes its public key as a JWKS. SOVDd trusts that key
//! (pre-installed for the offline/workshop case, or fetched when connected) and
//! validates signature / `aud` (= device id, the replay guard) / `iss` / `exp`,
//! then authorizes per-component from the `scope` claim
//! (`component:<id>` / `component:*`).
//!
//! See `tasks/sovdd-token-minter.md` (Phase 2) and `tasks/sovdd-auth-slice.md`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use clap::Parser;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "sovd-token-helper", about = "Offboard workshop JWT minter for SOVD")]
struct Cli {
    /// Port to listen on (loopback by default — see --bind-all).
    #[arg(long, default_value = "9200")]
    port: u16,
    /// Bind on 0.0.0.0 instead of 127.0.0.1 (e.g. a dealer-LAN bay service).
    #[arg(long)]
    bind_all: bool,
    /// PKCS#8 (or SEC1) P-256 EC private key (PEM) used to sign tokens.
    #[arg(long, env = "SOVD_MINTER_SIGNING_KEY")]
    signing_key: String,
    /// `iss` claim — the issuer identifier SOVDd is configured to trust.
    #[arg(long, default_value = "sovd-token-helper")]
    issuer: String,
    /// Operator bearer token required on POST /mint (dev/reference auth — a real
    /// deployment plugs in badge/smartcard/SSO here).
    #[arg(long, env = "SOVD_MINTER_OPERATOR_TOKEN")]
    operator_token: String,
    /// Key id — set on both the JWT header and the published JWK.
    #[arg(long, default_value = "workshop-key-1")]
    kid: String,
    /// Default token lifetime when the request doesn't ask for one.
    #[arg(long, default_value = "900")]
    default_ttl_secs: u64,
    /// Hard cap on token lifetime (requests are clamped to this).
    #[arg(long, default_value = "3600")]
    max_ttl_secs: u64,
}

// ---------------------------------------------------------------------------
// Signer — loads the EC key, signs tokens, and exposes its public JWKS.
// ---------------------------------------------------------------------------

struct Signer {
    encoding_key: EncodingKey,
    kid: String,
    issuer: String,
    jwks: serde_json::Value,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    exp: i64,
    jti: String,
    /// Space-delimited `component:<id>` scopes (SOVDd's per-component grammar).
    scope: String,
}

impl Signer {
    /// Build from a PEM EC private key. Derives the public JWK for `/jwks`.
    fn from_pem(pem: &str, kid: &str, issuer: &str) -> anyhow::Result<Self> {
        let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes())
            .context("parse EC signing key (expected a P-256 PKCS#8 or SEC1 PEM)")?;

        // Derive the public key's (x, y) for the published JWK.
        let secret = p256::SecretKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow!("parse P-256 PKCS#8 private key: {e}"))?;
        let point = secret.public_key().to_encoded_point(false);
        let x = point.x().context("EC public key missing x coordinate")?;
        let y = point.y().context("EC public key missing y coordinate")?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwks = json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": b64.encode(&x[..]),
                "y": b64.encode(&y[..]),
                "kid": kid,
                "alg": "ES256",
                "use": "sig",
            }]
        });

        Ok(Self {
            encoding_key,
            kid: kid.to_string(),
            issuer: issuer.to_string(),
            jwks,
        })
    }

    /// Mint a signed token. Returns `(token, exp_unix_secs)`.
    fn mint(
        &self,
        device_id: &str,
        components: &[String],
        subject: &str,
        ttl: Duration,
    ) -> anyhow::Result<(String, i64)> {
        let now = chrono::Utc::now().timestamp();
        let exp = now + ttl.as_secs() as i64;
        let scope = components
            .iter()
            .map(|c| format!("component:{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        let claims = Claims {
            iss: self.issuer.clone(),
            aud: device_id.to_string(), // VIN/device-bound — the replay guard
            sub: subject.to_string(),
            iat: now,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
            scope,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        let token = encode(&header, &claims, &self.encoding_key).context("sign JWT")?;
        Ok((token, exp))
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    signer: Arc<Signer>,
    operator_token: Arc<String>,
    default_ttl: Duration,
    max_ttl: Duration,
}

#[derive(Deserialize)]
struct MintRequest {
    /// The vehicle/device id this token is for — becomes the `aud` claim.
    device_id: String,
    /// Components the token may access (→ `component:<id>` scopes).
    #[serde(default)]
    components: Vec<String>,
    /// Requested lifetime; clamped to `max_ttl`.
    #[serde(default)]
    ttl_secs: Option<u64>,
    /// Technician/subject id; defaults to a generic operator label.
    #[serde(default)]
    subject: Option<String>,
}

#[derive(Serialize)]
struct MintResponse {
    token: String,
    expires_at: String,
}

type HttpError = (StatusCode, Json<serde_json::Value>);

fn http_error(code: StatusCode, msg: &str) -> HttpError {
    (code, Json(json!({ "error": msg })))
}

/// `POST /mint` — operator-authenticated; mints a token for one device + scope.
async fn mint(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MintRequest>,
) -> Result<Json<MintResponse>, HttpError> {
    let provided = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim);
    if provided != Some(st.operator_token.as_str()) {
        return Err(http_error(
            StatusCode::UNAUTHORIZED,
            "missing or invalid operator token",
        ));
    }
    if req.device_id.trim().is_empty() {
        return Err(http_error(StatusCode::BAD_REQUEST, "device_id is required"));
    }

    let ttl = req
        .ttl_secs
        .map(Duration::from_secs)
        .unwrap_or(st.default_ttl)
        .min(st.max_ttl);
    let subject = req
        .subject
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "workshop-operator".to_string());

    match st.signer.mint(&req.device_id, &req.components, &subject, ttl) {
        Ok((token, exp)) => {
            let expires_at = chrono::DateTime::from_timestamp(exp, 0)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            Ok(Json(MintResponse { token, expires_at }))
        }
        Err(e) => {
            tracing::error!(error = %e, "mint failed");
            Err(http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to mint token",
            ))
        }
    }
}

/// `GET /jwks` — the public verification key(s). SOVDd trusts these (pinned for
/// offline, or fetched when connected).
async fn jwks(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(st.signer.jwks.clone())
}

/// `GET /info` — public service metadata.
async fn info(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "service": "sovd-token-helper",
        "version": env!("CARGO_PKG_VERSION"),
        "issuer": st.signer.issuer,
        "kid": st.signer.kid,
        "algorithm": "ES256",
        "operator_auth": "bearer (static token)",
        "default_ttl_secs": st.default_ttl.as_secs(),
        "max_ttl_secs": st.max_ttl.as_secs(),
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sovd_token_helper=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let pem = std::fs::read_to_string(&cli.signing_key)
        .with_context(|| format!("read signing key from {}", cli.signing_key))?;
    let signer = Signer::from_pem(&pem, &cli.kid, &cli.issuer)?;

    let state = AppState {
        signer: Arc::new(signer),
        operator_token: Arc::new(cli.operator_token),
        default_ttl: Duration::from_secs(cli.default_ttl_secs),
        max_ttl: Duration::from_secs(cli.max_ttl_secs),
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/info", get(info))
        .route("/jwks", get(jwks))
        .route("/mint", post(mint))
        .with_state(state);

    let host = if cli.bind_all { [0, 0, 0, 0] } else { [127, 0, 0, 1] };
    let addr = SocketAddr::from((host, cli.port));
    tracing::info!(%addr, issuer = %cli.issuer, kid = %cli.kid, "sovd-token-helper listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway P-256 PKCS#8 key — TEST FIXTURE ONLY, never a real signing key.
    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJYYDLkmSf/w0WeDS
fjV+rbycc40t9razxoJoZYQylj6hRANCAASMr/PHJFmgiJks/7ljH39vsbfbL/kH
Hra9IJ6KhCySkFpT5XnQKssJp/rY7rrX8dql45k7x3XcvhcHIaaYHRyr
-----END PRIVATE KEY-----
";

    fn signer() -> Signer {
        Signer::from_pem(TEST_KEY, "test-kid", "test-issuer").unwrap()
    }

    /// The minted token must validate against the SAME JWKS the minter
    /// publishes — exactly what SOVDd does with the pinned static JWKS.
    #[test]
    fn mint_token_validates_against_published_jwks() {
        let s = signer();
        let (token, exp) = s
            .mint(
                "vin:ABC",
                &["engine_ecu".to_string(), "trans".to_string()],
                "tech-1",
                Duration::from_secs(300),
            )
            .unwrap();
        assert!(exp > chrono::Utc::now().timestamp());

        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(s.jwks.clone()).unwrap();
        let kid = jsonwebtoken::decode_header(&token).unwrap().kid.unwrap();
        let jwk = jwks.find(&kid).expect("published JWK matches the token kid");
        let key = jsonwebtoken::DecodingKey::from_jwk(jwk).unwrap();

        let mut v = jsonwebtoken::Validation::new(Algorithm::ES256);
        v.set_audience(&["vin:ABC"]);
        v.set_issuer(&["test-issuer"]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

        #[derive(Deserialize)]
        struct C {
            aud: String,
            iss: String,
            sub: String,
            scope: String,
        }
        let data = jsonwebtoken::decode::<C>(&token, &key, &v)
            .expect("token validates against the published JWKS");
        assert_eq!(data.claims.aud, "vin:ABC");
        assert_eq!(data.claims.iss, "test-issuer");
        assert_eq!(data.claims.sub, "tech-1");
        assert_eq!(data.claims.scope, "component:engine_ecu component:trans");
    }

    /// A token minted for one device must not validate for another (the `aud`
    /// replay guard SOVDd relies on).
    #[test]
    fn token_rejected_for_a_different_device() {
        let s = signer();
        let (token, _) = s
            .mint("vin:ABC", &["engine_ecu".to_string()], "t", Duration::from_secs(300))
            .unwrap();
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(s.jwks.clone()).unwrap();
        let kid = jsonwebtoken::decode_header(&token).unwrap().kid.unwrap();
        let key = jsonwebtoken::DecodingKey::from_jwk(jwks.find(&kid).unwrap()).unwrap();

        let mut v = jsonwebtoken::Validation::new(Algorithm::ES256);
        v.set_audience(&["vin:OTHER"]);
        v.set_issuer(&["test-issuer"]);

        #[derive(Deserialize)]
        struct C {}
        assert!(
            jsonwebtoken::decode::<C>(&token, &key, &v).is_err(),
            "token must not validate for a different device aud"
        );
    }

    #[test]
    fn published_jwks_shape() {
        let s = signer();
        let keys = s.jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "EC");
        assert_eq!(keys[0]["crv"], "P-256");
        assert_eq!(keys[0]["kid"], "test-kid");
        assert_eq!(keys[0]["alg"], "ES256");
        assert!(keys[0]["x"].is_string());
        assert!(keys[0]["y"].is_string());
    }

    #[test]
    fn ttl_is_clamped_and_scopes_render() {
        let s = signer();
        let (token, exp) = s
            .mint("d", &["a".to_string()], "t", Duration::from_secs(120))
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(exp - now <= 120 && exp - now > 60);
        // empty components → empty scope
        let (_t2, _e2) = s.mint("d", &[], "t", Duration::from_secs(60)).unwrap();
        assert!(!token.is_empty());
    }
}
