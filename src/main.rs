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
//! validates signature / `aud` / `iss` / `exp`, then authorizes per-component
//! from the `scope` claim (`component:<id>` / `component:*`).
//!
//! `aud` is the device's immutable **ecu id** — the 64-hex SHA-256 thumbprint
//! of its device key's SPKI (what it serves at `x-sumo-id`) — NEVER its Tower
//! roster name. `/mint` accepts either: an ecu id passes through, a roster
//! name resolves via Tower 1 (`--ca-url`) or is refused.
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
#[command(
    name = "sovd-token-helper",
    about = "Offboard workshop JWT minter for SOVD"
)]
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
    /// PEM cert chain (leaf first, then intermediates), e.g. from
    /// `scripts/gen-workshop-pki.sh`. Embedded as the JWT `x5c` header so the
    /// vehicle verifies the chain to its pinned workshop CA.
    #[arg(long, env = "SOVD_MINTER_CERT_CHAIN")]
    cert_chain: Option<String>,
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
    /// Tower 1 (identity) base URL for resolving a roster NAME to the device's
    /// immutable ecu id (`GET /devices/{id}` → `ecu_id`). Without it, /mint
    /// only accepts an ecu id (the 64-hex `x-sumo-id` thumbprint) as
    /// `device_id` — a roster name would mint a token the device rejects with
    /// InvalidAudience.
    #[arg(long, env = "SOVD_MINTER_CA_URL")]
    ca_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Signer — loads the EC key, signs tokens, and exposes its public JWKS.
// ---------------------------------------------------------------------------

struct Signer {
    encoding_key: EncodingKey,
    kid: String,
    issuer: String,
    jwks: serde_json::Value,
    /// Base64(DER) cert chain (leaf first) for the JWT `x5c` header; empty when
    /// no chain is configured (connected / JWKS-only mode).
    x5c: Vec<String>,
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
    /// §7.1 freshness: binds the token to the device's current boot. Present only
    /// when the caller supplies it (read live from `x-sumo-boot-id`); the device
    /// rejects a destructive token whose `boot_id` != its current boot.
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_id: Option<String>,
}

/// Extract a JWT `x5c` array (base64-DER per cert, leaf first) from a PEM chain.
fn chain_to_x5c(chain_pem: &str) -> anyhow::Result<Vec<String>> {
    let blocks = pem::parse_many(chain_pem).context("parse --cert-chain PEM")?;
    let std_b64 = base64::engine::general_purpose::STANDARD;
    let certs: Vec<String> = blocks
        .iter()
        .filter(|b| b.tag() == "CERTIFICATE")
        .map(|b| std_b64.encode(b.contents()))
        .collect();
    anyhow::ensure!(
        !certs.is_empty(),
        "--cert-chain contained no CERTIFICATE blocks"
    );
    Ok(certs)
}

impl Signer {
    /// Build from a PEM EC private key + optional PEM cert chain (leaf first).
    /// Derives the public JWK for `/jwks`; the chain becomes the `x5c` header.
    fn new(
        key_pem: &str,
        chain_pem: Option<&str>,
        kid: &str,
        issuer: &str,
    ) -> anyhow::Result<Self> {
        let encoding_key = EncodingKey::from_ec_pem(key_pem.as_bytes())
            .context("parse EC signing key (expected a P-256 PKCS#8 or SEC1 PEM)")?;

        // Derive the public key's (x, y) for the published JWK.
        let secret = p256::SecretKey::from_pkcs8_pem(key_pem)
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

        let x5c = match chain_pem {
            Some(chain) => chain_to_x5c(chain)?,
            None => Vec::new(),
        };

        Ok(Self {
            encoding_key,
            kid: kid.to_string(),
            issuer: issuer.to_string(),
            jwks,
            x5c,
        })
    }

    /// Mint a signed token. Returns `(token, exp_unix_secs)`.
    fn mint(
        &self,
        device_id: &str,
        components: &[String],
        verbs: &[String],
        subject: &str,
        boot_id: Option<&str>,
        ttl: Duration,
    ) -> anyhow::Result<(String, i64)> {
        let now = chrono::Utc::now().timestamp();
        let exp = now + ttl.as_secs() as i64;
        // `component:<id>` scopes (which components) plus the verb scopes the
        // device gates on (`reset:execute`, `update:transfer`, …). For a delegated
        // token these are still bounded at the device by the delegate cert's
        // granted-rights ceiling — minting a verb is necessary, not sufficient.
        let scope = components
            .iter()
            .map(|c| format!("component:{c}"))
            .chain(verbs.iter().cloned())
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
            boot_id: boot_id.map(str::to_string),
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        if !self.x5c.is_empty() {
            header.x5c = Some(self.x5c.clone());
        }
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
    /// Tower 1 base URL for roster-name → ecu id resolution (`--ca-url`).
    ca_url: Option<Arc<String>>,
}

/// The verb scopes a workshop token carries when the caller doesn't specify any —
/// the operational set plus `reset:execute` (the cable-connected ECU reboot). NOT
/// `factory-reset`, which stays a Tower / online authority (`authorization.md` §5).
const DEFAULT_WORKSHOP_VERBS: &[&str] = &[
    "data:read",
    "data:write",
    "operations:execute",
    "modes:set",
    "update:transfer",
    "update:execute",
    "update:verdict",
    "reset:execute",
];

#[derive(Deserialize)]
struct MintRequest {
    /// The device this token is for. Either its immutable ecu id (the 64-hex
    /// `x-sumo-id` thumbprint — used verbatim as `aud`), or a Tower 1 roster
    /// name, resolved to the ecu id via `--ca-url`. The DEVICE verifies
    /// `aud == its ecu id`; a roster name minted verbatim is rejected with
    /// InvalidAudience.
    device_id: String,
    /// Components the token may access (→ `component:<id>` scopes).
    #[serde(default)]
    components: Vec<String>,
    /// Verb capabilities the token grants (e.g. `reset:execute`,
    /// `update:transfer`). Empty → the default workshop set
    /// (`DEFAULT_WORKSHOP_VERBS`).
    #[serde(default)]
    verbs: Vec<String>,
    /// Requested lifetime; clamped to `max_ttl`.
    #[serde(default)]
    ttl_secs: Option<u64>,
    /// Technician/subject id; defaults to a generic operator label.
    #[serde(default)]
    subject: Option<String>,
    /// The device's current boot nonce (read from `x-sumo-boot-id`) — becomes the
    /// `boot_id` claim binding the token to this boot (§7.1 freshness). Omit for
    /// no binding (e.g. a non-destructive token).
    #[serde(default)]
    boot_id: Option<String>,
}

#[derive(Serialize)]
struct MintResponse {
    token: String,
    expires_at: String,
    /// The `aud` actually minted (the device's ecu id) — echoes the resolution
    /// so a caller that passed a roster name sees the id the device verifies.
    aud: String,
}

/// An ecu id as the device serves it at `x-sumo-id`: 64 hex chars (the SHA-256
/// thumbprint of its device key's SPKI DER).
fn is_ecu_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Resolve the caller-supplied `device_id` to the token `aud` the DEVICE
/// verifies — its immutable ecu id. A 64-hex id passes through (lowercased to
/// match the device's rendering); anything else is a roster NAME and resolves
/// through Tower 1's `GET /devices/{id}` → `ecu_id`. Minting a name verbatim
/// was the historical aud-mismatch trap: the device rejects the token with
/// InvalidAudience only after the operator walked away.
async fn resolve_aud(ca_url: Option<&str>, device_id: &str) -> Result<String, HttpError> {
    let id = device_id.trim();
    if is_ecu_id(id) {
        return Ok(id.to_ascii_lowercase());
    }
    let Some(ca) = ca_url else {
        return Err(http_error(
            StatusCode::BAD_REQUEST,
            "device_id is not an ecu id (the 64-hex x-sumo-id thumbprint) and no --ca-url is \
             configured to resolve roster names — pass the device's x-sumo-id, or start the \
             minter with --ca-url <tower-1>",
        ));
    };
    let url = format!("{}/devices/{}", ca.trim_end_matches('/'), id);
    let resp = reqwest::get(&url).await.map_err(|e| {
        http_error(
            StatusCode::BAD_GATEWAY,
            &format!("roster lookup {url} failed: {e}"),
        )
    })?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(http_error(
            StatusCode::BAD_REQUEST,
            &format!("device '{id}' is not in the Tower 1 roster"),
        ));
    }
    if !resp.status().is_success() {
        return Err(http_error(
            StatusCode::BAD_GATEWAY,
            &format!("roster lookup {url} returned HTTP {}", resp.status()),
        ));
    }
    let device: serde_json::Value = resp.json().await.map_err(|e| {
        http_error(
            StatusCode::BAD_GATEWAY,
            &format!("roster lookup {url}: bad JSON: {e}"),
        )
    })?;
    match device.get("ecu_id").and_then(|v| v.as_str()) {
        Some(ecu_id) if is_ecu_id(ecu_id) => {
            tracing::info!(roster_name = %id, %ecu_id, "resolved roster name to ecu id for aud");
            Ok(ecu_id.to_ascii_lowercase())
        }
        _ => Err(http_error(
            StatusCode::BAD_REQUEST,
            &format!(
                "device '{id}' has no ecu id in the roster yet (not enrolled) — enroll it, or \
                 pass its x-sumo-id directly"
            ),
        )),
    }
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
    // The aud the DEVICE verifies is its ecu id — resolve a roster name to it
    // rather than minting a token the device will reject.
    let aud = resolve_aud(st.ca_url.as_deref().map(String::as_str), &req.device_id).await?;

    let ttl = req
        .ttl_secs
        .map(Duration::from_secs)
        .unwrap_or(st.default_ttl)
        .min(st.max_ttl);
    let subject = req
        .subject
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "workshop-operator".to_string());

    // Default to the workshop's verb set when the caller doesn't narrow it; the
    // device still caps a delegated token at its cert's granted rights.
    let verbs: Vec<String> = if req.verbs.is_empty() {
        DEFAULT_WORKSHOP_VERBS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        req.verbs.clone()
    };
    match st.signer.mint(
        &aud,
        &req.components,
        &verbs,
        &subject,
        req.boot_id.as_deref(),
        ttl,
    ) {
        Ok((token, exp)) => {
            let expires_at = chrono::DateTime::from_timestamp(exp, 0)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            Ok(Json(MintResponse {
                token,
                expires_at,
                aud,
            }))
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
        "x5c_certs": st.signer.x5c.len(),
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
    let key_pem = std::fs::read_to_string(&cli.signing_key)
        .with_context(|| format!("read signing key from {}", cli.signing_key))?;
    let chain_pem = match &cli.cert_chain {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("read cert chain from {path}"))?,
        ),
        None => None,
    };
    let signer = Signer::new(&key_pem, chain_pem.as_deref(), &cli.kid, &cli.issuer)?;

    let state = AppState {
        signer: Arc::new(signer),
        operator_token: Arc::new(cli.operator_token),
        default_ttl: Duration::from_secs(cli.default_ttl_secs),
        max_ttl: Duration::from_secs(cli.max_ttl_secs),
        ca_url: cli.ca_url.map(Arc::new),
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/info", get(info))
        .route("/jwks", get(jwks))
        .route("/mint", post(mint))
        .with_state(state);

    let host = if cli.bind_all {
        [0, 0, 0, 0]
    } else {
        [127, 0, 0, 1]
    };
    let addr = SocketAddr::from((host, cli.port));
    tracing::info!(%addr, issuer = %cli.issuer, kid = %cli.kid, "sovd-token-helper listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway test PKI (from scripts/gen-workshop-pki.sh) — TEST FIXTURES
    // ONLY. leaf.key signs; leaf.crt + int.crt are the x5c chain (leaf first)
    // chaining to the OEM Workshop CA.
    const LEAF_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0f0shY0eYUdamL01
lY+KDWz0y9nKYHs7KwplnY+T752hRANCAAR49pTZHSd+ggE7+KJOuWYW2OfSOLyL
cAwP8JERhQ6jpQRX5N3dx6ydnCpWxjqrU2afQhNDj1tN7V/GaL9j9f3p
-----END PRIVATE KEY-----
";
    const LEAF_CRT: &str = "-----BEGIN CERTIFICATE-----
MIIBlDCCATugAwIBAgIUfVbqOs0W/+MMymiqpYwV+bNgLYgwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPUmVnaW9uLUVVLVN1YkNBMB4XDTI2MDYwMzE0MzEwNFoXDTI3
MDYwMzE0MzEwNFowGTEXMBUGA1UEAwwOV29ya3Nob3AtQmF5LTcwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAAR49pTZHSd+ggE7+KJOuWYW2OfSOLyLcAwP8JERhQ6j
pQRX5N3dx6ydnCpWxjqrU2afQhNDj1tN7V/GaL9j9f3po2AwXjAMBgNVHRMBAf8E
AjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUZjZdhdHkZB4D58vvS0AQMKt+
W38wHwYDVR0jBBgwFoAUta2HrmG3cb+p0ClF2WxVA6MYh8MwCgYIKoZIzj0EAwID
RwAwRAIgZfMsu0h0kvWWaSL5yfXAx9L7WKZdm0j1AlY9i3/emP8CIEwXr76+Iz9Y
6J+wSkgfsnmUGQdz0v+68CgW9dTFvLpH
-----END CERTIFICATE-----
";
    const INT_CRT: &str = "-----BEGIN CERTIFICATE-----
MIIBmTCCAT+gAwIBAgIUA07s6iSRDhI4refSVvo8NnJwrfUwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPT0VNLVdvcmtzaG9wLUNBMB4XDTI2MDYwMzE0MzEwNFoXDTMx
MDYwMjE0MzEwNFowGjEYMBYGA1UEAwwPUmVnaW9uLUVVLVN1YkNBMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEw5NWUViXwxeO1NEuiZMQJxTayZxMkBFR7ZwAk4x3
AJb8nFEopboFGtr4VD2/4NO9CGyY6gg4fBfGsx62Q5nbcKNjMGEwDwYDVR0TAQH/
BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFLWth65ht3G/qdApRdls
VQOjGIfDMB8GA1UdIwQYMBaAFDO7tH5nczIUeFDzRYUrB8o8OGVsMAoGCCqGSM49
BAMCA0gAMEUCIQDqqoJLopLrgj50KszzJinNN2ExYEvDFTQaMxu18WovTgIgE5T0
QKOsCi7I7QyUBCUbBKZYmS2yjJnuk7RO40aKwq0=
-----END CERTIFICATE-----
";

    fn signer() -> Signer {
        let chain = format!("{LEAF_CRT}{INT_CRT}");
        Signer::new(LEAF_KEY, Some(&chain), "test-kid", "test-issuer").unwrap()
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
                &[],
                "tech-1",
                None,
                Duration::from_secs(300),
            )
            .unwrap();
        assert!(exp > chrono::Utc::now().timestamp());

        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(s.jwks.clone()).unwrap();
        let kid = jsonwebtoken::decode_header(&token).unwrap().kid.unwrap();
        let jwk = jwks
            .find(&kid)
            .expect("published JWK matches the token kid");
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

    /// The `boot_id` claim (§7.1 freshness) is present iff the caller supplies it.
    #[test]
    fn mint_sets_boot_id_only_when_provided() {
        let s = signer();
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(s.jwks.clone()).unwrap();
        let mut v = jsonwebtoken::Validation::new(Algorithm::ES256);
        v.set_audience(&["d"]);
        v.set_issuer(&["test-issuer"]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let decode = |tok: &str| -> serde_json::Value {
            let kid = jsonwebtoken::decode_header(tok).unwrap().kid.unwrap();
            let key = jsonwebtoken::DecodingKey::from_jwk(jwks.find(&kid).unwrap()).unwrap();
            jsonwebtoken::decode::<serde_json::Value>(tok, &key, &v)
                .unwrap()
                .claims
        };
        // Provided → the claim binds this boot.
        let (with, _) = s
            .mint(
                "d",
                &[],
                &[],
                "t",
                Some("boot-xyz"),
                Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(decode(&with)["boot_id"], "boot-xyz");
        // Omitted → no claim (a non-destructive token isn't boot-bound).
        let (without, _) = s
            .mint("d", &[], &[], "t", None, Duration::from_secs(60))
            .unwrap();
        assert!(decode(&without).get("boot_id").is_none());
    }

    /// Verb scopes (the device gates on these) ride in the same `scope` claim,
    /// after the `component:<id>` scopes.
    #[test]
    fn mint_includes_verb_scopes() {
        let s = signer();
        let (token, _) = s
            .mint(
                "d",
                &["hsm".to_string()],
                &["reset:execute".to_string(), "update:transfer".to_string()],
                "tech",
                None,
                Duration::from_secs(60),
            )
            .unwrap();
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(s.jwks.clone()).unwrap();
        let kid = jsonwebtoken::decode_header(&token).unwrap().kid.unwrap();
        let key = jsonwebtoken::DecodingKey::from_jwk(jwks.find(&kid).unwrap()).unwrap();
        let mut v = jsonwebtoken::Validation::new(Algorithm::ES256);
        v.set_audience(&["d"]);
        v.set_issuer(&["test-issuer"]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        #[derive(Deserialize)]
        struct C {
            scope: String,
        }
        let scope = jsonwebtoken::decode::<C>(&token, &key, &v)
            .unwrap()
            .claims
            .scope;
        assert_eq!(scope, "component:hsm reset:execute update:transfer");
    }

    /// A token minted for one device must not validate for another (the `aud`
    /// replay guard SOVDd relies on).
    #[test]
    fn token_rejected_for_a_different_device() {
        let s = signer();
        let (token, _) = s
            .mint(
                "vin:ABC",
                &["engine_ecu".to_string()],
                &[],
                "t",
                None,
                Duration::from_secs(300),
            )
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
            .mint(
                "d",
                &["a".to_string()],
                &[],
                "t",
                None,
                Duration::from_secs(120),
            )
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(exp - now <= 120 && exp - now > 60);
        // empty components → empty scope
        let (_t2, _e2) = s
            .mint("d", &[], &[], "t", None, Duration::from_secs(60))
            .unwrap();
        assert!(!token.is_empty());
    }

    #[test]
    fn token_header_carries_x5c_chain() {
        let s = signer();
        let (token, _) = s
            .mint(
                "d",
                &["engine_ecu".to_string()],
                &[],
                "t",
                None,
                Duration::from_secs(60),
            )
            .unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        let x5c = header.x5c.expect("x5c chain present in JWT header");
        assert_eq!(x5c.len(), 2, "leaf + intermediate");
        // each entry is standard base64 of cert DER; DER starts with 0x30 (SEQUENCE)
        let der = base64::engine::general_purpose::STANDARD
            .decode(&x5c[0])
            .unwrap();
        assert_eq!(der[0], 0x30);
    }
}

#[cfg(test)]
mod resolve_aud_tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn ecu_id_shape() {
        assert!(is_ecu_id(&"a".repeat(64)));
        assert!(is_ecu_id(&"0123456789ABCDEF".repeat(4)));
        assert!(!is_ecu_id("cvc-host-f3aa8305f4f71800"));
        assert!(!is_ecu_id(&"a".repeat(63)));
        assert!(!is_ecu_id(&"g".repeat(64)));
    }

    /// A 64-hex device_id is the ecu id — used verbatim (lowercased), no
    /// roster call.
    #[tokio::test]
    async fn hex_id_passes_through_lowercased() {
        let id = "F3AA8305F4F71800254DB937886573CF2052EB2FB5604D93661C60CA881C418C";
        let aud = resolve_aud(None, id).await.unwrap();
        assert_eq!(aud, id.to_ascii_lowercase());
    }

    /// A roster name without --ca-url is refused with an actionable error —
    /// never minted verbatim (the InvalidAudience trap).
    #[tokio::test]
    async fn roster_name_without_ca_url_is_refused() {
        let err = resolve_aud(None, "cvc-host-f3aa8305f4f71800")
            .await
            .expect_err("must refuse");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    /// A roster name resolves through Tower 1's `GET /devices/{id}` → ecu_id.
    #[tokio::test]
    async fn roster_name_resolves_via_tower_1() {
        let ecu = "f3aa8305f4f71800254db937886573cf2052eb2fb5604d93661c60ca881c418c";
        let app = Router::new().route(
            "/devices/{id}",
            get(
                move |axum::extract::Path(id): axum::extract::Path<String>| async move {
                    if id == "rig-7" {
                        Json(serde_json::json!({
                            "id": "rig-7", "status": "enrolled", "ecu_id": ecu
                        }))
                        .into_response()
                    } else {
                        (StatusCode::NOT_FOUND, "unknown").into_response()
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ca = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        assert_eq!(resolve_aud(Some(&ca), "rig-7").await.unwrap(), ecu);

        let err = resolve_aud(Some(&ca), "rig-8")
            .await
            .expect_err("404 → 400");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
}
