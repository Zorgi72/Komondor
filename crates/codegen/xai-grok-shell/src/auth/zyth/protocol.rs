//! Pure Zyth login protocol helpers: paste parse, authorize URL, state check,
//! error classification, gateway exchange response parse.
//!
//! No secrets, no network side effects in pure functions — unit-tested.

use super::config::ZythLoginConfig;
use super::super::config::OidcAuthConfig;
use super::super::oidc::protocol::{
    Discovery, Pkce, build_authorize_url as oidc_build_authorize_url,
};
use std::collections::HashMap;

/// User-visible Zyth login errors (fail-closed, non-corruptive).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZythLoginError {
    #[error("Zyth login is not configured")]
    NotConfigured,
    #[error("failed to bind Zyth loopback server: {0}")]
    BindLoopback(String),
    #[error("Login timed out after 10 minutes. Please try again.")]
    CallbackTimeout,
    #[error("Zyth callback channel closed unexpectedly")]
    CallbackChannelClosed,
    #[error("Zyth authentication failed: {0}")]
    CallbackAuthFailed(String),
    #[error("failed to parse pasted input: {0}")]
    InvalidPastedInput(String),
    #[error("Zyth authentication failed: state mismatch")]
    StateMismatch,
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    #[error("OIDC token exchange failed: {0}")]
    TokenExchange(String),
    #[error("gateway key exchange failed: {0}")]
    KeyExchange(String),
    #[error("gateway returned invalid credential")]
    InvalidGatewayCredential,
    #[error("failed to save Zyth credentials: {0}")]
    SaveAuth(String),
    #[error("cancelled")]
    Cancelled,
    #[error("network error: {0}")]
    Network(String),
}

/// Map low-level / OIDC errors into stable user-facing Zyth errors.
pub fn classify_error(err: &anyhow::Error) -> ZythLoginError {
    // Walk the chain for known markers.
    let s = format!("{err:#}");
    let lower = s.to_lowercase();
    if lower.contains("state mismatch") {
        return ZythLoginError::StateMismatch;
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return ZythLoginError::CallbackTimeout;
    }
    if lower.contains("bind") && lower.contains("loopback") {
        return ZythLoginError::BindLoopback(s);
    }
    if lower.contains("invalid input") || lower.contains("pasted") {
        return ZythLoginError::InvalidPastedInput(s);
    }
    if lower.contains("discovery") {
        return ZythLoginError::Discovery(s);
    }
    if lower.contains("token exchange") {
        return ZythLoginError::TokenExchange(s);
    }
    if lower.contains("key exchange") || lower.contains("exchange") && lower.contains("gateway") {
        return ZythLoginError::KeyExchange(s);
    }
    if lower.contains("cancel") {
        return ZythLoginError::Cancelled;
    }
    ZythLoginError::Network(s)
}

/// Successful paste/callback payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastedCallback {
    pub code: String,
    pub state: String,
}

/// Parse user-pasted input into `(code, state)`.
///
/// Accepts full callback URL: `http://127.0.0.1:PORT/callback?code=XXX&state=YYY`
///
/// Bare authorization codes without `state` are **not** accepted for login
/// completion (CSRF): the caller must always validate a non-empty state.
/// This parser still returns bare codes with empty state so the login flow
/// can fail closed with [`ZythLoginError::StateMismatch`].
pub fn parse_pasted_input(input: &str) -> Result<PastedCallback, ZythLoginError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(ZythLoginError::InvalidPastedInput("empty input".into()));
    }

    if let Ok(url) = url::Url::parse(input) {
        // Only accept loopback callback URLs (open-redirect / paste of foreign IdP URLs).
        if let Some(host) = url.host_str() {
            let h = host.to_ascii_lowercase();
            if h != "127.0.0.1" && h != "localhost" && h != "::1" {
                return Err(ZythLoginError::InvalidPastedInput(
                    "callback URL host must be loopback (127.0.0.1/localhost)".into(),
                ));
            }
        }
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(ZythLoginError::InvalidPastedInput(
                "callback URL must be http(s)".into(),
            ));
        }
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        if let Some(code) = params.get("code") {
            let state = params.get("state").cloned().unwrap_or_default();
            if state.is_empty() {
                return Err(ZythLoginError::InvalidPastedInput(
                    "callback URL missing 'state' (required for CSRF protection)".into(),
                ));
            }
            return Ok(PastedCallback {
                code: code.clone(),
                state,
            });
        }
        if let Some(error) = params.get("error") {
            let desc = params.get("error_description").cloned().unwrap_or_default();
            return Err(ZythLoginError::CallbackAuthFailed(if desc.is_empty() {
                error.clone()
            } else {
                format!("{error}: {desc}")
            }));
        }
        return Err(ZythLoginError::InvalidPastedInput(
            "URL has no 'code' query parameter".into(),
        ));
    }

    // Reject obvious garbage that looks like a URL path without scheme.
    if input.contains("://") {
        return Err(ZythLoginError::InvalidPastedInput(
            "could not parse as URL or authorization code".into(),
        ));
    }

    // Bare code: allowed only as intermediate parse; login requires state.
    Ok(PastedCallback {
        code: input.to_owned(),
        state: String::new(),
    })
}

/// CSRF state validation — constant-time string compare for equal-length values.
pub fn validate_state(expected: &str, received: &str) -> Result<(), ZythLoginError> {
    if expected.is_empty() {
        return Err(ZythLoginError::StateMismatch);
    }
    if expected.len() != received.len() {
        return Err(ZythLoginError::StateMismatch);
    }
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(received.bytes()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(ZythLoginError::StateMismatch);
    }
    Ok(())
}

/// Build authorize URL for Zyth (delegates to shared OIDC builder; no oauth2 extras).
pub(crate) fn build_zyth_authorize_url(
    cfg: &ZythLoginConfig,
    discovery: &Discovery,
    redirect_uri: &str,
    pkce: &Pkce,
    state: &str,
    nonce: &str,
) -> String {
    let oidc = cfg.as_oidc();
    let mut url = oidc_build_authorize_url(&oidc, None, discovery, redirect_uri, pkce, state, nonce);
    // Auth0: ensure offline_access works with consent when needed
    if !url.contains("prompt=") {
        url.push_str("&prompt=login");
    }
    url
}

/// Successful gateway exchange payload (virtual key).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct GatewayExchangeResponse {
    pub api_key: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Validate and normalize a gateway-accepted credential.
pub fn validate_gateway_credential(api_key: &str) -> Result<(), ZythLoginError> {
    let k = api_key.trim();
    if k.is_empty() {
        return Err(ZythLoginError::InvalidGatewayCredential);
    }
    // Edge accepts sk-… virtual keys and cpa_… machine keys.
    // Require the `sk-` delimiter (not bare `sk` prefix) to reject junk / JWT-ish strings.
    if k.starts_with("sk-") || k.starts_with("cpa_") {
        // Minimum length guard against trivial placeholders.
        if k.len() < 8 {
            return Err(ZythLoginError::InvalidGatewayCredential);
        }
        return Ok(());
    }
    // Reject obvious Auth0 JWT-shaped tokens (three base64 segments) as insufficient.
    if k.matches('.').count() == 2 && k.len() > 40 {
        return Err(ZythLoginError::InvalidGatewayCredential);
    }
    Err(ZythLoginError::InvalidGatewayCredential)
}

/// Derive the revoke URL from an exchange URL (`…/exchange` → `…/revoke`).
pub fn revoke_url_from_exchange(exchange_url: &str) -> Option<String> {
    let u = exchange_url.trim();
    if u.is_empty() {
        return None;
    }
    if let Some(base) = u.strip_suffix("/exchange") {
        return Some(format!("{base}/revoke"));
    }
    if u.ends_with("/v1") {
        return Some(format!("{u}/revoke"));
    }
    // Fallback: sibling path under /zyth/cli/v1/
    if u.contains("/zyth/cli/v1/") {
        if let Some(idx) = u.find("/zyth/cli/v1/") {
            return Some(format!("{}{}", &u[..idx], "/zyth/cli/v1/revoke"));
        }
    }
    None
}

/// Parse exchange HTTP body without logging secrets.
pub fn parse_exchange_response(body: &str) -> Result<GatewayExchangeResponse, ZythLoginError> {
    let parsed: GatewayExchangeResponse = serde_json::from_str(body).map_err(|e| {
        ZythLoginError::KeyExchange(format!("invalid JSON response: {e}"))
    })?;
    validate_gateway_credential(&parsed.api_key)?;
    Ok(parsed)
}

/// Build a safe user-facing message (never includes tokens).
pub fn user_message(err: &ZythLoginError) -> String {
    match err {
        ZythLoginError::CallbackAuthFailed(msg) => {
            // Strip potential tokens if IdP echoed something weird.
            let safe = redact_secrets(msg);
            format!("Zyth sign-in denied: {safe}")
        }
        other => other.to_string(),
    }
}

fn redact_secrets(s: &str) -> String {
    // Replace secret-looking substrings repeatedly (not just the first 12 chars).
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &s[i..];
        let hit = ["sk-", "cpa_", "eyJ"]
            .iter()
            .find_map(|n| rest.find(n).map(|pos| (pos, n.len())));
        match hit {
            Some((0, nlen)) => {
                // Consume token-ish run (until whitespace / quote / amp).
                let mut j = nlen;
                while i + j < bytes.len() {
                    let c = bytes[i + j];
                    if c.is_ascii_whitespace()
                        || c == b'"'
                        || c == b'\''
                        || c == b'&'
                        || c == b'<'
                        || c == b'>'
                    {
                        break;
                    }
                    j += 1;
                    if j > 256 {
                        break;
                    }
                }
                out.push_str("[redacted]");
                i += j;
            }
            Some((pos, _)) => {
                out.push_str(&s[i..i + pos]);
                i += pos;
            }
            None => {
                out.push_str(rest);
                break;
            }
        }
    }
    out
}

/// True if host is an allowed Zyth gateway host (exact or DNS-label under zyth.app).
fn is_allowed_zyth_gateway_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host == "ai-gateway.zyth.app" || host == "zyth.app" {
        return true;
    }
    // Require a DNS-label boundary: `*.zyth.app`, not `notzyth.app` / `zyth.app.evil`.
    host.ends_with(".zyth.app")
        && !host.contains("..")
        && host
            .strip_suffix(".zyth.app")
            .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('/'))
}

/// Whether a URL looks like our loopback callback host.
pub fn is_loopback_redirect(redirect_uri: &str) -> bool {
    redirect_uri.starts_with("http://127.0.0.1:") || redirect_uri.starts_with("http://localhost:")
}

/// Fail-closed allowlist for the key-exchange endpoint (SSRF defense).
///
/// Accepts:
/// - `https://ai-gateway.zyth.app/...` (production)
/// - `https://*.zyth.app/...` other Zyth hosts (future regional)
/// - loopback `http://127.0.0.1` / `http://localhost` only when
///   `ZYTH_CLI_ALLOW_INSECURE_EXCHANGE=1` (local dev)
pub fn validate_exchange_url(url: &str) -> Result<(), ZythLoginError> {
    validate_zyth_https_url(url, "exchange")
}

/// Fail-closed allowlist for gateway `base_url` written to env / endpoints overlay.
/// Same host rules as the exchange URL (credential must not be pointed at third parties).
pub fn validate_gateway_base_url(url: &str) -> Result<(), ZythLoginError> {
    validate_zyth_https_url(url, "gateway base")
}

fn validate_zyth_https_url(url: &str, what: &str) -> Result<(), ZythLoginError> {
    let parsed = url::Url::parse(url).map_err(|e| {
        ZythLoginError::KeyExchange(format!("invalid {what} URL: {e}"))
    })?;
    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    let scheme = parsed.scheme();

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ZythLoginError::KeyExchange(format!(
            "{what} URL must not embed credentials"
        )));
    }

    let allow_insecure = std::env::var("ZYTH_CLI_ALLOW_INSECURE_EXCHANGE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    if scheme == "https" {
        if is_allowed_zyth_gateway_host(&host) {
            return Ok(());
        }
        return Err(ZythLoginError::KeyExchange(format!(
            "{what} host not allowlisted: {host}"
        )));
    }

    if allow_insecure
        && scheme == "http"
        && (host == "127.0.0.1" || host == "localhost" || host == "::1")
    {
        return Ok(());
    }

    Err(ZythLoginError::KeyExchange(format!(
        "{what} URL must be https://…zyth.app (or loopback with ZYTH_CLI_ALLOW_INSECURE_EXCHANGE=1)"
    )))
}

/// Pure helper used by authorize-url unit tests without discovery network.
pub fn build_authorize_url_parts(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &str,
    code_challenge: &str,
    state: &str,
    nonce: &str,
) -> String {
    format!(
        "{authorization_endpoint}?response_type=code&client_id={}&redirect_uri={}&scope={}\
         &code_challenge={}&code_challenge_method=S256&state={}&nonce={}&prompt=login",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(scopes),
        urlencoding::encode(code_challenge),
        urlencoding::encode(state),
        urlencoding::encode(nonce),
    )
}

/// Unused import keep for OidcAuthConfig type re-export in tests.
#[allow(dead_code)]
fn _oidc_cfg_marker(c: OidcAuthConfig) -> OidcAuthConfig {
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pasted_full_url() {
        let r = parse_pasted_input(
            "http://127.0.0.1:54321/callback?code=abc123&state=xyz",
        )
        .unwrap();
        assert_eq!(r.code, "abc123");
        assert_eq!(r.state, "xyz");
    }

    #[test]
    fn parse_pasted_bare_code_has_empty_state_for_csrf_reject() {
        let r = parse_pasted_input("  bare-code-99  ").unwrap();
        assert_eq!(r.code, "bare-code-99");
        assert!(r.state.is_empty());
        assert!(validate_state("expected", &r.state).is_err());
    }

    #[test]
    fn parse_pasted_rejects_non_loopback_callback() {
        assert!(matches!(
            parse_pasted_input("https://evil.example/callback?code=a&state=b"),
            Err(ZythLoginError::InvalidPastedInput(_))
        ));
    }

    #[test]
    fn parse_pasted_rejects_missing_state_on_url() {
        assert!(matches!(
            parse_pasted_input("http://127.0.0.1:1/callback?code=only"),
            Err(ZythLoginError::InvalidPastedInput(_))
        ));
    }

    #[test]
    fn parse_pasted_empty_fails() {
        assert!(matches!(
            parse_pasted_input("   "),
            Err(ZythLoginError::InvalidPastedInput(_))
        ));
    }

    #[test]
    fn parse_pasted_idp_error() {
        let err = parse_pasted_input(
            "http://127.0.0.1:1/callback?error=access_denied&error_description=nope",
        )
        .unwrap_err();
        assert!(matches!(err, ZythLoginError::CallbackAuthFailed(_)));
        assert!(user_message(&err).contains("denied") || user_message(&err).contains("nope"));
    }

    #[test]
    fn parse_pasted_url_missing_code() {
        assert!(matches!(
            parse_pasted_input("http://127.0.0.1:1/callback?foo=bar"),
            Err(ZythLoginError::InvalidPastedInput(_))
        ));
    }

    #[test]
    fn redact_secrets_strips_full_token_runs() {
        let msg = user_message(&ZythLoginError::CallbackAuthFailed(
            "denied sk-supersecrettokenvalue and eyJhbGciOiJSUzI1NiJ9.aa.bb".into(),
        ));
        assert!(!msg.contains("sk-super"));
        assert!(!msg.contains("eyJhbGci"));
        assert!(msg.contains("[redacted]"));
    }

    #[test]
    fn state_ok_and_mismatch() {
        validate_state("abc", "abc").unwrap();
        assert!(matches!(
            validate_state("abc", "abd"),
            Err(ZythLoginError::StateMismatch)
        ));
        assert!(matches!(
            validate_state("abc", "ab"),
            Err(ZythLoginError::StateMismatch)
        ));
        assert!(matches!(
            validate_state("", "x"),
            Err(ZythLoginError::StateMismatch)
        ));
    }

    #[test]
    fn gateway_cred_accepts_sk_and_cpa() {
        validate_gateway_credential("sk-testkey1234567890").unwrap();
        validate_gateway_credential("cpa_machine_key_here").unwrap();
        assert!(validate_gateway_credential("").is_err());
        // Bare `sk` without hyphen must be rejected (was overly broad).
        assert!(validate_gateway_credential("sknotdashed").is_err());
        assert!(validate_gateway_credential("sk").is_err());
        assert!(validate_gateway_credential("sk-x").is_err()); // too short
        assert!(validate_gateway_credential(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"
        )
        .is_err());
    }

    #[test]
    fn revoke_url_from_exchange_path() {
        assert_eq!(
            revoke_url_from_exchange("https://ai-gateway.zyth.app/zyth/cli/v1/exchange")
                .as_deref(),
            Some("https://ai-gateway.zyth.app/zyth/cli/v1/revoke")
        );
        assert!(revoke_url_from_exchange("").is_none());
    }

    #[test]
    fn parse_exchange_ok() {
        let body = r#"{"api_key":"sk-abc","base_url":"https://ai-gateway.zyth.app/v1","user_id":"u1"}"#;
        let r = parse_exchange_response(body).unwrap();
        assert_eq!(r.api_key, "sk-abc");
    }

    #[test]
    fn parse_exchange_rejects_jwt_as_key() {
        let body = r#"{"api_key":"eyJhbGciOiJSUzI1NiJ9.e30.sig"}"#;
        assert!(parse_exchange_response(body).is_err());
    }

    #[test]
    fn authorize_url_contains_pkce_and_state() {
        let url = build_authorize_url_parts(
            "https://auth.zyth.app/authorize",
            "client",
            "http://127.0.0.1:9/callback",
            "openid email",
            "challenge",
            "state1",
            "nonce1",
        );
        assert!(url.contains("code_challenge=challenge"));
        assert!(url.contains("state=state1"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("prompt=login"));
        assert!(url.contains(urlencoding::encode("http://127.0.0.1:9/callback").as_ref()));
    }

    #[test]
    fn classify_timeout() {
        let e = anyhow::anyhow!("Login timed out after 10 minutes");
        assert!(matches!(classify_error(&e), ZythLoginError::CallbackTimeout));
    }

    #[test]
    fn is_loopback_redirect_ok() {
        assert!(is_loopback_redirect("http://127.0.0.1:1234/callback"));
        assert!(!is_loopback_redirect("https://evil.example/callback"));
    }

    #[test]
    fn exchange_url_allowlist() {
        validate_exchange_url("https://ai-gateway.zyth.app/zyth/cli/v1/exchange").unwrap();
        validate_gateway_base_url("https://ai-gateway.zyth.app/v1").unwrap();
        assert!(validate_exchange_url("https://evil.example/zyth/cli/v1/exchange").is_err());
        assert!(validate_exchange_url("http://ai-gateway.zyth.app/zyth/cli/v1/exchange").is_err());
        assert!(validate_exchange_url("https://user:pass@ai-gateway.zyth.app/x").is_err());
        assert!(validate_exchange_url("https://ai-gateway.zyth.app.evil.com/x").is_err());
        assert!(validate_gateway_base_url("https://evil.example/v1").is_err());
        assert!(validate_gateway_base_url("https://notzyth.app/v1").is_err());
        assert!(validate_gateway_base_url("https://ai-gateway.zyth.app.evil.com/v1").is_err());
    }

    #[test]
    fn config_scope_distinct_from_xai() {
        let cfg = ZythLoginConfig {
            issuer: "https://auth.zyth.app/".into(),
            client_id: "cli".into(),
            scopes: vec![],
            audience: None,
            gateway_base_url: "https://ai-gateway.zyth.app/v1".into(),
            exchange_url: "https://ai-gateway.zyth.app/zyth/cli/v1/exchange".into(),
        };
        assert!(!cfg.auth_scope().contains("auth.x.ai"));
        assert!(cfg.auth_scope().starts_with("https://auth.zyth.app::"));
    }
}
