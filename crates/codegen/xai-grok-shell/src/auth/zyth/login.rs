//! Interactive `/loginzyth` orchestration: OIDC PKCE + loopback/paste + gateway key mint.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::{Path};
use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::Html,
    routing::get,
};
use chrono::Utc;
use tokio::net::TcpListener;

use super::super::config::GrokComConfig;
use super::super::flow::{AuthChannels, AuthUrlInfo, AuthUrlMode};
use super::super::model::{AuthMode, GrokAuth};
use super::super::oidc::protocol::{
    OidcError, OidcUserInfo, discover, exchange_code, extract_user_info, generate_pkce,
};
use super::super::storage::{read_auth_json, store_api_key, write_auth_json};
use super::config::{ZYTH_LOOPBACK_PORTS, ZythLoginConfig};
use super::models::sync_zyth_models_from_gateway;
use super::protocol::{
    GatewayExchangeResponse, PastedCallback, ZythLoginError, build_zyth_authorize_url,
    parse_exchange_response, parse_pasted_input, user_message, validate_exchange_url,
    validate_gateway_base_url, validate_gateway_credential, validate_state,
};

const AUTH_CALLBACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Bind the first free loopback port from the Auth0-registered range.
async fn bind_zyth_loopback() -> Result<TcpListener, String> {
    let mut last_err = String::from("no ports available");
    for &port in ZYTH_LOOPBACK_PORTS {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => return Ok(l),
            Err(e) => last_err = format!("port {port}: {e}"),
        }
    }
    Err(format!(
        "could not bind any registered loopback port {:?}: {last_err}",
        ZYTH_LOOPBACK_PORTS
    ))
}

type CallbackResult = Result<PastedCallback, String>;

fn callback_page(title: &str, message: &str, is_success: bool) -> String {
    let color = if is_success { "#22c55e" } else { "#ef4444" };
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="color-scheme" content="light dark"/>
<title>{title}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;
background:#0a0a0a;color:#e5e5e5}}
.card{{text-align:center;padding:48px;max-width:420px}}
h1{{font-size:18px;font-weight:600;color:{color}}}
p{{font-size:14px;color:#a3a3a3;margin-top:12px}}
@media(prefers-color-scheme:light){{body{{background:#fafafa;color:#171717}}p{{color:#525252}}}}
</style></head>
<body><div class="card"><h1>{title}</h1><p>{message}</p></div></body></html>"#
    )
}

fn parse_callback_params(params: &HashMap<String, String>) -> CallbackResult {
    if let Some(code) = params.get("code") {
        let state = params.get("state").cloned().unwrap_or_default();
        return Ok(PastedCallback {
            code: code.clone(),
            state,
        });
    }
    let error = params.get("error").cloned().unwrap_or_default();
    let desc = params.get("error_description").cloned().unwrap_or_default();
    Err(if desc.is_empty() {
        error
    } else {
        format!("{error}: {desc}")
    })
}

async fn handle_callback(
    State(tx): State<tokio::sync::mpsc::Sender<CallbackResult>>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Html<String>) {
    let result = parse_callback_params(&params);
    let (title, message, ok) = match &result {
        Ok(_) => (
            "Signed in to Zyth",
            "You can close this window and return to the CLI.",
            true,
        ),
        Err(_) => ("Access denied", "Close this window and try /loginzyth again.", false),
    };
    let _ = tx.try_send(result);
    (StatusCode::OK, Html(callback_page(title, message, ok)))
}

async fn race_callback_and_client_ui(
    listener: TcpListener,
    code_rx: &mut tokio::sync::mpsc::Receiver<String>,
) -> anyhow::Result<PastedCallback> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<CallbackResult>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let app = Router::new()
        .route("/callback", get(handle_callback))
        .with_state(tx.clone());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let client_tx = tx.clone();
    let client_bridge = async {
        while let Some(code) = code_rx.recv().await {
            match parse_pasted_input(&code) {
                Ok(result) => {
                    let _ = client_tx.send(Ok(result)).await;
                    return;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "loginzyth: invalid client paste");
                }
            }
        }
    };
    drop(tx);

    let result = tokio::select! {
        r = tokio::time::timeout(AUTH_CALLBACK_TIMEOUT, rx.recv()) => {
            r.map_err(|_| anyhow::Error::new(ZythLoginError::CallbackTimeout))?
                .ok_or_else(|| anyhow::Error::new(ZythLoginError::CallbackChannelClosed))?
        }
        _ = client_bridge => {
            rx.recv().await
                .ok_or_else(|| anyhow::Error::new(ZythLoginError::CallbackChannelClosed))?
        }
    };
    let _ = shutdown_tx.send(());
    let _ = server.await;
    result.map_err(|e| anyhow::Error::new(ZythLoginError::CallbackAuthFailed(e)))
}

async fn race_callback_and_stdin(
    listener: TcpListener,
    enable_stdin: bool,
) -> anyhow::Result<PastedCallback> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<CallbackResult>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let app = Router::new()
        .route("/callback", get(handle_callback))
        .with_state(tx.clone());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    if enable_stdin {
        let stdin_tx = tx.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            let mut buf = String::new();
            loop {
                if stdin_tx.is_closed() {
                    return;
                }
                buf.clear();
                let mut handle = stdin.lock();
                match handle.read_line(&mut buf) {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(_) => return,
                }
                drop(handle);
                let trimmed = buf.trim().to_owned();
                if trimmed.is_empty() {
                    continue;
                }
                match parse_pasted_input(&trimmed) {
                    Ok(result) => {
                        let _ = stdin_tx.blocking_send(Ok(result));
                        return;
                    }
                    Err(ZythLoginError::InvalidPastedInput(msg)) => {
                        eprintln!("  Invalid input: {msg}. Try again:");
                    }
                    Err(e) => {
                        let _ = stdin_tx.blocking_send(Err(e.to_string()));
                        return;
                    }
                }
            }
        });
    }
    drop(tx);

    let result = tokio::time::timeout(AUTH_CALLBACK_TIMEOUT, rx.recv())
        .await
        .map_err(|_| anyhow::Error::new(ZythLoginError::CallbackTimeout))?
        .ok_or_else(|| anyhow::Error::new(ZythLoginError::CallbackChannelClosed))?;

    let _ = shutdown_tx.send(());
    let _ = server.await;
    result.map_err(|e| anyhow::Error::new(ZythLoginError::CallbackAuthFailed(e)))
}

async fn exchange_for_virtual_key(
    exchange_url: &str,
    id_or_access_token: &str,
    client_id: &str,
) -> anyhow::Result<GatewayExchangeResponse> {
    validate_exchange_url(exchange_url).map_err(anyhow::Error::new)?;
    // Log host only — never the bearer token.
    tracing::debug!(url = %exchange_url, "loginzyth: exchanging Auth0 token for gateway key");
    let resp = crate::http::shared_client()
        .post(exchange_url)
        .header("Authorization", format!("Bearer {id_or_access_token}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&serde_json::json!({ "client_id": client_id }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| anyhow::Error::new(ZythLoginError::Network(e.to_string())))?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        // Never log body if it might contain secrets; surface status only at info.
        tracing::warn!(status = %status.as_u16(), "loginzyth: key exchange HTTP error");
        return Err(anyhow::Error::new(ZythLoginError::KeyExchange(format!(
            "HTTP {} — check Auth0 login and gateway /zyth/cli exchange",
            status.as_u16()
        ))));
    }
    parse_exchange_response(&body).map_err(anyhow::Error::new)
}

/// Persist Zyth credentials under a distinct scope without touching auth.x.ai scopes.
pub fn persist_zyth_credentials(
    grok_home: &Path,
    scope: &str,
    auth: &GrokAuth,
) -> Result<(), ZythLoginError> {
    let path = grok_home.join("auth.json");
    let mut map = match read_auth_json(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Default::default(),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            // Corrupted file: do not clobber; surface error.
            return Err(ZythLoginError::SaveAuth(format!(
                "auth.json unreadable ({e}); fix or remove it before retrying"
            )));
        }
        Err(e) => return Err(ZythLoginError::SaveAuth(e.to_string())),
    };
    map.insert(scope.to_owned(), auth.clone());
    write_auth_json(&path, &map).map_err(|e| ZythLoginError::SaveAuth(e.to_string()))
}

/// Write gateway endpoint overrides so inference targets Zyth AI Gateway.
pub fn persist_zyth_endpoint_overlay(grok_home: &Path, gateway_base: &str) -> Result<(), ZythLoginError> {
    // Fail closed on injection / non-allowlisted hosts before writing TOML.
    validate_gateway_base_url(gateway_base)?;
    let gateway_base = gateway_base.trim_end_matches('/');
    // Defensive: quotes/newlines must never reach TOML (allowlist already rejects).
    if gateway_base.bytes().any(|b| b == b'"' || b == b'\n' || b == b'\r' || b == b'\\') {
        return Err(ZythLoginError::KeyExchange(
            "gateway base URL contains forbidden characters".into(),
        ));
    }
    let path = grok_home.join("zyth_endpoints.toml");
    let contents = format!(
        "# Generated by /loginzyth — points inference at Zyth AI Gateway.\n\
         # Safe to delete to restore defaults. Does not contain secrets.\n\
         [endpoints]\n\
         xai_api_base_url = \"{gateway_base}\"\n\
         models_base_url = \"{gateway_base}\"\n"
    );
    crate::util::secure_file::write_secure_file(&path, contents.as_bytes())
        .map_err(|e| ZythLoginError::SaveAuth(format!("zyth_endpoints.toml: {e}")))?;
    Ok(())
}

/// Apply process env so the running session uses the gateway without restart.
pub fn activate_zyth_runtime(gateway_base: &str, api_key: &str) {
    // SAFETY: called from login path on the agent/CLI thread before concurrent sampling.
    unsafe {
        std::env::set_var("XAI_API_KEY", api_key);
        std::env::set_var("GROK_XAI_API_BASE_URL", gateway_base);
        std::env::set_var("GROK_MODELS_BASE_URL", gateway_base);
    }
}

/// Outcome of a successful `/loginzyth` (auth + optional gateway catalog).
pub struct LoginZythOutcome {
    pub auth: GrokAuth,
    pub gateway_base: String,
    /// Enriched gateway catalog ready for `ModelsManager::install_gateway_catalog`.
    pub models: Option<indexmap::IndexMap<String, crate::agent::config::ModelEntry>>,
    pub models_count: usize,
}

/// Full `/loginzyth` flow.
///
/// 1. OIDC Auth Code + PKCE against AuthStack (`auth.zyth.app`)
/// 2. Loopback `/callback` race vs paste
/// 3. Exchange Auth0 id_token for LiteLLM virtual key (gateway)
/// 4. Persist under distinct scope + activate API-key inference toward gateway
/// 5. Fetch/enrich all gateway models (`[ZYTH]` prefix)
pub async fn run_loginzyth_flow(
    grok_home: &Path,
    channels: Option<AuthChannels>,
) -> anyhow::Result<LoginZythOutcome> {
    let cfg = ZythLoginConfig::resolve();
    validate_exchange_url(&cfg.exchange_url).map_err(anyhow::Error::new)?;
    tracing::info!(
        issuer = %cfg.issuer,
        client_id = %cfg.client_id,
        gateway = %cfg.gateway_base_url,
        "loginzyth: starting Zyth SSO"
    );

    jsonwebtoken::crypto::CryptoProvider::install_default(
        &jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER,
    )
    .ok();

    let oidc = cfg.as_oidc();
    let discovery = discover(&cfg.issuer)
        .await
        .map_err(|e| anyhow::Error::new(ZythLoginError::Discovery(e.to_string())))?;
    let pkce = generate_pkce();
    let state = uuid::Uuid::now_v7().to_string();
    let nonce = uuid::Uuid::now_v7().to_string();

    // Bind a fixed Auth0-registered port (see ZYTH_LOOPBACK_PORTS). Random OS
    // ports are rejected by Auth0 ("Callback URL mismatch").
    let listener = bind_zyth_loopback()
        .await
        .map_err(|e| anyhow::Error::new(ZythLoginError::BindLoopback(e)))?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let auth_url =
        build_zyth_authorize_url(&cfg, &discovery, &redirect_uri, &pkce, &state, &nonce);

    let (url_tx, code_rx) = match channels {
        Some(ch) => (ch.url_tx, Some(ch.code_rx)),
        None => (None, None),
    };
    let has_client_ui = code_rx.is_some();

    if has_client_ui {
        if let Err(e) = webbrowser::open(&auth_url) {
            tracing::debug!(error = %e, "loginzyth: failed to open browser");
        }
    } else {
        eprintln!();
        eprintln!("Signing in with Zyth (auth.zyth.app)...");
        eprintln!();
        if let Err(e) = webbrowser::open(&auth_url) {
            tracing::debug!(error = %e, "loginzyth: failed to open browser");
        }
        eprintln!("Open this URL to sign in:");
        eprintln!("  {auth_url}");
    }

    let use_stdin = !has_client_ui && std::io::stdin().is_terminal();
    if use_stdin {
        eprintln!();
        eprintln!("Paste the callback URL here if the browser does not return automatically:");
    }

    if let Some(tx) = url_tx {
        let _ = tx.send(AuthUrlInfo {
            url: auth_url.clone(),
            mode: AuthUrlMode::Loopback,
        });
    }

    let PastedCallback {
        code,
        state: received_state,
    } = if let Some(mut rx) = code_rx {
        race_callback_and_client_ui(listener, &mut rx).await?
    } else {
        race_callback_and_stdin(listener, use_stdin).await?
    };

    // Always enforce CSRF state (reject bare codes without state).
    // Empty/mismatched state → login-CSRF / session fixation risk.
    validate_state(&state, &received_state).map_err(anyhow::Error::new)?;

    let tokens = exchange_code(
        &discovery.token_endpoint,
        &code,
        &redirect_uri,
        &cfg.client_id,
        &pkce.code_verifier,
    )
    .await
    .map_err(|e| anyhow::Error::new(ZythLoginError::TokenExchange(e.to_string())))?;

    // Prefer id_token (always JWT) for gateway exchange; fall back to access_token.
    let jwt_for_exchange = tokens
        .id_token
        .as_deref()
        .filter(|t| t.matches('.').count() == 2)
        .unwrap_or(tokens.access_token.as_str());

    let exchange = exchange_for_virtual_key(&cfg.exchange_url, jwt_for_exchange, &cfg.client_id)
        .await?;
    validate_gateway_credential(&exchange.api_key)
        .map_err(anyhow::Error::new)?;

    // Prefer server-provided base_url only if it passes the same host allowlist
    // (prevents credential exfil if exchange response is tampered/compromised).
    let gateway_base = if let Some(ref remote) = exchange.base_url {
        validate_gateway_base_url(remote).map_err(anyhow::Error::new)?;
        remote.trim_end_matches('/').to_owned()
    } else {
        validate_gateway_base_url(&cfg.gateway_base_url).map_err(anyhow::Error::new)?;
        cfg.gateway_base_url.trim_end_matches('/').to_owned()
    };

    // Build user profile from id_token when present.
    let user_info = extract_user_info(
        tokens.id_token.as_deref(),
        &discovery,
        &cfg.issuer,
        &cfg.client_id,
        &nonce,
        None,
        None,
        None,
    )
    .await
    .unwrap_or_else(|_| OidcUserInfo {
        user_id: exchange
            .user_id
            .clone()
            .unwrap_or_else(|| "zyth-user".into()),
        email: exchange.email.clone(),
        first_name: None,
        last_name: None,
        profile_image_asset_id: None,
        principal_type: None,
        principal_id: None,
        team_id: None,
        team_name: None,
        team_role: None,
        organization_id: None,
        organization_name: None,
        organization_role: None,
        user_blocked_reason: None,
        team_blocked_reasons: vec![],
        coding_data_retention_opt_out: false,
    });

    let now = Utc::now();
    let auth = GrokAuth {
        // SSO-minted gateway virtual key (Bearer). Provenance is OIDC login —
        // not a manually pasted BYOK API key.
        key: exchange.api_key.clone(),
        auth_mode: AuthMode::Oidc,
        create_time: now,
        user_id: user_info.user_id,
        email: user_info.email.or(exchange.email),
        first_name: user_info.first_name,
        last_name: user_info.last_name,
        profile_image_asset_id: user_info.profile_image_asset_id,
        principal_type: user_info.principal_type,
        principal_id: user_info.principal_id,
        team_id: user_info.team_id,
        team_name: user_info.team_name,
        team_role: user_info.team_role,
        organization_id: user_info.organization_id,
        organization_name: user_info.organization_name,
        organization_role: user_info.organization_role,
        user_blocked_reason: user_info.user_blocked_reason,
        team_blocked_reasons: user_info.team_blocked_reasons,
        coding_data_retention_opt_out: user_info.coding_data_retention_opt_out,
        has_grok_code_access: None,
        // Keep Auth0 refresh token for future re-mint flows (not used as API bearer).
        refresh_token: tokens.refresh_token,
        expires_at: None, // virtual keys are long-lived; re-login via /loginzyth
        oidc_issuer: Some(cfg.issuer.clone()),
        oidc_client_id: Some(cfg.client_id.clone()),
    };

    let scope = cfg.auth_scope();
    persist_zyth_credentials(grok_home, &scope, &auth).map_err(anyhow::Error::new)?;
    // Also activate as the process API key for inference (does not remove auth.x.ai OIDC scopes).
    store_api_key(grok_home, &auth.key)
        .map_err(|e| anyhow::Error::new(ZythLoginError::SaveAuth(e.to_string())))?;
    persist_zyth_endpoint_overlay(grok_home, &gateway_base).map_err(anyhow::Error::new)?;
    activate_zyth_runtime(&gateway_base, &auth.key);

    let (models, models_count) =
        match sync_zyth_models_from_gateway(grok_home, &gateway_base, &auth.key).await {
            Ok((catalog, r)) => {
                tracing::info!(
                    count = r.count,
                    "loginzyth: model catalog synced from gateway"
                );
                (Some(catalog), r.count)
            }
            Err(e) => {
                tracing::warn!(error = %e, "loginzyth: model catalog sync failed");
                (None, 0)
            }
        };

    tracing::info!(
        user_id = %auth.user_id,
        scope = %scope,
        gateway = %gateway_base,
        models = models_count,
        "loginzyth: complete — SSO session + gateway credential stored"
    );

    if !has_client_ui {
        eprintln!();
        eprintln!(
            "Signed in to Zyth as {}.",
            auth.email.as_deref().unwrap_or(&auth.user_id)
        );
        eprintln!("AI endpoint: {gateway_base}");
        if models_count > 0 {
            eprintln!("Loaded {models_count} [ZYTH] models from gateway.");
        }
        eprintln!();
    }

    Ok(LoginZythOutcome {
        auth,
        gateway_base,
        models,
        models_count,
    })
}

/// Build a GrokComConfig that uses Zyth OIDC as the active scope (for AuthManager).
pub fn zyth_grok_com_config() -> GrokComConfig {
    let z = ZythLoginConfig::resolve();
    GrokComConfig {
        oidc: Some(z.as_oidc()),
        oauth2: None,
        ..GrokComConfig::default()
    }
}

/// Result helper for UI.
pub fn format_loginzyth_error(err: &anyhow::Error) -> String {
    if let Some(z) = err.downcast_ref::<ZythLoginError>() {
        return user_message(z);
    }
    if let Some(o) = err.downcast_ref::<OidcError>() {
        return format!("Zyth sign-in failed: {o}");
    }
    format!("Zyth sign-in failed: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::model::AuthStore;

    #[test]
    fn persist_does_not_drop_other_scopes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        let mut existing = AuthStore::new();
        existing.insert(
            "https://auth.x.ai::other".into(),
            GrokAuth {
                key: "xai-token".into(),
                auth_mode: AuthMode::Oidc,
                user_id: "x".into(),
                ..GrokAuth::default()
            },
        );
        write_auth_json(&path, &existing).unwrap();

        let zyth = GrokAuth {
            key: "sk-zyth-test".into(),
            auth_mode: AuthMode::ApiKey,
            user_id: "u".into(),
            oidc_issuer: Some("https://auth.zyth.app/".into()),
            oidc_client_id: Some("cli".into()),
            ..GrokAuth::default()
        };
        persist_zyth_credentials(dir.path(), "https://auth.zyth.app::cli", &zyth).unwrap();

        let map = read_auth_json(&path).unwrap();
        assert!(map.contains_key("https://auth.x.ai::other"));
        assert_eq!(
            map.get("https://auth.zyth.app::cli").map(|a| a.key.as_str()),
            Some("sk-zyth-test")
        );
        assert_eq!(
            map.get("https://auth.x.ai::other").map(|a| a.key.as_str()),
            Some("xai-token")
        );
    }

    #[test]
    fn endpoint_overlay_written_securely() {
        let dir = tempfile::tempdir().unwrap();
        persist_zyth_endpoint_overlay(dir.path(), "https://ai-gateway.zyth.app/v1").unwrap();
        let text = std::fs::read_to_string(dir.path().join("zyth_endpoints.toml")).unwrap();
        assert!(text.contains("ai-gateway.zyth.app"));
        assert!(!text.contains("sk-"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("zyth_endpoints.toml"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn format_error_redacts_via_user_message() {
        let e = anyhow::Error::new(ZythLoginError::CallbackAuthFailed(
            "access_denied sk-secretvaluehere".into(),
        ));
        let msg = format_loginzyth_error(&e);
        assert!(!msg.contains("sk-secret"));
    }
}
