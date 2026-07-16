//! `x.ai/auth/*` and legacy `x.ai/{get,set}ApiKey` extension handlers.
//!
//! These methods let the client read/write the API key via the agent and
//! drive the OAuth login flow. The agent is the single source of truth for
//! `auth.json`.

use agent_client_protocol as acp;
use serde::{Deserialize, Serialize};

use super::{ExtResult, parse_params, to_raw_response};
use crate::agent::MvpAgent;
use crate::session::ExtMethodResult;

#[tracing::instrument(skip_all, fields(method = %args.method))]
pub async fn handle(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    match args.method.as_ref() {
        "x.ai/auth/getBearerToken" => handle_get_bearer_token(agent).await,
        "x.ai/getApiKey" => handle_get_api_key(),
        "x.ai/setApiKey" => handle_set_api_key(args),
        "x.ai/auth/submit_code" => handle_submit_code(agent, args),
        "x.ai/auth/get_url" => handle_get_url(agent).await,
        "x.ai/auth/logout" => handle_logout(agent, args).await,
        "x.ai/auth/info" => handle_info(agent),
        "x.ai/auth/check_subscription" => handle_check_subscription(agent).await,
        "x.ai/auth/loginzyth" => handle_loginzyth(agent).await,
        "x.ai/auth/logoutzyth" => handle_logoutzyth(agent).await,
        _ => Err(acp::Error::method_not_found()),
    }
}

/// `/loginzyth` — Zyth AuthStack OIDC + AI gateway virtual-key mint.
async fn handle_loginzyth(agent: &MvpAgent) -> ExtResult {
    let grok_home = crate::util::grok_home::grok_home();
    let (url_tx, url_rx) = tokio::sync::oneshot::channel();
    let (code_tx, code_rx) = tokio::sync::mpsc::channel(1);
    *agent.auth_code_tx.borrow_mut() = Some(code_tx);
    *agent.auth_url_rx.borrow_mut() = Some(url_rx);

    let result = crate::auth::run_loginzyth_flow(
        &grok_home,
        Some(crate::auth::AuthChannels {
            url_tx: Some(url_tx),
            code_rx,
        }),
    )
    .await;

    *agent.auth_code_tx.borrow_mut() = None;
    *agent.auth_url_rx.borrow_mut() = None;

    match result {
        Ok(outcome) => {
            let auth = &outcome.auth;
            {
                let mut sampling_config = agent.sampling_config.borrow_mut();
                sampling_config.api_key = Some(auth.key.clone());
                // Point sampling base at the Zyth gateway (not cli-chat-proxy).
                if let Some(ref models) = outcome.models {
                    // Prefer first model base_url if present.
                    if let Some(entry) = models.values().next() {
                        sampling_config.base_url = entry.info.base_url.clone();
                    }
                }
            }
            // Update agent endpoints so inference + future fetches use gateway.
            {
                let mut cfg = agent.cfg.borrow_mut();
                cfg.endpoints.xai_api_base_url = outcome.gateway_base.clone();
                cfg.endpoints.models_base_url = Some(outcome.gateway_base.clone());
                cfg.endpoints.models_list_url =
                    Some(format!("{}/models", outcome.gateway_base.trim_end_matches('/')));
            }
            // Install catalog into ModelsManager WITHOUT on_auth_changed
            // (that would re-fetch from SpaceXAI cli-chat-proxy and wipe Zyth models).
            if let Some(models) = outcome.models {
                agent
                    .models_manager
                    .install_gateway_catalog(&outcome.gateway_base, models);
            }
            tracing::info_span!("auth.lifecycle", action = "loginzyth", success = true)
                .in_scope(|| {});
            to_raw_response(&serde_json::json!({
                "ok": true,
                "provider": "zyth",
                "auth": "sso",
                "user_id": auth.user_id,
                "email": auth.email,
                "gateway": outcome.gateway_base,
                "models_count": outcome.models_count,
            }))
        }
        Err(e) => {
            let msg = crate::auth::format_loginzyth_error(&e);
            tracing::warn!(error = %msg, "loginzyth failed");
            // Use internal_error so the TUI shows the message as a failed
            // login attempt, not a generic "auth required" re-login loop.
            Err(acp::Error::internal_error().data(msg))
        }
    }
}

async fn handle_get_bearer_token(agent: &MvpAgent) -> ExtResult {
    let token = match agent.auth_manager.get_valid_token().await {
        Ok(token) => Some(token),
        Err(_) => agent
            .sampling_config
            .borrow()
            .api_key
            .clone()
            .or_else(|| agent.auth_manager.current().map(|a| a.key)),
    };
    ExtMethodResult::success(serde_json::json!({ "token": token }))
        .to_ext_response()
        .map_err(|e| acp::Error::internal_error().data(e.to_string()))
}

fn handle_get_api_key() -> ExtResult {
    let key = crate::agent::auth_method::read_xai_api_key_env().ok();
    ExtMethodResult::success(serde_json::json!({ "key": key }))
        .to_ext_response()
        .map_err(|e| acp::Error::internal_error().data(e.to_string()))
}

fn handle_set_api_key(args: &acp::ExtRequest) -> ExtResult {
    let params: serde_json::Value = parse_params(args)?;
    let key = params.get("key").and_then(|v| v.as_str());
    let grok_home = crate::util::grok_home::grok_home();
    if let Some(k) = key {
        if k.is_empty() {
            crate::auth::clear_api_key(&grok_home)
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            // SAFETY: ext_method is single-threaded per agent
            unsafe { std::env::remove_var("XAI_API_KEY") };
        } else {
            crate::auth::store_api_key(&grok_home, k)
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            // SAFETY: ext_method is single-threaded per agent
            unsafe { std::env::set_var("XAI_API_KEY", k) };
        }
    } else {
        crate::auth::clear_api_key(&grok_home)
            .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
        // SAFETY: ext_method is single-threaded per agent
        unsafe { std::env::remove_var("XAI_API_KEY") };
    }
    ExtMethodResult::success(serde_json::json!({ "ok": true }))
        .to_ext_response()
        .map_err(|e| acp::Error::internal_error().data(e.to_string()))
}

/// Handle auth code submission from TUI.
fn handle_submit_code(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    #[derive(Deserialize)]
    struct SubmitCodeParams {
        code: String,
    }

    let params: SubmitCodeParams = serde_json::from_str(args.params.get())
        .map_err(|e| acp::Error::invalid_params().data(format!("invalid params: {e}")))?;

    let auth_code_tx = agent.auth_code_tx.borrow();
    if let Some(ref tx) = *auth_code_tx {
        tx.try_send(params.code).map_err(|e| {
            acp::Error::internal_error().data(format!("failed to submit auth code: {e}"))
        })?;
        to_raw_response(&serde_json::json!({ "submitted": true }))
    } else {
        Err(acp::Error::invalid_params().data("no pending auth session"))
    }
}

/// Awaits the auth URL from the oneshot channel (blocks until ready).
async fn handle_get_url(agent: &MvpAgent) -> ExtResult {
    let rx = agent.auth_url_rx.borrow_mut().take();
    // `None` when no URL was sent (cached creds, early error, second poll):
    // report mode as `null` rather than mislabeling it `loopback`.
    let (auth_url, mode) = match rx {
        Some(rx) => match rx.await {
            Ok(info) => (Some(info.url), Some(info.mode)),
            Err(_) => (None, None),
        },
        None => (None, None),
    };
    to_raw_response(&serde_json::json!({
        "auth_url": auth_url,
        // `external_provider` kept for older clients; `mode` is authoritative.
        "external_provider": mode.is_some_and(|m| m.is_external_provider()),
        "mode": mode.map(|m| m.as_wire_str()),
    }))
}

/// `/logoutzyth` — remove Zyth scopes + gateway models; keep the CLI session.
///
/// Does **not** clear SpaceXAI OIDC or force a full logout. The pager must
/// never treat this as `LogoutComplete` (welcome screen).
async fn handle_logoutzyth(agent: &MvpAgent) -> ExtResult {
    let grok_home = crate::util::grok_home::grok_home();
    // Snapshot in-memory key before disk logout so we can drop it even if the
    // disk `xai::api_key` was rotated independently of the Zyth scope.
    let prior_sampling_key = agent.sampling_config.borrow().api_key.clone();

    let result = crate::auth::perform_logoutzyth(&grok_home).map_err(|e| {
        acp::Error::internal_error().data(format!("failed to logoutzyth: {e}"))
    })?;

    // Drop Zyth gateway key from sampling config so inference no longer hits
    // ai-gateway. Keep any remaining disk/env API key (non-Zyth BYOK).
    if result.cleared_api_key || result.was_logged_in {
        let mut sampling_config = agent.sampling_config.borrow_mut();
        let disk_or_env = crate::auth::read_api_key(&grok_home).or_else(|| {
            crate::agent::auth_method::read_xai_api_key_env().ok()
        });
        if result.cleared_api_key
            || prior_sampling_key
                .as_ref()
                .is_some_and(|k| disk_or_env.as_ref() != Some(k))
        {
            sampling_config.api_key = disk_or_env;
        }
    }

    // If AuthManager was holding a Zyth-minted entry in memory (should be rare;
    // loginzyth writes a separate scope), drop it and re-read disk so SpaceXAI
    // OIDC can re-surface without a full clear().
    if let Some(current) = agent.auth_manager.current_or_expired() {
        if crate::auth::is_zyth_auth_entry(&current) {
            agent.auth_manager.clear_in_memory();
            agent.auth_manager.force_reload_from_disk();
        }
    }

    tracing::info_span!(
        "auth.lifecycle",
        action = "logoutzyth",
        success = true,
        was_logged_in = result.was_logged_in,
        scopes_removed = result.scopes_removed,
    )
    .in_scope(|| {});

    // Strip [ZYTH] gateway catalog / restore pre-Zyth models. Does not log out.
    agent.models_manager.uninstall_gateway_catalog().await;

    // Remaining non-Zyth credentials (informational for clients; must NOT drive
    // welcome-screen navigation — see pager send_logoutzyth).
    let still_authenticated = remaining_non_zyth_auth(&grok_home, agent);

    let message = crate::auth::format_logoutzyth_result(&result);
    to_raw_response(&serde_json::json!({
        "ok": true,
        "was_logged_in": result.was_logged_in,
        "email": result.email,
        "cleared_api_key": result.cleared_api_key,
        "cleared_endpoints": result.cleared_endpoints,
        "scopes_removed": result.scopes_removed,
        "restored_models": result.restored_models,
        "api_key_env_still_set": result.api_key_env_still_set,
        "still_authenticated": still_authenticated,
        // Explicit contract for older pagers that used to map !still → full logout.
        "force_welcome": false,
        "message": message,
    }))
}

/// True if any non-Zyth credential remains after logoutzyth (disk + env + manager).
fn remaining_non_zyth_auth(grok_home: &std::path::Path, agent: &MvpAgent) -> bool {
    if crate::agent::auth_method::has_xai_api_key_env() {
        return true;
    }
    if crate::auth::read_api_key(grok_home).is_some() {
        return true;
    }
    if let Some(auth) = agent.auth_manager.current_or_expired() {
        if !crate::auth::is_zyth_auth_entry(&auth) {
            return true;
        }
    }
    // Disk may still have SpaceXAI OIDC even if AuthManager's active scope was Zyth.
    match crate::auth::read_auth_json(&grok_home.join("auth.json")) {
        Ok(store) => store.keys().any(|k| {
            k != crate::auth::API_KEY_SCOPE && !crate::auth::is_zyth_auth_scope(k)
        }) || store
            .get(crate::auth::API_KEY_SCOPE)
            .is_some_and(|a| !a.key.is_empty()),
        Err(_) => false,
    }
}

async fn handle_logout(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    #[derive(Deserialize)]
    struct LogoutParams {
        scope: Option<String>,
    }

    let params: LogoutParams = serde_json::from_str(args.params.get())
        .map_err(|e| acp::Error::invalid_params().data(format!("invalid params: {e}")))?;

    let result = crate::auth::perform_logout(&agent.auth_manager, params.scope.as_deref())
        .map_err(|e| acp::Error::internal_error().data(format!("failed to logout: {e}")))?;
    // `auth.lifecycle` (not `auth`) avoids colliding with the pre-existing
    // per-request `AuthManager::auth()` `#[instrument]` span.
    tracing::info_span!("auth.lifecycle", action = "logout", success = true).in_scope(|| {});

    agent.models_manager.on_auth_changed().await;

    to_raw_response(&serde_json::json!({
        "ok": true,
        "was_logged_in": result.was_logged_in,
        "email": result.email,
        "api_key_still_set": result.api_key_still_set,
    }))
}

/// Single-shot subscription re-check (retry button on paywall screen).
///
/// Calls `retry_subscription_check()`, then returns the updated auth
/// response with gate info so the pager can refresh the gate state.
async fn handle_check_subscription(agent: &MvpAgent) -> ExtResult {
    agent.retry_subscription_check().await;
    let response = agent.auth_response_with_meta();
    to_raw_response(&serde_json::json!({
        "authenticated": response.meta.is_some(),
        "meta": response.meta,
    }))
}

/// Returns current auth method ID, user profile fields, and team/principal
/// metadata.
fn handle_info(agent: &MvpAgent) -> ExtResult {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthInfoResponse {
        method_id: Option<String>,
        email: Option<String>,
        first_name: Option<String>,
        last_name: Option<String>,
        /// `grok-asset://` URL resolved by the Electron protocol handler,
        /// or a full `http(s)://` URL passed through unchanged.
        profile_image_url: Option<String>,
        team_id: Option<String>,
        team_name: Option<String>,
        team_role: Option<String>,
        organization_id: Option<String>,
        organization_name: Option<String>,
        organization_role: Option<String>,
        principal_type: Option<String>,
        principal_id: Option<String>,
        user_blocked_reason: Option<String>,
        team_blocked_reasons: Vec<String>,
        coding_data_retention_opt_out: bool,
    }

    let method_id = agent
        .auth_method_id
        .load()
        .as_ref()
        .map(|m| m.0.to_string());
    let auth = agent.auth_manager.current();
    let raw_asset_id = auth.as_ref().and_then(|a| a.profile_image_asset_id.clone());

    // Return a grok-asset:// URL that the Electron renderer resolves at
    // display time via a custom protocol handler. The handler proxies
    // through cli-chat-proxy's /asset endpoint; Electron's HTTP cache
    // handles reuse. No disk-cache or network call needed here.
    let profile_image_url = match raw_asset_id.as_deref().filter(|k| !k.is_empty()) {
        Some(key) if key.starts_with("http://") || key.starts_with("https://") => {
            Some(key.to_owned())
        }
        Some(key) => Some(format!("grok-asset:///{key}")),
        None => None,
    };
    to_raw_response(&AuthInfoResponse {
        method_id,
        email: auth.as_ref().and_then(|a| a.email.clone()),
        first_name: auth.as_ref().and_then(|a| a.first_name.clone()),
        last_name: auth.as_ref().and_then(|a| a.last_name.clone()),
        profile_image_url,
        team_id: auth.as_ref().and_then(|a| a.team_id.clone()),
        team_name: auth.as_ref().and_then(|a| a.team_name.clone()),
        team_role: auth.as_ref().and_then(|a| a.team_role.clone()),
        organization_id: auth.as_ref().and_then(|a| a.organization_id.clone()),
        organization_name: auth.as_ref().and_then(|a| a.organization_name.clone()),
        organization_role: auth.as_ref().and_then(|a| a.organization_role.clone()),
        principal_type: auth.as_ref().and_then(|a| a.principal_type.clone()),
        principal_id: auth.as_ref().and_then(|a| a.principal_id.clone()),
        user_blocked_reason: auth.as_ref().and_then(|a| a.user_blocked_reason.clone()),
        team_blocked_reasons: auth
            .as_ref()
            .map(|a| a.team_blocked_reasons.clone())
            .unwrap_or_default(),
        coding_data_retention_opt_out: auth
            .as_ref()
            .is_some_and(|a| a.coding_data_retention_opt_out),
    })
}
