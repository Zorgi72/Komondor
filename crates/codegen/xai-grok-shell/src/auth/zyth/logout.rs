//! `/logoutzyth` — clear Zyth AuthStack + AI gateway credentials without
//! touching SpaceXAI (`auth.x.ai`) OAuth sessions.
//!
//! Mirrors [`crate::auth::perform_logout`] structure (telemetry identity flush,
//! attributable unified log, non-corruptive disk updates) but is **scope-scoped**
//! to Zyth only.

use std::path::Path;

use super::config::{ZYTH_AI_GATEWAY_BASE_URL, ZythLoginConfig, normalize_issuer};
use super::models::restore_models_after_logoutzyth;
use super::protocol::ZythLoginError;
use super::super::model::{API_KEY_SCOPE, AuthStore, GrokAuth};
use super::super::storage::{read_auth_json, write_auth_json};

/// Outcome of a Zyth logout (presentation layer formats this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutZythResult {
    /// True if a Zyth auth.json scope was present and removed.
    pub was_logged_in: bool,
    /// Email from the removed Zyth session, if any.
    pub email: Option<String>,
    /// True if `xai::api_key` was cleared because it matched the Zyth virtual key.
    pub cleared_api_key: bool,
    /// True if `zyth_endpoints.toml` was removed.
    pub cleared_endpoints: bool,
    /// True if process env still has a non-Zyth `XAI_API_KEY` after logout.
    pub api_key_env_still_set: bool,
    /// Number of Zyth scopes removed (normally 0 or 1; can be >1 if client_id rotated).
    pub scopes_removed: usize,
    /// True if the pre-Zyth model catalog was restored (or gateway models stripped).
    pub restored_models: bool,
    /// True if at least one gateway virtual key was successfully revoked server-side.
    pub remote_revoked: bool,
    /// True if a remote revoke was attempted but failed (local clear still applied).
    pub remote_revoke_failed: bool,
}

/// True if this auth.json scope key is a Zyth AuthStack scope.
///
/// Matches `{issuer}::{client_id}` for Zyth product / known tenant issuers only.
/// Env-configured issuers are honored **only** when they are still Zyth hosts —
/// a mis-set `ZYTH_OIDC_ISSUER=https://auth.x.ai/` must never make logoutzyth
/// wipe SpaceXAI scopes.
pub fn is_zyth_auth_scope(scope: &str) -> bool {
    let s = scope.trim();
    // Primary product issuer (scope format `{issuer}::{client_id}`)
    if s.starts_with("https://auth.zyth.app::") {
        return true;
    }
    // Auth0 tenant fallback issuer form (if someone logged in with tenant domain)
    if s.starts_with("https://dev-yil7bnsv13ztmhuq.us.auth0.com::") {
        return true;
    }
    // Explicit configured issuer — only if it is still a Zyth issuer host.
    let cfg = ZythLoginConfig::resolve();
    let iss = cfg.issuer.trim_end_matches('/');
    let issuer_is_zyth = iss == "https://auth.zyth.app"
        || iss.ends_with(".zyth.app")
        || iss == "https://dev-yil7bnsv13ztmhuq.us.auth0.com"
        || (iss.ends_with(".us.auth0.com") && iss.contains("dev-yil7bnsv13ztmhuq"));
    if !issuer_is_zyth {
        return false;
    }
    let prefix = format!("{}::", iss);
    s == cfg.auth_scope() || s.starts_with(&prefix)
}

/// Collect all Zyth scopes currently present in an auth store.
pub fn zyth_scopes_in_store(store: &AuthStore) -> Vec<String> {
    store
        .keys()
        .filter(|k| is_zyth_auth_scope(k))
        .cloned()
        .collect()
}

/// Deactivate Zyth runtime env **only** when values match what `/loginzyth` set.
///
/// Never unsets an unrelated `XAI_API_KEY` / base URL the user configured
/// independently.
pub fn deactivate_zyth_runtime(zyth_key: Option<&str>, gateway_base: &str) {
    let gateway_base = gateway_base.trim_end_matches('/');
    // SAFETY: logout path on agent/CLI thread; same process model as activate.
    unsafe {
        if let Some(key) = zyth_key {
            if std::env::var("XAI_API_KEY").ok().as_deref() == Some(key) {
                std::env::remove_var("XAI_API_KEY");
            }
            if std::env::var("GROK_CODE_XAI_API_KEY").ok().as_deref() == Some(key) {
                std::env::remove_var("GROK_CODE_XAI_API_KEY");
            }
        }
        for var in ["GROK_XAI_API_BASE_URL", "GROK_MODELS_BASE_URL"] {
            if let Ok(v) = std::env::var(var) {
                let v = v.trim_end_matches('/');
                if v == gateway_base
                    || v == ZYTH_AI_GATEWAY_BASE_URL.trim_end_matches('/')
                    || v.starts_with("https://ai-gateway.zyth.app")
                {
                    std::env::remove_var(var);
                }
            }
        }
    }
}

fn remove_endpoint_overlay(grok_home: &Path) -> bool {
    let path = grok_home.join("zyth_endpoints.toml");
    match std::fs::remove_file(&path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "logoutzyth: failed to remove zyth_endpoints.toml"
            );
            false
        }
    }
}

/// Best-effort server-side revoke of a LiteLLM virtual key via gateway.
///
/// Uses the virtual key as Bearer against `/zyth/cli/v1/revoke`. Never panics;
/// never logs the key. Returns whether the server reported success.
///
/// Set `ZYTH_SKIP_REMOTE_REVOKE=1` to skip network (unit tests / air-gapped).
pub fn try_remote_revoke_virtual_key(api_key: &str) -> bool {
    let key = api_key.trim();
    if !(key.starts_with("sk-") || key.starts_with("cpa_")) {
        return false;
    }
    if std::env::var("ZYTH_SKIP_REMOTE_REVOKE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
    {
        return false;
    }
    let cfg = ZythLoginConfig::resolve();
    let Some(revoke_url) = super::protocol::revoke_url_from_exchange(&cfg.exchange_url) else {
        return false;
    };
    // Fail closed: revoke URL host must pass the same allowlist as exchange.
    if super::protocol::validate_exchange_url(
        &revoke_url
            .replacen("/revoke", "/exchange", 1),
    )
    .is_err()
    {
        return false;
    }
    // Blocking best-effort; keep timeout short so offline logout stays snappy.
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client
        .post(&revoke_url)
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body("{}")
        .send()
    {
        Ok(resp) => {
            let ok = resp.status().is_success();
            if !ok {
                tracing::warn!(
                    status = resp.status().as_u16(),
                    "logoutzyth: remote key revoke HTTP failure"
                );
            }
            ok
        }
        Err(e) => {
            tracing::warn!(error = %e, "logoutzyth: remote key revoke network error");
            false
        }
    }
}

/// Core `/logoutzyth` logic — pure disk + env, no AuthManager current-scope assumption.
///
/// Guarantees:
/// - Never removes `https://auth.x.ai::*` or other non-Zyth scopes
/// - Never clears `xai::api_key` unless it **equals** a removed Zyth virtual key
/// - Fail-soft on missing files (idempotent re-logout)
/// - Does not log secret material
/// - Best-effort remote revoke of collected Zyth virtual keys before discard
pub fn perform_logoutzyth(grok_home: &Path) -> Result<LogoutZythResult, ZythLoginError> {
    let cfg = ZythLoginConfig::resolve();
    let path = grok_home.join("auth.json");

    let mut store = match read_auth_json(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => AuthStore::new(),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            return Err(ZythLoginError::SaveAuth(format!(
                "auth.json unreadable ({e}); fix or remove it before retrying"
            )));
        }
        Err(e) => return Err(ZythLoginError::SaveAuth(e.to_string())),
    };

    let scopes = zyth_scopes_in_store(&store);
    // Prefer configured scope first for email, then any other zyth scopes.
    let primary_scope = {
        let preferred = cfg.auth_scope();
        if scopes.iter().any(|s| s == &preferred) {
            Some(preferred)
        } else {
            scopes.first().cloned()
        }
    };

    let email = primary_scope
        .as_ref()
        .and_then(|sc| store.get(sc))
        .and_then(|a| a.email.clone());

    // Collect **all** Zyth virtual keys across scopes (client_id rotation edge case).
    let mut zyth_keys: Vec<String> = scopes
        .iter()
        .filter_map(|sc| store.get(sc).map(|a| a.key.clone()))
        .filter(|k| !k.is_empty())
        .collect();
    zyth_keys.sort();
    zyth_keys.dedup();

    let was_logged_in = !scopes.is_empty();

    // Best-effort remote revoke **before** discarding local material.
    let mut remote_revoked = false;
    let mut remote_revoke_failed = false;
    for key in &zyth_keys {
        if try_remote_revoke_virtual_key(key) {
            remote_revoked = true;
        } else {
            // Only count as failure when we actually had a key worth revoking.
            remote_revoke_failed = true;
        }
    }

    xai_grok_telemetry::unified_log::info(
        "auth: logoutzyth",
        None,
        Some(serde_json::json!({
            "was_logged_in": was_logged_in,
            "scopes_removed": scopes.len(),
            // Never log key material — only whether email present.
            "has_email": email.is_some(),
            "issuer": normalize_issuer(&cfg.issuer),
            "remote_revoked": remote_revoked,
            "remote_revoke_failed": remote_revoke_failed,
        })),
    );

    // Identity flush order matches perform_logout (no-leak for external OTEL).
    if was_logged_in {
        xai_grok_telemetry::external::set_identity(
            xai_grok_telemetry::external::IdentityAttrs::default(),
        );
        xai_grok_telemetry::external::flush();
    }

    // Capture non-Zyth scopes to assert we never drop them.
    let foreign_before: Vec<(String, String)> = store
        .iter()
        .filter(|(k, _)| !is_zyth_auth_scope(k) && k.as_str() != API_KEY_SCOPE)
        .map(|(k, a)| (k.clone(), a.key.clone()))
        .collect();

    for sc in &scopes {
        store.remove(sc);
    }

    // Clear xai::api_key when it equals **any** removed Zyth virtual key.
    let mut cleared_api_key = false;
    if let Some(api) = store.get(API_KEY_SCOPE).map(|a| a.key.clone()) {
        if zyth_keys.iter().any(|k| k == &api) {
            store.remove(API_KEY_SCOPE);
            cleared_api_key = true;
        }
    }

    // Persist or delete auth.json. Never delete the file while non-Zyth scopes remain.
    if was_logged_in || cleared_api_key {
        if store.is_empty() {
            if !foreign_before.is_empty() {
                return Err(ZythLoginError::SaveAuth(
                    "logoutzyth refused to wipe auth.json: non-Zyth scopes still required".into(),
                ));
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(ZythLoginError::SaveAuth(e.to_string())),
            }
        } else {
            write_auth_json(&path, &store).map_err(|e| ZythLoginError::SaveAuth(e.to_string()))?;
            // Integrity: foreign OAuth scopes must still be present with same keys.
            let after = read_auth_json(&path).map_err(|e| ZythLoginError::SaveAuth(e.to_string()))?;
            for (k, key) in &foreign_before {
                match after.get(k) {
                    Some(a) if a.key == *key => {}
                    Some(_) => {
                        return Err(ZythLoginError::SaveAuth(
                            "logoutzyth integrity check failed: non-Zyth scope key changed".into(),
                        ));
                    }
                    None => {
                        return Err(ZythLoginError::SaveAuth(format!(
                            "logoutzyth integrity check failed: non-Zyth scope missing: {k}"
                        )));
                    }
                }
            }
        }
    }

    let cleared_endpoints = remove_endpoint_overlay(grok_home);
    // Deactivate env for every collected Zyth key (not only primary).
    for key in &zyth_keys {
        deactivate_zyth_runtime(Some(key.as_str()), &cfg.gateway_base_url);
    }
    if zyth_keys.is_empty() {
        deactivate_zyth_runtime(None, &cfg.gateway_base_url);
    }

    let restored_models = restore_models_after_logoutzyth(grok_home).unwrap_or(false);

    let api_key_env_still_set = crate::agent::auth_method::has_xai_api_key_env();

    Ok(LogoutZythResult {
        was_logged_in,
        email,
        cleared_api_key,
        cleared_endpoints,
        api_key_env_still_set,
        scopes_removed: scopes.len(),
        restored_models,
        remote_revoked,
        remote_revoke_failed,
    })
}

/// User-facing summary lines for CLI / toast (no secrets).
///
/// Emphasizes model access removal — `/logoutzyth` never logs out of the whole CLI.
pub fn format_logoutzyth_result(r: &LogoutZythResult) -> String {
    if !r.was_logged_in
        && !r.cleared_api_key
        && !r.cleared_endpoints
        && !r.restored_models
        && !r.remote_revoked
    {
        return "No Zyth models / gateway session to remove.".to_owned();
    }
    let mut parts = Vec::new();
    // Lead with models — that is the product intent of /logoutzyth.
    if r.restored_models {
        parts.push("Removed Zyth models; restored previous catalog".to_owned());
    } else if r.was_logged_in || r.cleared_endpoints {
        parts.push("Removed Zyth gateway models".to_owned());
    }
    if r.was_logged_in {
        if let Some(ref email) = r.email {
            parts.push(format!("cleared Zyth SSO for {email}"));
        } else {
            parts.push("cleared Zyth SSO credentials".to_owned());
        }
    }
    if r.remote_revoked {
        parts.push("revoked gateway API key on server".to_owned());
    } else if r.cleared_api_key {
        // Honest wording: local clear is not remote revoke.
        parts.push("cleared local gateway API key".to_owned());
    }
    if r.remote_revoke_failed && !r.remote_revoked {
        parts.push("note: server-side key revoke failed (key may remain valid until expiry)".to_owned());
    }
    if r.cleared_endpoints {
        parts.push("restored default AI endpoints".to_owned());
    }
    if r.api_key_env_still_set {
        parts.push("note: XAI_API_KEY is still set in the environment".to_owned());
    }
    // Capitalize first clause for toast polish.
    let s = parts.join("; ");
    let mut chars = s.chars();
    let mut out = match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => s,
    };
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

/// Whether a GrokAuth entry looks like a Zyth-minted credential.
///
/// Requires a Zyth issuer host — bare `sk-` + client_id is **not** enough
/// (would misclassify unrelated BYOK keys).
pub fn is_zyth_auth_entry(auth: &GrokAuth) -> bool {
    auth.oidc_issuer.as_deref().is_some_and(|iss| {
        let n = normalize_issuer(iss);
        n.contains("auth.zyth.app") || n.contains("dev-yil7bnsv13ztmhuq.us.auth0.com")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::model::{AuthMode, GrokAuth};
    use chrono::Utc;

    fn skip_remote_revoke() {
        // Unit tests must not block on production gateway network.
        // SAFETY: test-only process env.
        unsafe {
            std::env::set_var("ZYTH_SKIP_REMOTE_REVOKE", "1");
        }
    }

    fn sample_zyth() -> GrokAuth {
        GrokAuth {
            key: "sk-zyth-secret-key".into(),
            auth_mode: AuthMode::ApiKey,
            create_time: Utc::now(),
            user_id: "auth0|u1".into(),
            email: Some("user@zyth.net".into()),
            oidc_issuer: Some("https://auth.zyth.app/".into()),
            oidc_client_id: Some("cli-client".into()),
            ..GrokAuth::default()
        }
    }

    fn sample_xai() -> GrokAuth {
        GrokAuth {
            key: "xai-oauth-token".into(),
            auth_mode: AuthMode::Oidc,
            create_time: Utc::now(),
            user_id: "xai-user".into(),
            email: Some("user@x.ai".into()),
            oidc_issuer: Some("https://auth.x.ai".into()),
            oidc_client_id: Some("xai-client".into()),
            ..GrokAuth::default()
        }
    }

    #[test]
    fn is_zyth_scope_detects_product_and_rejects_xai() {
        assert!(is_zyth_auth_scope("https://auth.zyth.app::abc"));
        assert!(is_zyth_auth_scope(
            "https://dev-yil7bnsv13ztmhuq.us.auth0.com::cli"
        ));
        assert!(!is_zyth_auth_scope("https://auth.x.ai::abc"));
        assert!(!is_zyth_auth_scope("xai::api_key"));
        // Substring embedding must not match
        assert!(!is_zyth_auth_scope(
            "https://evil.com/https://auth.zyth.app::abc"
        ));
    }

    #[test]
    fn logout_removes_zyth_keeps_xai() {
        skip_remote_revoke();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        let mut store = AuthStore::new();
        store.insert("https://auth.x.ai::xai-client".into(), sample_xai());
        store.insert("https://auth.zyth.app::cli-client".into(), sample_zyth());
        store.insert(
            API_KEY_SCOPE.to_owned(),
            GrokAuth {
                key: "sk-zyth-secret-key".into(),
                auth_mode: AuthMode::ApiKey,
                ..GrokAuth::default()
            },
        );
        write_auth_json(&path, &store).unwrap();
        std::fs::write(
            dir.path().join("zyth_endpoints.toml"),
            "[endpoints]\nxai_api_base_url = \"https://ai-gateway.zyth.app/v1\"\n",
        )
        .unwrap();

        let r = perform_logoutzyth(dir.path()).unwrap();
        assert!(r.was_logged_in);
        assert_eq!(r.email.as_deref(), Some("user@zyth.net"));
        assert!(r.cleared_api_key);
        assert!(r.cleared_endpoints);
        assert_eq!(r.scopes_removed, 1);
        // no models cache in this fixture — restored_models may be false
        assert!(!r.remote_revoked);

        let after = read_auth_json(&path).unwrap();
        assert!(after.contains_key("https://auth.x.ai::xai-client"));
        assert_eq!(
            after.get("https://auth.x.ai::xai-client").map(|a| a.key.as_str()),
            Some("xai-oauth-token")
        );
        assert!(!after.keys().any(|k| is_zyth_auth_scope(k)));
        assert!(!after.contains_key(API_KEY_SCOPE));
        assert!(!dir.path().join("zyth_endpoints.toml").exists());
    }

    #[test]
    fn logout_idempotent_when_nothing_to_clear() {
        skip_remote_revoke();
        let dir = tempfile::tempdir().unwrap();
        let r = perform_logoutzyth(dir.path()).unwrap();
        assert!(!r.was_logged_in);
        assert!(!r.cleared_api_key);
        assert!(!r.cleared_endpoints);
        assert_eq!(r.scopes_removed, 0);
    }

    #[test]
    fn logout_does_not_clear_unrelated_api_key() {
        skip_remote_revoke();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        let mut store = AuthStore::new();
        store.insert("https://auth.zyth.app::cli".into(), sample_zyth());
        store.insert(
            API_KEY_SCOPE.to_owned(),
            GrokAuth {
                key: "xai-byok-different".into(),
                auth_mode: AuthMode::ApiKey,
                ..GrokAuth::default()
            },
        );
        write_auth_json(&path, &store).unwrap();

        let r = perform_logoutzyth(dir.path()).unwrap();
        assert!(r.was_logged_in);
        assert!(!r.cleared_api_key);
        let after = read_auth_json(&path).unwrap();
        assert_eq!(
            after.get(API_KEY_SCOPE).map(|a| a.key.as_str()),
            Some("xai-byok-different")
        );
    }

    #[test]
    fn format_messages_are_secret_free() {
        let msg = format_logoutzyth_result(&LogoutZythResult {
            was_logged_in: true,
            email: Some("a@b.c".into()),
            cleared_api_key: true,
            cleared_endpoints: true,
            api_key_env_still_set: false,
            scopes_removed: 1,
            restored_models: true,
            remote_revoked: false,
            remote_revoke_failed: true,
        });
        assert!(!msg.contains("sk-"));
        assert!(msg.contains("Zyth") || msg.contains("models"));
        assert!(msg.to_lowercase().contains("model"));
        // Must not claim remote "revoked" when only local clear happened.
        assert!(!msg.to_lowercase().contains("revoked gateway api key on server"));
        assert!(
            msg.to_lowercase().contains("cleared local")
                || msg.to_lowercase().contains("model")
        );
    }

    #[test]
    fn format_emphasizes_models_not_full_cli_logout() {
        let msg = format_logoutzyth_result(&LogoutZythResult {
            was_logged_in: true,
            email: Some("a@b.c".into()),
            cleared_api_key: true,
            cleared_endpoints: true,
            api_key_env_still_set: false,
            scopes_removed: 1,
            restored_models: false,
            remote_revoked: false,
            remote_revoke_failed: false,
        });
        let lower = msg.to_lowercase();
        assert!(lower.contains("model") || lower.contains("gateway"));
        // Must not sound like full CLI logout / welcome.
        assert!(!lower.contains("welcome"));
        assert!(!lower.contains("session ended"));
    }

    #[test]
    fn logout_clears_api_key_matching_any_zyth_scope() {
        skip_remote_revoke();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        let mut store = AuthStore::new();
        let mut z1 = sample_zyth();
        z1.key = "sk-primary-aaaa".into();
        let mut z2 = sample_zyth();
        z2.key = "sk-secondary-bbbb".into();
        store.insert("https://auth.zyth.app::cli-client".into(), z1);
        store.insert("https://auth.zyth.app::old-client".into(), z2);
        store.insert(
            API_KEY_SCOPE.to_owned(),
            GrokAuth {
                key: "sk-secondary-bbbb".into(),
                auth_mode: AuthMode::ApiKey,
                ..GrokAuth::default()
            },
        );
        write_auth_json(&path, &store).unwrap();

        // Remote revoke skipped via env — local clear must still work.
        let r = perform_logoutzyth(dir.path()).unwrap();
        assert!(r.was_logged_in);
        assert!(r.cleared_api_key);
        assert_eq!(r.scopes_removed, 2);
        // File may be deleted when empty after clearing only Zyth keys.
        if path.exists() {
            let after = read_auth_json(&path).unwrap();
            assert!(!after.contains_key(API_KEY_SCOPE));
            assert!(!after.keys().any(|k| is_zyth_auth_scope(k)));
        }
    }

    #[test]
    fn is_zyth_auth_entry_requires_issuer() {
        let mut auth = sample_zyth();
        assert!(is_zyth_auth_entry(&auth));
        auth.oidc_issuer = None;
        assert!(!is_zyth_auth_entry(&auth));
        auth.oidc_issuer = Some("https://auth.x.ai".into());
        assert!(!is_zyth_auth_entry(&auth));
    }
}
