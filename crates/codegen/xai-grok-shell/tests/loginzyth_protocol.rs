//! Gating tests for `/loginzyth` pure protocol helpers (shipped code paths).

use xai_grok_shell::auth::{
    ZYTH_AI_GATEWAY_BASE_URL, ZYTH_CLI_CLIENT_ID, ZYTH_ISSUER, ZythLoginConfig, ZythLoginError,
    build_authorize_url_parts, parse_exchange_response, parse_pasted_input, perform_logoutzyth,
    scope_key, user_message, validate_exchange_url, validate_gateway_credential, validate_state,
};

#[test]
fn pasted_full_callback_url() {
    let r = parse_pasted_input("http://127.0.0.1:4242/callback?code=abc&state=s1").unwrap();
    assert_eq!(r.code, "abc");
    assert_eq!(r.state, "s1");
}

#[test]
fn pasted_bare_code() {
    let r = parse_pasted_input("only-code").unwrap();
    assert_eq!(r.code, "only-code");
    assert!(r.state.is_empty());
}

#[test]
fn pasted_empty_and_idp_error() {
    assert!(matches!(
        parse_pasted_input(""),
        Err(ZythLoginError::InvalidPastedInput(_))
    ));
    let e = parse_pasted_input("http://127.0.0.1/callback?error=access_denied").unwrap_err();
    assert!(matches!(e, ZythLoginError::CallbackAuthFailed(_)));
    assert!(!user_message(&e).is_empty());
}

#[test]
fn state_validation() {
    validate_state("same", "same").unwrap();
    assert!(matches!(
        validate_state("a", "b"),
        Err(ZythLoginError::StateMismatch)
    ));
}

#[test]
fn scope_distinct_from_xai() {
    let s = scope_key(ZYTH_ISSUER, ZYTH_CLI_CLIENT_ID);
    assert!(s.starts_with("https://auth.zyth.app::"));
    assert!(!s.contains("auth.x.ai"));
    let cfg = ZythLoginConfig::resolve();
    assert_eq!(cfg.auth_scope(), scope_key(&cfg.issuer, &cfg.client_id));
}

#[test]
fn gateway_credential_rules() {
    validate_gateway_credential("sk-virtual-key-xyz").unwrap();
    validate_gateway_credential("cpa_machine").unwrap();
    assert!(validate_gateway_credential("").is_err());
    assert!(
        validate_gateway_credential("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig").is_err()
    );
}

#[test]
fn exchange_response_parse() {
    let body = r#"{"api_key":"sk-ok","base_url":"https://ai-gateway.zyth.app/v1"}"#;
    let r = parse_exchange_response(body).unwrap();
    assert_eq!(r.api_key, "sk-ok");
    assert!(parse_exchange_response(r#"{"api_key":"not-a-key"}"#).is_err());
}

#[test]
fn authorize_url_has_pkce_state_prompt() {
    let url = build_authorize_url_parts(
        "https://auth.zyth.app/authorize",
        ZYTH_CLI_CLIENT_ID,
        "http://127.0.0.1:9/callback",
        "openid profile email offline_access",
        "ch",
        "st",
        "nn",
    );
    assert!(url.contains("code_challenge=ch"));
    assert!(url.contains("state=st"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("prompt=login"));
    assert!(url.contains("response_type=code"));
}

#[test]
fn defaults_point_at_zyth_gateway() {
    assert!(ZYTH_AI_GATEWAY_BASE_URL.contains("ai-gateway.zyth.app"));
    assert!(ZYTH_ISSUER.contains("auth.zyth.app"));
}

#[test]
fn exchange_url_allowlist_shipped() {
    validate_exchange_url("https://ai-gateway.zyth.app/zyth/cli/v1/exchange").unwrap();
    assert!(validate_exchange_url("https://evil.example/exchange").is_err());
    assert!(validate_exchange_url("http://ai-gateway.zyth.app/exchange").is_err());
}

#[test]
fn logoutzyth_idempotent_empty_home() {
    let dir = tempfile::tempdir().unwrap();
    let r = perform_logoutzyth(dir.path()).unwrap();
    assert!(!r.was_logged_in);
    assert_eq!(r.scopes_removed, 0);
}

#[test]
fn model_enrichment_covers_all_gateway_ids_with_thinking() {
    // Mirrors live inventory from ai-gateway (13 models as of deploy).
    use xai_grok_shell::auth::zyth::enrich_ids_for_test;
    let ids = [
        "grok-4.20-0309-non-reasoning",
        "grok-4.20-multi-agent-0309",
        "grok-3-mini",
        "grok-3-mini-fast",
        "grok-imagine-image",
        "grok-imagine-video-1.5-preview",
        "grok-build-0.1",
        "grok-4.3",
        "grok-4.20-0309-reasoning",
        "grok-composer-2.5-fast",
        "grok-imagine-image-quality",
        "grok-imagine-video",
        "grok-4.5",
    ];
    let map = enrich_ids_for_test(&ids);
    assert_eq!(map.len(), 13);
    let g = map.get("grok-4.5").expect("grok-4.5");
    assert_eq!(g.info.context_window.get(), 500_000);
    assert!(g.info.supports_reasoning_effort);
    assert!(g.info.reasoning_efforts.len() >= 3);
    assert!(g.info.base_url.contains("ai-gateway.zyth.app"));
    assert!(g.info.supported_in_api);
    let r = map.get("grok-4.20-0309-reasoning").unwrap();
    assert!(r.info.supports_reasoning_effort);
    let n = map.get("grok-4.20-0309-non-reasoning").unwrap();
    assert!(!n.info.supports_reasoning_effort);
}

#[test]
fn logoutzyth_preserves_xai_scope() {
    use chrono::Utc;
    use xai_grok_shell::auth::{AuthMode, GrokAuth, read_auth_json, store_api_key};
    use std::collections::BTreeMap;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.json");
    let mut store = BTreeMap::new();
    store.insert(
        "https://auth.x.ai::client".to_string(),
        GrokAuth {
            key: "xai-token-keep".into(),
            auth_mode: AuthMode::Oidc,
            create_time: Utc::now(),
            user_id: "x".into(),
            oidc_issuer: Some("https://auth.x.ai".into()),
            oidc_client_id: Some("client".into()),
            ..GrokAuth::default()
        },
    );
    store.insert(
        "https://auth.zyth.app::cli".to_string(),
        GrokAuth {
            key: "sk-zyth-to-clear".into(),
            auth_mode: AuthMode::ApiKey,
            create_time: Utc::now(),
            user_id: "z".into(),
            email: Some("z@zyth.net".into()),
            oidc_issuer: Some("https://auth.zyth.app/".into()),
            oidc_client_id: Some("cli".into()),
            ..GrokAuth::default()
        },
    );
    // Write via public store_api_key + raw json for multi-scope
    let json = serde_json::to_string_pretty(&store).unwrap();
    std::fs::write(&path, json).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    store_api_key(dir.path(), "sk-zyth-to-clear").unwrap();

    let r = perform_logoutzyth(dir.path()).unwrap();
    assert!(r.was_logged_in);
    assert!(r.cleared_api_key);
    let after = read_auth_json(&path).unwrap();
    assert!(after.contains_key("https://auth.x.ai::client"));
    assert_eq!(
        after.get("https://auth.x.ai::client").map(|a| a.key.as_str()),
        Some("xai-token-keep")
    );
    assert!(!after.keys().any(|k| k.contains("auth.zyth.app")));
}
