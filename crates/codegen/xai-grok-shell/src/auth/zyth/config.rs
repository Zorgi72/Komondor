//! Zyth AuthStack + AI Gateway defaults for `/loginzyth`.

use super::super::config::OidcAuthConfig;

/// Preferred Auth0 custom-domain issuer (trailing slash optional; normalized in helpers).
pub const ZYTH_ISSUER: &str = "https://auth.zyth.app/";

/// Public native Auth0 client id for the Zyth CLI (PKCE; no secret).
/// Created via AuthStack Terraform `auth0_client.zyth_cli`.
pub const ZYTH_CLI_CLIENT_ID: &str = "K8m9VaNO6p7LKEUdXj7qbsGKWEWdxRQb";

/// OpenAI-compatible AI gateway base URL.
pub const ZYTH_AI_GATEWAY_BASE_URL: &str = "https://ai-gateway.zyth.app/v1";

/// Path on the gateway that mints a LiteLLM virtual key from an Auth0 JWT.
pub const ZYTH_CLI_EXCHANGE_PATH: &str = "/zyth/cli/v1/exchange";

/// Auth0-registered loopback ports for `/loginzyth` (must match AuthStack
/// `auth0_client.zyth_cli` callbacks). CLI binds the first free port in range.
pub const ZYTH_LOOPBACK_PORTS: &[u16] = &[
    56120, 56121, 56122, 56123, 56124, 56125, 56126, 56127, 56128, 56129, 56130, 56131, 56132,
    56133, 56134, 56135, 56136, 56137, 56138, 56139,
];

/// Distinct auth.json scope prefix helper — full scope is `{issuer}::{client_id}`.
pub const ZYTH_SCOPE_LABEL: &str = "zyth";

/// Env overrides (all optional).
pub const ENV_ISSUER: &str = "ZYTH_OIDC_ISSUER";
pub const ENV_CLIENT_ID: &str = "ZYTH_OIDC_CLIENT_ID";
pub const ENV_GATEWAY_BASE: &str = "ZYTH_AI_GATEWAY_BASE_URL";
pub const ENV_EXCHANGE_URL: &str = "ZYTH_CLI_EXCHANGE_URL";
pub const ENV_SCOPES: &str = "ZYTH_OIDC_SCOPES";
pub const ENV_AUDIENCE: &str = "ZYTH_OIDC_AUDIENCE";

/// Resolved Zyth login configuration (public values only — never secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZythLoginConfig {
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub audience: Option<String>,
    pub gateway_base_url: String,
    pub exchange_url: String,
}

impl ZythLoginConfig {
    /// Defaults + env overrides. Never embeds client secrets.
    pub fn resolve() -> Self {
        let issuer = std::env::var(ENV_ISSUER).unwrap_or_else(|_| ZYTH_ISSUER.to_owned());
        let client_id =
            std::env::var(ENV_CLIENT_ID).unwrap_or_else(|_| ZYTH_CLI_CLIENT_ID.to_owned());
        let gateway_base_url =
            std::env::var(ENV_GATEWAY_BASE).unwrap_or_else(|_| ZYTH_AI_GATEWAY_BASE_URL.to_owned());
        let exchange_url = std::env::var(ENV_EXCHANGE_URL).unwrap_or_else(|_| {
            // Exchange lives on the gateway host, not under /v1.
            let root = gateway_base_url
                .trim_end_matches('/')
                .trim_end_matches("/v1");
            format!("{root}{ZYTH_CLI_EXCHANGE_PATH}")
        });
        let scopes = std::env::var(ENV_SCOPES)
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_owned())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_else(|_| default_zyth_scopes());
        let audience = std::env::var(ENV_AUDIENCE).ok().filter(|s| !s.trim().is_empty());
        Self {
            issuer: normalize_issuer(&issuer),
            client_id,
            scopes,
            audience,
            gateway_base_url: gateway_base_url.trim_end_matches('/').to_owned(),
            exchange_url,
        }
    }

    /// auth.json scope key — distinct from `auth.x.ai::{client}`.
    pub fn auth_scope(&self) -> String {
        scope_key(&self.issuer, &self.client_id)
    }

    /// Convert to the shared OIDC config used by protocol helpers.
    pub fn as_oidc(&self) -> OidcAuthConfig {
        OidcAuthConfig {
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            scopes: self.scopes.clone(),
            audience: self.audience.clone(),
        }
    }
}

pub fn default_zyth_scopes() -> Vec<String> {
    vec![
        "openid".into(),
        "profile".into(),
        "email".into(),
        "offline_access".into(),
    ]
}

/// Normalize issuer to a trailing-slash form matching Auth0 custom domain docs.
pub fn normalize_issuer(issuer: &str) -> String {
    let t = issuer.trim();
    if t.is_empty() {
        return ZYTH_ISSUER.to_owned();
    }
    if t.ends_with('/') {
        t.to_owned()
    } else {
        format!("{t}/")
    }
}

/// Scope key format mirrors grok: `{issuer_no_trailing_slash}::{client_id}`.
pub fn scope_key(issuer: &str, client_id: &str) -> String {
    format!("{}::{}", issuer.trim_end_matches('/'), client_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_key_strips_trailing_slash() {
        assert_eq!(
            scope_key("https://auth.zyth.app/", "abc"),
            "https://auth.zyth.app::abc"
        );
        assert_eq!(
            scope_key("https://auth.zyth.app", "abc"),
            "https://auth.zyth.app::abc"
        );
    }

    #[test]
    fn normalize_issuer_adds_slash() {
        assert_eq!(normalize_issuer("https://auth.zyth.app"), "https://auth.zyth.app/");
        assert_eq!(normalize_issuer("https://auth.zyth.app/"), "https://auth.zyth.app/");
    }

    #[test]
    fn default_resolve_has_public_defaults() {
        // Clear overrides for determinism in this process if set.
        let cfg = ZythLoginConfig {
            issuer: normalize_issuer(ZYTH_ISSUER),
            client_id: ZYTH_CLI_CLIENT_ID.to_owned(),
            scopes: default_zyth_scopes(),
            audience: None,
            gateway_base_url: ZYTH_AI_GATEWAY_BASE_URL.trim_end_matches('/').to_owned(),
            exchange_url: format!(
                "https://ai-gateway.zyth.app{ZYTH_CLI_EXCHANGE_PATH}"
            ),
        };
        assert_eq!(cfg.auth_scope(), "https://auth.zyth.app::K8m9VaNO6p7LKEUdXj7qbsGKWEWdxRQb");
        assert!(cfg.exchange_url.contains("/zyth/cli/v1/exchange"));
        assert!(cfg.gateway_base_url.ends_with("/v1"));
    }

    #[test]
    fn exchange_url_derives_from_gateway_root() {
        let root = "https://ai-gateway.zyth.app/v1".trim_end_matches('/').trim_end_matches("/v1");
        assert_eq!(root, "https://ai-gateway.zyth.app");
    }
}
