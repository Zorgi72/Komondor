//! Zyth AuthStack SSO + LiteLLM AI Gateway login (`/loginzyth` / `/logoutzyth`).
//!
//! Parallel to SpaceXAI `/login` (auth.x.ai): Auth Code + PKCE loopback against
//! `auth.zyth.app`, then server-side virtual-key mint for `ai-gateway.zyth.app`.

mod config;
mod login;
mod logout;
mod models;
pub mod protocol;

pub use config::{
    ZYTH_AI_GATEWAY_BASE_URL, ZYTH_CLI_CLIENT_ID, ZYTH_ISSUER, ZythLoginConfig, scope_key,
};
pub use login::{
    activate_zyth_runtime, format_loginzyth_error, persist_zyth_credentials,
    persist_zyth_endpoint_overlay, run_loginzyth_flow, zyth_grok_com_config,
};
pub use logout::{
    LogoutZythResult, deactivate_zyth_runtime, format_logoutzyth_result, is_zyth_auth_scope,
    perform_logoutzyth, zyth_scopes_in_store,
};
pub use models::{
    ZythModelsSyncResult, enrich_ids_for_test, restore_models_after_logoutzyth,
    sync_zyth_models_from_gateway,
};
pub use protocol::{
    PastedCallback, ZythLoginError, build_authorize_url_parts, parse_exchange_response,
    parse_pasted_input, user_message, validate_exchange_url, validate_gateway_base_url,
    validate_gateway_credential, validate_state,
};
