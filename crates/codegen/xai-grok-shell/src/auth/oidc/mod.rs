//! OIDC authentication: protocol, login, and refresh submodules.

mod login;
pub(crate) mod protocol;
pub(crate) mod refresh;
#[cfg(test)]
mod test_helpers;

pub use login::{run_login_flow, run_login_flow_with_config};
pub(crate) use protocol::{
    Discovery, OidcError, OidcUserInfo, Pkce, TokenResponse, build_authorize_url, build_grok_auth,
    discover, enforce_login_principal, exchange_code, generate_pkce, is_configured,
    login_principal_policy, peek_access_token_principal, peek_access_token_principal_id,
    validate_state, with_alpha_test_key,
};
pub(crate) use refresh::{OidcRefreshResult, oidc_token_exchange};
