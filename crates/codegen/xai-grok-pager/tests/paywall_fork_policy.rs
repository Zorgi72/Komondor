//! Integration tests for fork paywall removal — drives **shipped** functions.
//!
//! Does not use `include_str` source theater. Calls public helpers that the
//! pager and tools crates actually use on the access / Imagine paths.

use xai_grok_pager::app::{
    billing_upsell_opens_stop_ui, impose_gate_applies_visible_paywall, session_has_access,
};
use xai_grok_shell::agent::settings_allow_access;
use xai_grok_shell::util::config::RemoteSettings;
use xai_grok_tools::implementations::grok_build::{
    imagine_tier_gate_blocks, video_tier_gate_blocks,
};

#[test]
fn session_has_access_always_open_even_when_gate_field_set() {
    assert!(session_has_access(false));
    assert!(
        session_has_access(true),
        "residual gate field must not block session access"
    );
}

#[test]
fn impose_gate_never_applies_visible_paywall() {
    assert!(
        !impose_gate_applies_visible_paywall(),
        "impose_gate must not paint SuperGrok paywall"
    );
}

#[test]
fn billing_upsell_never_opens_stop_ui() {
    assert!(
        !billing_upsell_opens_stop_ui(),
        "credit/free-usage paths must not open stop modal/card"
    );
}

#[test]
fn settings_allow_access_ignores_remote_false() {
    assert!(settings_allow_access(None));
    let rs = RemoteSettings {
        allow_access: Some(false),
        gate_message: Some("Subscribe".into()),
        gate_url: Some("https://grok.com/supergrok?referrer=grok-build".into()),
        ..Default::default()
    };
    assert!(settings_allow_access(Some(&rs)));
}

#[test]
fn imagine_tools_never_super_grok_gate() {
    // Even if config stored tier_restricted=true, gate helper is always false.
    assert!(!imagine_tier_gate_blocks(true));
    assert!(!imagine_tier_gate_blocks(false));
    assert!(!video_tier_gate_blocks(true));
    assert!(!video_tier_gate_blocks(false));
}

#[test]
fn free_usage_user_message_has_no_supergrok_cta() {
    // Drive the shipped constant (re-exported from pager app/dispatch).
    let msg = xai_grok_pager::FREE_USAGE_USER_MESSAGE;
    let lower = msg.to_ascii_lowercase();
    assert!(!lower.contains("supergrok"), "msg={msg}");
    assert!(!msg.contains("grok.com/supergrok"), "msg={msg}");
}
