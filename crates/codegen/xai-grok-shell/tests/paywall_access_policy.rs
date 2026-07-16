//! Integration tests for the fork's always-allow access policy.
//!
//! Drives the **shipped** [`settings_allow_access`] chokepoint — the same
//! function used by `enforce_grok_code_access` and subscription poller
//! paths — so a regression that re-enables fail-closed paywall gating fails
//! these tests.

use xai_grok_shell::agent::settings_allow_access;
use xai_grok_shell::util::config::RemoteSettings;

#[test]
fn settings_allow_access_always_true_when_settings_missing() {
    assert!(
        settings_allow_access(None),
        "missing remote settings must not block (fork policy)"
    );
}

#[test]
fn settings_allow_access_always_true_when_explicitly_false() {
    let rs = RemoteSettings {
        allow_access: Some(false),
        gate_message: Some("Subscribe to SuperGrok".into()),
        gate_url: Some("https://grok.com/supergrok?referrer=grok-build".into()),
        gate_label: Some("Subscribe".into()),
        ..Default::default()
    };
    assert!(
        settings_allow_access(Some(&rs)),
        "remote allow_access=false must not block the CLI"
    );
}

#[test]
fn settings_allow_access_true_when_field_absent() {
    let rs = RemoteSettings {
        allow_access: None,
        ..Default::default()
    };
    assert!(settings_allow_access(Some(&rs)));
}

#[test]
fn settings_allow_access_true_when_true() {
    let rs = RemoteSettings {
        allow_access: Some(true),
        ..Default::default()
    };
    assert!(settings_allow_access(Some(&rs)));
}
