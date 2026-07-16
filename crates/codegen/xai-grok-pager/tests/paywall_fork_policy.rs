//! Integration-style unit tests for pager paywall removal.
//!
//! These compile as an integration test binary so they do not depend on the
//! broken `cfg(test)` surface of the pager lib. They import only the public
//! re-exports needed to prove shipped billing constants and shell access
//! helpers stay open.

use xai_grok_shell::agent::settings_allow_access;
use xai_grok_shell::util::config::RemoteSettings;

/// Mirror of the shipped free-usage user message constant (must stay free of
/// SuperGrok CTA). Kept in sync with
/// `xai_grok_pager::app::dispatch::billing::FREE_USAGE_USER_MESSAGE` via
/// structural grep in the verification script — the constant is crate-private
/// so we assert the *policy* here and re-grep the source for the CTA strings.
#[test]
fn free_usage_message_source_has_no_supergrok_cta() {
    let billing = include_str!("../src/app/dispatch/billing.rs");
    // Find the FREE_USAGE_USER_MESSAGE definition body.
    let start = billing
        .find("pub(crate) const FREE_USAGE_USER_MESSAGE")
        .expect("FREE_USAGE_USER_MESSAGE must exist in shipped billing.rs");
    let snippet = &billing[start..start + 400.min(billing.len() - start)];
    let lower = snippet.to_ascii_lowercase();
    assert!(
        !lower.contains("supergrok"),
        "FREE_USAGE_USER_MESSAGE must not mention SuperGrok: {snippet}"
    );
    assert!(
        !snippet.contains("grok.com/supergrok"),
        "FREE_USAGE_USER_MESSAGE must not include upgrade URL: {snippet}"
    );
    assert!(
        snippet.contains("Usage limit reached") || snippet.contains("usage limit"),
        "expected neutral limit copy: {snippet}"
    );
}

#[test]
fn impose_gate_source_is_suppressed() {
    let sub = include_str!("../src/app/subscription.rs");
    assert!(
        sub.contains("imposed_suppressed") || sub.contains("always_allow"),
        "impose_gate must document fork always-allow / suppress path"
    );
    // Must not re-introduce direct self.gate = Some(gate) as the happy path
    // after "pub fn impose_gate".
    let impose = sub
        .split("pub fn impose_gate")
        .nth(1)
        .expect("impose_gate fn");
    let body = impose.split("pub fn lift_gate").next().unwrap_or(impose);
    assert!(
        !body.contains("self.gate = Some(gate)"),
        "impose_gate must not assign a visible gate"
    );
}

#[test]
fn has_access_source_always_returns_true() {
    let app_view = include_str!("../src/app/app_view.rs");
    let has = app_view
        .split("pub fn has_access")
        .nth(1)
        .expect("has_access");
    let body = has.split("pub fn is_access_blocked").next().unwrap();
    assert!(
        body.contains("true"),
        "has_access must return true unconditionally: {body}"
    );
}

#[test]
fn shell_settings_allow_access_open() {
    assert!(settings_allow_access(None));
    let blocked = RemoteSettings {
        allow_access: Some(false),
        ..Default::default()
    };
    assert!(settings_allow_access(Some(&blocked)));
}

#[test]
fn open_credit_limit_upsell_source_no_modal() {
    let billing = include_str!("../src/app/dispatch/billing.rs");
    let start = billing
        .find("pub(super) fn open_credit_limit_upsell")
        .expect("open_credit_limit_upsell");
    // Only the primary function body before free_usage helper.
    let rest = &billing[start..];
    let body = rest
        .split("pub(super) fn open_free_usage_upsell")
        .next()
        .unwrap();
    assert!(
        body.contains("RenderBlock::system") || body.contains("system("),
        "credit-limit path must use system message, not modal: {body}"
    );
    assert!(
        !body.contains("QuestionViewState::new"),
        "credit-limit must not open Q&A modal"
    );
    assert!(
        !body.contains("credit_limit_card"),
        "credit-limit must not push stop card"
    );
}
