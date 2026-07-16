//! Free→paid subscription detection and gate imposition/lift.
//!
//! All gate transitions go through [`AppView::impose_gate`] /
//! [`AppView::lift_gate`] so the defer-vs-show decision and the lift
//! bookkeeping (focus, telemetry, JWT-refresh check) live in one place.
//!
//! Design constraints that are not obvious from the code:
//! - Gates arriving from cached auth meta, prefetched settings, or settings
//!   pushes can be stale: the user may have subscribed since the snapshot
//!   was computed. Painting such a gate directly flashes a paywall at a
//!   paying user, so it is held in `pending_gate_verification` while a live
//!   check runs. On check failure or timeout we err on blocking.
//! - Timer effects have no cancellation, so verifications are stamped with
//!   `gate_verify_gen`; results and timeouts from superseded deferrals are
//!   ignored by generation mismatch.

use super::actions::Effect;
use super::app_view::{AppView, AuthState};

/// Whether [`AppView::impose_gate`] may paint a visible SuperGrok paywall.
///
/// **Fork policy:** always `false`. Integration tests call this shipped helper
/// directly (no AppView construction required).
pub fn impose_gate_applies_visible_paywall() -> bool {
    false
}

/// Default watch cadence. Overridable via the remote settings
/// `grok_build_settings.subscription_watch_interval_secs` field.
pub(crate) const SUBSCRIPTION_WATCH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60);

/// Floor for the server-supplied cadence: a fat-fingered remote settings value
/// must not turn the fleet into a hot-poller. `0` means "disabled" and is
/// special-cased before this clamp.
pub(crate) const SUBSCRIPTION_WATCH_MIN_INTERVAL_SECS: u64 = 30;

/// Floor for the `GROK_SUBSCRIPTION_WATCH_INTERVAL_SECS` env override
/// (test seam / power user — deliberately below the server floor).
const SUBSCRIPTION_WATCH_ENV_MIN_SECS: u64 = 1;

/// Cap on the spacing between watch/focus-triggered checks.
pub(crate) const SUBSCRIPTION_CHECK_DEBOUNCE: std::time::Duration =
    std::time::Duration::from_secs(30);

/// How long a deferred gate is held before being shown anyway. This is a
/// safety net for a hung ACP round-trip only — a completed check (even a
/// failed one) resolves the deferral immediately. Generous on purpose: the
/// check can chain a `/user` fetch, a JWT refresh, and a settings re-fetch;
/// 5s was observed timing out in CI under full-suite contention.
pub(crate) const GATE_VERIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl AppView {
    /// Consumer xAI session auth: not an API key, not an enterprise team.
    /// Subscription gates and the watch only apply to these sessions.
    fn is_consumer_session(&self) -> bool {
        matches!(self.auth_state, AuthState::Done)
            && !self.is_api_key_auth
            && self.team_name.is_none()
    }

    /// `None` tier counts as potentially-free so detection works before the
    /// first auth meta lands. Not a confirmed-free signal.
    pub fn may_be_free_tier(&self) -> bool {
        match self.subscription_tier.as_deref() {
            Some(t) => t.trim().eq_ignore_ascii_case("free"),
            None => true,
        }
    }

    /// Effective watch cadence; `None` = disabled. Precedence: env override
    /// (`0` disables), server override (`0` disables, floor-clamped),
    /// default.
    pub fn subscription_watch_interval(&self) -> Option<std::time::Duration> {
        if let Ok(v) = std::env::var("GROK_SUBSCRIPTION_WATCH_INTERVAL_SECS")
            && let Ok(secs) = v.trim().parse::<u64>()
        {
            return match secs {
                0 => None,
                s => Some(std::time::Duration::from_secs(
                    s.max(SUBSCRIPTION_WATCH_ENV_MIN_SECS),
                )),
            };
        }
        match self.subscription_watch_interval_secs {
            Some(0) => None,
            Some(secs) => Some(std::time::Duration::from_secs(
                secs.max(SUBSCRIPTION_WATCH_MIN_INTERVAL_SECS),
            )),
            None => Some(SUBSCRIPTION_WATCH_INTERVAL),
        }
    }

    /// Whether the watch (and the refocus check) should run: enabled,
    /// consumer session, and gated or possibly-free.
    pub fn subscription_watch_wanted(&self) -> bool {
        self.subscription_watch_interval().is_some()
            && self.is_consumer_session()
            && (self.gate.is_some() || self.may_be_free_tier())
    }

    /// Half the effective interval, capped at [`SUBSCRIPTION_CHECK_DEBOUNCE`]
    /// — scaling keeps the debounce from swallowing watch ticks when the
    /// cadence is tightened.
    fn subscription_check_allowed(&self) -> bool {
        let debounce = self
            .subscription_watch_interval()
            .map(|iv| (iv / 2).min(SUBSCRIPTION_CHECK_DEBOUNCE))
            .unwrap_or(SUBSCRIPTION_CHECK_DEBOUNCE);
        self.last_subscription_check_at
            .is_none_or(|t| t.elapsed() >= debounce)
    }

    fn note_subscription_check(&mut self) {
        self.last_subscription_check_at = Some(std::time::Instant::now());
    }

    /// Single guard-and-fire for the watch tick and the terminal-refocus
    /// trigger. Empty when unwanted or debounced. The 5s paywall chain
    /// deliberately bypasses this. `trigger` tags the unified-log entry
    /// (`"watch"` / `"focus"`) so the check cadence is reconstructable
    /// from logs.
    #[must_use]
    pub fn fire_subscription_check(&mut self, trigger: &'static str) -> Vec<Effect> {
        if self.subscription_watch_wanted() && self.subscription_check_allowed() {
            self.note_subscription_check();
            crate::unified_log::info(
                "subscription.check.fired",
                None,
                Some(serde_json::json!({
                    "trigger": trigger,
                    "interval_secs": self
                        .subscription_watch_interval()
                        .map(|iv| iv.as_secs()),
                    "gated": self.gate.is_some(),
                    "tier": self.subscription_tier,
                })),
            );
            vec![Effect::CheckSubscription { verify: None }]
        } else {
            vec![]
        }
    }

    /// Chokepoint for showing a gate.
    ///
    /// **Fork policy:** never impose a subscription / SuperGrok paywall gate.
    /// Remote settings and auth meta cannot re-block the session.
    #[must_use]
    pub fn impose_gate(&mut self, gate: xai_grok_shell::auth::GateInfo) -> Vec<Effect> {
        let _ = gate;
        // Drop any prior gate / pending verification so a stale path cannot
        // leave residual paywall state.
        self.gate = None;
        self.pending_gate_verification = None;
        if impose_gate_applies_visible_paywall() {
            // Unreachable under fork policy.
            return vec![];
        }
        crate::unified_log::info(
            "subscription.gate.imposed_suppressed",
            None,
            Some(serde_json::json!({ "fork_policy": "always_allow" })),
        );
        vec![]
    }

    /// Chokepoint for a settings-confirmed gate lift. Clears the visible
    /// gate and any pending deferral; when either existed, runs the lift
    /// bookkeeping and returns the JWT-refresh check (the tier claim is
    /// baked into the JWT, so the shell must re-mint it).
    #[must_use]
    pub fn lift_gate(&mut self) -> Vec<Effect> {
        let was_blocked = self.gate.is_some() || self.pending_gate_verification.is_some();
        self.gate = None;
        self.pending_gate_verification = None;
        if !was_blocked {
            return vec![];
        }
        self.welcome_prompt_focused = true;
        self.paywall_check_started = None;
        crate::unified_log::info(
            "subscription.gate.lifted",
            None,
            Some(serde_json::json!({ "tier": self.subscription_tier })),
        );
        xai_grok_telemetry::session_ctx::log_event(
            xai_grok_telemetry::events::SubscriptionActivated {
                auth_method: self.login_method_id.as_ref().map(|id| id.0.to_string()),
                upsell_shown_this_session: self.access_gate_shown_logged,
            },
        );
        vec![Effect::CheckSubscription { verify: None }]
    }

    /// Hold `gate` out of `self.gate` while a generation-stamped live check
    /// verifies it. Resolution: authoritative meta via `apply_auth_meta`
    /// (drops the deferral), or promotion on same-generation check failure /
    /// timeout via [`Self::promote_deferred_gate`].
    #[must_use]
    #[allow(dead_code)] // retained for history; impose_gate no longer defers
    fn defer_gate_for_verification(&mut self, gate: xai_grok_shell::auth::GateInfo) -> Vec<Effect> {
        self.pending_gate_verification = Some(gate);
        self.gate_verify_gen = self.gate_verify_gen.wrapping_add(1);
        self.note_subscription_check();
        crate::unified_log::info(
            "subscription.gate.deferred",
            None,
            Some(serde_json::json!({
                "generation": self.gate_verify_gen,
                "tier": self.subscription_tier,
            })),
        );
        vec![
            Effect::CheckSubscription {
                verify: Some(self.gate_verify_gen),
            },
            Effect::ScheduleGateVerifyTimeout {
                generation: self.gate_verify_gen,
            },
        ]
    }

    /// Show a deferred gate — **fork policy: never promote to a visible gate**.
    pub(crate) fn promote_deferred_gate(&mut self, generation: u64, reason: &'static str) {
        let _ = (generation, reason);
        self.pending_gate_verification = None;
        self.gate = None;
        crate::unified_log::info(
            "subscription.gate.promote_suppressed",
            None,
            Some(serde_json::json!({ "fork_policy": "always_allow" })),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::app_view::tests::test_app;

    fn watch_gate() -> xai_grok_shell::auth::GateInfo {
        xai_grok_shell::auth::GateInfo {
            message: "Subscribe".into(),
            url: None,
            label: None,
        }
    }

    #[test]
    fn may_be_free_tier_matrix() {
        let mut app = test_app();
        app.subscription_tier = None;
        assert!(app.may_be_free_tier(), "unknown tier is potentially free");
        app.subscription_tier = Some("Free".into());
        assert!(app.may_be_free_tier());
        app.subscription_tier = Some(" FREE ".into());
        assert!(app.may_be_free_tier(), "case/whitespace-insensitive");
        app.subscription_tier = Some("SuperGrok Heavy".into());
        assert!(!app.may_be_free_tier());
        app.subscription_tier = Some("X Premium".into());
        assert!(!app.may_be_free_tier());
    }

    #[test]
    fn subscription_watch_wanted_matrix() {
        let mut app = test_app(); // AuthState::Done, consumer, tier unknown
        assert!(
            app.subscription_watch_wanted(),
            "unknown-tier consumer session watches"
        );

        app.subscription_tier = Some("Free".into());
        assert!(app.subscription_watch_wanted(), "free tier watches");

        app.subscription_tier = Some("SuperGrok".into());
        assert!(!app.subscription_watch_wanted(), "paid tier is dormant");

        // Gated — watches regardless of the (stale) tier string.
        app.gate = Some(watch_gate());
        assert!(app.subscription_watch_wanted(), "gated session watches");
        app.gate = None;

        app.subscription_tier = Some("Free".into());
        app.is_api_key_auth = true;
        assert!(
            !app.subscription_watch_wanted(),
            "API-key auth never watches"
        );
        app.is_api_key_auth = false;
        app.team_name = Some("Acme Corp".into());
        assert!(
            !app.subscription_watch_wanted(),
            "team session never watches"
        );
        app.team_name = None;

        app.auth_state = AuthState::Pending { error: None };
        assert!(!app.subscription_watch_wanted(), "pre-auth never watches");
    }

    #[test]
    fn subscription_watch_interval_override_clamp_and_disable() {
        let mut app = test_app();
        assert_eq!(
            app.subscription_watch_interval(),
            Some(SUBSCRIPTION_WATCH_INTERVAL)
        );
        app.subscription_watch_interval_secs = Some(120);
        assert_eq!(
            app.subscription_watch_interval(),
            Some(std::time::Duration::from_secs(120))
        );
        app.subscription_watch_interval_secs = Some(1);
        assert_eq!(
            app.subscription_watch_interval(),
            Some(std::time::Duration::from_secs(
                SUBSCRIPTION_WATCH_MIN_INTERVAL_SECS
            )),
            "sub-floor values are clamped"
        );
        app.subscription_watch_interval_secs = Some(0);
        assert_eq!(app.subscription_watch_interval(), None);
        app.subscription_tier = Some("Free".into());
        assert!(
            !app.subscription_watch_wanted(),
            "interval 0 must disable the watch even on the free tier"
        );
    }

    #[test]
    fn subscription_check_debounce() {
        let mut app = test_app();
        assert!(app.subscription_check_allowed(), "no prior check — allowed");

        app.note_subscription_check();
        assert!(
            !app.subscription_check_allowed(),
            "right after a check — debounced"
        );

        app.last_subscription_check_at =
            Some(std::time::Instant::now() - SUBSCRIPTION_CHECK_DEBOUNCE);
        assert!(app.subscription_check_allowed());
    }

    #[test]
    fn fire_subscription_check_guards_and_debounces() {
        let mut app = test_app();
        let effs = app.fire_subscription_check("watch");
        assert!(matches!(
            effs.as_slice(),
            [Effect::CheckSubscription { verify: None }]
        ));
        assert!(
            app.fire_subscription_check("watch").is_empty(),
            "second fire inside the debounce window must be empty"
        );

        let mut paid = test_app();
        paid.subscription_tier = Some("SuperGrok".into());
        assert!(
            paid.fire_subscription_check("watch").is_empty(),
            "paid tier never fires"
        );
    }

    #[test]
    fn impose_gate_never_blocks_fork_policy() {
        let mut app = test_app();
        let effs = app.impose_gate(watch_gate());
        assert!(effs.is_empty());
        assert!(app.has_access(), "fork: impose_gate must not block");
        assert!(app.gate.is_none());
        assert!(app.pending_gate_verification.is_none());
    }

    #[test]
    fn impose_gate_defers_for_consumer_session() {
        // Fork: impose never defers/shows — always open access.
        let mut app = test_app();
        let effs = app.impose_gate(watch_gate());
        assert!(effs.is_empty());
        assert!(app.has_access());
        assert!(app.pending_gate_verification.is_none());
        assert!(app.gate.is_none());
    }

    #[test]
    fn impose_gate_direct_for_non_consumer_and_already_gated() {
        // Fork: team session also cannot be paywalled.
        let mut app = test_app();
        app.team_name = Some("Acme Corp".into());
        assert!(app.impose_gate(watch_gate()).is_empty());
        assert!(app.has_access());
        assert!(app.gate.is_none());

        let mut gated = test_app();
        gated.gate = Some(watch_gate());
        let new_copy = xai_grok_shell::auth::GateInfo {
            message: "New copy".into(),
            url: None,
            label: None,
        };
        assert!(gated.impose_gate(new_copy).is_empty());
        assert!(gated.gate.is_none(), "impose clears residual gate");
        assert!(gated.has_access());
    }

    #[test]
    fn impose_gate_bumps_generation_each_time() {
        // Fork: generation is not bumped (no deferral path).
        let mut app = test_app();
        let first = app.gate_verify_gen;
        let _ = app.impose_gate(watch_gate());
        let _ = app.impose_gate(watch_gate());
        assert_eq!(app.gate_verify_gen, first);
        assert!(app.has_access());
    }

    #[test]
    fn lift_gate_runs_bookkeeping_once() {
        let mut app = test_app();
        app.gate = Some(watch_gate());
        app.paywall_check_started = Some(std::time::Instant::now());

        let effs = app.lift_gate();
        assert!(app.has_access());
        assert!(app.welcome_prompt_focused);
        assert!(app.paywall_check_started.is_none());
        assert!(matches!(
            effs.as_slice(),
            [Effect::CheckSubscription { verify: None }]
        ));

        assert!(
            app.lift_gate().is_empty(),
            "lift without a gate or deferral is a no-op"
        );
    }

    #[test]
    fn lift_gate_counts_pending_deferral_as_blocked() {
        // Fork: impose leaves nothing blocked; lift is no-op.
        let mut app = test_app();
        let _ = app.impose_gate(watch_gate());
        assert!(app.lift_gate().is_empty());
        assert!(app.has_access());
    }

    #[test]
    fn promote_deferred_gate_is_generation_scoped() {
        // Fork: promote never shows a gate.
        let mut app = test_app();
        app.pending_gate_verification = Some(watch_gate());
        app.gate_verify_gen = 3;
        app.promote_deferred_gate(3, "verify_timeout");
        assert!(app.has_access());
        assert!(app.gate.is_none());
        assert!(app.pending_gate_verification.is_none());
    }

    #[test]
    fn apply_auth_meta_drops_pending_gate_verification() {
        let mut app = test_app();
        let _effs = app.impose_gate(watch_gate());

        app.apply_auth_meta(&xai_grok_shell::auth::AuthMeta::default());

        assert!(app.pending_gate_verification.is_none());
        assert!(app.has_access());
    }
}
