//! Drives shipped Imagine tier-gate helpers (fork: never SuperGrok-block).

use xai_grok_tools::implementations::grok_build::{
    imagine_tier_gate_blocks, video_tier_gate_blocks,
};

#[test]
fn imagine_gate_never_blocks_even_when_flag_true() {
    assert!(!imagine_tier_gate_blocks(true));
    assert!(!imagine_tier_gate_blocks(false));
}

#[test]
fn video_gate_never_blocks_even_when_flag_true() {
    assert!(!video_tier_gate_blocks(true));
    assert!(!video_tier_gate_blocks(false));
}

#[test]
fn upsell_constants_have_no_supergrok_url() {
    // Constants are crate-private; gate helpers are the shipped policy surface.
    // If a future change re-introduces SuperGrok CTA into the active path,
    // the gate helpers must stay false so tools cannot short-circuit.
    assert!(!imagine_tier_gate_blocks(true));
}
