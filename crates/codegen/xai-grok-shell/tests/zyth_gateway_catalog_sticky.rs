//! Race-safe Zyth gateway catalog stickiness.
//!
//! Drives **shipped** [`ModelsManager`] APIs: `install_gateway_catalog` then
//! `on_auth_changed` must keep gateway / `[ZYTH]` models. Logout strip clears them.

use std::sync::Arc;

use indexmap::IndexMap;
use xai_grok_shell::agent::config::{Config, ModelEntry};
use xai_grok_shell::agent::models::ModelsManager;
use xai_grok_shell::auth::zyth::enrich_ids_for_test;
use xai_grok_shell::auth::{AuthManager, GrokComConfig};

fn spacexai_catalog() -> IndexMap<String, ModelEntry> {
    // Strip gateway markers from enriched entries to simulate cli-chat-proxy.
    let mut m = enrich_ids_for_test(&["grok-4.5", "grok-composer-2.5-fast"]);
    for (_k, e) in m.iter_mut() {
        e.info.base_url = "https://cli-chat-proxy.grok.com/v1".into();
        e.info.name = e.info.name.as_ref().map(|n| {
            n.trim_start_matches("[ZYTH] ").to_owned()
        });
    }
    m
}

fn test_manager() -> ModelsManager {
    let dir = tempfile::tempdir().expect("tempdir");
    let auth = Arc::new(AuthManager::new(dir.path(), GrokComConfig::default()));
    ModelsManager::from_config(&Config::default(), Some(IndexMap::new()), auth)
        .expect("ModelsManager::from_config")
}

fn gateway_catalog() -> IndexMap<String, ModelEntry> {
    enrich_ids_for_test(&["grok-3-mini", "grok-4.5"])
}

#[test]
fn catalog_looks_like_gateway_detects_zyth_markers() {
    assert!(ModelsManager::catalog_looks_like_gateway(&gateway_catalog()));
    assert!(!ModelsManager::catalog_looks_like_gateway(&spacexai_catalog()));
}

#[test]
fn install_sets_sticky_and_keeps_gateway_models() {
    let mgr = test_manager();
    assert!(!mgr.gateway_catalog_is_sticky());
    mgr.install_gateway_catalog("https://ai-gateway.zyth.app/v1", gateway_catalog());
    assert!(mgr.gateway_catalog_is_sticky());
    let models = mgr.models();
    assert!(
        models.contains_key("grok-3-mini"),
        "gateway model missing: {:?}",
        models.keys().collect::<Vec<_>>()
    );
    assert!(ModelsManager::catalog_looks_like_gateway(&models));
}

#[tokio::test]
async fn on_auth_changed_does_not_wipe_sticky_gateway() {
    let mgr = test_manager();
    mgr.install_gateway_catalog("https://ai-gateway.zyth.app/v1", gateway_catalog());
    assert!(mgr.gateway_catalog_is_sticky());

    // Simulates auth.json watcher → ConfigUpdate::Auth → on_auth_changed after
    // loginzyth. Sticky path must preserve Zyth models even when Session fetch
    // would otherwise replace them with SpaceXAI.
    mgr.on_auth_changed().await;

    assert!(
        mgr.gateway_catalog_is_sticky(),
        "sticky must survive on_auth_changed"
    );
    let models = mgr.models();
    assert!(
        models.contains_key("grok-3-mini"),
        "Zyth model vanished after on_auth_changed: keys={:?}",
        models.keys().collect::<Vec<_>>()
    );
    assert!(
        ModelsManager::catalog_looks_like_gateway(&models),
        "catalog no longer looks like gateway after auth change"
    );
}

#[tokio::test]
async fn uninstall_clears_sticky_and_strips_gateway_models() {
    let mgr = test_manager();
    mgr.install_gateway_catalog("https://ai-gateway.zyth.app/v1", gateway_catalog());
    assert!(mgr.gateway_catalog_is_sticky());
    mgr.uninstall_gateway_catalog().await;
    assert!(!mgr.gateway_catalog_is_sticky());
    let models = mgr.models();
    assert!(
        !ModelsManager::catalog_looks_like_gateway(&models),
        "gateway models must be gone after uninstall"
    );
}

#[test]
fn install_then_second_install_stays_sticky() {
    let mgr = test_manager();
    mgr.install_gateway_catalog("https://ai-gateway.zyth.app/v1", gateway_catalog());
    let more = enrich_ids_for_test(&["grok-3-mini", "grok-4.5", "grok-build-0.1"]);
    mgr.install_gateway_catalog("https://ai-gateway.zyth.app/v1", more);
    assert!(mgr.gateway_catalog_is_sticky());
    assert!(mgr.models().contains_key("grok-build-0.1"));
}
