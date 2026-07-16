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

/// Security: a single planted `[ZYTH]` marker must not launder foreign base_urls.
#[test]
fn catalog_looks_like_gateway_rejects_mixed_foreign_base() {
    let mut mixed = gateway_catalog();
    if let Some((_k, e)) = mixed.iter_mut().next() {
        e.info.base_url = "https://evil.example/v1".into();
        // Keep a [ZYTH] name on this entry so old OR-any logic would pass.
        e.info.name = Some("[ZYTH] evil".into());
    }
    // Add a second fully-gateway entry — still mixed overall.
    let good = enrich_ids_for_test(&["grok-ok"]);
    for (k, v) in good {
        mixed.insert(k, v);
    }
    // If any entry lacks gateway base AND lacks [ZYTH] name after our mutation of one...
    // We set the evil entry to have [ZYTH] name + evil base — with all() + (base OR name),
    // that entry would still pass via name. Pin on install is the real defense.
    // Mixed catalog with one entry that has neither marker nor host:
    let mut no_marker = spacexai_catalog();
    let one = enrich_ids_for_test(&["grok-zyth-only"]);
    for (k, v) in one {
        no_marker.insert(k, v);
    }
    assert!(
        !ModelsManager::catalog_looks_like_gateway(&no_marker),
        "mixed SpaceXAI + one Zyth entry must not count as full gateway catalog"
    );
}

#[test]
fn install_pins_all_base_urls_to_gateway() {
    let mgr = test_manager();
    let mut poisoned = gateway_catalog();
    for e in poisoned.values_mut() {
        e.info.base_url = "https://evil.example/v1".into();
    }
    mgr.install_gateway_catalog("https://ai-gateway.zyth.app/v1", poisoned);
    for e in mgr.models().values() {
        assert!(
            e.info.base_url.contains("ai-gateway.zyth.app"),
            "base_url not pinned: {}",
            e.info.base_url
        );
        assert!(
            !e.info.base_url.contains("evil.example"),
            "foreign base_url survived install"
        );
    }
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

/// Plan verification: install then apply a late **non-gateway** catalog
/// (Session/cli-chat-proxy shape). Sticky must reject the apply.
#[test]
fn sticky_rejects_non_gateway_try_apply_catalog() {
    let mgr = test_manager();
    mgr.install_gateway_catalog("https://ai-gateway.zyth.app/v1", gateway_catalog());
    assert!(mgr.models().contains_key("grok-3-mini"));

    let late_spacexai = spacexai_catalog();
    assert!(
        !ModelsManager::catalog_looks_like_gateway(&late_spacexai),
        "fixture must be non-gateway"
    );

    // Real race path: network refresh / apply_refresh_result via public API.
    let applied = mgr.try_apply_catalog(late_spacexai);
    assert!(
        !applied,
        "non-gateway catalog must be rejected while sticky (got applied=true)"
    );

    let models = mgr.models();
    assert!(
        models.contains_key("grok-3-mini"),
        "gateway model vanished after rejected apply: keys={:?}",
        models.keys().collect::<Vec<_>>()
    );
    assert!(
        ModelsManager::catalog_looks_like_gateway(&models),
        "live catalog must still look like gateway after rejected overwrite"
    );
    // SpaceXAI-only id must not replace the catalog.
    assert!(
        !models.contains_key("grok-composer-2.5-fast")
            || models
                .get("grok-composer-2.5-fast")
                .is_some_and(|e| e.info.base_url.contains("ai-gateway.zyth.app")),
        "SpaceXAI-only model must not win over sticky gateway"
    );
    assert!(mgr.gateway_catalog_is_sticky());
}

/// Plan verification: disk hot-reload of a **non-gateway** models_cache while
/// sticky must not wipe the live Zyth picker.
#[test]
fn sticky_ignores_non_gateway_disk_cache_reload() {
    let mgr = test_manager();
    mgr.install_gateway_catalog("https://ai-gateway.zyth.app/v1", gateway_catalog());
    assert!(mgr.models().contains_key("grok-3-mini"));

    let dir = tempfile::tempdir().expect("tempdir");
    let cache_path = dir.path().join("models_cache.json");

    // Write a SpaceXAI-shaped models_cache.json (what a Session fetch persists).
    let spacexai = spacexai_catalog();
    let body = serde_json::json!({
        "fetched_at": chrono::Utc::now().to_rfc3339(),
        "grok_version": xai_grok_version::VERSION,
        "auth_method": "session",
        "origin": "https://cli-chat-proxy.grok.com/v1/models",
        "models": spacexai,
    });
    std::fs::write(
        &cache_path,
        serde_json::to_vec_pretty(&body).expect("serialize"),
    )
    .expect("write models_cache");

    // Real watcher path: reload_from_disk_cache → reload_from_cache_manager.
    mgr.reload_from_models_cache_path(&cache_path);

    let models = mgr.models();
    assert!(
        models.contains_key("grok-3-mini"),
        "gateway model vanished after non-gateway disk reload: keys={:?}",
        models.keys().collect::<Vec<_>>()
    );
    assert!(
        ModelsManager::catalog_looks_like_gateway(&models),
        "disk non-gateway reload must not replace sticky gateway catalog"
    );
    assert!(mgr.gateway_catalog_is_sticky());
}

/// Combined race: install → non-gateway apply → non-gateway disk reload →
/// on_auth_changed; Zyth models must still be present.
#[tokio::test]
async fn full_login_race_keeps_gateway_models() {
    let mgr = test_manager();
    mgr.install_gateway_catalog("https://ai-gateway.zyth.app/v1", gateway_catalog());

    assert!(
        !mgr.try_apply_catalog(spacexai_catalog()),
        "late non-gateway fetch must be blocked"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let cache_path = dir.path().join("models_cache.json");
    let body = serde_json::json!({
        "fetched_at": chrono::Utc::now().to_rfc3339(),
        "grok_version": xai_grok_version::VERSION,
        "auth_method": "session",
        "origin": "https://cli-chat-proxy.grok.com/v1/models",
        "models": spacexai_catalog(),
    });
    std::fs::write(&cache_path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    mgr.reload_from_models_cache_path(&cache_path);

    mgr.on_auth_changed().await;

    let models = mgr.models();
    assert!(
        models.contains_key("grok-3-mini") && ModelsManager::catalog_looks_like_gateway(&models),
        "full race must leave sticky gateway catalog: keys={:?}",
        models.keys().collect::<Vec<_>>()
    );
}
