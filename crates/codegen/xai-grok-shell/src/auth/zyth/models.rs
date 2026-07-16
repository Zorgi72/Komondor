//! Sync the local model catalog with Zyth AI Gateway `/v1/models`.
//!
//! On `/loginzyth`: fetch live inventory, enrich with known metadata
//! (context windows, thinking/reasoning efforts), write `models_cache.json`.
//!
//! On `/logoutzyth`: restore the pre-Zyth cache if saved, else strip
//! Zyth-gateway-origin entries.

use std::num::NonZeroU64;
use std::path::Path;

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::config::ZYTH_AI_GATEWAY_BASE_URL;
use super::protocol::ZythLoginError;
use crate::agent::config::{ModelEntry, ModelInfo};
use crate::sampling::ApiBackend;
use xai_grok_sampler::AuthScheme;
use xai_grok_sampling_types::{ReasoningEffort, ReasoningEffortOption};

const MODELS_CACHE_FILE: &str = "models_cache.json";
const PRE_ZYTH_CACHE: &str = "models_cache.pre-zyth.json";
const ZYTH_MODELS_MARKER: &str = "zyth_models_active.json";

/// Result of a catalog sync.
#[derive(Debug, Clone)]
pub struct ZythModelsSyncResult {
    pub count: usize,
    pub origin: String,
    pub model_ids: Vec<String>,
}

/// On-disk shape matching `agent::models::ModelsCache` (private there).
#[derive(Debug, Serialize, Deserialize)]
struct DiskModelsCache {
    fetched_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grok_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    models: IndexMap<String, ModelEntry>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModelsList {
    #[serde(default)]
    data: Vec<OpenAiModel>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModel {
    id: String,
}

/// Fetch + enrich gateway models; returns the catalog map for
/// [`crate::agent::models::ModelsManager::install_gateway_catalog`].
pub async fn fetch_and_enrich_zyth_models(
    gateway_base: &str,
    bearer: &str,
    prior: &IndexMap<String, ModelEntry>,
) -> Result<(IndexMap<String, ModelEntry>, ZythModelsSyncResult), ZythLoginError> {
    let base = gateway_base.trim_end_matches('/');
    let list_url = if base.ends_with("/models") {
        base.to_owned()
    } else {
        format!("{base}/models")
    };

    let resp = crate::http::shared_client()
        .get(&list_url)
        .header("Authorization", format!("Bearer {bearer}"))
        .header("Accept", "application/json")
        .header(
            "User-Agent",
            format!("zyth-cli/{}", xai_grok_version::VERSION),
        )
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| ZythLoginError::Network(format!("models list: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(ZythLoginError::Network(format!(
            "models list HTTP {status}"
        )));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| ZythLoginError::Network(e.to_string()))?;
    let parsed: OpenAiModelsList = serde_json::from_str(&body).map_err(|e| {
        ZythLoginError::Network(format!("models list JSON: {e}"))
    })?;

    if parsed.data.is_empty() {
        return Err(ZythLoginError::Network(
            "gateway returned zero models".into(),
        ));
    }

    let mut models = IndexMap::new();
    let mut ids = Vec::new();
    for m in &parsed.data {
        let id = m.id.trim();
        if id.is_empty() {
            continue;
        }
        ids.push(id.to_owned());
        models.insert(id.to_owned(), enrich_model_entry(id, base, prior.get(id)));
    }

    let result = ZythModelsSyncResult {
        count: ids.len(),
        origin: list_url,
        model_ids: ids,
    };
    Ok((models, result))
}

/// Fetch models from the gateway with the SSO-minted virtual key and write
/// `~/.grok/models_cache.json` so the TUI loads them all.
pub async fn sync_zyth_models_from_gateway(
    grok_home: &Path,
    gateway_base: &str,
    bearer: &str,
) -> Result<(IndexMap<String, ModelEntry>, ZythModelsSyncResult), ZythLoginError> {
    let cache_path = grok_home.join(MODELS_CACHE_FILE);
    let backup_path = grok_home.join(PRE_ZYTH_CACHE);
    // Only backup a non-Zyth catalog so logout can restore SpaceXAI models.
    if cache_path.exists() && !backup_path.exists() {
        if let Ok(raw) = std::fs::read(&cache_path) {
            if let Ok(existing) = serde_json::from_slice::<DiskModelsCache>(&raw) {
                let is_zyth = existing
                    .origin
                    .as_deref()
                    .is_some_and(|o| o.contains("ai-gateway.zyth.app"));
                if !is_zyth {
                    let _ = std::fs::copy(&cache_path, &backup_path);
                }
            }
        }
    }

    let prior: IndexMap<String, ModelEntry> = std::fs::read(&cache_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<DiskModelsCache>(&b).ok())
        .map(|c| c.models)
        .unwrap_or_default();

    let (models, result) =
        fetch_and_enrich_zyth_models(gateway_base, bearer, &prior).await?;

    let base = gateway_base.trim_end_matches('/');
    let cache = DiskModelsCache {
        fetched_at: Utc::now(),
        grok_version: Some(xai_grok_version::VERSION.to_string()),
        // Matches CacheAuthMethod::ApiKey — SSO-minted virtual key Bearer.
        auth_method: Some("api_key".into()),
        origin: Some(result.origin.clone()),
        etag: None,
        models: models.clone(),
    };

    write_models_cache_atomic(&cache_path, &cache)?;
    write_zyth_marker(grok_home, &result.model_ids, base)?;

    tracing::info!(
        count = result.count,
        origin = %result.origin,
        "loginzyth: synced gateway models into models_cache.json"
    );

    Ok((models, result))
}

/// Remove Zyth gateway models and restore pre-login catalog if available.
pub fn restore_models_after_logoutzyth(grok_home: &Path) -> Result<bool, ZythLoginError> {
    let cache_path = grok_home.join(MODELS_CACHE_FILE);
    let backup_path = grok_home.join(PRE_ZYTH_CACHE);
    let marker_path = grok_home.join(ZYTH_MODELS_MARKER);

    let restored = if backup_path.exists() {
        std::fs::copy(&backup_path, &cache_path)
            .map_err(|e| ZythLoginError::SaveAuth(format!("restore models cache: {e}")))?;
        let _ = std::fs::remove_file(&backup_path);
        true
    } else if cache_path.exists() {
        if let Ok(raw) = std::fs::read(&cache_path) {
            if let Ok(mut cache) = serde_json::from_slice::<DiskModelsCache>(&raw) {
                let before = cache.models.len();
                cache
                    .models
                    .retain(|_, e| !e.info.base_url.contains("ai-gateway.zyth.app"));
                if cache
                    .origin
                    .as_deref()
                    .is_some_and(|o| o.contains("ai-gateway.zyth.app"))
                {
                    cache.origin = None;
                }
                if cache.models.len() != before {
                    write_models_cache_atomic(&cache_path, &cache)?;
                }
            }
        }
        false
    } else {
        false
    };

    let _ = std::fs::remove_file(marker_path);
    Ok(restored)
}

fn write_zyth_marker(
    grok_home: &Path,
    ids: &[String],
    gateway_base: &str,
) -> Result<(), ZythLoginError> {
    let path = grok_home.join(ZYTH_MODELS_MARKER);
    let body = serde_json::json!({
        "gateway_base": gateway_base,
        "model_ids": ids,
        "updated_at": Utc::now().to_rfc3339(),
    });
    let bytes =
        serde_json::to_vec_pretty(&body).map_err(|e| ZythLoginError::SaveAuth(e.to_string()))?;
    crate::util::secure_file::write_secure_file(&path, &bytes)
        .map_err(|e| ZythLoginError::SaveAuth(e.to_string()))
}

fn write_models_cache_atomic(path: &Path, cache: &DiskModelsCache) -> Result<(), ZythLoginError> {
    let bytes = serde_json::to_vec_pretty(cache)
        .map_err(|e| ZythLoginError::SaveAuth(format!("serialize models cache: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    crate::util::secure_file::write_secure_file(&tmp, &bytes)
        .map_err(|e| ZythLoginError::SaveAuth(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| ZythLoginError::SaveAuth(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn enrich_model_entry(id: &str, gateway_base: &str, prior: Option<&ModelEntry>) -> ModelEntry {
    let meta = model_metadata_for_id(id);
    let prior_info = prior.map(|p| &p.info);

    let context_window = prior_info
        .map(|i| i.context_window)
        .unwrap_or(meta.context_window);

    let supports_reasoning = prior_info
        .map(|i| i.supports_reasoning_effort)
        .unwrap_or(meta.supports_reasoning_effort);

    let reasoning_efforts = if let Some(p) = prior_info {
        if !p.reasoning_efforts.is_empty() {
            p.reasoning_efforts.clone()
        } else {
            meta.reasoning_efforts.clone()
        }
    } else {
        meta.reasoning_efforts.clone()
    };

    let reasoning_effort = prior_info
        .and_then(|i| i.reasoning_effort)
        .or(meta.default_effort);

    // Always show [ZYTH] prefix in the model selector for gateway SSO models.
    let bare_name = prior_info
        .and_then(|i| i.name.clone())
        .filter(|n| !n.is_empty())
        .map(|n| n.trim_start_matches("[ZYTH] ").to_owned())
        .unwrap_or_else(|| meta.display_name.to_owned());
    let name = Some(format!("[ZYTH] {bare_name}"));

    let description = prior_info
        .and_then(|i| i.description.clone())
        .or_else(|| meta.description.map(|s| s.to_owned()));

    let api_backend = prior_info
        .map(|i| i.api_backend.clone())
        .unwrap_or(meta.api_backend);

    let agent_type = prior_info
        .map(|i| i.agent_type.clone())
        .unwrap_or_else(|| meta.agent_type.to_owned());

    let hidden = meta.hidden || prior_info.map(|i| i.hidden).unwrap_or(false);

    ModelEntry {
        info: ModelInfo {
            id: Some(id.to_owned()),
            model: id.to_owned(),
            base_url: gateway_base.to_owned(),
            name,
            description,
            max_completion_tokens: prior_info.and_then(|i| i.max_completion_tokens),
            temperature: None,
            top_p: None,
            api_backend,
            auth_scheme: AuthScheme::Bearer,
            extra_headers: IndexMap::new(),
            context_window,
            auto_compact_threshold_percent: prior_info
                .and_then(|i| i.auto_compact_threshold_percent)
                .or(Some(80)),
            system_prompt_label: prior_info
                .and_then(|i| i.system_prompt_label.clone())
                .or_else(|| Some(meta.display_name.to_owned())),
            use_concise: false,
            agent_type,
            inference_idle_timeout_secs: None,
            max_retries: None,
            hidden,
            user_selectable: !hidden,
            supported_in_api: true,
            reasoning_effort,
            supports_reasoning_effort: supports_reasoning,
            reasoning_efforts,
            supports_backend_search: prior_info
                .map(|i| i.supports_backend_search)
                .unwrap_or(false),
            compactions_remaining: None,
            compaction_at_tokens: prior_info.and_then(|i| i.compaction_at_tokens.clone()),
            show_model_fingerprint: false,
            stream_tool_calls: None,
            laziness_detector: Default::default(),
        },
        api_key: None,
        env_key: None,
        api_base_url: Some(gateway_base.to_owned()),
    }
}

struct ModelMeta {
    display_name: &'static str,
    description: Option<&'static str>,
    context_window: NonZeroU64,
    supports_reasoning_effort: bool,
    default_effort: Option<ReasoningEffort>,
    reasoning_efforts: Vec<ReasoningEffortOption>,
    api_backend: ApiBackend,
    agent_type: &'static str,
    hidden: bool,
}

fn nz(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).unwrap_or_else(|| NonZeroU64::new(128_000).unwrap())
}

fn default_efforts() -> Vec<ReasoningEffortOption> {
    vec![
        ReasoningEffortOption {
            id: "high".into(),
            value: ReasoningEffort::High,
            label: "High Effort".into(),
            description: Some("Highest quality with extensive reasoning".into()),
            default: true,
        },
        ReasoningEffortOption {
            id: "medium".into(),
            value: ReasoningEffort::Medium,
            label: "Medium Effort".into(),
            description: Some("Balanced effort".into()),
            default: false,
        },
        ReasoningEffortOption {
            id: "low".into(),
            value: ReasoningEffort::Low,
            label: "Low Effort".into(),
            description: Some("Quick implementations".into()),
            default: false,
        },
    ]
}

fn model_metadata_for_id(id: &str) -> ModelMeta {
    let lower = id.to_ascii_lowercase();
    if lower.contains("imagine") || lower.contains("image") || lower.contains("video") {
        return ModelMeta {
            display_name: static_or_leak(id),
            description: Some("Media generation model via Zyth AI Gateway (SSO)"),
            context_window: nz(128_000),
            supports_reasoning_effort: false,
            default_effort: None,
            reasoning_efforts: vec![],
            api_backend: ApiBackend::ChatCompletions,
            agent_type: "grok-build-plan",
            hidden: false,
        };
    }
    if lower.contains("4.5") {
        return ModelMeta {
            display_name: "Grok 4.5",
            description: Some("Frontier model via Zyth AI Gateway (SSO)"),
            context_window: nz(500_000),
            supports_reasoning_effort: true,
            default_effort: Some(ReasoningEffort::High),
            reasoning_efforts: default_efforts(),
            api_backend: ApiBackend::Responses,
            agent_type: "grok-build-plan",
            hidden: false,
        };
    }
    if lower.contains("reasoning") || lower.contains("4.3") || lower.contains("4.20") {
        let reasoning = !lower.contains("non-reasoning");
        return ModelMeta {
            display_name: static_or_leak(id),
            description: Some("Grok 4.x via Zyth AI Gateway (SSO)"),
            context_window: nz(256_000),
            supports_reasoning_effort: reasoning,
            default_effort: reasoning.then_some(ReasoningEffort::High),
            reasoning_efforts: if reasoning {
                default_efforts()
            } else {
                vec![]
            },
            api_backend: if reasoning {
                ApiBackend::Responses
            } else {
                ApiBackend::ChatCompletions
            },
            agent_type: "grok-build-plan",
            hidden: false,
        };
    }
    if lower.contains("composer") {
        return ModelMeta {
            display_name: "Composer 2.5",
            description: Some("Coding model via Zyth AI Gateway (SSO)"),
            context_window: nz(200_000),
            supports_reasoning_effort: true,
            default_effort: Some(ReasoningEffort::Medium),
            reasoning_efforts: default_efforts(),
            api_backend: ApiBackend::ChatCompletions,
            agent_type: "grok-build-plan",
            hidden: false,
        };
    }
    if lower.contains("build") {
        return ModelMeta {
            display_name: static_or_leak(id),
            description: Some("Build agent model via Zyth AI Gateway (SSO)"),
            context_window: nz(200_000),
            supports_reasoning_effort: true,
            default_effort: Some(ReasoningEffort::Medium),
            reasoning_efforts: default_efforts(),
            api_backend: ApiBackend::ChatCompletions,
            agent_type: "grok-build-plan",
            hidden: false,
        };
    }
    if lower.contains("mini") {
        return ModelMeta {
            display_name: static_or_leak(id),
            description: Some("Fast mini model via Zyth AI Gateway (SSO)"),
            context_window: nz(128_000),
            supports_reasoning_effort: false,
            default_effort: None,
            reasoning_efforts: vec![],
            api_backend: ApiBackend::ChatCompletions,
            agent_type: "grok-build-plan",
            hidden: false,
        };
    }
    ModelMeta {
        display_name: static_or_leak(id),
        description: Some("Model via Zyth AI Gateway (SSO)"),
        context_window: nz(200_000),
        supports_reasoning_effort: false,
        default_effort: None,
        reasoning_efforts: vec![],
        api_backend: ApiBackend::ChatCompletions,
        agent_type: "grok-build-plan",
        hidden: false,
    }
}

/// Known static labels; otherwise leak a boxed str for 'static (test-only volume).
fn static_or_leak(id: &str) -> &'static str {
    match id {
        "grok-4.5" => "Grok 4.5",
        "grok-composer-2.5-fast" => "Composer 2.5",
        "grok-3-mini" => "Grok 3 Mini",
        "grok-3-mini-fast" => "Grok 3 Mini Fast",
        "grok-4.3" => "Grok 4.3",
        "grok-build-0.1" => "Grok Build 0.1",
        other => Box::leak(other.to_owned().into_boxed_str()),
    }
}

/// Test/helper: build enriched catalog for a list of gateway model ids.
pub fn enrich_ids_for_test(ids: &[&str]) -> IndexMap<String, ModelEntry> {
    let base = ZYTH_AI_GATEWAY_BASE_URL;
    let mut m = IndexMap::new();
    for id in ids {
        m.insert((*id).to_owned(), enrich_model_entry(id, base, None));
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enriches_all_live_gateway_ids() {
        let ids = [
            "grok-4.20-0309-non-reasoning",
            "grok-4.20-multi-agent-0309",
            "grok-3-mini",
            "grok-3-mini-fast",
            "grok-imagine-image",
            "grok-imagine-video-1.5-preview",
            "grok-build-0.1",
            "grok-4.3",
            "grok-4.20-0309-reasoning",
            "grok-composer-2.5-fast",
            "grok-imagine-image-quality",
            "grok-imagine-video",
            "grok-4.5",
        ];
        let map = enrich_ids_for_test(&ids);
        assert_eq!(map.len(), 13);
        let g45 = map.get("grok-4.5").unwrap();
        assert_eq!(g45.info.context_window.get(), 500_000);
        assert!(g45.info.supports_reasoning_effort);
        assert!(!g45.info.reasoning_efforts.is_empty());
        assert!(g45.info.base_url.contains("ai-gateway.zyth.app"));
        assert!(g45.info.supported_in_api);

        let non_r = map.get("grok-4.20-0309-non-reasoning").unwrap();
        assert!(!non_r.info.supports_reasoning_effort);

        let reason = map.get("grok-4.20-0309-reasoning").unwrap();
        assert!(reason.info.supports_reasoning_effort);
    }

    #[test]
    fn logout_restore_strips_gateway_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join(MODELS_CACHE_FILE);
        let mut models = IndexMap::new();
        models.insert(
            "keep-me".into(),
            enrich_model_entry("keep-me", "https://cli-chat-proxy.grok.com/v1", None),
        );
        models.insert(
            "zyth-one".into(),
            enrich_model_entry("zyth-one", "https://ai-gateway.zyth.app/v1", None),
        );
        let cache = DiskModelsCache {
            fetched_at: Utc::now(),
            grok_version: Some("test".into()),
            auth_method: None,
            origin: Some("https://ai-gateway.zyth.app/v1/models".into()),
            etag: None,
            models,
        };
        write_models_cache_atomic(&cache_path, &cache).unwrap();
        let restored = restore_models_after_logoutzyth(dir.path()).unwrap();
        assert!(!restored);
        let after: DiskModelsCache =
            serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
        assert!(after.models.contains_key("keep-me"));
        assert!(!after.models.contains_key("zyth-one"));
    }
}
