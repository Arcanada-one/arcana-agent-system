//! `arcana models` — the curated model list, and choosing one (ARAS-0065).
//!
//! The list comes from the LIVE Model Connector catalogue
//! (`GET /connectors/catalog`), never from a hard-coded table: a table would
//! start lying the first time a provider changed its lineup, and the operator
//! would have no way to tell. Prices are shown next to each model because the
//! whole point of choosing is trading capability against cost.
//!
//! ## Curation
//!
//! The raw catalogue is large. A CLI list that scrolls past the terminal is not
//! a choice, it is a wall, so at most [`MAX_PER_PROVIDER`] models are shown per
//! provider. Curation is deliberately *presentational*: it never hides a model
//! from `use`, so an operator who knows the id can still select one that did
//! not make the shortlist.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Default model when the operator has not chosen one.
pub const DEFAULT_MODEL: &str = "deepseek-v4-flash";

/// Cap per provider. The catalogue carries hundreds of entries; a shortlist is
/// what makes the list usable, and the cap is per-provider so one large
/// provider cannot crowd every other out of the list.
pub const MAX_PER_PROVIDER: usize = 10;

/// The tariffs for one catalogue entry.
///
/// Nested under `pricing` on the wire, not flat on the entry. Absent entirely
/// for a model the catalogue has no price for, which is why the whole struct is
/// optional rather than its fields defaulting to zero -- an unknown price is
/// not a free one.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogPricing {
    #[serde(default)]
    pub input_per_m_tok: Option<f64>,
    #[serde(default)]
    pub output_per_m_tok: Option<f64>,
}

/// One catalogue entry, in the shape `GET /connectors/catalog` actually sends.
///
/// `connector` and `model` carry no `#[serde(default)]` on purpose. Everything
/// this list is keyed by must be present or the decode fails loudly; a
/// defaulting identity field would render a row of empty strings and call it
/// success.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    pub connector: String,
    pub model: String,
    #[serde(default)]
    pub pricing: Option<CatalogPricing>,
    #[serde(default)]
    pub free: Option<bool>,
    /// `false` for a catalogued model the connector cannot currently dispatch.
    #[serde(default)]
    pub available: Option<bool>,
}

impl CatalogEntry {
    #[must_use]
    pub fn input_per_m_tok(&self) -> Option<f64> {
        self.pricing.as_ref().and_then(|p| p.input_per_m_tok)
    }

    #[must_use]
    pub fn output_per_m_tok(&self) -> Option<f64> {
        self.pricing.as_ref().and_then(|p| p.output_per_m_tok)
    }
}

/// The envelope the route wraps the entries in.
///
/// This is the defect #99 reports: the client decoded a bare `Vec<CatalogEntry>`
/// against `{"models": [...], "generatedAt": ..., "count": 969}`, which cannot
/// deserialize at all, so `arcana models` failed on the first byte for its whole
/// life regardless of what the entries looked like.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogResponse {
    pub models: Vec<CatalogEntry>,
    #[serde(default)]
    pub count: Option<usize>,
}

/// The operator's persisted choice.
#[derive(Debug, Serialize, Deserialize)]
pub struct ModelPreference {
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector: Option<String>,
}

/// Where the choice is stored: the per-user XDG state home, beside the audit
/// log and credentials.
fn state_dir() -> PathBuf {
    xdg::BaseDirectories::with_prefix("arcana").map_or_else(
        |_| PathBuf::from(".arcana-state"),
        |base| base.get_state_home(),
    )
}

#[must_use]
pub fn preference_path() -> PathBuf {
    state_dir().join("model.json")
}

/// The operator's EXPLICIT choice, if they have made one.
///
/// Distinct from [`selected_model`], which folds the default in. The caller
/// needs the distinction: an explicit choice overrides the tiered model policy,
/// whereas merely having a default must not — defaulting would silently pin
/// every turn to one model and disable cost-tiered dispatch for everybody.
#[must_use]
pub fn explicit_model() -> Option<String> {
    std::fs::read_to_string(preference_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<ModelPreference>(&raw).ok())
        .map(|pref| pref.model)
        .filter(|model| !model.trim().is_empty())
}

/// Read the operator's chosen model, falling back to the default.
///
/// A corrupt or unreadable preference file is treated as "no choice" rather
/// than an error: the agent must still run, and silently defaulting is better
/// than refusing to start over a cache file.
#[must_use]
pub fn selected_model() -> String {
    std::fs::read_to_string(preference_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<ModelPreference>(&raw).ok())
        .map(|pref| pref.model)
        .filter(|model| !model.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MODEL.to_owned())
}

/// Persist the operator's choice.
///
/// # Errors
/// Propagates any filesystem failure; the caller reports it rather than
/// pretending the choice was saved.
pub fn save_preference(pref: &ModelPreference) -> std::io::Result<PathBuf> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("model.json");
    let json = serde_json::to_vec_pretty(pref)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    std::fs::write(&path, json)?;
    Ok(path)
}

/// Trim the catalogue to at most [`MAX_PER_PROVIDER`] per provider.
///
/// Ordering within a provider is cheapest-first, so the shortlist is the part
/// of the catalogue an operator is most likely to want, rather than whichever
/// entries happened to sort first. Free models lead; unpriced models sort last,
/// because an unknown price is not a cheap price and presenting it as one would
/// invite exactly the wrong choice.
#[must_use]
pub fn curate(mut entries: Vec<CatalogEntry>) -> Vec<CatalogEntry> {
    entries.sort_by(|a, b| {
        a.connector
            .cmp(&b.connector)
            .then_with(|| sort_price(a).total_cmp(&sort_price(b)))
            .then_with(|| a.model.cmp(&b.model))
    });

    let mut kept: Vec<CatalogEntry> = Vec::new();
    let mut per_provider = 0usize;
    let mut current = String::new();
    for entry in entries {
        if entry.connector != current {
            current.clone_from(&entry.connector);
            per_provider = 0;
        }
        if per_provider < MAX_PER_PROVIDER {
            per_provider += 1;
            kept.push(entry);
        }
    }
    kept
}

/// Sort key: total price per 1M tokens, with unknown pricing pushed last.
fn sort_price(entry: &CatalogEntry) -> f64 {
    match (entry.input_per_m_tok(), entry.output_per_m_tok()) {
        (None, None) => f64::MAX,
        (input, output) => input.unwrap_or(0.0) + output.unwrap_or(0.0),
    }
}

/// Human-readable price for one entry.
#[must_use]
pub fn price_label(entry: &CatalogEntry) -> String {
    if entry.free.unwrap_or(false) {
        return "free".to_owned();
    }
    match (entry.input_per_m_tok(), entry.output_per_m_tok()) {
        (None, None) => "price unknown".to_owned(),
        (input, output) => format!(
            "in ${:.2} / out ${:.2} per 1M tok",
            input.unwrap_or(0.0),
            output.unwrap_or(0.0)
        ),
    }
}

/// Fetch the live catalogue from the Model Connector.
///
/// # Errors
/// Returns a human-readable message; the caller turns it into an exit code.
pub async fn fetch_catalog() -> Result<Vec<CatalogEntry>, String> {
    let token = std::env::var("ARCANA_MC_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            "ARCANA_MC_TOKEN is not set, so the live model catalogue cannot be read. \
             The list is never hard-coded, so there is nothing to show without it."
                .to_owned()
        })?;
    let base = std::env::var("ARCANA_MC_BASE_URL")
        .ok()
        .filter(|b| !b.trim().is_empty())
        .unwrap_or_else(|| "https://connector.arcanada.ai".to_owned());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|err| format!("could not build an HTTP client: {err}"))?;

    let url = format!("{}/connectors/catalog", base.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|err| format!("cannot reach the Model Connector at {base}: {err}"))?;

    if !resp.status().is_success() {
        return Err(format!(
            "the Model Connector returned HTTP {} for {url}",
            resp.status().as_u16()
        ));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|err| format!("the catalogue response could not be read: {err}"))?;
    let parsed: CatalogResponse = serde_json::from_slice(&bytes).map_err(|err| {
        format!(
            "the catalogue response could not be read: {err}. \
             Expected {{\"models\": [...]}} from {url}; got {} bytes.",
            bytes.len()
        )
    })?;
    // A model the connector cannot dispatch has no business in a chooser: the
    // operator would pick it and get a dispatch failure with no hint that the
    // list already knew.
    Ok(parsed
        .models
        .into_iter()
        .filter(|entry| entry.available.unwrap_or(true))
        .collect())
}

/// `arcana models` — print the curated list. Returns a process exit code.
#[must_use]
pub fn run_list() -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("arcana models: failed to start async runtime: {err}");
            return 1;
        }
    };
    let entries = match runtime.block_on(fetch_catalog()) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("arcana models: {err}");
            return 1;
        }
    };

    let current = selected_model();
    let curated = curate(entries);
    if curated.is_empty() {
        println!("The Model Connector returned an empty catalogue.");
        return 1;
    }

    println!("Selected: {current}\n");
    let mut provider = String::new();
    for entry in &curated {
        if entry.connector != provider {
            provider.clone_from(&entry.connector);
            println!("{provider}:");
        }
        let marker = if entry.model == current { "*" } else { " " };
        println!("  {marker} {:<38} {}", entry.model, price_label(entry));
    }
    println!(
        "\nShowing at most {MAX_PER_PROVIDER} per provider, cheapest first. \
         `arcana models use <id>` accepts any id, including one not listed."
    );
    0
}

/// `arcana models use <id>` — persist a choice. Returns a process exit code.
#[must_use]
pub fn run_use(model: &str) -> i32 {
    let model = model.trim();
    if model.is_empty() {
        eprintln!("arcana models use: a model id is required");
        return 1;
    }
    let pref = ModelPreference {
        model: model.to_owned(),
        connector: None,
    };
    match save_preference(&pref) {
        Ok(path) => {
            println!("Model set to {model} ({})", path.display());
            0
        }
        Err(err) => {
            eprintln!("arcana models use: could not save the choice: {err}");
            1
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        curate, price_label, sort_price, CatalogEntry, CatalogPricing, CatalogResponse,
        MAX_PER_PROVIDER,
    };

    fn entry(
        connector: &str,
        model: &str,
        input: Option<f64>,
        output: Option<f64>,
    ) -> CatalogEntry {
        CatalogEntry {
            connector: connector.to_owned(),
            model: model.to_owned(),
            pricing: Some(CatalogPricing {
                input_per_m_tok: input,
                output_per_m_tok: output,
            }),
            free: None,
            available: None,
        }
    }

    /// The real body, captured from `GET /connectors/catalog` on production.
    ///
    /// Checked in rather than hand-written. The fixture this replaces was
    /// written from the Rust struct, so it agreed with the code and both
    /// disagreed with the server -- which is exactly how a command that could
    /// never work shipped with passing tests.
    const LIVE_CATALOGUE: &str = include_str!("../tests/fixtures/connectors-catalog.json");

    #[test]
    fn the_live_catalogue_body_decodes() {
        let parsed: CatalogResponse =
            serde_json::from_str(LIVE_CATALOGUE).expect("the real wire body must decode");
        assert_eq!(parsed.count, Some(5));
        let grok = parsed
            .models
            .iter()
            .find(|m| m.model == "grok-3-latest")
            .expect("fixture carries grok-3-latest");
        // Nested under `pricing` on the wire, not flat on the entry.
        assert_eq!(grok.input_per_m_tok(), Some(3.0));
        assert_eq!(grok.output_per_m_tok(), Some(15.0));
    }

    #[test]
    fn a_bare_array_is_no_longer_what_we_decode() {
        // The defect: the client expected this shape and the server never sent
        // it. Asserting the envelope is required stops a silent revert.
        let bare = r#"[{"connector":"orq","model":"m"}]"#;
        assert!(serde_json::from_str::<CatalogResponse>(bare).is_err());
    }

    #[test]
    fn an_entry_missing_its_identity_fails_loudly() {
        // `connector`/`model` must not default: a row of empty strings
        // presented as a choice is worse than an error.
        let body = r#"{"models":[{"model":"m","pricing":{"inputPerMTok":1}}]}"#;
        assert!(serde_json::from_str::<CatalogResponse>(body).is_err());
    }

    #[test]
    fn an_unpriced_model_is_not_shown_as_free() {
        // `pricing: null` is common on the live route (every STT/TTS row).
        // Reading it as 0.00 would advertise a paid model as costless.
        let parsed: CatalogResponse = serde_json::from_str(LIVE_CATALOGUE).expect("decodes");
        let stt = parsed
            .models
            .iter()
            .find(|m| m.model == "universal-2")
            .expect("fixture carries an unpriced entry");
        assert_eq!(stt.input_per_m_tok(), None);
        assert_eq!(price_label(stt), "price unknown");
        assert!(
            sort_price(stt) > 1e300,
            "unpriced must sort last, not first"
        );
    }

    #[test]
    fn a_catalogued_free_model_is_labelled_free() {
        let parsed: CatalogResponse = serde_json::from_str(LIVE_CATALOGUE).expect("decodes");
        let free = parsed
            .models
            .iter()
            .find(|m| m.free == Some(true))
            .expect("fixture carries a free entry");
        assert_eq!(price_label(free), "free");
    }

    #[test]
    fn caps_each_provider_independently() {
        let mut entries = Vec::new();
        for i in 0..25 {
            entries.push(entry(
                "groq",
                &format!("g{i}"),
                Some(f64::from(i)),
                Some(0.0),
            ));
            entries.push(entry(
                "openrouter",
                &format!("o{i}"),
                Some(f64::from(i)),
                Some(0.0),
            ));
        }
        let kept = curate(entries);
        for provider in ["groq", "openrouter"] {
            let n = kept.iter().filter(|e| e.connector == provider).count();
            assert_eq!(n, MAX_PER_PROVIDER, "{provider} should be capped, got {n}");
        }
    }

    #[test]
    fn a_small_provider_is_not_crowded_out_by_a_large_one() {
        // The cap is PER PROVIDER precisely so one big lineup cannot fill the
        // whole list and hide a provider entirely.
        let mut entries: Vec<CatalogEntry> = (0..50)
            .map(|i| entry("huge", &format!("h{i}"), Some(1.0), Some(1.0)))
            .collect();
        entries.push(entry("tiny", "only-one", Some(2.0), Some(2.0)));

        let kept = curate(entries);
        assert_eq!(kept.iter().filter(|e| e.connector == "tiny").count(), 1);
    }

    #[test]
    fn cheapest_first_within_a_provider() {
        let kept = curate(vec![
            entry("groq", "dear", Some(50.0), Some(50.0)),
            entry("groq", "cheap", Some(1.0), Some(1.0)),
        ]);
        assert_eq!(kept[0].model, "cheap");
    }

    #[test]
    fn unpriced_models_sort_last_not_first() {
        // An unknown price is not a cheap price. Sorting it first would put the
        // model whose cost nobody knows at the top of a list people pick from.
        let kept = curate(vec![
            entry("groq", "unknown", None, None),
            entry("groq", "priced", Some(9.0), Some(9.0)),
        ]);
        assert_eq!(kept[0].model, "priced");
        assert!(sort_price(&kept[1]) > sort_price(&kept[0]));
    }

    #[test]
    fn price_label_distinguishes_free_from_unknown() {
        // Collapsing these would tell the operator a model costs nothing when
        // the truth is that nobody knows what it costs.
        let mut free = entry("groq", "f", None, None);
        free.free = Some(true);
        assert_eq!(price_label(&free), "free");
        assert_eq!(
            price_label(&entry("groq", "u", None, None)),
            "price unknown"
        );
    }
}
