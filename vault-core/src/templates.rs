//! Secret templates: predefined field presets for common services (a GitHub PAT,
//! an AWS key, a Postgres DSN). One JSON file at the repo root,
//! `secret-templates.json`, compiled in here and imported by the app's
//! Templates pane, so `envv entry add --template ID` and the pane offer the same
//! presets (Phase 33.6).

use serde::Deserialize;
use serde_json::Value;

const RAW: &str = include_str!("../../secret-templates.json");

#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub category: String,
    #[serde(rename = "secretType")]
    pub secret_type: String,
    /// Entry fields the template pre-fills.
    pub defaults: serde_json::Map<String, Value>,
    #[serde(rename = "requiredFields", default)]
    pub required_fields: Vec<String>,
    #[serde(default)]
    pub hints: serde_json::Map<String, Value>,
}

#[derive(Deserialize)]
struct File {
    templates: Vec<Template>,
}

pub fn list() -> Vec<Template> {
    serde_json::from_str::<File>(RAW)
        .expect("secret-templates.json failed to parse: a build-time defect")
        .templates
}

pub fn find(id: &str) -> Option<Template> {
    list().into_iter().find(|t| t.id.eq_ignore_ascii_case(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_parses_and_has_a_known_type() {
        let all = list();
        assert!(all.len() >= 10);
        for t in &all {
            assert!(
                crate::secret_types::find(&t.secret_type).is_some(),
                "{}: unknown secretType {}",
                t.id,
                t.secret_type
            );
            assert!(!t.defaults.is_empty(), "{} pre-fills nothing", t.id);
        }
        let mut ids: Vec<_> = all.iter().map(|t| t.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), all.len(), "duplicate template id");
    }

    #[test]
    fn find_is_case_insensitive() {
        assert_eq!(find("GitHub-PAT").unwrap().id, "github-pat");
        assert!(find("nope").is_none());
    }
}
