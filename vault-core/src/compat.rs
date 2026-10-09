//! What carried over from the product's earlier name (EnvVault, command `envv`).
//!
//! UnENVerse reads `UNV_*` environment variables. The old `ENVV_*` ones keep
//! working, so a compose file, a CI job or a systemd unit written before the
//! rename does not silently lose its password or server URL: each legacy variable
//! is copied to its `UNV_` name unless that is already set, and the new name wins
//! when both are.
//!
//! Call [`adopt_legacy_env`] first thing in `main`, before any thread exists
//! (changing the environment of a process that already has threads is not sound
//! on every platform).

/// Copies each `ENVV_X` to `UNV_X` unless `UNV_X` is set. Returns the names that
/// were adopted, for a one-line notice.
pub fn adopt_legacy_env() -> Vec<String> {
    let legacy: Vec<(String, String, String)> = std::env::vars()
        .filter_map(|(k, v)| {
            let rest = k.strip_prefix("ENVV_")?;
            (!rest.is_empty()).then(|| (k.clone(), format!("UNV_{rest}"), v))
        })
        .collect();
    let mut adopted = Vec::new();
    for (old, new, value) in legacy {
        if std::env::var_os(&new).is_none() {
            std::env::set_var(&new, value);
            adopted.push(old);
        }
    }
    adopted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_legacy_variable_fills_in_its_new_name_and_never_overrides_it() {
        std::env::set_var("ENVV_COMPAT_TEST_ONLY_OLD", "old");
        std::env::set_var("ENVV_COMPAT_TEST_BOTH", "old");
        std::env::set_var("UNV_COMPAT_TEST_BOTH", "new");
        let adopted = adopt_legacy_env();
        assert_eq!(std::env::var("UNV_COMPAT_TEST_ONLY_OLD").unwrap(), "old");
        assert_eq!(std::env::var("UNV_COMPAT_TEST_BOTH").unwrap(), "new");
        assert!(adopted.contains(&"ENVV_COMPAT_TEST_ONLY_OLD".to_string()));
        assert!(!adopted.contains(&"ENVV_COMPAT_TEST_BOTH".to_string()));
        for k in [
            "ENVV_COMPAT_TEST_ONLY_OLD",
            "ENVV_COMPAT_TEST_BOTH",
            "UNV_COMPAT_TEST_ONLY_OLD",
            "UNV_COMPAT_TEST_BOTH",
        ] {
            std::env::remove_var(k);
        }
    }
}
