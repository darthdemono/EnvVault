//! Import TOML config values as environment-style name/value pairs.

use std::collections::BTreeMap;

/// Parse TOML and flatten tables into uppercase underscore-separated names.
pub fn parse(source: &str) -> Result<Vec<(String, String)>, String> {
    let value: toml::Value = toml::from_str(source).map_err(|error| error.to_string())?;
    let mut values = BTreeMap::new();
    flatten("", &value, &mut values)?;
    Ok(values.into_iter().collect())
}

fn flatten(
    prefix: &str,
    value: &toml::Value,
    output: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    if let Some(table) = value.as_table() {
        for (key, value) in table {
            let key = key
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() {
                        ch.to_ascii_uppercase()
                    } else {
                        '_'
                    }
                })
                .collect::<String>();
            let name = if prefix.is_empty() {
                key
            } else {
                format!("{prefix}_{key}")
            };
            flatten(&name, value, output)?;
        }
    } else {
        if prefix.is_empty() {
            return Err("TOML root must be a table".into());
        }
        if output.insert(prefix.to_owned(), scalar(value)).is_some() {
            return Err(format!(
                "TOML keys collide after environment-name conversion: {prefix}"
            ));
        }
    }
    Ok(())
}

fn scalar(value: &toml::Value) -> String {
    match value {
        toml::Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn flattens_tables_and_preserves_scalar_values() {
        assert_eq!(
            parse("token = 'abc'\n[bot]\nchannel_id = 123456789012345678\ncolour = 0x800000")
                .unwrap(),
            vec![
                ("BOT_CHANNEL_ID".into(), "123456789012345678".into()),
                ("BOT_COLOUR".into(), "8388608".into()),
                ("TOKEN".into(), "abc".into()),
            ]
        );
    }

    #[test]
    fn refuses_invalid_toml_and_colliding_names() {
        assert!(parse("token = [").is_err());
        assert!(parse("a-b = 1\na_b = 2").is_err());
    }
}
