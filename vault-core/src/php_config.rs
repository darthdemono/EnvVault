//! A reader for PHP array literals, enough for application config files such as
//! Nextcloud's `config/config.php` (Phase 38.1, ADR-0148).
//!
//! Nothing here executes anything. The file is *data written in PHP syntax*:
//! `$CONFIG = array ( 'key' => 'value', ... );`, with the short `[ ... ]` form
//! accepted too. What is understood is strings (single and double quoted),
//! integers, floats, `true`/`false`/`null`, nested arrays, and the three comment
//! styles. Anything else - a function call, a constant, a concatenation, a
//! variable - cannot be known without running PHP, so its value becomes `null`
//! and a warning naming the key and line is recorded instead of guessing.
//!
//! Every length the file can control is bounded: nesting depth and total node
//! count, so a hostile file cannot make this recurse or allocate without limit.

use serde_json::{Map, Value};

const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 100_000;

/// The parsed array and anything that could not be read.
#[derive(Debug, PartialEq)]
pub struct Parsed {
    pub value: Value,
    pub warnings: Vec<String>,
}

/// Parse the array assigned to the first `=` in `src`.
pub fn parse(src: &str) -> Result<Parsed, String> {
    parse_inner(src, None)
}

/// Parse the array assigned to `$name` (for Nextcloud, `CONFIG`). A file that is a
/// script rather than a config array - one that sets other variables first - is
/// read from the right assignment instead of the first `=`.
pub fn parse_var(src: &str, name: &str) -> Result<Parsed, String> {
    parse_inner(src, Some(name))
}

fn parse_inner(src: &str, var: Option<&str>) -> Result<Parsed, String> {
    let mut p = P {
        s: src.as_bytes(),
        i: 0,
        nodes: 0,
        warnings: Vec::new(),
    };
    p.skip_to_array(var)?;
    let value = p.array(0)?;
    Ok(Parsed {
        value,
        warnings: p.warnings,
    })
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    nodes: usize,
    warnings: Vec<String>,
}

impl P<'_> {
    fn line(&self) -> usize {
        self.line_at(self.i)
    }

    /// Computed on demand only: counting newlines is O(n), and doing it per value
    /// made a large file quadratic.
    fn line_at(&self, at: usize) -> usize {
        1 + self.s[..at.min(self.s.len())]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => self.i += 1,
                Some(b'#') => self.line_comment(),
                Some(b'/') if self.s.get(self.i + 1) == Some(&b'/') => self.line_comment(),
                Some(b'/') if self.s.get(self.i + 1) == Some(&b'*') => {
                    self.i += 2;
                    while self.i < self.s.len()
                        && !(self.s[self.i] == b'*' && self.s.get(self.i + 1) == Some(&b'/'))
                    {
                        self.i += 1;
                    }
                    self.i = (self.i + 2).min(self.s.len());
                }
                _ => return,
            }
        }
    }

    fn line_comment(&mut self) {
        while let Some(b) = self.peek() {
            if b == b'\n' {
                return;
            }
            self.i += 1;
        }
    }

    /// Move to the opening of the array that follows the wanted `=`: the first one,
    /// or the one assigned to `$var`.
    fn skip_to_array(&mut self, var: Option<&str>) -> Result<(), String> {
        while self.i < self.s.len() {
            self.ws();
            match self.peek() {
                Some(b'$') if var.is_some() => {
                    let want = var.unwrap_or("").as_bytes();
                    let name_end = self.i + 1 + want.len();
                    let named = self.s.get(self.i + 1..name_end) == Some(want)
                        && !self
                            .s
                            .get(name_end)
                            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
                    self.i += 1;
                    if named {
                        self.i = name_end;
                        self.ws();
                        if self.peek() == Some(b'=') && self.s.get(self.i + 1) != Some(&b'=') {
                            self.i += 1;
                            self.ws();
                            return Ok(());
                        }
                    }
                }
                Some(b'=') if var.is_none() => {
                    self.i += 1;
                    self.ws();
                    return Ok(());
                }
                Some(b'\'' | b'"') => {
                    self.string()?;
                }
                Some(_) => self.i += 1,
                None => break,
            }
        }
        Err("No `$CONFIG = array(...)` assignment found".into())
    }

    fn keyword_ci(&mut self, kw: &str) -> bool {
        let end = self.i + kw.len();
        if end <= self.s.len() && self.s[self.i..end].eq_ignore_ascii_case(kw.as_bytes()) {
            let after = self.s.get(end).copied();
            if !after.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_') {
                self.i = end;
                return true;
            }
        }
        false
    }

    fn array(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err(format!(
                "Arrays nest deeper than {MAX_DEPTH} (line {})",
                self.line()
            ));
        }
        self.ws();
        let close = if self.keyword_ci("array") {
            self.ws();
            if self.peek() != Some(b'(') {
                return Err(format!(
                    "Expected `(` after `array` on line {}",
                    self.line()
                ));
            }
            self.i += 1;
            b')'
        } else if self.peek() == Some(b'[') {
            self.i += 1;
            b']'
        } else {
            return Err(format!("Expected an array on line {}", self.line()));
        };

        let mut items: Vec<(Option<Value>, Value)> = Vec::new();
        loop {
            self.ws();
            match self.peek() {
                None => return Err("The array is never closed".into()),
                Some(b) if b == close => {
                    self.i += 1;
                    break;
                }
                Some(b',') => {
                    self.i += 1;
                    continue;
                }
                _ => {}
            }
            self.nodes += 1;
            if self.nodes > MAX_NODES {
                return Err("The file has too many entries to read".into());
            }
            let first = self.value(depth, close)?;
            self.ws();
            if self.s[self.i..].starts_with(b"=>") {
                self.i += 2;
                let v = self.value(depth, close)?;
                items.push((Some(first), v));
            } else {
                items.push((None, first));
            }
        }

        // A list when no key was written, or the keys are exactly 0..n.
        let sequential = items.iter().enumerate().all(|(n, (k, _))| match k {
            None => true,
            Some(Value::Number(x)) => x.as_u64() == Some(n as u64),
            _ => false,
        });
        if sequential {
            return Ok(Value::Array(items.into_iter().map(|(_, v)| v).collect()));
        }
        let mut m = Map::new();
        for (n, (k, v)) in items.into_iter().enumerate() {
            let key = match k {
                Some(Value::String(s)) => s,
                Some(Value::Number(x)) => x.to_string(),
                Some(_) | None => n.to_string(),
            };
            m.insert(key, v);
        }
        Ok(Value::Object(m))
    }

    fn value(&mut self, depth: usize, close: u8) -> Result<Value, String> {
        self.ws();
        let start = self.i;
        let v = match self.peek() {
            Some(b'\'' | b'"') => Value::String(self.string()?),
            Some(b'[') => self.array(depth + 1)?,
            Some(b) if b.is_ascii_digit() || b == b'-' || b == b'+' => self.number(),
            _ if self.keyword_ci("array") => {
                self.i -= "array".len();
                self.array(depth + 1)?
            }
            _ if self.keyword_ci("true") => Value::Bool(true),
            _ if self.keyword_ci("false") => Value::Bool(false),
            _ if self.keyword_ci("null") => Value::Null,
            _ => {
                self.skip_expression(close);
                self.warnings.push(format!(
                    "line {}: an expression that needs PHP to evaluate was left out",
                    self.line_at(start)
                ));
                return Ok(Value::Null);
            }
        };
        // A string followed by `.` is a concatenation: its value is not what was read.
        self.ws();
        if self.peek() == Some(b'.') {
            self.skip_expression(close);
            self.warnings.push(format!(
                "line {}: a concatenation was left out",
                self.line_at(start)
            ));
            return Ok(Value::Null);
        }
        Ok(v)
    }

    /// Skip to the next `,`, `=>` or closing bracket at this nesting level.
    fn skip_expression(&mut self, close: u8) {
        let mut depth = 0usize;
        while let Some(b) = self.peek() {
            match b {
                b'\'' | b'"' => {
                    let _ = self.string();
                    continue;
                }
                b'(' | b'[' => depth += 1,
                b')' | b']' if depth > 0 => depth -= 1,
                b',' if depth == 0 => return,
                b'=' if depth == 0 && self.s.get(self.i + 1) == Some(&b'>') => return,
                b if depth == 0 && b == close => return,
                _ => {}
            }
            self.i += 1;
        }
    }

    fn number(&mut self) -> Value {
        let start = self.i;
        if matches!(self.peek(), Some(b'-' | b'+')) {
            self.i += 1;
        }
        while matches!(self.peek(), Some(b) if b.is_ascii_digit() || b == b'.' || b == b'e' || b == b'E' || b == b'_')
        {
            self.i += 1;
        }
        let text: String = String::from_utf8_lossy(&self.s[start..self.i]).replace('_', "");
        if let Ok(n) = text.parse::<i64>() {
            return Value::from(n);
        }
        text.parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map_or(Value::Null, Value::Number)
    }

    fn string(&mut self) -> Result<String, String> {
        let quote = self.s[self.i];
        let start = self.i;
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(b) = self.peek() else {
                return Err(format!(
                    "The string opened on line {} is never closed",
                    self.line_at(start)
                ));
            };
            self.i += 1;
            if b == quote {
                break;
            }
            if b != b'\\' {
                out.push(b);
                continue;
            }
            let Some(e) = self.peek() else {
                return Err(format!(
                    "The string opened on line {} is never closed",
                    self.line_at(start)
                ));
            };
            self.i += 1;
            if quote == b'\'' {
                // Single quotes: only `\\` and `\'` are escapes; any other backslash stays.
                match e {
                    b'\\' | b'\'' => out.push(e),
                    _ => {
                        out.push(b'\\');
                        out.push(e);
                    }
                }
            } else {
                match e {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'v' => out.push(0x0b),
                    b'e' => out.push(0x1b),
                    b'f' => out.push(0x0c),
                    b'\\' | b'"' | b'$' => out.push(e),
                    b'0'..=b'7' => {
                        let mut n = u32::from(e - b'0');
                        for _ in 0..2 {
                            match self.peek() {
                                Some(d @ b'0'..=b'7') => {
                                    n = n * 8 + u32::from(d - b'0');
                                    self.i += 1;
                                }
                                _ => break,
                            }
                        }
                        out.push((n & 0xff) as u8);
                    }
                    b'x' => {
                        let mut n = 0u32;
                        let mut got = 0;
                        while got < 2 {
                            match self.peek().and_then(|d| (d as char).to_digit(16)) {
                                Some(d) => {
                                    n = n * 16 + d;
                                    self.i += 1;
                                    got += 1;
                                }
                                None => break,
                            }
                        }
                        if got == 0 {
                            out.extend_from_slice(b"\\x");
                        } else {
                            out.push(n as u8);
                        }
                    }
                    _ => {
                        out.push(b'\\');
                        out.push(e);
                    }
                }
            }
        }
        // `$name` inside double quotes would be interpolated by PHP; it is kept
        // literally, and the caller sees a `$` in the value.
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_the_shape_nextcloud_writes() {
        let src = r#"<?php
$CONFIG = array (
  'passwordsalt' => 'abc\'def',
  'secret' => "line\nbreak $x",
  'trusted_domains' =>
  array (
    0 => 'localhost',
    1 => 'cloud.example.com',
  ),
  'dbtype' => 'sqlite3',
  'version' => '29.0.4.1',
  'installed' => true,
  'maintenance' => false,
  'port' => 3306,
  'ratio' => 1.5,
  'objectstore' =>
  array (
    'class' => '\\OC\\Files\\ObjectStore\\S3',
    'arguments' =>
    array (
      'bucket' => 'b',
      'key' => 'AKIA',
      'secret' => 's3cret',
    ),
  ),
);
"#;
        let p = parse(src).unwrap();
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
        assert_eq!(p.value["passwordsalt"], "abc'def");
        assert_eq!(p.value["secret"], "line\nbreak $x");
        assert_eq!(
            p.value["trusted_domains"],
            json!(["localhost", "cloud.example.com"])
        );
        assert_eq!(p.value["installed"], true);
        assert_eq!(p.value["port"], 3306);
        assert_eq!(p.value["ratio"], 1.5);
        assert_eq!(
            p.value["objectstore"]["class"],
            "\\OC\\Files\\ObjectStore\\S3"
        );
        assert_eq!(p.value["objectstore"]["arguments"]["secret"], "s3cret");
    }

    #[test]
    fn short_arrays_comments_and_trailing_commas() {
        let p = parse("<?php\n// a\n$c = [ # b\n 'a' => 1, /* c */ 'b' => [1, 2,], ];").unwrap();
        assert_eq!(p.value, json!({"a": 1, "b": [1, 2]}));
    }

    #[test]
    fn expressions_that_need_php_are_left_out_and_reported() {
        let p = parse(
            "<?php $c = array('a' => getenv('X'), 'b' => 'x' . 'y', 'c' => OC::$ROOT . '/d', 'e' => 'ok');",
        )
        .unwrap();
        assert_eq!(p.value["e"], "ok");
        assert_eq!(p.value["a"], Value::Null);
        assert_eq!(p.value["b"], Value::Null);
        assert_eq!(p.value["c"], Value::Null);
        assert_eq!(p.warnings.len(), 3, "{:?}", p.warnings);
    }

    #[test]
    fn reads_the_named_variable_from_a_script_and_not_the_first_equals() {
        let src = "<?php\n$use = getenv('X');\nif ($use) {\n  $CONFIG = array('a' => getenv('A') ?: 'd', 'b' => 'ok');\n}";
        assert!(parse(src).is_err(), "the first `=` is not an array");
        let p = parse_var(src, "CONFIG").unwrap();
        assert_eq!(p.value["b"], "ok");
        assert!(!p.warnings.is_empty());
        assert!(parse_var("<?php $CONFIGX = [1];", "CONFIG").is_err());
        assert!(parse_var("<?php $CONFIG == [1];", "CONFIG").is_err());
    }

    #[test]
    fn refuses_what_it_cannot_bound_or_close() {
        assert!(parse("<?php $c = array('a' => 'unterminated);").is_err());
        assert!(parse("<?php nothing here").is_err());
        assert!(parse("<?php $c = array('a' => 1").is_err());
        let deep = format!("<?php $c = {}{}", "[".repeat(200), "]".repeat(200));
        assert!(parse(&deep).unwrap_err().contains("nest deeper"));
        let wide = format!("<?php $c = [{}];", "1,".repeat(150_000));
        assert!(parse(&wide).unwrap_err().contains("too many"));
    }
}
