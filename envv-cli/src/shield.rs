//! Exact-value redaction for child output and filesystem exposure scans.
//!
//! The matcher is built from values the vault actually holds, not token-shaped
//! regexes. A finding is therefore an exact exposure rather than a guess.

use crate::access::Access;
use crate::data;
use crate::error::{CliError, CliResult};
use crate::out;
use aho_corasick::AhoCorasick;
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

const READ_SIZE: usize = 16 * 1024;

#[derive(Clone)]
struct Pattern {
    fingerprint: String,
}

#[derive(Clone)]
struct Match {
    start: usize,
    end: usize,
    pattern: usize,
}

/// A single exact-value matcher for both outward-redaction commands.
pub struct Engine {
    matcher: Option<AhoCorasick>,
    patterns: Vec<Pattern>,
    suffix_window: usize,
}

impl Engine {
    /// Build from every value that [`out::redact_entry`] would keep private.
    pub fn from_vault(vault: &Value) -> Self {
        Self::from_values(data::entries(vault).iter().flat_map(out::secret_values))
    }

    fn from_values(values: impl IntoIterator<Item = String>) -> Self {
        let values: Vec<String> = values
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let suffix_window = values
            .iter()
            .map(String::len)
            .max()
            .unwrap_or(0)
            .saturating_sub(1);
        let matcher = (!values.is_empty()).then(|| {
            AhoCorasick::new(&values).expect("valid vault strings build an Aho-Corasick matcher")
        });
        let patterns = values
            .iter()
            .map(|value| Pattern {
                fingerprint: out::fingerprint(value),
            })
            .collect();
        Self {
            matcher,
            patterns,
            suffix_window,
        }
    }

    fn matches(&self, text: &[u8]) -> Vec<Match> {
        let Some(matcher) = &self.matcher else {
            return Vec::new();
        };
        matcher
            .find_overlapping_iter(text)
            .map(|found| Match {
                start: found.start(),
                end: found.end(),
                pattern: found.pattern().as_usize(),
            })
            .collect()
    }

    /// Leftmost-longest, non-overlapping hits for output replacement.
    fn redaction_matches(&self, text: &[u8]) -> Vec<Match> {
        let mut matches = self.matches(text);
        matches.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));
        let mut selected = Vec::new();
        let mut consumed = 0;
        for found in matches {
            if found.start >= consumed {
                consumed = found.end;
                selected.push(found);
            }
        }
        selected
    }

    fn fingerprint(&self, pattern: usize) -> &str {
        &self.patterns[pattern].fingerprint
    }

    /// Scan one path without following directory links.
    pub fn scan_path(&self, path: &Path) -> CliResult<Vec<Exposure>> {
        if path.is_file() {
            return self.scan_file(path);
        }
        if !path.is_dir() {
            return Err(CliError::not_found(format!(
                "No file or directory at {}",
                path.display()
            )));
        }
        let mut findings = Vec::new();
        for entry in walkdir::WalkDir::new(path).follow_links(false) {
            let entry = entry.map_err(|error| CliError::from(error.to_string()))?;
            if entry.file_type().is_file() {
                findings.extend(self.scan_file(entry.path())?);
            }
        }
        findings.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then(a.line.cmp(&b.line))
                .then(a.fingerprint.cmp(&b.fingerprint))
        });
        Ok(findings)
    }

    fn scan_file(&self, path: &Path) -> CliResult<Vec<Exposure>> {
        let file = std::fs::File::open(path)
            .map_err(|error| CliError::from(format!("Cannot read {}: {error}", path.display())))?;
        let mut scanner = FileScanner::new(self);
        scanner
            .read(file)
            .map_err(|error| CliError::from(format!("Cannot read {}: {error}", path.display())))?;
        Ok(scanner
            .findings
            .into_iter()
            .map(|finding| Exposure {
                path: path.to_path_buf(),
                line: finding.line,
                fingerprint: finding.fingerprint,
            })
            .collect())
    }
}

/// A location report contains fingerprints and paths, never a plaintext value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    pub path: PathBuf,
    pub line: usize,
    pub fingerprint: String,
}

/// Text for the file-only exposure report.
pub fn exposure_report(findings: &[Exposure]) -> String {
    if findings.is_empty() {
        return "No exposed vault values found.\n".to_string();
    }
    let mut report = String::new();
    for finding in findings {
        report.push_str(&format!(
            "{}:{}: {}\n",
            finding.path.display(),
            finding.line,
            finding.fingerprint
        ));
    }
    report
}

/// Retains the only bytes that could begin a secret in the next read.
struct StreamRedactor<'a> {
    engine: &'a Engine,
    pending: Vec<u8>,
}

impl<'a> StreamRedactor<'a> {
    fn new(engine: &'a Engine) -> Self {
        Self {
            engine,
            pending: Vec::new(),
        }
    }

    fn push(&mut self, bytes: &[u8], final_chunk: bool) -> Vec<u8> {
        self.pending.extend_from_slice(bytes);
        let cutoff = if final_chunk {
            self.pending.len()
        } else {
            self.pending.len().saturating_sub(self.engine.suffix_window)
        };
        let mut output = Vec::new();
        let mut consumed = 0;
        for found in self.engine.redaction_matches(&self.pending) {
            if found.start >= cutoff {
                break;
            }
            output.extend_from_slice(&self.pending[consumed..found.start]);
            output.extend_from_slice(self.engine.fingerprint(found.pattern).as_bytes());
            consumed = found.end;
        }
        if consumed < cutoff {
            output.extend_from_slice(&self.pending[consumed..cutoff]);
        }
        self.pending.drain(..cutoff.max(consumed));
        output
    }
}

/// Invalid UTF-8 or NUL makes a stream binary. Incomplete UTF-8 at a read
/// boundary is retained so ordinary Unicode text is not mistaken for binary.
#[derive(Default)]
struct TextProbe {
    pending: Vec<u8>,
}

impl TextProbe {
    fn push(&mut self, bytes: &[u8]) -> bool {
        if bytes.contains(&0) {
            return false;
        }
        self.pending.extend_from_slice(bytes);
        match std::str::from_utf8(&self.pending) {
            Ok(_) => {
                self.pending.clear();
                true
            }
            Err(error) if error.error_len().is_none() => {
                self.pending.drain(..error.valid_up_to());
                true
            }
            Err(_) => false,
        }
    }

    fn finish(&self) -> bool {
        self.pending.is_empty()
    }
}

fn shield_stream(
    mut reader: impl Read,
    mut writer: impl Write,
    engine: &Engine,
    stream_name: &str,
) -> CliResult {
    let mut redactor = StreamRedactor::new(engine);
    let mut probe = TextProbe::default();
    let mut buffer = [0_u8; READ_SIZE];
    let mut binary = false;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| CliError::from(error.to_string()))?;
        if count == 0 {
            break;
        }
        if !binary && probe.push(&buffer[..count]) {
            writer
                .write_all(&redactor.push(&buffer[..count], false))
                .map_err(|error| CliError::from(error.to_string()))?;
        } else {
            // Keep draining so a child cannot block on a full pipe, but do not
            // write a stream that would be partly redacted and partly binary.
            binary = true;
        }
    }
    if binary || !probe.finish() {
        return Err(CliError::invalid(format!(
            "envv shield refused binary {stream_name}; it cannot safely redact partial binary output"
        )));
    }
    writer
        .write_all(&redactor.push(&[], true))
        .and_then(|_| writer.flush())
        .map_err(|error| CliError::from(error.to_string()))
}

/// Run a child and preserve its exit code after shielding both text streams.
pub fn run(access: &Access, argv: &[String]) -> CliResult<i32> {
    if out::is_json() {
        return Err(CliError::invalid(
            "envv shield forwards child output and cannot be combined with --json",
        ));
    }
    let Some((program, args)) = argv.split_first() else {
        return Err(CliError::invalid(
            "No command given — use `envv shield -- <command>`",
        ));
    };
    let engine = Arc::new(Engine::from_vault(&access.load_vault()?));
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CliError::not_found(format!("Cannot run '{program}': {error}")))?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let stdout_engine = Arc::clone(&engine);
    let stdout_task = std::thread::spawn(move || {
        shield_stream(stdout, std::io::stdout().lock(), &stdout_engine, "stdout")
    });
    let stderr_task = std::thread::spawn(move || {
        shield_stream(stderr, std::io::stderr().lock(), &engine, "stderr")
    });
    let status = child
        .wait()
        .map_err(|error| CliError::from(error.to_string()))?;
    let stdout_result = stdout_task
        .join()
        .map_err(|_| CliError::from("envv shield stdout reader panicked"))?;
    let stderr_result = stderr_task
        .join()
        .map_err(|_| CliError::from("envv shield stderr reader panicked"))?;
    stdout_result?;
    stderr_result?;
    Ok(status.code().unwrap_or(1))
}

struct FileFinding {
    line: usize,
    fingerprint: String,
}

struct FileScanner<'a> {
    engine: &'a Engine,
    pending: Vec<u8>,
    first_line: usize,
    findings: Vec<FileFinding>,
}

impl<'a> FileScanner<'a> {
    fn new(engine: &'a Engine) -> Self {
        Self {
            engine,
            pending: Vec::new(),
            first_line: 1,
            findings: Vec::new(),
        }
    }

    fn read(&mut self, mut reader: impl Read) -> std::io::Result<()> {
        let mut buffer = [0_u8; READ_SIZE];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            self.pending.extend_from_slice(&buffer[..count]);
            self.report_through(self.pending.len().saturating_sub(self.engine.suffix_window));
        }
        self.report_through(self.pending.len());
        Ok(())
    }

    fn report_through(&mut self, cutoff: usize) {
        for found in self.engine.matches(&self.pending) {
            if found.start < cutoff {
                let line = self.first_line
                    + self.pending[..found.start]
                        .iter()
                        .filter(|byte| **byte == b'\n')
                        .count();
                self.findings.push(FileFinding {
                    line,
                    fingerprint: self.engine.fingerprint(found.pattern).to_string(),
                });
            }
        }
        self.first_line += self.pending[..cutoff]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count();
        self.pending.drain(..cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    #[test]
    fn split_secret_never_emits_its_prefix() {
        let engine = Engine::from_values(["top-secret".to_string()]);
        let mut redactor = StreamRedactor::new(&engine);
        let first = redactor.push(b"before top-", false);
        assert!(!String::from_utf8_lossy(&first).contains("top-"));
        let mut output = first;
        output.extend(redactor.push(b"secret after", true));
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("before {} after", out::fingerprint("top-secret"))
        );
    }

    #[test]
    fn longest_overlap_is_replaced_once() {
        let engine = Engine::from_values(["key".to_string(), "key-long".to_string()]);
        let mut redactor = StreamRedactor::new(&engine);
        assert_eq!(
            String::from_utf8(redactor.push(b"key-long", true)).unwrap(),
            out::fingerprint("key-long")
        );
    }

    #[test]
    fn exposure_scan_reports_line_and_fingerprint_without_the_value() {
        let engine = Engine::from_values(["vault-value".to_string()]);
        let mut scanner = FileScanner::new(&engine);
        scanner
            .read(Cursor::new(b"safe\nvault-value\nsafe vault-value"))
            .unwrap();
        let findings: Vec<Exposure> = scanner
            .findings
            .into_iter()
            .map(|finding| Exposure {
                path: PathBuf::from("fixture.env"),
                line: finding.line,
                fingerprint: finding.fingerprint,
            })
            .collect();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[1].line, 3);
        let report = exposure_report(&findings);
        assert!(!report.contains("vault-value"));
        assert!(report.contains(&out::fingerprint("vault-value")));
    }

    #[test]
    fn exposure_scan_finds_a_value_split_across_file_reads() {
        let engine = Engine::from_values(["cross-boundary".to_string()]);
        let mut bytes = vec![b'x'; READ_SIZE - 5];
        bytes.extend_from_slice(b"cross-boundary");
        let mut scanner = FileScanner::new(&engine);
        scanner.read(Cursor::new(bytes)).unwrap();
        assert_eq!(scanner.findings.len(), 1);
        assert_eq!(scanner.findings[0].line, 1);
    }

    #[test]
    fn public_values_are_not_patterns_but_private_history_is() {
        let vault = json!({ "api_keys": [{
            "provider": "Example",
            "api_key": "public-client-id",
            "primary_public": true,
            "api_secret": "private-secret",
            "extra_vars": [
                { "key": "REGION", "value": "public-region", "public": true },
                { "key": "TOKEN", "value": "private-var" }
            ],
            "version_history": [{ "value": "old-secret" }],
            "future_private_field": "private-future"
        }]});
        let engine = Engine::from_vault(&vault);
        assert!(engine.matches(b"public-client-id").is_empty());
        assert!(engine.matches(b"public-region").is_empty());
        for private in [
            "private-secret",
            "private-var",
            "old-secret",
            "private-future",
        ] {
            assert!(!engine.matches(private.as_bytes()).is_empty(), "{private}");
        }
    }

    #[test]
    fn binary_stream_is_refused_without_writing_binary_bytes() {
        let engine = Engine::from_values(["secret".to_string()]);
        let mut output = Vec::new();
        let error = shield_stream(
            Cursor::new(b"secret\0binary"),
            &mut output,
            &engine,
            "stdout",
        )
        .unwrap_err();
        assert_eq!(error.code, crate::error::Code::Invalid);
        assert!(output.is_empty());
    }
}
