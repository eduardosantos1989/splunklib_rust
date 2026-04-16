//! Splunk `.conf.spec` loader and validator.
//!
//! Splunk ships `.conf.spec` files that describe which stanzas and keys are valid
//! for each `.conf` file type (e.g. `inputs.conf.spec` describes `inputs.conf`).
//!
//! This module loads all available spec files, merges their definitions, and
//! provides validation helpers for parsed configuration documents.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::Path;

use walkdir::WalkDir;

/// The merged spec registry, keyed by config filename (e.g. `inputs.conf`).
#[derive(Debug, Default, Clone)]
pub struct ConfSpecRegistry {
    specs: HashMap<String, ConfSpec>,
    loaded_files: usize,
}

impl ConfSpecRegistry {
    /// Load all `.conf.spec` files under the Splunk installation root and merge them.
    ///
    /// This scans `splunk_root/etc/**` for files ending in `.conf.spec`.
    /// If no specs are found, an empty registry is returned.
    pub fn load_from_splunk_root(splunk_root: &Path) -> io::Result<Self> {
        let etc_dir = splunk_root.join("etc");
        Self::load_from_dir(&etc_dir)
    }

    /// Load all `.conf.spec` files under the provided directory and merge them.
    pub fn load_from_dir(root: &Path) -> io::Result<Self> {
        if !root.try_exists()? {
            return Ok(Self::default());
        }

        let mut registry = Self::default();
        let walker = WalkDir::new(root).follow_links(false);
        for entry in walker.into_iter().filter_map(Result::ok) {
            let ft = entry.file_type();
            if ft.is_symlink() || !ft.is_file() {
                continue;
            }
            let Some(name) = entry.path().file_name().and_then(OsStr::to_str) else {
                continue;
            };
            if !name.ends_with(".conf.spec") {
                continue;
            }
            registry.merge_spec_file(entry.path())?;
        }
        Ok(registry)
    }

    /// Number of `.conf.spec` files successfully loaded and merged.
    pub fn loaded_files(&self) -> usize {
        self.loaded_files
    }

    /// Number of distinct `.conf` config types present in the registry.
    pub fn conf_types(&self) -> usize {
        self.specs.len()
    }

    /// Validate a parsed config document against the merged spec for `conf_file_name`.
    ///
    /// If no spec exists for this config type, returns an empty vector.
    pub fn validate_doc(
        &self,
        conf_file_name: &str,
        doc: &[crate::splunk_config_processor::ConfigStanza],
    ) -> Vec<SpecViolation> {
        self.specs
            .get(conf_file_name)
            .map(|spec| spec.validate_doc(doc))
            .unwrap_or_default()
    }

    fn merge_spec_file(&mut self, path: &Path) -> io::Result<()> {
        let Some(file_name) = path.file_name().and_then(OsStr::to_str) else {
            return Ok(());
        };
        // `inputs.conf.spec` -> `inputs.conf`
        let Some(conf_file_name) = file_name.strip_suffix(".spec") else {
            return Ok(());
        };

        let content = fs::read_to_string(path)?;
        let parsed = parse_conf_spec_content(&content);

        let spec = self
            .specs
            .entry(conf_file_name.to_string())
            .or_default();

        spec.merge_parsed(parsed);
        self.loaded_files += 1;
        Ok(())
    }
}

/// A merged spec for a single `.conf` file type (e.g. `inputs.conf`).
#[derive(Debug, Default, Clone)]
struct ConfSpec {
    stanza_rules: HashMap<String, StanzaRule>,
}

impl ConfSpec {
    fn merge_parsed(&mut self, parsed: HashMap<String, HashSet<String>>) {
        for (raw_stanza_pattern, keys) in parsed {
            let rule = self
                .stanza_rules
                .entry(raw_stanza_pattern.clone())
                .or_insert_with(|| StanzaRule {
                    pattern: StanzaPattern::new(raw_stanza_pattern),
                    keys: HashSet::new(),
                });
            rule.keys.extend(keys);
        }
    }

    fn validate_doc(
        &self,
        doc: &[crate::splunk_config_processor::ConfigStanza],
    ) -> Vec<SpecViolation> {
        let mut violations = Vec::new();

        for stanza in doc {
            if stanza.entries.is_empty() {
                continue;
            }

            let mut matching_rules: Vec<&StanzaRule> = Vec::new();
            for rule in self.stanza_rules.values() {
                if rule.pattern.matches(&stanza.name) {
                    matching_rules.push(rule);
                }
            }

            if matching_rules.is_empty() {
                violations.push(SpecViolation::UnknownStanza {
                    stanza: stanza.name.clone(),
                });
                continue;
            }

            for entry in &stanza.entries {
                let mut allowed = false;
                for rule in &matching_rules {
                    if rule.keys.contains(&entry.key) {
                        allowed = true;
                        break;
                    }
                }

                if !allowed {
                    violations.push(SpecViolation::UnknownKey {
                        stanza: stanza.name.clone(),
                        key: entry.key.clone(),
                    });
                }
            }
        }

        violations
    }
}

#[derive(Debug, Clone)]
struct StanzaRule {
    pattern: StanzaPattern,
    keys: HashSet<String>,
}

/// Validation findings against `.conf.spec` rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecViolation {
    /// Stanza did not match any stanza rule in the spec.
    UnknownStanza { stanza: String },
    /// Key is not allowed for the stanza according to the spec.
    UnknownKey { stanza: String, key: String },
}

/// A simple wildcard stanza matcher supporting common `.conf.spec` patterns:
/// - `...` matches any substring
/// - `<...>` (placeholders) matches any substring
#[derive(Debug, Clone)]
struct StanzaPattern {
    raw: String,
    pieces: Vec<String>,
    starts_with_wildcard: bool,
    ends_with_wildcard: bool,
    has_wildcard: bool,
}

impl StanzaPattern {
    fn new(raw: String) -> Self {
        let mut pieces = Vec::new();
        let mut buf = String::new();
        let mut starts_with_wildcard = false;
        let mut ends_with_wildcard = false;
        let mut has_wildcard = false;

        let mut i = 0;
        let bytes = raw.as_bytes();
        while i < bytes.len() {
            // `...` wildcard
            if bytes[i..].starts_with(b"...") {
                if i == 0 {
                    starts_with_wildcard = true;
                }
                has_wildcard = true;
                ends_with_wildcard = true;
                if !buf.is_empty() {
                    pieces.push(std::mem::take(&mut buf));
                }
                i += 3;
                continue;
            }

            // `<...>` wildcard (placeholder)
            if bytes[i] == b'<'
                && let Some(end) = raw[i + 1..].find('>') {
                    if i == 0 {
                        starts_with_wildcard = true;
                    }
                    has_wildcard = true;
                    ends_with_wildcard = true;
                    if !buf.is_empty() {
                        pieces.push(std::mem::take(&mut buf));
                    }
                    // skip past '>'
                    i = i + 1 + end + 1;
                    continue;
                }

            ends_with_wildcard = false;
            buf.push(bytes[i] as char);
            i += 1;
        }

        if !buf.is_empty() {
            pieces.push(buf);
        }

        Self {
            raw,
            pieces,
            starts_with_wildcard,
            ends_with_wildcard,
            has_wildcard,
        }
    }

    fn matches(&self, stanza: &str) -> bool {
        if !self.has_wildcard {
            return stanza == self.raw;
        }

        if self.pieces.is_empty() {
            return true;
        }

        let mut search_start = 0usize;
        let mut search_end = stanza.len();
        let mut first_piece_index = 0usize;
        let mut last_piece_exclusive = self.pieces.len();

        if !self.starts_with_wildcard {
            let first = &self.pieces[0];
            if !stanza.starts_with(first) {
                return false;
            }
            search_start = first.len();
            first_piece_index = 1;
        }

        if !self.ends_with_wildcard {
            let last = &self.pieces[self.pieces.len() - 1];
            if !stanza.ends_with(last) {
                return false;
            }
            search_end = stanza.len().saturating_sub(last.len());
            last_piece_exclusive = last_piece_exclusive.saturating_sub(1);
        }

        if search_start > search_end {
            return false;
        }

        let mut pos = search_start;
        for piece in &self.pieces[first_piece_index..last_piece_exclusive] {
            if piece.is_empty() {
                continue;
            }
            let Some(found) = stanza[pos..search_end].find(piece) else {
                return false;
            };
            pos += found + piece.len();
            if pos > search_end {
                return false;
            }
        }

        true
    }
}

fn parse_conf_spec_content(content: &str) -> HashMap<String, HashSet<String>> {
    let mut stanzas: HashMap<String, HashSet<String>> = HashMap::new();
    let mut current_stanza: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
            let inner = line[1..line.len() - 1].trim();
            if inner.is_empty() {
                current_stanza = None;
                continue;
            }

            current_stanza = Some(inner.to_string());
            stanzas.entry(inner.to_string()).or_default();
            continue;
        }

        let Some(stanza) = current_stanza.as_ref() else {
            continue;
        };

        let mut candidate = line;
        if let Some(rest) = candidate.strip_prefix('*') {
            candidate = rest.trim_start();
        }
        if candidate.is_empty() || candidate.starts_with('#') || candidate.starts_with(';') {
            continue;
        }

        let Some(eq) = candidate.find('=') else {
            continue;
        };
        let key = candidate[..eq].trim();
        if key.is_empty() {
            continue;
        }

        stanzas
            .entry(stanza.clone())
            .or_default()
            .insert(key.to_string());
    }

    stanzas
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::splunk_config_processor::{ConfigEntry, ConfigStanza};

    #[test]
    fn stanza_pattern_matches_spec_placeholders_and_ellipsis() {
        let p = StanzaPattern::new("monitor://...".to_string());
        assert!(p.matches("monitor:///var/log/syslog"));
        assert!(p.matches("monitor://C:\\Windows\\Temp"));

        let p = StanzaPattern::new("script://<name>".to_string());
        assert!(p.matches("script://cpu"));
        assert!(p.matches("script://cpu.sh"));

        let p = StanzaPattern::new("<stanza>".to_string());
        assert!(p.matches("anything"));
        assert!(p.matches("default"));

        let p = StanzaPattern::new("exact".to_string());
        assert!(p.matches("exact"));
        assert!(!p.matches("exactly"));
    }

    #[test]
    fn parse_conf_spec_content_extracts_stanzas_and_keys() {
        let spec = r#"
# comment
[default]
foo = <string>
* bar = <bool>

[monitor://...]
disabled = <bool>
"#;

        let parsed = parse_conf_spec_content(spec);
        assert!(parsed.contains_key("default"));
        assert!(parsed.get("default").unwrap().contains("foo"));
        assert!(parsed.get("default").unwrap().contains("bar"));
        assert!(parsed.contains_key("monitor://..."));
        assert!(parsed.get("monitor://...").unwrap().contains("disabled"));
    }

    #[test]
    fn validate_doc_reports_unknown_stanza_and_keys() {
        let mut spec = ConfSpec::default();
        spec.merge_parsed(HashMap::from([
            ("default".to_string(), HashSet::from(["foo".to_string()])),
            ("monitor://...".to_string(), HashSet::from(["disabled".to_string()])),
        ]));

        let doc = vec![
            ConfigStanza {
                name: "default".to_string(),
                entries: vec![ConfigEntry {
                    key: "foo".to_string(),
                    value: "1".to_string(),
                }],
            },
            ConfigStanza {
                name: "default".to_string(),
                entries: vec![ConfigEntry {
                    key: "nope".to_string(),
                    value: "x".to_string(),
                }],
            },
            ConfigStanza {
                name: "unknown_stanza".to_string(),
                entries: vec![ConfigEntry {
                    key: "k".to_string(),
                    value: "v".to_string(),
                }],
            },
        ];

        let violations = spec.validate_doc(&doc);
        assert!(violations.contains(&SpecViolation::UnknownKey {
            stanza: "default".to_string(),
            key: "nope".to_string()
        }));
        assert!(violations.contains(&SpecViolation::UnknownStanza {
            stanza: "unknown_stanza".to_string()
        }));
    }
}
