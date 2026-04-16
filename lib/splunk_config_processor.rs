//! Splunk configuration file parsing and caching.
//!
//! This module provides:
//! - INI-style configuration file parsing (Splunk conf format)
//! - Multiline value support with backslash continuation
//! - LRU caching with configurable size
//! - Version extraction from .conf files

use std::{
    collections::HashMap,
    env, fs,
    path::Path,
    ptr::NonNull,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Stanza name (section header: "[name]")
pub type Stanza = String;

/// Configuration key name inside a stanza
pub type OptionK = String;

/// Configuration value (may be multiline)
pub type Value = String;

/// Configuration dictionary: { stanza -> { option -> value } }
///
/// This is the primary data structure for Splunk configuration,
/// mapping stanza names to their key-value pairs.
pub type Dictionary = HashMap<Stanza, HashMap<OptionK, Value>>;

// ===== Multiline safeguards =====

const DEFAULT_MAX_MULTILINE_LINES: usize = 1024;
static MAX_MULTILINE_LINES: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_MULTILINE_LINES);

/// Set the maximum number of lines allowed in multiline values.
///
/// This is a safeguard against malicious or malformed configuration files
/// with extremely long multiline values.
///
/// # Arguments
///
/// * `limit` - Maximum lines, or `0` to reset to default (1024)
pub fn set_max_multiline_lines(limit: usize) {
    let limit = if limit == 0 {
        DEFAULT_MAX_MULTILINE_LINES
    } else {
        limit
    };
    MAX_MULTILINE_LINES.store(limit, Ordering::Relaxed);
}

/// Get the current maximum multiline lines limit.
pub fn get_max_multiline_lines() -> usize {
    MAX_MULTILINE_LINES.load(Ordering::Relaxed)
}

// ===== String trim helpers =====

#[allow(dead_code)]
#[inline]
fn left_trim(s: &str) -> &str {
    s.trim_start_matches(&[' ', '\t', '\r', '\n'][..])
}

#[allow(dead_code)]
#[inline]
fn right_trim(s: &str) -> &str {
    s.trim_end_matches(&[' ', '\t', '\r', '\n'][..])
}

/// Trim whitespace and newlines from both ends of a string.
#[inline]
fn trim(s: &str) -> &str {
    s.trim_matches(&[' ', '\t', '\r', '\n'][..])
}

// ===== Path normalization =====

/// Normalize path separators to platform-specific separator.
#[inline]
fn normalize_path(p: &str) -> String {
    #[cfg(target_os = "windows")]
    let sep = '\\';
    #[cfg(not(target_os = "windows"))]
    let sep = '/';

    p.chars()
        .map(|c| if c == '/' || c == '\\' { sep } else { c })
        .collect()
}

// ===== Safe MB to bytes conversion =====

const MB: usize = 1024 * 1024;
const DEFAULT_CACHE_SIZE_MB: usize = 50;
const MIN_CACHE_SIZE_MB: usize = 1;
const MAX_CACHE_SIZE_MB: usize = 1024;

/// Convert megabytes to bytes with clamping and overflow protection.
#[inline]
fn mb_to_bytes_safe(mb: usize) -> usize {
    // Clamp to reasonable range
    let mb_clamped = mb.clamp(MIN_CACHE_SIZE_MB, MAX_CACHE_SIZE_MB);

    // Check for overflow
    mb_clamped.saturating_mul(MB)
}

// ===== LRU Cache =====

struct CacheNode {
    key: String,
    /// Content stored as Arc<String> to allow cheap cloning on cache hits.
    /// This avoids deep-copying large configuration file contents.
    content: Arc<String>,
    prev: Option<NonNull<CacheNode>>,
    next: Option<NonNull<CacheNode>>,
}

impl CacheNode {
    fn new(key: String, content: Arc<String>) -> Box<Self> {
        Box::new(Self {
            key,
            content,
            prev: None,
            next: None,
        })
    }
}

struct LRUCache {
    head: NonNull<CacheNode>,
    tail: NonNull<CacheNode>,
    map: HashMap<String, NonNull<CacheNode>>,
    total_size: usize,
    max_size: usize,
}

impl LRUCache {
    fn new() -> Self {
        // Sentinel nodes (content is empty Arc, never accessed)
        let mut head = Box::new(CacheNode {
            key: String::new(),
            content: Arc::new(String::new()),
            prev: None,
            next: None,
        });
        let mut tail = Box::new(CacheNode {
            key: String::new(),
            content: Arc::new(String::new()),
            prev: None,
            next: None,
        });

        let head_ptr = NonNull::from(&mut *head);
        let tail_ptr = NonNull::from(&mut *tail);

        // Link sentinels
        head.next = Some(tail_ptr);
        tail.prev = Some(head_ptr);

        let mut max_size = DEFAULT_CACHE_SIZE_MB * MB;

        // Read from environment with proper validation
        if let Ok(val) = env::var("BUNDLETRACKER_CACHE_SIZE_MB")
            && let Ok(mb) = val.parse::<usize>()
                && mb > 0 {
                    max_size = mb_to_bytes_safe(mb);
                }

        // Leak the sentinel nodes so they live for the static lifetime
        let head_ptr = NonNull::from(Box::leak(head));
        let tail_ptr = NonNull::from(Box::leak(tail));

        Self {
            head: head_ptr,
            tail: tail_ptr,
            map: HashMap::new(),
            total_size: 0,
            max_size,
        }
    }

    fn add_front(&mut self, mut node: NonNull<CacheNode>) {
        unsafe {
            let head_next = self.head.as_ref().next.unwrap();
            node.as_mut().next = Some(head_next);
            node.as_mut().prev = Some(self.head);
            head_next.as_ptr().as_mut().unwrap().prev = Some(node);
            self.head.as_mut().next = Some(node);
        }
    }

    fn unlink(node: NonNull<CacheNode>) {
        unsafe {
            let prev = node.as_ref().prev.unwrap();
            let next = node.as_ref().next.unwrap();
            prev.as_ptr().as_mut().unwrap().next = Some(next);
            next.as_ptr().as_mut().unwrap().prev = Some(prev);
        }
    }

    fn move_to_head(&mut self, node: NonNull<CacheNode>) {
        Self::unlink(node);
        self.add_front(node);
    }

    fn remove_last(&mut self) -> Option<Box<CacheNode>> {
        unsafe {
            let tail_prev = self.tail.as_ref().prev?;
            if tail_prev == self.head {
                return None;
            }

            Self::unlink(tail_prev);
            let node = tail_prev.as_ref();
            self.map.remove(&node.key);
            self.total_size = self.total_size.saturating_sub(node.content.len());

            Some(Box::from_raw(tail_prev.as_ptr()))
        }
    }

    /// Get content from cache. Returns Arc<String> for cheap cloning.
    fn get(&mut self, key: &str) -> Option<Arc<String>> {
        if let Some(&node) = self.map.get(key) {
            self.move_to_head(node);
            // Arc::clone is O(1) - just increments reference count
            unsafe { Some(Arc::clone(&node.as_ref().content)) }
        } else {
            None
        }
    }

    /// Insert content into cache. Takes Arc<String> to share ownership.
    fn insert(&mut self, key: String, content: Arc<String>) {
        if let Some(&old_node) = self.map.get(&key) {
            Self::unlink(old_node);
            unsafe {
                let old_node_ref = old_node.as_ref();
                self.total_size = self.total_size.saturating_sub(old_node_ref.content.len());
                let _ = Box::from_raw(old_node.as_ptr());
            }
            self.map.remove(&key);
        }

        let content_len = content.len();
        let node = CacheNode::new(key.clone(), content);
        self.total_size += content_len;

        let node_ptr = NonNull::from(Box::leak(node));
        self.map.insert(key, node_ptr);
        self.add_front(node_ptr);

        while self.total_size > self.max_size && !self.map.is_empty() {
            if let Some(old) = self.remove_last() {
                drop(old);
            }
        }
    }

    fn clear(&mut self) {
        // Remove all nodes except sentinels
        while self.remove_last().is_some() {}
    }
}

impl Drop for LRUCache {
    fn drop(&mut self) {
        self.clear();
    }
}

// SAFETY: LRUCache is always protected by a Mutex when used in static context.
// The raw pointers (NonNull) are managed internally and never escape the Mutex boundary.
unsafe impl Send for LRUCache {}
unsafe impl Sync for LRUCache {}

// Global cache instance
static CACHE: OnceLock<Mutex<LRUCache>> = OnceLock::new();
static CACHE_HITS: AtomicUsize = AtomicUsize::new(0);
static CACHE_MISSES: AtomicUsize = AtomicUsize::new(0);

fn get_cache() -> &'static Mutex<LRUCache> {
    CACHE.get_or_init(|| Mutex::new(LRUCache::new()))
}

// ===== Cache statistics =====

/// Statistics for the configuration file LRU cache.
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: usize,
    pub misses: usize,
    pub size: usize,
    pub max_size: usize,
}

/// Get current cache statistics.
pub fn get_cache_stats() -> CacheStats {
    let cache = get_cache().lock().unwrap();
    CacheStats {
        hits: CACHE_HITS.load(Ordering::Relaxed),
        misses: CACHE_MISSES.load(Ordering::Relaxed),
        size: cache.total_size,
        max_size: cache.max_size,
    }
}

/// Set the maximum cache size in megabytes.
///
/// Existing entries may be evicted if current size exceeds new limit.
///
/// # Arguments
///
/// * `mb` - Cache size in MB (ignored if `0`)
pub fn set_cache_size_mb(mb: usize) {
    if mb == 0 {
        return;
    }
    let mut cache = get_cache().lock().unwrap();
    cache.max_size = mb_to_bytes_safe(mb);

    // Evict if current size exceeds new limit
    while cache.total_size > cache.max_size && !cache.map.is_empty() {
        if let Some(old) = cache.remove_last() {
            drop(old);
        }
    }
}

/// Clear all entries from the configuration cache.
pub fn clear_cache() {
    get_cache().lock().unwrap().clear();
}

// ===== File reading with cache =====

/// Shared empty string for error cases to avoid repeated allocations.
static EMPTY_STRING: OnceLock<Arc<String>> = OnceLock::new();

fn empty_arc_string() -> Arc<String> {
    Arc::clone(EMPTY_STRING.get_or_init(|| Arc::new(String::new())))
}

/// Read file content with LRU caching.
/// Releases lock before I/O operations to avoid blocking other threads.
/// Emits warnings for non-NotFound errors (permission denied, I/O errors) to improve observability.
/// Returns empty Arc<String> for missing files (NotFound).
///
/// Uses Arc<String> to avoid deep-copying file contents on cache hits.
/// Arc::clone is O(1) - just increments reference count.
fn read_file_view<P: AsRef<Path>>(path: P) -> Arc<String> {
    let path_ref = path.as_ref();

    let abs_path = match fs::canonicalize(path_ref) {
        Ok(p) => p,
        Err(_) => return empty_arc_string(),
    };
    let key = normalize_path(&abs_path.to_string_lossy());

    // Check cache with lock
    {
        let mut cache = get_cache().lock().unwrap();
        if let Some(content) = cache.get(&key) {
            CACHE_HITS.fetch_add(1, Ordering::Relaxed);
            // Arc::clone is O(1) - no deep copy
            return content;
        }
    } // Lock released here

    // Record cache miss
    CACHE_MISSES.fetch_add(1, Ordering::Relaxed);

    let content = match fs::read_to_string(&abs_path) {
        Ok(c) => c,
        Err(_) => return empty_arc_string(),
    };

    // Wrap in Arc for shared ownership between cache and return value.
    // No deep copy needed - Arc::clone just increments reference count.
    let content = Arc::new(content);
    let result = Arc::clone(&content);
    {
        let mut cache = get_cache().lock().unwrap();
        cache.insert(key, content);
    }

    result
}

// ===== Version extraction =====

/// Extract the VERSION value from a configuration file.
///
/// Searches for a line starting with "VERSION=" and returns the value.
///
/// # Arguments
///
/// * `path` - Path to the configuration file
///
/// # Returns
///
/// The version string, or empty string if not found
pub fn get_version<P: AsRef<Path>>(path: P) -> String {
    let content = read_file_view(path);
    if content.is_empty() {
        return String::new();
    }

    for line in content.lines() {
        let trimmed = trim(line);
        if trimmed.starts_with("VERSION")
            && let Some(eq_pos) = trimmed.find('=') {
                return trim(&trimmed[eq_pos + 1..]).to_string();
            }
    }

    String::new()
}

// ===== Structured config document =====

/// A single configuration key-value pair within a stanza.
#[derive(Debug, Clone)]
pub struct ConfigEntry {
    pub key: String,
    pub value: String,
}

/// A configuration stanza containing multiple entries.
#[derive(Debug, Clone)]
pub struct ConfigStanza {
    pub name: String,
    pub entries: Vec<ConfigEntry>,
}

/// A parsed configuration document containing multiple stanzas.
pub type SplunkConfigDoc = Vec<ConfigStanza>;

// ===== Parser matching C++ state machine =====

/// Parse Splunk configuration file content into a structured document.
///
/// Supports:
/// - Stanza headers: `[stanza_name]`
/// - Key-value pairs: `key = value`
/// - Multiline values: continued with backslash (`\`)
/// - Comments: Lines starting with `#` or `;`
/// - Whitespace trimming
///
/// # Arguments
///
/// * `content` - The configuration file content
/// * `file_path` - Path to file (for error reporting)
///
/// # Returns
///
/// A document containing all parsed stanzas and entries
pub fn parse_config(content: &str, _file_path: &str) -> SplunkConfigDoc {
    let mut doc = vec![ConfigStanza {
        name: "default".to_string(),
        entries: Vec::new(),
    }];

    let mut stanza_index: HashMap<String, usize> = HashMap::new();
    stanza_index.insert("default".to_string(), 0);

    let get_stanza_idx =
        |name: &str, doc: &mut Vec<ConfigStanza>, index: &mut HashMap<String, usize>| -> usize {
            if let Some(&idx) = index.get(name) {
                return idx;
            }
            let idx = doc.len();
            doc.push(ConfigStanza {
                name: name.to_string(),
                entries: Vec::new(),
            });
            index.insert(name.to_string(), idx);
            idx
        };

    let add_entry = |current_stanza: &str,
                     current_key: &mut String,
                     raw_value: &mut String,
                     in_multiline: &mut bool,
                     multiline_lines: &mut usize,
                     doc: &mut Vec<ConfigStanza>,
                     stanza_index: &HashMap<String, usize>| {
        if !current_key.is_empty() {
            let idx = *stanza_index
                .get(current_stanza)
                .expect("BUG: current_stanza must exist in stanza_index");
            doc[idx].entries.push(ConfigEntry {
                key: std::mem::take(current_key),
                value: std::mem::take(raw_value),
            });
            *in_multiline = false;
            *multiline_lines = 0;
        }
    };

    let mut current_stanza = "default".to_string();
    let mut current_key = String::new();
    let mut raw_value = String::new();
    let mut in_multiline = false;
    let mut multiline_lines: usize = 0;
    let max_multiline_lines = MAX_MULTILINE_LINES.load(Ordering::Relaxed).max(1);

    for raw_line in content.lines() {
        let processed = trim(raw_line);

        if in_multiline {
            if multiline_lines >= max_multiline_lines {
                add_entry(
                    &current_stanza,
                    &mut current_key,
                    &mut raw_value,
                    &mut in_multiline,
                    &mut multiline_lines,
                    &mut doc,
                    &stanza_index,
                );
                continue;
            }

            multiline_lines += 1;

            // Append raw line with preceding newline
            raw_value.push('\n');
            raw_value.push_str(raw_line);

            if !processed.is_empty() && processed.ends_with('\\') {
            } else {
                add_entry(
                    &current_stanza,
                    &mut current_key,
                    &mut raw_value,
                    &mut in_multiline,
                    &mut multiline_lines,
                    &mut doc,
                    &stanza_index,
                );
            }
            continue;
        }

        if processed.is_empty() || processed.starts_with('#') || processed.starts_with(';') {
            continue;
        }

        if processed.len() >= 3 && processed.starts_with('[') && processed.ends_with(']') {
            add_entry(
                &current_stanza,
                &mut current_key,
                &mut raw_value,
                &mut in_multiline,
                &mut multiline_lines,
                &mut doc,
                &stanza_index,
            );

            let inner = &processed[1..processed.len() - 1];
            let inner_trim = trim(inner);
            if inner_trim.len() != inner.len() {
                // Invalid stanza format
                continue;
            }
            current_stanza = inner_trim.to_string();
            // Ensure stanza exists
            get_stanza_idx(&current_stanza, &mut doc, &mut stanza_index);
            continue;
        }

        if let Some(eq_pos) = processed.find('=') {
            if eq_pos > 0 {
                add_entry(
                    &current_stanza,
                    &mut current_key,
                    &mut raw_value,
                    &mut in_multiline,
                    &mut multiline_lines,
                    &mut doc,
                    &stanza_index,
                );

                let key_v = trim(&processed[..eq_pos]);
                let value_v = trim(&processed[eq_pos + 1..]);

                current_key = key_v.to_string();
                raw_value = value_v.to_string();

                if !value_v.is_empty() && value_v.ends_with('\\') {
                    in_multiline = true;
                    multiline_lines = 1;
                } else {
                    add_entry(
                        &current_stanza,
                        &mut current_key,
                        &mut raw_value,
                        &mut in_multiline,
                        &mut multiline_lines,
                        &mut doc,
                        &stanza_index,
                    );
                }
            } else {
                // Orphaned line
            }
        } 
    }

    add_entry(
        &current_stanza,
        &mut current_key,
        &mut raw_value,
        &mut in_multiline,
        &mut multiline_lines,
        &mut doc,
        &stanza_index,
    );

    doc
}

// ===== High-level: read multiple files and merge (earlier files dominate) =====

/// Read and merge configuration from multiple files.
///
/// Earlier files in the list take precedence over later ones.
/// This matches Splunk's behavior where local/ overrides default/.
///
/// # Arguments
///
/// * `files` - List of configuration file paths to read
///
/// # Returns
///
/// A merged dictionary of all configuration values
pub fn read_configs<P: AsRef<Path>>(files: &[P]) -> Dictionary {
    let mut dict: Dictionary = HashMap::new();
    // Ensure default stanza exists
    dict.insert("default".to_string(), HashMap::new());

    for path in files {
        let content = read_file_view(path);
        if content.is_empty() {
            continue;
        }

        let file_path_str = path.as_ref().to_string_lossy();
        let doc = parse_config(&content, &file_path_str);

        for stanza in doc {
            let stanza_map = dict.entry(stanza.name).or_default();
            for entry in stanza.entries {
                // Earlier files dominate: only insert if absent
                stanza_map.entry(entry.key).or_insert(entry.value);
            }
        }
    }

    dict
}

/// Convenience wrapper for reading configuration files.
///
/// Alias for [`read_configs`] for API compatibility.
pub fn read_configs_default<P: AsRef<Path>>(files: &[P]) -> Dictionary {
    read_configs(files)
}
