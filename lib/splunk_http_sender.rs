// src/lib.rs
// src/lib.rs
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use dashmap::DashMap;
use flate2::Compression;
use flate2::write::GzEncoder;
use once_cell::sync::Lazy;
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use url::Url;

type ResponseCache = DashMap<String, (SystemTime, Bytes)>;
type HeaderList = Arc<RwLock<Vec<(Arc<str>, Arc<str>)>>>;

/// Custom error types for the Splunk event sender
#[derive(Error, Debug)]
pub enum SplunkError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("JSON serialization failed: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("URL parsing failed: {0}")]
    UrlError(#[from] url::ParseError),
    #[error("Compression failed: {0}")]
    CompressionError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("HTTP status {code}: {body}")]
    HttpStatus { code: u16, body: String },
}

pub type Result<T> = std::result::Result<T, SplunkError>;

/// Event metadata for Splunk indexing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub index: Arc<str>,
    pub source: Arc<str>,
    pub sourcetype: Arc<str>,
    pub host: Arc<str>,
    pub time: Option<u64>,
}

impl EventMetadata {
    pub fn new(
        index: impl Into<Arc<str>>,
        source: impl Into<Arc<str>>,
        sourcetype: impl Into<Arc<str>>,
        host: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            index: index.into(),
            source: source.into(),
            sourcetype: sourcetype.into(),
            host: host.into(),
            time: None,
        }
    }
}

/// Splunk HEC event envelope (caller constructs `time` / `index` / `fields` as needed).
///
/// This is designed for the `/services/collector/event` endpoint where each event is a JSON
/// object, and batches are sent by concatenating multiple objects in the request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HecEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Arc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Arc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sourcetype: Option<Arc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<Arc<str>>,
    pub event: JsonValue,
    /// Optional indexed fields (HEC `fields` object). This must be constructed by the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<JsonValue>,
}

impl HecEvent {
    pub fn new(event: JsonValue) -> Self {
        Self {
            time: None,
            host: None,
            source: None,
            sourcetype: None,
            index: None,
            event,
            fields: None,
        }
    }
}

/// Debug configuration options
#[derive(Debug, Clone)]
pub struct DebugOptions {
    pub enabled: bool,
    pub log_headers: bool,
    pub log_payload: bool,
    pub log_response_body: bool,
    pub enable_http_tracing: bool,
    pub max_bytes_to_log: usize,
}

impl Default for DebugOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            log_headers: false,
            log_payload: false,
            log_response_body: false,
            enable_http_tracing: false,
            max_bytes_to_log: 1024,
        }
    }
}

/// Logger trait for flexible logging backends
pub trait Logger: Send + Sync {
    fn log(&self, message: &str);
}

/// Default stderr logger implementation
#[derive(Debug)]
pub struct StderrLogger;

impl Logger for StderrLogger {
    fn log(&self, message: &str) {
        eprintln!("{}", message);
    }
}

/// Tracing logger implementation for structured logging
#[derive(Debug)]
pub struct TracingLogger;

impl Logger for TracingLogger {
    fn log(&self, message: &str) {
        info!("{}", message);
    }
}

/// Header cache for efficient header management
#[derive(Debug, Clone)]
struct HeaderCache {
    base: reqwest::header::HeaderMap,
    json: reqwest::header::HeaderMap,
    base_gzip: reqwest::header::HeaderMap,
    json_gzip: reqwest::header::HeaderMap,
}

impl HeaderCache {
    fn new() -> Self {
        Self {
            base: reqwest::header::HeaderMap::new(),
            json: reqwest::header::HeaderMap::new(),
            base_gzip: reqwest::header::HeaderMap::new(),
            json_gzip: reqwest::header::HeaderMap::new(),
        }
    }
}

/// High-performance HTTP event sender for Splunk
pub struct HttpEventSender {
    client: Client,
    base_url: Url,
    extra_headers: HeaderList,
    header_cache: ArcSwap<HeaderCache>,
    headers_dirty: Arc<RwLock<bool>>,
    debug_options: Arc<RwLock<DebugOptions>>,
    logger: Arc<dyn Logger>,
    gzip_enabled: Arc<RwLock<bool>>,
    gzip_min_bytes: Arc<RwLock<usize>>,
    // Connection pooling and caching
    response_cache: ResponseCache,
}

impl HttpEventSender {
    /// Create a new HTTP event sender
    pub fn new(post_url: impl AsRef<str>, verify_ssl: bool) -> Result<Self> {
        let base_url = Url::parse(post_url.as_ref())?;

        let client = ClientBuilder::new()
            .danger_accept_invalid_certs(!verify_ssl)
            .danger_accept_invalid_hostnames(!verify_ssl)
            .tcp_keepalive(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .user_agent("SplunkEventSender-Rust/1.0")
            .build()?;

        Ok(Self {
            client,
            base_url,
            extra_headers: Arc::new(RwLock::new(Vec::new())),
            header_cache: ArcSwap::new(Arc::new(HeaderCache::new())),
            headers_dirty: Arc::new(RwLock::new(true)),
            debug_options: Arc::new(RwLock::new(DebugOptions::default())),
            logger: Arc::new(StderrLogger),
            gzip_enabled: Arc::new(RwLock::new(false)),
            gzip_min_bytes: Arc::new(RwLock::new(1024)),
            response_cache: DashMap::new(),
        })
    }

    /// Set extra headers (replaces all existing extra headers)
    pub async fn set_extra_headers(&self, headers: Vec<(String, String)>) {
        let headers: Vec<(Arc<str>, Arc<str>)> = headers
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();

        *self.extra_headers.write().await = headers;
        *self.headers_dirty.write().await = true;
    }

    /// Add a single extra header
    pub async fn add_extra_header(&self, name: String, value: String) {
        self.extra_headers
            .write()
            .await
            .push((name.into(), value.into()));
        *self.headers_dirty.write().await = true;
    }

    /// Set connect timeout
    pub fn set_connect_timeout(&self, _seconds: u64) {
        // Note: reqwest doesn't allow changing timeout after client creation
        // This would require recreating the client, which we skip for performance
        warn!("Connect timeout cannot be changed after client creation in reqwest");
    }

    /// Enable/disable debug logging
    pub async fn set_debug(&self, enabled: bool) {
        self.debug_options.write().await.enabled = enabled;
    }

    /// Set debug options
    pub async fn set_debug_options(&self, options: DebugOptions) {
        *self.debug_options.write().await = options;
    }

    /// Get current debug options
    pub async fn get_debug_options(&self) -> DebugOptions {
        self.debug_options.read().await.clone()
    }

    /// Set custom logger
    pub fn set_logger(&mut self, logger: Arc<dyn Logger>) {
        self.logger = logger;
    }

    /// Enable/disable gzip compression
    pub async fn set_request_gzip(&self, enabled: bool, min_bytes: usize) {
        *self.gzip_enabled.write().await = enabled;
        *self.gzip_min_bytes.write().await = min_bytes;
    }

    /// Rebuild header cache if dirty
    async fn rebuild_header_cache_if_dirty(&self) -> Result<()> {
        let is_dirty = *self.headers_dirty.read().await;
        if !is_dirty {
            return Ok(());
        }

        // Clone once and derive flags from the cloned data to avoid extra locking.
        let extra_headers = self.extra_headers.read().await.clone();
        let has_content_type = extra_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
        let has_content_encoding = extra_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-encoding"));

        let mut new_cache = HeaderCache::new();

        // Build base headers
        for (name, value) in &extra_headers {
            let header_name =
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                    SplunkError::ConfigError(format!("Invalid header name '{}': {}", name, e))
                })?;
            let header_value = reqwest::header::HeaderValue::from_str(value).map_err(|e| {
                SplunkError::ConfigError(format!("Invalid header value '{}': {}", value, e))
            })?;

            new_cache
                .base
                .insert(header_name.clone(), header_value.clone());
            new_cache
                .json
                .insert(header_name.clone(), header_value.clone());
            new_cache
                .base_gzip
                .insert(header_name.clone(), header_value.clone());
            new_cache
                .json_gzip
                .insert(header_name.clone(), header_value.clone());
        }

        // Add JSON Content-Type if not present
        if !has_content_type {
            new_cache.json.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/json"),
            );
            new_cache.json_gzip.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/json"),
            );
        }

        // Add gzip Content-Encoding if not present
        if !has_content_encoding {
            new_cache.base_gzip.insert(
                reqwest::header::CONTENT_ENCODING,
                reqwest::header::HeaderValue::from_static("gzip"),
            );
            new_cache.json_gzip.insert(
                reqwest::header::CONTENT_ENCODING,
                reqwest::header::HeaderValue::from_static("gzip"),
            );
        }

        self.header_cache.store(Arc::new(new_cache));
        *self.headers_dirty.write().await = false;

        Ok(())
    }

    /// Get appropriate headers for request
    async fn get_headers(
        &self,
        want_json_content_type: bool,
        want_gzip_encoding: bool,
    ) -> Result<reqwest::header::HeaderMap> {
        self.rebuild_header_cache_if_dirty().await?;

        let cache = self.header_cache.load();
        let headers = match (want_json_content_type, want_gzip_encoding) {
            (true, true) => &cache.json_gzip,
            (true, false) => &cache.json,
            (false, true) => &cache.base_gzip,
            (false, false) => &cache.base,
        };

        Ok(headers.clone())
    }

    /// Compress data using gzip
    fn gzip_compress(data: &[u8]) -> Result<Vec<u8>> {
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        encoder
            .finish()
            .map_err(|e| SplunkError::CompressionError(e.to_string()))
    }

    /// Build URL with query parameters
    fn build_url(&self, metadata: &EventMetadata) -> Result<Url> {
        let mut url = self.base_url.clone();

        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("index", &metadata.index)
                .append_pair("source", &metadata.source)
                .append_pair("sourcetype", &metadata.sourcetype)
                .append_pair("host", &metadata.host);

            if let Some(time) = metadata.time {
                qp.append_pair("time", &time.to_string());
            }
        }

        Ok(url)
    }

    /// Log a message if debugging is enabled
    async fn log_line(&self, message: &str) {
        let debug_enabled = self.debug_options.read().await.enabled;
        if debug_enabled {
            self.logger.log(message);
        }
    }

    /// Redact sensitive headers for logging
    fn redact_header_for_logging(name: &str, value: &str) -> String {
        if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("x-splunk-token")
        {
            format!("{}: ***REDACTED***", name)
        } else {
            format!("{}: {}", name, value)
        }
    }

    fn truncate_to_char_boundary(input: &str, max_bytes: usize) -> &str {
        if max_bytes >= input.len() {
            return input;
        }
        if input.is_char_boundary(max_bytes) {
            return &input[..max_bytes];
        }
        input
            .char_indices()
            .take_while(|(idx, _)| *idx < max_bytes)
            .last()
            .map(|(idx, _)| &input[..idx])
            .unwrap_or("")
    }

    /// Core send implementation (accepts owned payload as Into<Bytes> to avoid extra copies)
    async fn do_send_to_url<P>(
        &self,
        url: Url,
        payload: P,
        is_json_payload: bool,
    ) -> Result<(u16, String)>
    where
        P: Into<Bytes>,
    {
        let debug_opts = self.debug_options.read().await.clone();

        // Convert into Bytes once (consumes owned payload without extra to_vec copy).
        let body_bytes: Bytes = payload.into();
        let payload_len = body_bytes.len();

        if debug_opts.enabled {
            self.log_line(&format!(
                "[HTTP] doSend: begin, payload_size={}",
                payload_len
            ))
            .await;
        }

        // Determine if we should use gzip compression
        let gzip_enabled = *self.gzip_enabled.read().await;
        let gzip_min_bytes = *self.gzip_min_bytes.read().await;
        let use_gzip = gzip_enabled && payload_len >= gzip_min_bytes;

        // Compress payload if needed
        let (body_data, compressed_size) = if use_gzip {
            match Self::gzip_compress(body_bytes.as_ref()) {
                Ok(compressed) => {
                    if debug_opts.enabled {
                        self.log_line(&format!(
                            "[HTTP] Compressed {} bytes to {} bytes",
                            payload_len,
                            compressed.len()
                        ))
                        .await;
                    }
                    let comp_len = compressed.len();
                    (Bytes::from(compressed), Some(comp_len))
                }
                Err(e) => {
                    warn!("Gzip compression failed: {}, sending uncompressed", e);
                    // use the original bytes without copying
                    (body_bytes.clone(), None)
                }
            }
        } else {
            // no compression, move the bytes into request body
            (body_bytes.clone(), None)
        };

        // Get appropriate headers
        let headers = self
            .get_headers(is_json_payload, compressed_size.is_some())
            .await?;

        // Debug logging for request
        if debug_opts.enabled {
            self.log_line(&format!("[HTTP] POST {}", url)).await;

            if debug_opts.log_headers {
                for (name, value) in &headers {
                    let header_str = Self::redact_header_for_logging(
                        name.as_str(),
                        value.to_str().unwrap_or("<invalid-utf8>"),
                    );
                    self.log_line(&format!("[HTTP] header: {}", header_str))
                        .await;
                }
            }

            if debug_opts.log_payload {
                let show_bytes = std::cmp::min(debug_opts.max_bytes_to_log, payload_len);
                let size_info = if let Some(comp_size) = compressed_size {
                    format!(
                        "payload bytes={}, compressed={}, showing={}",
                        payload_len, comp_size, show_bytes
                    )
                } else {
                    format!("payload bytes={}, showing={}", payload_len, show_bytes)
                };
                self.log_line(&format!("[HTTP] {}", size_info)).await;

                // Try to log as UTF-8 string; fall back to byte-length info if not valid UTF-8.
                if let Ok(s) = std::str::from_utf8(body_bytes.as_ref()) {
                    let truncated = Self::truncate_to_char_boundary(s, show_bytes);
                    self.log_line(truncated).await;
                } else {
                    self.log_line("<binary payload: not valid UTF-8>").await;
                }
            } else {
                let size_info = if let Some(comp_size) = compressed_size {
                    format!("payload bytes={}, compressed={}", payload_len, comp_size)
                } else {
                    format!("payload bytes={}", payload_len)
                };
                self.log_line(&format!("[HTTP] {}", size_info)).await;
            }
        }

        // Execute HTTP request
        let mut request_builder = self
            .client
            .post(url.clone())
            .headers(headers)
            .body(body_data);

        // Add timeout if configured
        request_builder = request_builder.timeout(Duration::from_secs(30));

        let response = request_builder.send().await?;
        let status_code = response.status().as_u16();
        let response_body = response.text().await?;

        // Debug logging for response
        if debug_opts.enabled {
            self.log_line(&format!(
                "[HTTP] status={} ({})",
                status_code,
                if (200..300).contains(&status_code) {
                    "OK"
                } else {
                    "ERROR"
                }
            ))
            .await;

            if debug_opts.log_response_body {
                let show_bytes = std::cmp::min(debug_opts.max_bytes_to_log, response_body.len());
                self.log_line(&format!(
                    "[HTTP] response bytes={}, showing={}",
                    response_body.len(),
                    show_bytes
                ))
                .await;
                let truncated = Self::truncate_to_char_boundary(&response_body, show_bytes);
                self.log_line(truncated).await;
            } else {
                self.log_line(&format!("[HTTP] response bytes={}", response_body.len()))
                    .await;
            }
        }

        if !(200..300).contains(&status_code) {
            return Err(SplunkError::HttpStatus {
                code: status_code,
                body: response_body,
            });
        }
        Ok((status_code, response_body))
    }

    /// Core send implementation with query parameters from `EventMetadata`.
    async fn do_send<P>(
        &self,
        metadata: &EventMetadata,
        payload: P,
        is_json_payload: bool,
    ) -> Result<(u16, String)>
    where
        P: Into<Bytes>,
    {
        let url = self.build_url(metadata)?;
        self.do_send_to_url(url, payload, is_json_payload).await
    }

    /// Send events as delimited string
    pub async fn send_events_delimited(
        &self,
        metadata: &EventMetadata,
        event_payloads: &[String],
    ) -> Result<(u16, String)> {
        self.send_events_delimited_with(metadata, event_payloads, "<EOE>\n")
            .await
    }

    /// Send events as a delimited string using a caller-provided delimiter (e.g. `\"\\n\"` for NDJSON).
    pub async fn send_events_delimited_with(
        &self,
        metadata: &EventMetadata,
        event_payloads: &[String],
        delimiter: &str,
    ) -> Result<(u16, String)> {
        if self.debug_options.read().await.enabled {
            self.log_line("[HTTP] sendEventsDelimited: begin").await;
        }

        let payload = if event_payloads.is_empty() {
            String::new()
        } else if event_payloads.len() == 1 {
            event_payloads[0].clone()
        } else {
            // Pre-calculate total size for efficient allocation
            let total_size: usize = event_payloads.iter().map(|s| s.len()).sum::<usize>()
                + (event_payloads.len() - 1) * delimiter.len();

            let mut result = String::with_capacity(total_size);
            for (i, payload) in event_payloads.iter().enumerate() {
                result.push_str(payload);
                if i < event_payloads.len() - 1 {
                    result.push_str(delimiter);
                }
            }
            result
        };

        // Convert the owned String into Bytes without an extra copy
        let bytes = Bytes::from(payload.into_bytes());
        self.do_send(metadata, bytes, false).await
    }

    /// Send JSON events (borrowed version)
    pub async fn send_events(
        &self,
        metadata: &EventMetadata,
        event_payloads: &[JsonValue],
    ) -> Result<(u16, String)> {
        if self.debug_options.read().await.enabled {
            self.log_line("[HTTP] sendEvents: begin").await;
        }

        // FIX: Use serde_json::to_writer to serialize directly into Vec<u8>,
        // avoiding the intermediate String allocation from to_string().
        // This reduces peak memory usage for large JSON payloads.
        let mut buf = Vec::with_capacity(event_payloads.len() * 128);
        serde_json::to_writer(&mut buf, event_payloads)?;
        let bytes = Bytes::from(buf);
        self.do_send(metadata, bytes, true).await
    }

    /// Batch send multiple events with automatic chunking
    pub async fn send_events_batched(
        &self,
        metadata: &EventMetadata,
        events: Vec<JsonValue>,
        batch_size: usize,
    ) -> Result<Vec<(u16, String)>> {
        if batch_size == 0 {
            return Err(SplunkError::ConfigError(
                "batch_size must be greater than 0".to_string(),
            ));
        }

        let mut results =
            Vec::with_capacity((events.len() + batch_size.saturating_sub(1)) / batch_size);

        for chunk in events.chunks(batch_size) {
            let result = self.send_events(metadata, chunk).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Batch send delimited events with automatic chunking (e.g. for Splunk HEC streaming mode).
    pub async fn send_events_delimited_batched(
        &self,
        metadata: &EventMetadata,
        events: Vec<String>,
        batch_size: usize,
        delimiter: &str,
    ) -> Result<Vec<(u16, String)>> {
        if batch_size == 0 {
            return Err(SplunkError::ConfigError(
                "batch_size must be greater than 0".to_string(),
            ));
        }

        let mut results =
            Vec::with_capacity((events.len() + batch_size.saturating_sub(1)) / batch_size);
        for chunk in events.chunks(batch_size) {
            results.push(
                self.send_events_delimited_with(metadata, chunk, delimiter)
                    .await?,
            );
        }
        Ok(results)
    }

    fn encode_hec_payload<T: Serialize>(events: &[T]) -> Result<Bytes> {
        let mut buf = Vec::with_capacity(events.len() * 256);
        for event in events {
            serde_json::to_writer(&mut buf, event)?;
        }
        Ok(Bytes::from(buf))
    }

    /// Send multiple events in Splunk HEC concatenated JSON format to the sender's base URL.
    pub async fn send_hec_batch<T: Serialize>(&self, events: &[T]) -> Result<(u16, String)> {
        if self.debug_options.read().await.enabled {
            self.log_line("[HTTP] send_hec_batch: begin").await;
        }

        let bytes = Self::encode_hec_payload(events)?;
        self.do_send_to_url(self.base_url.clone(), bytes, true)
            .await
    }

    /// Batch send multiple HEC events with automatic chunking.
    pub async fn send_hec_batched<T: Serialize>(
        &self,
        events: Vec<T>,
        batch_size: usize,
    ) -> Result<Vec<(u16, String)>> {
        if batch_size == 0 {
            return Err(SplunkError::ConfigError(
                "batch_size must be greater than 0".to_string(),
            ));
        }

        let mut results =
            Vec::with_capacity((events.len() + batch_size.saturating_sub(1)) / batch_size);
        for chunk in events.chunks(batch_size) {
            results.push(self.send_hec_batch(chunk).await?);
        }
        Ok(results)
    }

    /// Send multiple events in Splunk HEC concatenated JSON format (legacy API).
    pub async fn send_hec_events(
        &self,
        metadata: &EventMetadata,
        events: &[JsonValue],
    ) -> Result<(u16, String)> {
        if self.debug_options.read().await.enabled {
            self.log_line("[HTTP] send_hec_events: begin").await;
        }

        let bytes = Self::encode_hec_payload(events)?;
        self.do_send(metadata, bytes, true).await
    }

    /// Clear response cache (useful for testing or memory management)
    pub fn clear_cache(&self) {
        self.response_cache.clear();
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, usize) {
        let len = self.response_cache.len();
        let capacity = self.response_cache.capacity();
        (len, capacity)
    }
}

// Thread-safe global initialization (equivalent to C++ ensure_curl_global_inited)
static INIT: Lazy<()> = Lazy::new(|| {
    // reqwest handles global initialization internally
    debug!("Splunk HTTP Event Sender initialized");
});

/// Ensure global initialization is called
pub fn ensure_global_init() {
    Lazy::force(&INIT);
}

/// Builder pattern for creating HttpEventSender with custom configuration
pub struct HttpEventSenderBuilder {
    url: String,
    verify_ssl: bool,
    connect_timeout: Duration,
    request_timeout: Duration,
    gzip_enabled: bool,
    gzip_min_bytes: usize,
    debug_options: DebugOptions,
    extra_headers: Vec<(String, String)>,
    logger: Option<Arc<dyn Logger>>,
}

impl HttpEventSenderBuilder {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            verify_ssl: true,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            gzip_enabled: false,
            gzip_min_bytes: 1024,
            debug_options: DebugOptions::default(),
            extra_headers: Vec::new(),
            logger: None,
        }
    }

    pub fn verify_ssl(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn enable_gzip(mut self, enabled: bool, min_bytes: usize) -> Self {
        self.gzip_enabled = enabled;
        self.gzip_min_bytes = min_bytes;
        self
    }

    pub fn debug_options(mut self, options: DebugOptions) -> Self {
        self.debug_options = options;
        self
    }

    pub fn extra_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.extra_headers = headers;
        self
    }

    pub fn logger(mut self, logger: Arc<dyn Logger>) -> Self {
        self.logger = Some(logger);
        self
    }

    pub async fn build(self) -> Result<HttpEventSender> {
        let base_url = Url::parse(&self.url)?;

        let client = ClientBuilder::new()
            .danger_accept_invalid_certs(!self.verify_ssl)
            .danger_accept_invalid_hostnames(!self.verify_ssl)
            .tcp_keepalive(Duration::from_secs(60))
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .user_agent("SplunkEventSender-Rust/1.0")
            .build()?;

        let sender = HttpEventSender {
            client,
            base_url,
            extra_headers: Arc::new(RwLock::new(
                self.extra_headers
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            )),
            header_cache: ArcSwap::new(Arc::new(HeaderCache::new())),
            headers_dirty: Arc::new(RwLock::new(true)),
            debug_options: Arc::new(RwLock::new(self.debug_options)),
            logger: self.logger.unwrap_or_else(|| Arc::new(StderrLogger)),
            gzip_enabled: Arc::new(RwLock::new(self.gzip_enabled)),
            gzip_min_bytes: Arc::new(RwLock::new(self.gzip_min_bytes)),
            response_cache: DashMap::new(),
        };

        Ok(sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn send_events_batched_rejects_zero_batch_size() {
        let sender = HttpEventSender::new("http://example.com", true).unwrap();
        let metadata = EventMetadata::new("main", "src", "st", "host");
        let res = sender.send_events_batched(&metadata, vec![], 0).await;
        assert!(matches!(res, Err(SplunkError::ConfigError(_))));
    }

    #[test]
    fn build_url_includes_time_query_when_set() {
        let sender = HttpEventSender::new("http://example.com/ingest", true).unwrap();
        let mut metadata = EventMetadata::new("main", "src", "st", "host");
        metadata.time = Some(1_735_000_000);

        let url = sender.build_url(&metadata).unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

        assert_eq!(query.get("index").map(String::as_str), Some("main"));
        assert_eq!(query.get("source").map(String::as_str), Some("src"));
        assert_eq!(query.get("sourcetype").map(String::as_str), Some("st"));
        assert_eq!(query.get("host").map(String::as_str), Some("host"));
        assert_eq!(query.get("time").map(String::as_str), Some("1735000000"));
    }

    #[test]
    fn encode_hec_payload_concatenates_json_objects() {
        let events = vec![json!({"a": 1}), json!({"b": 2})];
        let payload = HttpEventSender::encode_hec_payload(&events).unwrap();
        assert_eq!(
            std::str::from_utf8(payload.as_ref()).unwrap(),
            r#"{"a":1}{"b":2}"#
        );
    }
}
