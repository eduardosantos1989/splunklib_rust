//! JSON-first application logger with HTTP or file destinations.
//!
//! Records are JSON objects from the start (`time`, `sid`, `level`, `message`,
//! plus any extra fields). Destination selection:
//!
//! 1. If an HTTP URL is configured, events are batched and POSTed.
//! 2. If HTTP is missing or the URL is invalid, logs go to a rotating file as
//!    NDJSON.
//! 3. If both are configured, HTTP is primary and the file is used when a
//!    send fails.
//!
//! HTTP encoding is controlled by [`crate::splunk_http_sender::IngestMode`]:
//! Splunk HEC (token + envelopes) vs the custom no-auth JSON-array collector.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

#[cfg(not(target_has_atomic = "64"))]
use portable_atomic::AtomicU64;
use rand::RngExt;
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;

use crate::splunk_conf_layering::ConfContext;
use crate::splunk_config_processor::Dictionary;
use crate::splunk_file_logger::{FileLogger, FileLoggerConfig};
use crate::splunk_http_sender::{EventMetadata, HttpEventSenderBuilder, IngestMode};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError, bounded};
use serde_json::{Map, Value as JsonValue, json};
use thiserror::Error;
use tracing::warn;
use url::Url;

const MIN_QUEUE_CAPACITY: usize = 64;

/// Errors from constructing or enqueueing JSON log records.
#[derive(Debug, Error)]
pub enum JsonLoggerError {
    #[error("no log destination configured (need an HTTP url or a file path)")]
    NoDestination,
    #[error("invalid log url: {0}")]
    InvalidUrl(String),
    #[error("http logger setup failed: {0}")]
    HttpSetup(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("logger queue is full")]
    QueueFull,
    #[error("json logger is shutting down")]
    ShuttingDown,
    #[error("logger worker disconnected")]
    Disconnected,
}

pub type Result<T> = std::result::Result<T, JsonLoggerError>;

/// Severity attached to JSON log records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Where records will be written after config is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogDestination {
    Http,
    File,
    HttpWithFileFallback,
}

/// HTTP destination for [`JsonLogger`].
#[derive(Debug, Clone)]
pub struct HttpLogConfig {
    pub url: String,
    pub mode: IngestMode,
    pub token: Option<String>,
    pub verify_ssl: bool,
    pub metadata: EventMetadata,
    pub gzip: bool,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl HttpLogConfig {
    pub fn new(url: impl Into<String>, mode: IngestMode) -> Self {
        Self {
            url: url.into(),
            mode,
            token: None,
            verify_ssl: true,
            metadata: EventMetadata::new("main", "splunklib_rust", "_json", "localhost"),
            gzip: true,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
        }
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    pub fn with_metadata(mut self, metadata: EventMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn verify_ssl(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }
}

/// Configuration for [`JsonLogger`].
#[derive(Debug, Clone)]
pub struct JsonLoggerConfig {
    pub http: Option<HttpLogConfig>,
    pub file: Option<FileLoggerConfig>,
    pub session_id: Option<u64>,
    pub queue_capacity: Option<usize>,
    pub batch_size: usize,
    pub auto_flush_interval: Option<Duration>,
}

impl JsonLoggerConfig {
    pub fn file_only(file: FileLoggerConfig) -> Self {
        Self {
            http: None,
            file: Some(file),
            session_id: None,
            queue_capacity: Some(1024),
            batch_size: 50,
            auto_flush_interval: Some(Duration::from_secs(1)),
        }
    }

    pub fn http_only(http: HttpLogConfig) -> Self {
        Self {
            http: Some(http),
            file: None,
            session_id: None,
            queue_capacity: Some(1024),
            batch_size: 50,
            auto_flush_interval: Some(Duration::from_secs(1)),
        }
    }

    pub fn http_with_file_fallback(http: HttpLogConfig, file: FileLoggerConfig) -> Self {
        Self {
            http: Some(http),
            file: Some(file),
            session_id: None,
            queue_capacity: Some(1024),
            batch_size: 50,
            auto_flush_interval: Some(Duration::from_secs(1)),
        }
    }

    /// Build logger config from a parsed conf dictionary.
    ///
    /// Looks for `[logging]`, then a stanza named `http::*`, then `[default]`.
    ///
    /// Keys: `url`, `token`, `ingest`/`mode` (`hec` \| `custom` \| `file`),
    /// `file`/`path`, `index`, `source`, `sourcetype`, `host`, `verify_ssl`,
    /// `rotate_size_bytes`, `max_rotate_files`, `batch_size`,
    /// `auto_flush_interval`, `gzip`.
    pub fn from_dictionary(ctx: &ConfContext, dict: &Dictionary) -> Self {
        let stanza = select_logging_stanza(dict);
        let vars = ctx.variable_map(None);

        let raw_ingest = stanza
            .and_then(|s| s.get("ingest").or_else(|| s.get("mode")))
            .map(|s| s.as_str());
        let force_file = raw_ingest.is_some_and(|s| s.eq_ignore_ascii_case("file"));

        let url = stanza
            .and_then(|s| s.get("url"))
            .map(|s| crate::splunk_conf_layering::expand_value(s, &vars))
            .filter(|s| !s.is_empty());
        let file_path = stanza
            .and_then(|s| s.get("file").or_else(|| s.get("path")))
            .map(|s| crate::splunk_conf_layering::expand_value(s, &vars))
            .filter(|s| !s.is_empty());
        let token = stanza
            .and_then(|s| s.get("token"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let mode = raw_ingest.and_then(IngestMode::parse).unwrap_or_else(|| {
            if token.is_some() {
                IngestMode::SplunkHec
            } else {
                IngestMode::Custom
            }
        });

        let host = stanza
            .and_then(|s| s.get("host"))
            .map(|s| crate::splunk_conf_layering::expand_value(s, &vars))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| ctx.hostname.clone());
        let index = stanza
            .and_then(|s| s.get("index"))
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "main".to_string());
        let source = stanza
            .and_then(|s| s.get("source"))
            .cloned()
            .filter(|s| !s.is_empty())
            .or_else(|| ctx.app.clone())
            .unwrap_or_else(|| "splunklib_rust".to_string());
        let sourcetype = stanza
            .and_then(|s| s.get("sourcetype"))
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "_json".to_string());

        let http = if !force_file {
            url.map(|url| {
                let mut http = HttpLogConfig::new(url, mode)
                    .with_metadata(EventMetadata::new(index, source, sourcetype, host));
                if let Some(token) = token {
                    http = http.with_token(token);
                }
                if let Some(verify) = stanza
                    .and_then(|s| s.get("verify_ssl"))
                    .and_then(|v| parse_bool(v))
                {
                    http = http.verify_ssl(verify);
                }
                if let Some(gzip) = stanza
                    .and_then(|s| s.get("gzip"))
                    .and_then(|v| parse_bool(v))
                {
                    http.gzip = gzip;
                }
                http
            })
        } else {
            None
        };

        let file = file_path.map(|path| {
            let mut cfg = FileLoggerConfig::new(path);
            if let Some(bytes) = stanza
                .and_then(|s| s.get("rotate_size_bytes"))
                .and_then(|v| v.parse().ok())
            {
                cfg = cfg.with_rotate_size_bytes(Some(bytes));
            }
            if let Some(max) = stanza
                .and_then(|s| s.get("max_rotate_files"))
                .and_then(|v| v.parse().ok())
            {
                cfg = cfg.with_max_rotate_files(max);
            }
            cfg
        });

        let batch_size = stanza
            .and_then(|s| s.get("batch_size"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(50)
            .max(1);
        let auto_flush_interval = stanza
            .and_then(|s| s.get("auto_flush_interval"))
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .or(Some(Duration::from_secs(1)));
        let queue_capacity = stanza
            .and_then(|s| s.get("queue_capacity"))
            .and_then(|v| v.parse().ok());

        Self {
            http,
            file,
            session_id: None,
            queue_capacity: Some(queue_capacity.unwrap_or(1024)),
            batch_size,
            auto_flush_interval,
        }
    }
}

fn select_logging_stanza(dict: &Dictionary) -> Option<&MapLike> {
    if let Some(stanza) = dict.get("logging") {
        return Some(stanza);
    }
    if let Some(stanza) = dict.get("http") {
        return Some(stanza);
    }
    let mut http_stanzas: Vec<&String> = dict
        .keys()
        .filter(|name| name.starts_with("http::"))
        .collect();
    http_stanzas.sort();
    if let Some(name) = http_stanzas.first() {
        return dict.get(*name);
    }
    dict.get("default")
}

type MapLike = std::collections::HashMap<String, String>;

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

/// Snapshot of JSON logger counters.
#[derive(Clone, Debug)]
pub struct JsonLoggerStats {
    pub records_queued: u64,
    pub http_batches_ok: u64,
    pub http_batches_failed: u64,
    pub file_records: u64,
    pub last_error: Option<String>,
    pub destination: LogDestination,
}

/// Thread-safe JSON logger. HTTP when a URL is configured, otherwise file.
pub struct JsonLogger {
    inner: Arc<JsonLoggerInner>,
    session_id: Arc<AtomicU64>,
    destination: LogDestination,
}

struct JsonLoggerInner {
    command_tx: Sender<Command>,
    command_lock: Mutex<()>,
    join: Mutex<Option<JoinHandle<JsonLoggerStats>>>,
    shutdown: AtomicBool,
    final_stats: Mutex<Option<JsonLoggerStats>>,
}

enum Command {
    Log(JsonValue),
    Flush(Sender<std::io::Result<()>>),
    Stats(Sender<JsonLoggerStats>),
    Shutdown(Sender<JsonLoggerStats>),
}

impl JsonLogger {
    pub fn new(mut config: JsonLoggerConfig) -> Result<Self> {
        if let Some(http) = &config.http
            && let Err(err) = Url::parse(&http.url)
        {
            warn!("invalid JSON logger url ({err}); falling back to file if configured");
            if config.file.is_none() {
                return Err(JsonLoggerError::InvalidUrl(err.to_string()));
            }
            config.http = None;
        }

        let http_runtime = if let Some(http_cfg) = &config.http {
            match build_http_runtime_on_thread(http_cfg) {
                Ok(runtime) => Some(runtime),
                Err(err) => {
                    if config.file.is_none() {
                        return Err(JsonLoggerError::HttpSetup(err));
                    }
                    warn!("HTTP logger setup failed ({err}); falling back to file");
                    config.http = None;
                    None
                }
            }
        } else {
            None
        };

        if http_runtime.is_none() && config.file.is_none() {
            return Err(JsonLoggerError::NoDestination);
        }

        let destination = match (&http_runtime, &config.file) {
            (Some(_), Some(_)) => LogDestination::HttpWithFileFallback,
            (Some(_), None) => LogDestination::Http,
            (None, Some(_)) => LogDestination::File,
            (None, None) => return Err(JsonLoggerError::NoDestination),
        };

        let file_logger = match config.file.clone() {
            Some(file_cfg) => Some(FileLogger::new(file_cfg)?),
            None => None,
        };

        let capacity = match config.queue_capacity {
            Some(cap) if cap > 0 => cap,
            _ => MIN_QUEUE_CAPACITY,
        };
        let (command_tx, command_rx) = bounded(capacity);

        let session_id = Arc::new(AtomicU64::new(
            config
                .session_id
                .unwrap_or_else(|| rand::rng().random_range(..=9_999_999_999)),
        ));

        let handle = thread::Builder::new()
            .name("splunk-json-logger".into())
            .spawn(move || worker_loop(command_rx, config, http_runtime, file_logger, destination))
            .map_err(JsonLoggerError::Io)?;

        Ok(Self {
            inner: Arc::new(JsonLoggerInner {
                command_tx,
                command_lock: Mutex::new(()),
                join: Mutex::new(Some(handle)),
                shutdown: AtomicBool::new(false),
                final_stats: Mutex::new(None),
            }),
            session_id,
            destination,
        })
    }

    /// Read layered `conf_file_name` and build a logger from `[logging]` (etc).
    pub fn from_splunk_conf(ctx: &ConfContext, conf_file_name: &str) -> Result<Self> {
        let layered = crate::splunk_conf_layering::read_layered_conf(ctx, conf_file_name)?;
        Self::new(JsonLoggerConfig::from_dictionary(ctx, &layered.dict))
    }

    pub fn destination(&self) -> LogDestination {
        self.destination
    }

    pub fn session_id(&self) -> u64 {
        self.session_id.load(Ordering::Relaxed)
    }

    pub fn set_session_id(&self, sid: u64) {
        self.session_id.store(sid, Ordering::Relaxed);
    }

    pub fn info(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Info, message)
    }

    pub fn debug(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Debug, message)
    }

    pub fn warn(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Warn, message)
    }

    pub fn error(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Error, message)
    }

    pub fn log_level(&self, level: LogLevel, message: impl AsRef<str>) -> Result<()> {
        self.log_json(json!({
            "time": epoch_secs(),
            "sid": self.session_id(),
            "level": level.as_str(),
            "message": message.as_ref(),
        }))
    }

    /// Enqueue a JSON record. Object records get `time`/`sid` if missing.
    pub fn log_json(&self, value: JsonValue) -> Result<()> {
        let normalized = normalize_record(value, self.session_id());
        self.send_command(Command::Log(normalized))
    }

    pub fn log_fields(
        &self,
        level: LogLevel,
        message: impl AsRef<str>,
        fields: Map<String, JsonValue>,
    ) -> Result<()> {
        let mut obj = fields;
        obj.entry("time".to_string())
            .or_insert_with(|| json!(epoch_secs()));
        obj.entry("sid".to_string())
            .or_insert_with(|| json!(self.session_id()));
        obj.insert("level".to_string(), json!(level.as_str()));
        obj.insert("message".to_string(), json!(message.as_ref()));
        self.send_command(Command::Log(JsonValue::Object(obj)))
    }

    pub fn try_log_json(&self, value: JsonValue) -> Result<()> {
        let normalized = normalize_record(value, self.session_id());
        self.try_send_command(Command::Log(normalized))
    }

    pub fn flush(&self) -> Result<()> {
        let (tx, rx) = bounded(1);
        self.send_command(Command::Flush(tx))?;
        rx.recv()
            .map_err(|_| JsonLoggerError::Disconnected)?
            .map_err(JsonLoggerError::Io)
    }

    pub fn stats(&self) -> Result<JsonLoggerStats> {
        if self.inner.shutdown.load(Ordering::SeqCst)
            && let Some(stats) = self
                .inner
                .final_stats
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        {
            return Ok(stats);
        }
        let (tx, rx) = bounded(1);
        self.send_command(Command::Stats(tx))?;
        rx.recv().map_err(|_| JsonLoggerError::Disconnected)
    }

    pub fn shutdown(&self) -> Result<JsonLoggerStats> {
        let (tx, rx) = bounded(1);
        {
            let _guard = self
                .inner
                .command_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self.inner.shutdown.swap(true, Ordering::SeqCst) {
                drop(_guard);
                if let Some(stats) = self
                    .inner
                    .final_stats
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                {
                    return Ok(stats);
                }
                return Err(JsonLoggerError::Disconnected);
            }
            self.inner
                .command_tx
                .send(Command::Shutdown(tx))
                .map_err(|_| JsonLoggerError::Disconnected)?;
        }
        let final_stats = rx.recv().map_err(|_| JsonLoggerError::Disconnected)?;

        let mut join_guard = self.inner.join.lock().unwrap_or_else(|e| e.into_inner());
        let mut stats_guard = self
            .inner
            .final_stats
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(handle) = join_guard.take() {
            match handle.join() {
                Ok(stats) => {
                    *stats_guard = Some(stats.clone());
                    Ok(stats)
                }
                Err(_) => {
                    *stats_guard = Some(final_stats.clone());
                    Err(JsonLoggerError::Io(std::io::Error::other(
                        "json logger worker panicked during shutdown",
                    )))
                }
            }
        } else {
            *stats_guard = Some(final_stats.clone());
            Ok(final_stats)
        }
    }

    fn send_command(&self, command: Command) -> Result<()> {
        let _guard = self
            .inner
            .command_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.inner.shutdown.load(Ordering::SeqCst) {
            return Err(JsonLoggerError::ShuttingDown);
        }
        self.inner
            .command_tx
            .send(command)
            .map_err(|_| JsonLoggerError::Disconnected)
    }

    fn try_send_command(&self, command: Command) -> Result<()> {
        let _guard = self
            .inner
            .command_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.inner.shutdown.load(Ordering::SeqCst) {
            return Err(JsonLoggerError::ShuttingDown);
        }
        match self.inner.command_tx.try_send(command) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(JsonLoggerError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(JsonLoggerError::Disconnected),
        }
    }
}

impl Clone for JsonLogger {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            session_id: Arc::clone(&self.session_id),
            destination: self.destination,
        }
    }
}

impl fmt::Debug for JsonLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonLogger")
            .field("destination", &self.destination)
            .field("shutdown", &self.inner.shutdown.load(Ordering::SeqCst))
            .finish()
    }
}

impl Drop for JsonLogger {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) != 1 {
            return;
        }
        let _ = self.shutdown();
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn normalize_record(value: JsonValue, sid: u64) -> JsonValue {
    match value {
        JsonValue::Object(mut map) => {
            map.entry("time".to_string())
                .or_insert_with(|| json!(epoch_secs()));
            map.entry("sid".to_string()).or_insert_with(|| json!(sid));
            JsonValue::Object(map)
        }
        other => json!({
            "time": epoch_secs(),
            "sid": sid,
            "level": "info",
            "message": other,
        }),
    }
}

fn write_ndjson(
    file: &FileLogger,
    events: &[JsonValue],
    stats: &mut JsonLoggerStats,
) -> std::io::Result<()> {
    let mut first_err: Option<std::io::Error> = None;
    for event in events {
        match serde_json::to_vec(event) {
            Ok(bytes) => match file.log_with_header(bytes, false) {
                Ok(()) => stats.file_records += 1,
                Err(err) => {
                    stats.last_error = Some(err.to_string());
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            },
            Err(err) => {
                stats.last_error = Some(err.to_string());
                if first_err.is_none() {
                    first_err = Some(std::io::Error::other(err.to_string()));
                }
            }
        }
    }
    match first_err {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

struct WorkerCtx {
    http: Option<HttpRuntime>,
    file: Option<FileLogger>,
    metadata: EventMetadata,
    mode: IngestMode,
    batch_size: usize,
    auto_flush_interval: Option<Duration>,
    next_flush: Option<Instant>,
    stats: JsonLoggerStats,
    batch: Vec<JsonValue>,
    pending_delivery_error: Option<std::io::Error>,
}

struct HttpRuntime {
    runtime: tokio::runtime::Runtime,
    sender: crate::splunk_http_sender::HttpEventSender,
}

fn worker_loop(
    command_rx: Receiver<Command>,
    config: JsonLoggerConfig,
    http: Option<HttpRuntime>,
    file: Option<FileLogger>,
    destination: LogDestination,
) -> JsonLoggerStats {
    let mut ctx = WorkerCtx {
        http,
        file,
        metadata: config
            .http
            .as_ref()
            .map(|h| h.metadata.clone())
            .unwrap_or_else(|| EventMetadata::new("main", "splunklib_rust", "_json", "localhost")),
        mode: config
            .http
            .as_ref()
            .map(|h| h.mode)
            .unwrap_or(IngestMode::Custom),
        batch_size: config.batch_size.max(1),
        auto_flush_interval: config.auto_flush_interval,
        next_flush: config
            .auto_flush_interval
            .map(|interval| Instant::now() + interval),
        stats: JsonLoggerStats {
            records_queued: 0,
            http_batches_ok: 0,
            http_batches_failed: 0,
            file_records: 0,
            last_error: None,
            destination,
        },
        batch: Vec::new(),
        pending_delivery_error: None,
    };

    loop {
        let command = match ctx.auto_flush_interval {
            Some(_) => {
                let timeout = ctx
                    .next_flush
                    .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                    .unwrap_or(Duration::ZERO);
                match command_rx.recv_timeout(timeout) {
                    Ok(command) => command,
                    Err(RecvTimeoutError::Timeout) => {
                        let _ = flush_batch(&mut ctx);
                        if let Some(file) = &ctx.file
                            && let Err(err) = file.flush()
                        {
                            ctx.stats.last_error = Some(err.to_string());
                        }
                        if let Some(interval) = ctx.auto_flush_interval {
                            ctx.next_flush = Some(Instant::now() + interval);
                        }
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            None => match command_rx.recv() {
                Ok(command) => command,
                Err(_) => break,
            },
        };

        match command {
            Command::Log(value) => {
                ctx.stats.records_queued += 1;
                if ctx.http.is_some() {
                    ctx.batch.push(value);
                    if ctx.batch.len() >= ctx.batch_size {
                        let _ = flush_batch(&mut ctx);
                    }
                } else if let Some(file) = &ctx.file {
                    let _ = write_ndjson(file, std::slice::from_ref(&value), &mut ctx.stats);
                }
            }
            Command::Flush(reply) => {
                let mut result = flush_batch(&mut ctx);
                if result.is_ok() {
                    if let Some(err) = ctx.pending_delivery_error.take() {
                        result = Err(err);
                    } else if let Some(file) = &ctx.file {
                        result = file.flush();
                    }
                }
                let _ = reply.send(result);
            }
            Command::Stats(reply) => {
                let _ = reply.send(ctx.stats.clone());
            }
            Command::Shutdown(reply) => {
                let _ = flush_batch(&mut ctx);
                if let Some(file) = &ctx.file {
                    let _ = file.flush();
                    let _ = file.shutdown();
                }
                let _ = reply.send(ctx.stats.clone());
                return ctx.stats;
            }
        }
    }

    let _ = flush_batch(&mut ctx);
    if let Some(file) = &ctx.file {
        let _ = file.flush();
        let _ = file.shutdown();
    }
    ctx.stats
}

fn build_http_runtime_on_thread(
    http_cfg: &HttpLogConfig,
) -> std::result::Result<HttpRuntime, String> {
    let cfg = http_cfg.clone();
    thread::Builder::new()
        .name("splunk-json-logger-http-setup".into())
        .spawn(move || build_http_runtime(&cfg))
        .map_err(|e| e.to_string())?
        .join()
        .map_err(|_| "HTTP logger setup thread panicked".to_string())?
}

fn build_http_runtime(http_cfg: &HttpLogConfig) -> std::result::Result<HttpRuntime, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let mut builder = HttpEventSenderBuilder::new(&http_cfg.url)
        .verify_ssl(http_cfg.verify_ssl)
        .connect_timeout(http_cfg.connect_timeout)
        .request_timeout(http_cfg.request_timeout)
        .enable_gzip(http_cfg.gzip, 1024)
        .ingest_mode(http_cfg.mode);
    if let Some(token) = &http_cfg.token {
        builder = builder.hec_token(token.clone());
    }
    let sender = runtime
        .block_on(builder.build())
        .map_err(|e| e.to_string())?;
    Ok(HttpRuntime { runtime, sender })
}

fn flush_batch(ctx: &mut WorkerCtx) -> std::io::Result<()> {
    if ctx.batch.is_empty() {
        return Ok(());
    }
    let batch = std::mem::take(&mut ctx.batch);
    if let Some(http) = &ctx.http {
        let send_result = http.runtime.block_on(http.sender.send_json_events_with(
            ctx.mode,
            &ctx.metadata,
            &batch,
        ));
        match send_result {
            Ok(_) => {
                ctx.stats.http_batches_ok += 1;
                ctx.pending_delivery_error = None;
                Ok(())
            }
            Err(err) => {
                ctx.stats.http_batches_failed += 1;
                ctx.stats.last_error = Some(err.to_string());
                if let Some(file) = &ctx.file {
                    ctx.pending_delivery_error = None;
                    write_ndjson(file, &batch, &mut ctx.stats)
                } else {
                    let io_err = std::io::Error::other(err.to_string());
                    ctx.pending_delivery_error = Some(std::io::Error::other(err.to_string()));
                    Err(io_err)
                }
            }
        }
    } else if let Some(file) = &ctx.file {
        write_ndjson(file, &batch, &mut ctx.stats)
    } else {
        Err(std::io::Error::other("no log destination available"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::splunk_conf_layering::ConfContext;
    use std::collections::HashMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn file_backend_writes_ndjson_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        let logger = JsonLogger::new(JsonLoggerConfig::file_only(
            FileLoggerConfig::new(&path).with_auto_flush_interval(None),
        ))
        .unwrap();
        logger.set_session_id(42);
        logger.info("hello").unwrap();
        logger
            .log_json(json!({"message": "obj", "code": 7}))
            .unwrap();
        logger.shutdown().unwrap();

        let text = fs::read_to_string(&path).unwrap();
        let mut lines = text.lines().filter(|l| !l.is_empty());
        let first: JsonValue = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(first["message"], "hello");
        assert_eq!(first["sid"], 42);
        assert_eq!(first["level"], "info");
        let second: JsonValue = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(second["message"], "obj");
        assert_eq!(second["code"], 7);
        assert!(first.get("time").is_some());
    }

    #[test]
    fn from_dictionary_selects_hec_when_token_set_and_keeps_file_fallback() {
        let ctx = ConfContext::from_splunk_home("/opt/splunk");
        let mut logging = HashMap::new();
        logging.insert(
            "url".into(),
            "http://127.0.0.1:8088/services/collector/event".into(),
        );
        logging.insert("ingest".into(), "hec".into());
        logging.insert("token".into(), "abc".into());
        logging.insert("file".into(), "$SPLUNK_HOME/var/log/splunk/app.log".into());
        logging.insert("index".into(), "security".into());
        let mut dict = Dictionary::new();
        dict.insert("logging".into(), logging);

        let cfg = JsonLoggerConfig::from_dictionary(&ctx, &dict);
        let http = cfg.http.expect("http");
        assert_eq!(http.mode, IngestMode::SplunkHec);
        assert_eq!(http.token.as_deref(), Some("abc"));
        assert_eq!(http.metadata.index.as_ref(), "security");
        let file = cfg.file.expect("file");
        assert_eq!(
            file.base_path(),
            std::path::PathBuf::from("/opt/splunk/var/log/splunk/app.log")
        );
    }

    #[test]
    fn from_dictionary_custom_mode_ignores_file_only_ingest() {
        let ctx = ConfContext::from_splunk_home("/opt/splunk");
        let mut logging = HashMap::new();
        logging.insert("url".into(), "http://127.0.0.1:8089/stream".into());
        logging.insert("ingest".into(), "custom".into());
        logging.insert("token".into(), "should-not-force-hec".into());
        let mut dict = Dictionary::new();
        dict.insert("http::debprog".into(), logging);

        let cfg = JsonLoggerConfig::from_dictionary(&ctx, &dict);
        let http = cfg.http.expect("http");
        assert_eq!(http.mode, IngestMode::Custom);
        assert_eq!(http.token.as_deref(), Some("should-not-force-hec"));
    }

    #[test]
    fn from_dictionary_picks_http_stanzas_in_name_order() {
        let ctx = ConfContext::from_splunk_home("/opt/splunk");
        let mut zebra = HashMap::new();
        zebra.insert("url".into(), "http://zebra.example/".into());
        let mut alpha = HashMap::new();
        alpha.insert("url".into(), "http://alpha.example/".into());
        let mut dict = Dictionary::new();
        dict.insert("http::zebra".into(), zebra);
        dict.insert("http::alpha".into(), alpha);

        let cfg = JsonLoggerConfig::from_dictionary(&ctx, &dict);
        assert_eq!(cfg.http.expect("http").url, "http://alpha.example/");
    }

    #[test]
    fn http_only_flush_reports_delivery_failure() {
        let mut http = HttpLogConfig::new("http://127.0.0.1:1/collector", IngestMode::Custom);
        http.connect_timeout = Duration::from_millis(200);
        http.request_timeout = Duration::from_millis(200);
        let logger = JsonLogger::new(JsonLoggerConfig {
            http: Some(http),
            file: None,
            session_id: Some(1),
            queue_capacity: Some(16),
            batch_size: 1,
            auto_flush_interval: None,
        })
        .unwrap();
        logger.info("lost").unwrap();
        let err = logger.flush().unwrap_err();
        assert!(
            matches!(err, JsonLoggerError::Io(_)),
            "flush should surface HTTP-only delivery failure, got {err:?}"
        );
        let _ = logger.shutdown();
    }

    #[test]
    fn new_requires_a_destination() {
        let err = JsonLogger::new(JsonLoggerConfig {
            http: None,
            file: None,
            session_id: None,
            queue_capacity: None,
            batch_size: 1,
            auto_flush_interval: None,
        })
        .unwrap_err();
        assert!(matches!(err, JsonLoggerError::NoDestination));
    }

    #[test]
    fn http_custom_mode_posts_json_array() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            listener.set_nonblocking(false).ok();
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 2048];
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(header_end) = find_double_crlf(&buf) {
                            let headers = String::from_utf8_lossy(&buf[..header_end]);
                            let content_len = headers
                                .lines()
                                .find_map(|l| {
                                    l.split_once(':').and_then(|(k, v)| {
                                        k.eq_ignore_ascii_case("content-length")
                                            .then(|| v.trim().parse::<usize>().ok())
                                            .flatten()
                                    })
                                })
                                .unwrap_or(0);
                            let body_start = header_end + 4;
                            while buf.len() < body_start + content_len {
                                match stream.read(&mut tmp) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                }
                            }
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"text\":\"ok\"}",
            );
            buf
        });

        let url = format!("http://{addr}/services/collector/event");
        let logger = JsonLogger::new(JsonLoggerConfig {
            http: Some(
                HttpLogConfig::new(url, IngestMode::Custom)
                    .with_token("must-not-appear")
                    .verify_ssl(true),
            ),
            file: None,
            session_id: Some(1),
            queue_capacity: Some(16),
            batch_size: 1,
            auto_flush_interval: Some(Duration::from_millis(50)),
        })
        .unwrap();
        logger.info("via-http").unwrap();
        logger.flush().unwrap();
        let _ = logger.shutdown();
        let captured = server.join().unwrap();
        let body = extract_http_body(&captured);
        assert!(
            body.trim_start().starts_with('['),
            "custom ingest should send a JSON array, got {body:?}"
        );
        assert!(body.contains("via-http"));
        assert!(
            !String::from_utf8_lossy(&captured)
                .to_ascii_lowercase()
                .contains("authorization"),
            "custom ingest must not send auth"
        );
    }

    fn find_double_crlf(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    fn extract_http_body(buf: &[u8]) -> String {
        if let Some(pos) = find_double_crlf(buf) {
            String::from_utf8_lossy(&buf[pos + 4..]).into_owned()
        } else {
            String::from_utf8_lossy(buf).into_owned()
        }
    }
}
