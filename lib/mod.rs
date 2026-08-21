//! # Splunk Rust Library
//!
//! A Rust library for integrating with Splunk, providing utilities for:
//! - Discovering Splunk installation locations (`SPLUNK_HOME` and install layout)
//! - Layered reading of Splunk `.conf` files with variable expansion
//! - High-performance file logging with rotation
//! - JSON logging over HTTP (Splunk HEC or a custom collector) with file fallback
//!
//! ## Modules
//!
//! - [`get_splunk_hostname`]: Retrieve hostnames from Splunk configuration or system
//! - [`get_splunk_location`]: Detect Splunk installation paths
//! - [`splunk_config_processor`]: Parse and cache Splunk configuration files
//! - [`splunk_conf_layering`]: btool-style overlay, `[default]` inheritance, `$SPLUNK_*`
//! - [`splunk_conf_spec`]: Load `.conf.spec` files and validate parsed conf
//! - [`splunk_file_locator`]: Recursively search for files in Splunk directories
//! - [`splunk_file_logger`]: Thread-safe file logger with rotation and batching
//! - [`splunk_json_logger`]: JSON logs via HTTP or rotating file
//! - [`splunk_http_sender`]: Send events to Splunk HEC or a custom HTTP endpoint

pub mod get_splunk_hostname;
pub mod get_splunk_location;
pub mod splunk_conf_layering;
pub mod splunk_conf_spec;
pub mod splunk_config_processor;
pub mod splunk_file_locator;
pub mod splunk_file_logger;
pub mod splunk_http_sender;
pub mod splunk_json_logger;

pub use get_splunk_hostname::{get_os_hostname, get_splunk_hostname, try_get_splunk_hostname};
pub use get_splunk_location::{
    SplunkLocation, get_splunk_location, looks_like_splunk_root, splunk_location_from_home,
};
pub use splunk_conf_layering::{
    ConfContext, LayeredConfig, LayeredReadOptions, expand_value, read_layered_conf,
};
pub use splunk_http_sender::{EventMetadata, HttpEventSender, HttpEventSenderBuilder, IngestMode};
pub use splunk_json_logger::{
    HttpLogConfig, JsonLogger, JsonLoggerConfig, JsonLoggerError, LogDestination, LogLevel,
};
