//! # Splunk Rust Library
//!
//! A Rust library for integrating with Splunk, providing utilities for:
//! - Discovering Splunk installation locations
//! - Reading and processing Splunk configuration files
//! - High-performance file logging with rotation
//! - Sending events to Splunk HTTP Event Collector (HEC)
//!
//! ## Modules
//!
//! - [`get_splunk_hostname`]: Retrieve hostnames from Splunk configuration or system
//! - [`get_splunk_location`]: Detect Splunk installation paths
//! - [`splunk_config_processor`]: Parse and cache Splunk configuration files
//! - [`splunk_file_locator`]: Recursively search for files in Splunk directories
//! - [`splunk_file_logger`]: Thread-safe file logger with rotation and batching
//! - [`splunk_http_sender`]: Send events to Splunk HEC with gzip compression

pub mod get_splunk_hostname;
pub mod get_splunk_location;
pub mod splunk_conf_spec;
pub mod splunk_config_processor;
pub mod splunk_file_locator;
pub mod splunk_file_logger;
pub mod splunk_http_sender;
