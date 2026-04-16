//! Hostname retrieval utilities for Splunk.
//!
//! This module provides functions to retrieve hostnames from Splunk configuration
//! files, with graceful fallback to the system hostname.

use std::io;
use std::path::Path;

/// Retrieve the hostname from Splunk configuration, falling back to system hostname.
///
/// This function attempts to get the hostname from Splunk's configuration files
/// (inputs.conf and server.conf) in the local directory. If that fails, it falls
/// back to the system hostname.
///
/// # Priority order:
/// 1. `inputs.conf` stanza `[default]` key `host`
/// 2. `server.conf` stanza `[general]` key `serverName`
/// 3. System hostname
///
/// # Arguments
///
/// `splunk_root` - Path to the Splunk installation root directory.
/// If empty or invalid, system hostname is returned.
///
/// # Returns
///
/// The hostname as a String.
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::Path;
/// use splunklib_rust::get_splunk_hostname::get_splunk_hostname;
///
/// let hostname = get_splunk_hostname(Path::new("/opt/splunk"));
/// println!("Hostname: {}", hostname);
/// ```
pub fn get_splunk_hostname(splunk_root: &Path) -> String {
    match try_get_splunk_hostname(splunk_root) {
        Ok(hostname) => hostname,
        Err(_) => get_os_hostname(),
    }
}

/// Try to retrieve hostname from Splunk configuration files.
///
/// Returns an error if configuration files are not accessible.
/// On success, returns the hostname found in config or system hostname as fallback.
///
/// # Arguments
///
/// * `splunk_root` - Path to the Splunk installation root directory.
///
/// # Returns
///
/// `io::Result<String>` - The hostname or an I/O error.
pub fn try_get_splunk_hostname(splunk_root: &Path) -> io::Result<String> {
    let local_dir = if splunk_root.as_os_str().is_empty() {
        return Ok(get_os_hostname());
    } else {
        splunk_root.join("etc").join("system").join("local")
    };

    // Read both config files in one pass
    let config_files = [local_dir.join("inputs.conf"), local_dir.join("server.conf")];

    let mut existing_files = Vec::new();
    for f in &config_files {
        if f.try_exists()? {
            existing_files.push(f);
        }
    }

    if !existing_files.is_empty() {
        let dict = crate::splunk_config_processor::read_configs_default(&existing_files);

        // Check inputs.conf first
        if let Some(stanza) = dict.get("default")
            && let Some(host) = stanza.get("host")
        {
            return Ok(host.clone());
        }

        // Check server.conf
        if let Some(stanza) = dict.get("general")
            && let Some(server_name) = stanza.get("serverName")
        {
            return Ok(server_name.clone());
        }
    }

    // Fallback to system hostname
    Ok(get_os_hostname())
}

/// Get the system hostname using the OS hostname facility.
///
/// This function retrieves the system hostname and falls back to "localhost"
/// if the hostname cannot be determined.
///
/// # Returns
///
/// The system hostname as a String, or "localhost" if unavailable.
pub fn get_os_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "localhost".to_string())
}
