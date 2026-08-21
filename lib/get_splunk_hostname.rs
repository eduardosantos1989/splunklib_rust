//! Hostname retrieval utilities for Splunk.
//!
//! Looks up hostname through layered Splunk configuration (`inputs.conf` then
//! `server.conf`), falling back to the system hostname.

use std::io;
use std::path::Path;

use crate::splunk_conf_layering::{ConfContext, read_layered_conf};

/// Retrieve the hostname from Splunk configuration, falling back to system hostname.
///
/// Priority:
/// 1. Layered `inputs.conf` stanza `[default]` key `host`
/// 2. Layered `server.conf` stanza `[general]` key `serverName`
/// 3. System hostname
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::Path;
/// use splunklib_rust::get_splunk_hostname;
///
/// let hostname = get_splunk_hostname(Path::new("/opt/splunk"));
/// println!("Hostname: {}", hostname);
/// ```
pub fn get_splunk_hostname(splunk_root: &Path) -> String {
    match try_get_splunk_hostname(splunk_root) {
        Ok(hostname) => hostname,
        Err(err) => {
            eprintln!(
                "Failed to read layered Splunk hostname configuration: {err}; checking system/local before using the OS hostname"
            );
            highest_priority_local_hostname(splunk_root)
                .unwrap_or_else(|fallback_err| {
                    eprintln!(
                        "Failed to read system/local hostname configuration: {fallback_err}; using the OS hostname"
                    );
                    None
                })
                .unwrap_or_else(get_os_hostname)
        }
    }
}

fn highest_priority_local_hostname(splunk_root: &Path) -> io::Result<Option<String>> {
    for (conf_name, stanza, key) in [
        ("inputs.conf", "default", "host"),
        ("server.conf", "general", "serverName"),
    ] {
        let path = splunk_root.join("etc/system/local").join(conf_name);
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        let path_label = path.to_string_lossy();
        let document = crate::splunk_config_processor::parse_config(&contents, &path_label);
        if let Some(value) = document
            .iter()
            .find(|item| item.name.eq_ignore_ascii_case(stanza))
            .and_then(|item| {
                item.entries
                    .iter()
                    .rev()
                    .find(|entry| entry.key.eq_ignore_ascii_case(key))
            })
            .map(|entry| entry.value.trim())
            .filter(|value| is_usable_hostname(value))
        {
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

/// Try to retrieve hostname from Splunk configuration files.
pub fn try_get_splunk_hostname(splunk_root: &Path) -> io::Result<String> {
    if splunk_root.as_os_str().is_empty() {
        return Ok(get_os_hostname());
    }

    let ctx = ConfContext::from_splunk_home(splunk_root);

    let inputs = read_layered_conf(&ctx, "inputs.conf")?;
    if let Some(host) = inputs
        .value("default", "host")
        .filter(|h| is_usable_hostname(h))
    {
        return Ok(host.to_string());
    }

    let server = read_layered_conf(&ctx, "server.conf")?;
    if let Some(server_name) = server
        .value("general", "serverName")
        .filter(|h| is_usable_hostname(h))
    {
        return Ok(server_name.to_string());
    }

    Ok(get_os_hostname())
}

fn is_usable_hostname(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && !trimmed.eq_ignore_ascii_case("$decideOnStartup")
        && trimmed != "${decideOnStartup}"
}

/// Get the system hostname using the OS hostname facility.
pub fn get_os_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "localhost".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn hostname_prefers_layered_inputs_default_host() {
        let dir = tempfile::tempdir().unwrap();
        let default_dir = dir.path().join("etc/system/default");
        let local_dir = dir.path().join("etc/system/local");
        fs::create_dir_all(&default_dir).unwrap();
        fs::create_dir_all(&local_dir).unwrap();
        fs::write(
            default_dir.join("inputs.conf"),
            "[default]\nhost = from-default\n",
        )
        .unwrap();
        fs::write(
            local_dir.join("inputs.conf"),
            "[default]\nhost = from-local\n",
        )
        .unwrap();

        let hostname = try_get_splunk_hostname(dir.path()).unwrap();
        assert_eq!(hostname, "from-local");
    }

    #[test]
    fn hostname_falls_back_to_server_name() {
        let dir = tempfile::tempdir().unwrap();
        let default_dir = dir.path().join("etc/system/default");
        fs::create_dir_all(&default_dir).unwrap();
        fs::write(
            default_dir.join("server.conf"),
            "[general]\nserverName = idx-01\n",
        )
        .unwrap();

        let hostname = try_get_splunk_hostname(dir.path()).unwrap();
        assert_eq!(hostname, "idx-01");
    }

    #[test]
    fn decide_on_startup_is_not_returned_as_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let default_dir = dir.path().join("etc/system/default");
        fs::create_dir_all(&default_dir).unwrap();
        fs::write(
            default_dir.join("inputs.conf"),
            "[default]\nhost = $decideOnStartup\n",
        )
        .unwrap();
        fs::write(
            default_dir.join("server.conf"),
            "[general]\nserverName = idx-from-server\n",
        )
        .unwrap();

        let hostname = try_get_splunk_hostname(dir.path()).unwrap();
        assert_ne!(hostname, "$decideOnStartup");
        // Expanded sentinel becomes the OS hostname; serverName is only used
        // when host is unset.
        assert_eq!(hostname, get_os_hostname());
    }

    #[test]
    fn public_fallback_preserves_system_local_host_when_an_app_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let local_dir = dir.path().join("etc/system/local");
        let app_default = dir.path().join("etc/apps/broken/default");
        fs::create_dir_all(&local_dir).unwrap();
        fs::create_dir_all(&app_default).unwrap();
        fs::write(
            local_dir.join("inputs.conf"),
            "[default]\nhost = trusted-local\n",
        )
        .unwrap();
        fs::write(app_default.join("app.conf"), [0xff, 0xfe]).unwrap();

        assert!(try_get_splunk_hostname(dir.path()).is_err());
        assert_eq!(get_splunk_hostname(dir.path()), "trusted-local");
    }
}
