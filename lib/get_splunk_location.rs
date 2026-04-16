//! Splunk installation location detection.
//!
//! This module provides utilities to automatically detect the Splunk installation
//! directory structure based on the current executable's location.

use std::path::PathBuf;

/// Represents the key paths in a Splunk installation.
///
/// # Fields
///
/// * `root` - The Splunk installation root directory (e.g., `/opt/splunk`)
/// * `app` - The app directory (e.g., `/opt/splunk/etc/apps/myapp`)
/// * `bin` - The bin directory containing executables (e.g., `/opt/splunk/bin`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplunkLocation {
    pub root: PathBuf,
    pub app: PathBuf,
    pub bin: PathBuf,
}

/// Determine Splunk installation location based on the current executable.
///
/// This function analyzes the path of the currently running executable to
/// determine the Splunk installation directory structure. It works both
/// for executables running within a Splunk installation and for standalone
/// executables.
///
/// # Detection logic
///
/// For Splunk environment (executable path contains "splunk"):
/// - Traverses up from the executable to find the root
/// - Assumes structure: `root/bin/...` → root is 4 levels up from bin
///
/// For non-Splunk environment:
/// - Uses parent directories as fallback locations
/// - `root` = executable's grandparent
/// - `app` = executable's parent
/// - `bin` = executable's directory
///
/// # Returns
///
/// `Result<SplunkLocation, io::Error>` containing the detected paths or an error.
///
/// # Examples
///
/// ```rust,no_run
/// use splunklib_rust::get_splunk_location::get_splunk_location;
///
/// match get_splunk_location() {
///     Ok(loc) => {
///         println!("Root: {:?}", loc.root);
///         println!("App: {:?}", loc.app);
///         println!("Bin: {:?}", loc.bin);
///     }
///     Err(e) => eprintln!("Failed to detect location: {}", e),
/// }
/// ```
pub fn get_splunk_location() -> Result<SplunkLocation, std::io::Error> {
    let exe_path = std::env::current_exe()?.canonicalize()?;

    // Normalize to ASCII lowercase for a simple "splunk" substring check.
    let path_text = exe_path.to_string_lossy().to_ascii_lowercase();
    let is_splunk = path_text.contains("splunk");

    // exe_path -> bin_dir -> app_parent -> apps_parent -> etc_parent -> root_candidate
    let bin_dir = exe_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| exe_path.clone());
    let app_parent = bin_dir.parent().map(PathBuf::from);
    let apps_parent = app_parent
        .as_ref()
        .and_then(|p| p.parent())
        .map(PathBuf::from);
    let etc_parent = apps_parent
        .as_ref()
        .and_then(|p| p.parent())
        .map(PathBuf::from);
    let root_candidate = etc_parent
        .as_ref()
        .and_then(|p| p.parent())
        .map(PathBuf::from);

    let (root, app, bin) = 'logic: {
        if is_splunk && let (Some(r), Some(a)) = (root_candidate, app_parent) {
            break 'logic (r, a, bin_dir.clone());
        }

        // Fallback for both Splunk and non-Splunk environments
        let fallback_app = bin_dir
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| bin_dir.clone());
        let fallback_root = fallback_app
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| fallback_app.clone());
        (fallback_root, fallback_app, bin_dir.clone())
    };

    Ok(SplunkLocation { root, app, bin })
}
