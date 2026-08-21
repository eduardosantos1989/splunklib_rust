//! Splunk installation location detection.
//!
//! Resolution order:
//! 1. `SPLUNK_HOME` environment variable
//! 2. Walk ancestors of the current executable looking for a Splunk root
//!    (`etc/system` + `bin`)
//! 3. Standalone fallback based on the executable directory

use std::fs;
use std::path::{Path, PathBuf};

/// Represents the key paths in a Splunk installation.
///
/// # Fields
///
/// * `root` - The Splunk installation root directory (e.g., `/opt/splunk`)
/// * `app` - The current app directory when running from `etc/apps/<app>`,
///   otherwise `$SPLUNK_HOME/etc/apps`
/// * `bin` - The bin directory containing executables (e.g., `/opt/splunk/bin`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplunkLocation {
    pub root: PathBuf,
    pub app: PathBuf,
    pub bin: PathBuf,
}

/// Determine Splunk installation location.
///
/// # Detection logic
///
/// 1. If `SPLUNK_HOME` is set, use [`splunk_location_from_home`].
/// 2. Otherwise walk up from the current executable until a directory that
///    looks like a Splunk root is found (`etc/system` and `bin` both exist).
/// 3. If the process is not inside a Splunk install, fall back to parent
///    directories of the executable.
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
    if let Some(home) = std::env::var_os("SPLUNK_HOME")
        && !home.is_empty()
    {
        return splunk_location_from_home(PathBuf::from(home));
    }
    detect_from_exe()
}

/// Build a [`SplunkLocation`] from an explicit Splunk home directory.
pub fn splunk_location_from_home(home: impl Into<PathBuf>) -> std::io::Result<SplunkLocation> {
    let home_in = home.into();
    if home_in.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SPLUNK_HOME is empty",
        ));
    }
    let home = fs::canonicalize(&home_in).unwrap_or(home_in);
    let bin = home.join("bin");
    let app = detect_app_dir(&home).unwrap_or_else(|| home.join("etc").join("apps"));
    Ok(SplunkLocation {
        root: home,
        app,
        bin,
    })
}

/// True when `path` looks like `$SPLUNK_HOME` (has `etc/system` and `bin`).
pub fn looks_like_splunk_root(path: &Path) -> bool {
    path.join("etc").join("system").is_dir() && path.join("bin").is_dir()
}

fn detect_from_exe() -> std::io::Result<SplunkLocation> {
    let exe_path = std::env::current_exe()?.canonicalize()?;
    if let Some(root) = exe_path.ancestors().find(|p| looks_like_splunk_root(p)) {
        return splunk_location_from_home(root.to_path_buf());
    }

    let bin_dir = exe_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| exe_path.clone());
    let fallback_app = bin_dir
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| bin_dir.clone());
    let fallback_root = fallback_app
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| fallback_app.clone());
    Ok(SplunkLocation {
        root: fallback_root,
        app: fallback_app,
        bin: bin_dir,
    })
}

fn detect_app_dir(home: &Path) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let apps = home.join("etc").join("apps");
    let apps_canon = fs::canonicalize(&apps).ok()?;
    let rel = exe.strip_prefix(&apps_canon).ok()?;
    let app_name = rel.components().next()?;
    Some(apps.join(app_name.as_os_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn fake_splunk_home() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("bin")).unwrap();
        fs::create_dir_all(dir.path().join("etc").join("system").join("default")).unwrap();
        fs::create_dir_all(dir.path().join("etc").join("apps")).unwrap();
        dir
    }

    #[test]
    fn location_from_home_uses_bin_and_apps() {
        let home = fake_splunk_home();
        let loc = splunk_location_from_home(home.path()).unwrap();
        assert_eq!(loc.bin, loc.root.join("bin"));
        assert_eq!(loc.app, loc.root.join("etc").join("apps"));
        assert!(looks_like_splunk_root(&loc.root));
    }

    #[test]
    fn get_splunk_location_honors_splunk_home() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = fake_splunk_home();
        let prev = std::env::var_os("SPLUNK_HOME");
        // SAFETY: tests that touch SPLUNK_HOME take ENV_LOCK.
        unsafe {
            std::env::set_var("SPLUNK_HOME", home.path());
        }
        let loc = get_splunk_location().unwrap();
        match prev {
            Some(v) => unsafe { std::env::set_var("SPLUNK_HOME", v) },
            None => unsafe { std::env::remove_var("SPLUNK_HOME") },
        }
        assert_eq!(loc.root, fs::canonicalize(home.path()).unwrap());
        assert_eq!(loc.bin, loc.root.join("bin"));
    }

    #[test]
    fn empty_splunk_home_is_invalid() {
        let err = splunk_location_from_home("").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
