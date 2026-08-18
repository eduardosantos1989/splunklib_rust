//! Splunk configuration layering, `[default]` inheritance, and variable expansion.
//!
//! Splunk does not treat a single `.conf` file as the source of truth. Values
//! are overlaid from several directories, later layers winning:
//!
//! 1. `etc/system/default`
//! 2. `etc/apps/*/default` (then `slave-apps` / `peer-apps`)
//! 3. `etc/system/local`
//! 4. `etc/apps/*/local` (then `slave-apps` / `peer-apps`)
//! 5. `etc/users/*/<app>/local`
//!
//! Apps are applied in ASCII name order, with `[install] priority` in `app.conf`
//! as a tie-break (higher priority is applied later and therefore wins). Apps
//! with `[install] state = disabled` are skipped unless requested.
//!
//! After the overlay, `[default]` keys are copied into other stanzas when
//! missing, then `$SPLUNK_HOME`, `$SPLUNK_DB`, `$_index_name`, and other
//! `$VAR` / `${VAR}` references are expanded.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::splunk_config_processor::{self, Dictionary, MergePrecedence, read_configs_last_wins};

/// Runtime paths and identity used while reading and expanding conf files.
#[derive(Debug, Clone)]
pub struct ConfContext {
    pub splunk_home: PathBuf,
    pub splunk_db: PathBuf,
    pub splunk_etc: PathBuf,
    /// Current app folder name (`myapp`), when known.
    pub app: Option<String>,
    pub hostname: String,
}

impl ConfContext {
    /// Build a context from `$SPLUNK_HOME` (or any equivalent root path).
    ///
    /// `SPLUNK_DB` is taken from the environment when set, otherwise
    /// `$SPLUNK_HOME/var/lib/splunk`.
    pub fn from_splunk_home(home: impl Into<PathBuf>) -> Self {
        let splunk_home = home.into();
        let splunk_db = std::env::var_os("SPLUNK_DB")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| splunk_home.join("var").join("lib").join("splunk"));
        let splunk_etc = splunk_home.join("etc");
        Self {
            splunk_home,
            splunk_db,
            splunk_etc,
            app: None,
            hostname: crate::get_splunk_hostname::get_os_hostname(),
        }
    }

    /// Build a context from a detected [`crate::SplunkLocation`].
    pub fn from_location(loc: &crate::get_splunk_location::SplunkLocation) -> Self {
        let mut ctx = Self::from_splunk_home(loc.root.clone());
        ctx.app = app_name_from_dir(&loc.app);
        ctx
    }

    /// Build a context from `SPLUNK_HOME` or auto-detected location.
    pub fn from_env() -> io::Result<Self> {
        let loc = crate::get_splunk_location::get_splunk_location()?;
        Ok(Self::from_location(&loc))
    }

    /// Variable map used by [`expand_value`], including stanza-specific
    /// `$_index_name` when `stanza` is an index-like name.
    pub fn variable_map(&self, stanza: Option<&str>) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert(
            "SPLUNK_HOME".to_string(),
            self.splunk_home.display().to_string(),
        );
        vars.insert(
            "SPLUNK_DB".to_string(),
            self.splunk_db.display().to_string(),
        );
        vars.insert(
            "SPLUNK_ETC".to_string(),
            self.splunk_etc.display().to_string(),
        );
        vars.insert("HOSTNAME".to_string(), self.hostname.clone());
        if let Some(app) = &self.app {
            vars.insert("APP".to_string(), app.clone());
        }
        if let Some(stanza) = stanza
            && stanza != "default"
            && !stanza.starts_with("volume:")
        {
            vars.insert("_index_name".to_string(), stanza.to_string());
        }
        vars
    }
}

/// Options for [`read_layered_conf_with_options`].
#[derive(Debug, Clone)]
pub struct LayeredReadOptions {
    /// Copy `[default]` keys into other stanzas when the key is absent.
    pub inherit_default: bool,
    /// Expand `$SPLUNK_HOME`, `$SPLUNK_DB`, `$_index_name`, and env vars.
    pub expand_variables: bool,
    /// Include apps whose `app.conf` has `[install] state = disabled`.
    pub include_disabled_apps: bool,
    /// When set, only this app (plus system and matching user dirs) is read.
    pub app_filter: Option<String>,
}

impl Default for LayeredReadOptions {
    fn default() -> Self {
        Self {
            inherit_default: true,
            expand_variables: true,
            include_disabled_apps: false,
            app_filter: None,
        }
    }
}

/// Result of a layered conf read: merged dictionary plus the files used.
#[derive(Debug, Clone)]
pub struct LayeredConfig {
    pub dict: Dictionary,
    /// Absolute or original paths, lowest priority first.
    pub sources: Vec<PathBuf>,
}

impl LayeredConfig {
    pub fn stanza(&self, name: &str) -> Option<&HashMap<String, String>> {
        self.dict.get(name)
    }

    pub fn value(&self, stanza: &str, key: &str) -> Option<&str> {
        self.dict
            .get(stanza)
            .and_then(|keys| keys.get(key))
            .map(String::as_str)
    }
}

/// Read `conf_file_name` (e.g. `inputs.conf`) using default layering options.
pub fn read_layered_conf(ctx: &ConfContext, conf_file_name: &str) -> io::Result<LayeredConfig> {
    read_layered_conf_with_options(ctx, conf_file_name, &LayeredReadOptions::default())
}

/// Read and overlay a conf file using Splunk directory precedence.
pub fn read_layered_conf_with_options(
    ctx: &ConfContext,
    conf_file_name: &str,
    options: &LayeredReadOptions,
) -> io::Result<LayeredConfig> {
    let sources = collect_conf_sources(ctx, conf_file_name, options);
    let mut dict = if sources.is_empty() {
        let mut dict = Dictionary::new();
        dict.insert("default".to_string(), HashMap::new());
        dict
    } else {
        read_configs_last_wins(&sources)
    };

    if options.inherit_default {
        inherit_default_stanza(&mut dict);
    }
    if options.expand_variables {
        expand_dictionary(ctx, &mut dict);
    }

    Ok(LayeredConfig { dict, sources })
}

/// List conf files in Splunk overlay order (lowest priority first).
pub fn collect_conf_sources(
    ctx: &ConfContext,
    conf_file_name: &str,
    options: &LayeredReadOptions,
) -> Vec<PathBuf> {
    let etc = &ctx.splunk_etc;
    let mut files = Vec::new();

    push_if_file(
        &mut files,
        &etc.join("system").join("default"),
        conf_file_name,
    );

    let app_roots = [
        etc.join("apps"),
        etc.join("slave-apps"),
        etc.join("peer-apps"),
    ];
    let layered_apps: Vec<Vec<AppMeta>> = app_roots
        .iter()
        .map(|root| list_app_dirs(root, options))
        .collect();

    for apps in &layered_apps {
        for app in apps {
            push_if_file(&mut files, &app.path.join("default"), conf_file_name);
        }
    }

    push_if_file(
        &mut files,
        &etc.join("system").join("local"),
        conf_file_name,
    );

    for apps in &layered_apps {
        for app in apps {
            push_if_file(&mut files, &app.path.join("local"), conf_file_name);
        }
    }

    collect_user_confs(etc, conf_file_name, options, &mut files);
    files
}

/// Copy keys from `[default]` into every other stanza when absent.
pub fn inherit_default_stanza(dict: &mut Dictionary) {
    let defaults = dict.get("default").cloned().unwrap_or_default();
    if defaults.is_empty() {
        return;
    }
    for (stanza, keys) in dict.iter_mut() {
        if stanza == "default" {
            continue;
        }
        for (key, value) in &defaults {
            keys.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
}

/// Expand Splunk/environment variables in every value of `dict`.
pub fn expand_dictionary(ctx: &ConfContext, dict: &mut Dictionary) {
    for (stanza, keys) in dict.iter_mut() {
        let vars = ctx.variable_map(Some(stanza.as_str()));
        for value in keys.values_mut() {
            *value = expand_value(value, &vars);
        }
    }
}

/// Expand `$VAR`, `${VAR}`, and `$$` (escaped dollar) in `input`.
///
/// Known names come from `vars` first, then the process environment.
/// Unknown references are left unchanged.
pub fn expand_value(input: &str, vars: &HashMap<String, String>) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '$' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        if i + 1 < chars.len() && chars[i + 1] == '$' {
            out.push('$');
            i += 2;
            continue;
        }
        if i + 1 < chars.len() && chars[i + 1] == '{' {
            if let Some(rel_end) = chars[i + 2..].iter().position(|&c| c == '}') {
                let name: String = chars[i + 2..i + 2 + rel_end].iter().collect();
                if is_ident(&name) {
                    if let Some(value) = lookup_var(&name, vars) {
                        out.push_str(&value);
                    } else {
                        out.push_str("${");
                        out.push_str(&name);
                        out.push('}');
                    }
                    i += 3 + rel_end;
                    continue;
                }
            }
            out.push('$');
            i += 1;
            continue;
        }

        let rest = &chars[i + 1..];
        let mut ident_len = 0usize;
        for (idx, ch) in rest.iter().enumerate() {
            let ok = if idx == 0 {
                ch.is_ascii_alphabetic() || *ch == '_'
            } else {
                ch.is_ascii_alphanumeric() || *ch == '_'
            };
            if !ok {
                break;
            }
            ident_len = idx + 1;
        }
        if ident_len > 0 {
            let name: String = rest[..ident_len].iter().collect();
            if let Some(value) = lookup_var(&name, vars) {
                out.push_str(&value);
                i += 1 + ident_len;
                continue;
            }
        }
        out.push('$');
        i += 1;
    }
    out
}

fn lookup_var(name: &str, vars: &HashMap<String, String>) -> Option<String> {
    vars.get(name)
        .cloned()
        .or_else(|| std::env::var(name).ok().filter(|v| !v.is_empty()))
}

fn is_ident(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn app_name_from_dir(app_dir: &Path) -> Option<String> {
    let name = app_dir.file_name()?.to_string_lossy();
    if name == "apps" || name == "slave-apps" || name == "peer-apps" {
        return None;
    }
    Some(name.into_owned())
}

fn push_if_file(files: &mut Vec<PathBuf>, dir: &Path, conf_file_name: &str) {
    let path = dir.join(conf_file_name);
    if path.is_file() {
        files.push(path);
    }
}

#[derive(Debug, Clone)]
struct AppMeta {
    name: String,
    path: PathBuf,
    priority: i64,
}

fn list_app_dirs(apps_root: &Path, options: &LayeredReadOptions) -> Vec<AppMeta> {
    let Ok(entries) = fs::read_dir(apps_root) else {
        return Vec::new();
    };
    let mut apps = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') {
            continue;
        }
        if let Some(filter) = &options.app_filter
            && filter != name_str.as_ref()
        {
            continue;
        }
        let path = entry.path();
        let (enabled, priority) = read_app_install(&path);
        if !enabled && !options.include_disabled_apps {
            continue;
        }
        apps.push(AppMeta {
            name: name_str.into_owned(),
            path,
            priority,
        });
    }
    apps.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.name.cmp(&b.name))
    });
    apps
}

fn read_app_install(app_dir: &Path) -> (bool, i64) {
    let app_conf = app_dir.join("default").join("app.conf");
    let app_conf_local = app_dir.join("local").join("app.conf");
    let mut enabled = true;
    let mut priority = 0i64;
    for path in [&app_conf, &app_conf_local] {
        if !path.is_file() {
            continue;
        }
        let dict = splunk_config_processor::merge_configs(&[path], MergePrecedence::LastWins);
        if let Some(install) = dict.get("install") {
            if let Some(state) = install.get("state")
                && state.eq_ignore_ascii_case("disabled")
            {
                enabled = false;
            } else if let Some(state) = install.get("state")
                && state.eq_ignore_ascii_case("enabled")
            {
                enabled = true;
            }
            if let Some(value) = install.get("priority")
                && let Ok(parsed) = value.trim().parse::<i64>()
            {
                priority = parsed;
            }
        }
    }
    (enabled, priority)
}

fn collect_user_confs(
    etc: &Path,
    conf_file_name: &str,
    options: &LayeredReadOptions,
    files: &mut Vec<PathBuf>,
) {
    let users_root = etc.join("users");
    let Ok(users) = fs::read_dir(&users_root) else {
        return;
    };
    let mut user_dirs: Vec<PathBuf> = users
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    user_dirs.sort();
    for user_dir in user_dirs {
        let Ok(apps) = fs::read_dir(&user_dir) else {
            continue;
        };
        let mut app_dirs: Vec<PathBuf> = apps
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.path())
            .collect();
        app_dirs.sort();
        for app_dir in app_dirs {
            if let Some(filter) = &options.app_filter {
                let name = app_dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name != filter {
                    continue;
                }
            }
            push_if_file(files, &app_dir.join("local"), conf_file_name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn fake_home() -> (tempfile::TempDir, ConfContext) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("bin")).unwrap();
        fs::create_dir_all(dir.path().join("etc").join("system").join("default")).unwrap();
        let ctx = ConfContext::from_splunk_home(dir.path());
        (dir, ctx)
    }

    #[test]
    fn expand_value_handles_dollar_forms_and_index_name() {
        let mut vars = HashMap::new();
        vars.insert("SPLUNK_HOME".into(), "/opt/splunk".into());
        vars.insert("SPLUNK_DB".into(), "/opt/splunk/var/lib/splunk".into());
        vars.insert("_index_name".into(), "netflow".into());

        assert_eq!(expand_value("$SPLUNK_HOME/etc", &vars), "/opt/splunk/etc");
        assert_eq!(
            expand_value("${SPLUNK_DB}/$_index_name/db", &vars),
            "/opt/splunk/var/lib/splunk/netflow/db"
        );
        assert_eq!(expand_value("cost is $$5", &vars), "cost is $5");
        assert_eq!(expand_value("keep $UNKNOWN", &vars), "keep $UNKNOWN");
    }

    #[test]
    fn layering_applies_local_over_default_and_inherits_default_keys() {
        let (_dir, ctx) = fake_home();
        write(
            &ctx.splunk_etc
                .join("system")
                .join("default")
                .join("inputs.conf"),
            "[default]\nhost = default-host\nindex = main\n",
        );
        write(
            &ctx.splunk_etc
                .join("apps")
                .join("myapp")
                .join("default")
                .join("inputs.conf"),
            "[monitor://app.log]\nindex = app-index\n",
        );
        write(
            &ctx.splunk_etc
                .join("system")
                .join("local")
                .join("inputs.conf"),
            "[default]\nhost = local-host\n",
        );
        write(
            &ctx.splunk_etc
                .join("apps")
                .join("myapp")
                .join("local")
                .join("inputs.conf"),
            "[monitor://app.log]\nsourcetype = local-st\n",
        );

        let layered = read_layered_conf(&ctx, "inputs.conf").unwrap();
        assert_eq!(layered.value("default", "host"), Some("local-host"));
        assert_eq!(layered.value("default", "index"), Some("main"));
        assert_eq!(
            layered.value("monitor://app.log", "index"),
            Some("app-index")
        );
        assert_eq!(
            layered.value("monitor://app.log", "sourcetype"),
            Some("local-st")
        );
        assert_eq!(
            layered.value("monitor://app.log", "host"),
            Some("local-host")
        );
        assert!(layered.sources.len() >= 4);
    }

    #[test]
    fn disabled_apps_are_skipped_and_priority_orders_overlay() {
        let (_dir, ctx) = fake_home();
        write(
            &ctx.splunk_etc
                .join("apps")
                .join("aaa")
                .join("default")
                .join("app.conf"),
            "[install]\nstate = enabled\npriority = 10\n",
        );
        write(
            &ctx.splunk_etc
                .join("apps")
                .join("aaa")
                .join("default")
                .join("inputs.conf"),
            "[default]\nhost = from-aaa\n",
        );
        write(
            &ctx.splunk_etc
                .join("apps")
                .join("zzz")
                .join("default")
                .join("app.conf"),
            "[install]\nstate = enabled\npriority = 0\n",
        );
        write(
            &ctx.splunk_etc
                .join("apps")
                .join("zzz")
                .join("default")
                .join("inputs.conf"),
            "[default]\nhost = from-zzz\n",
        );
        write(
            &ctx.splunk_etc
                .join("apps")
                .join("off")
                .join("default")
                .join("app.conf"),
            "[install]\nstate = disabled\n",
        );
        write(
            &ctx.splunk_etc
                .join("apps")
                .join("off")
                .join("default")
                .join("inputs.conf"),
            "[default]\nhost = from-disabled\n",
        );

        let layered = read_layered_conf(&ctx, "inputs.conf").unwrap();
        assert_eq!(layered.value("default", "host"), Some("from-aaa"));
        assert_ne!(layered.value("default", "host"), Some("from-disabled"));
    }

    #[test]
    fn user_local_wins_and_variables_expand_per_stanza() {
        let (_dir, mut ctx) = fake_home();
        ctx.app = Some("search".into());
        write(
            &ctx.splunk_etc
                .join("system")
                .join("default")
                .join("indexes.conf"),
            "[default]\nhomePath = $SPLUNK_DB/$_index_name/db\n",
        );
        write(
            &ctx.splunk_etc
                .join("apps")
                .join("search")
                .join("default")
                .join("indexes.conf"),
            "[netflow]\nmaxTotalDataSizeMB = 100\n",
        );
        write(
            &ctx.splunk_etc
                .join("users")
                .join("admin")
                .join("search")
                .join("local")
                .join("indexes.conf"),
            "[netflow]\nmaxTotalDataSizeMB = 250\n",
        );

        let layered = read_layered_conf(&ctx, "indexes.conf").unwrap();
        let expected = format!("{}/netflow/db", ctx.splunk_db.display());
        assert_eq!(
            layered.value("netflow", "homePath"),
            Some(expected.as_str())
        );
        assert_eq!(layered.value("netflow", "maxTotalDataSizeMB"), Some("250"));
    }

    #[test]
    fn inherit_can_be_disabled() {
        let (_dir, ctx) = fake_home();
        write(
            &ctx.splunk_etc
                .join("system")
                .join("default")
                .join("inputs.conf"),
            "[default]\nindex = main\n[monitor://x]\nsourcetype = log\n",
        );
        let opts = LayeredReadOptions {
            inherit_default: false,
            ..LayeredReadOptions::default()
        };
        let layered = read_layered_conf_with_options(&ctx, "inputs.conf", &opts).unwrap();
        assert_eq!(layered.value("monitor://x", "sourcetype"), Some("log"));
        assert_eq!(layered.value("monitor://x", "index"), None);
    }
}
