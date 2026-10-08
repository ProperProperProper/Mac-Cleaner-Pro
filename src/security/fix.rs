//! Fix actions. Every fix is a plan of explicit steps that the GUI shows the
//! user verbatim before anything runs. Admin steps go through macOS's own
//! administrator dialog (`osascript … with administrator privileges`) — this
//! app never asks for, stores or logs a password. Steps never contain secret
//! values (Keychain imports read values from the file at apply time and pass
//! them over stdin, never argv, never logs).

use crate::util::{sh_join, sh_quote};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Step {
    /// Run a program as the current user (no shell).
    Run { argv: Vec<String>, allow_fail: bool },
    /// Run a shell script as root via the standard macOS admin dialog.
    Admin { script: String },
    /// Open System Settings (x-apple.systempreferences: URL) or an app bundle id;
    /// the user makes the change there.
    Open { target: String, instruction: String },
    /// chmod a file or folder (current user's files only).
    Chmod { path: String, mode: u32 },
    /// Move a file (used for reversible quarantine).
    Move { from: String, to: String },
    /// Copy a file (used to restore backups on undo).
    CopyFile { from: String, to: String },
    /// Write a non-secret staging file in the app's own folder (e.g. a cleaned
    /// /etc/hosts that an admin step then installs).
    WriteFile { path: String, content: String },
    /// Append a line to a text file (e.g. .gitignore) if not already present.
    AppendLine { path: String, line: String },
    /// Remove an exact line from a text file (undo of AppendLine).
    RemoveLine { path: String, line: String },
    /// Back up a JSON file then remove the given keys (each a path of object keys).
    JsonRemove { path: String, keys: Vec<Vec<String>>, backup: String },
    /// Copy the named variables' values from a file into the login Keychain.
    KeychainImport { file: String, keys: Vec<String>, service: String },
    /// Back up a shell rc file, import the variables into the Keychain, and
    /// rewrite those lines to read from the Keychain at shell start-up.
    RcToKeychain { file: String, keys: Vec<String>, service: String, backup: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Fix {
    pub label: String,
    /// Plain-English list of what will change (before → after).
    pub changes: Vec<String>,
    pub steps: Vec<Step>,
    pub undo: Option<Vec<Step>>,
    /// Extra caution shown in the confirmation (restart, may break X, …).
    pub warning: Option<String>,
}

impl Fix {
    pub fn new(label: impl Into<String>) -> Self {
        Fix { label: label.into(), changes: vec![], steps: vec![], undo: None, warning: None }
    }
    pub fn change(mut self, c: impl Into<String>) -> Self {
        self.changes.push(c.into());
        self
    }
    pub fn step(mut self, s: Step) -> Self {
        self.steps.push(s);
        self
    }
    pub fn undo(mut self, steps: Vec<Step>) -> Self {
        self.undo = Some(steps);
        self
    }
    pub fn warn(mut self, w: impl Into<String>) -> Self {
        self.warning = Some(w.into());
        self
    }
    pub fn needs_admin(&self) -> bool {
        self.steps.iter().any(|s| matches!(s, Step::Admin { .. }))
    }
    pub fn opens_settings(&self) -> bool {
        self.steps.iter().all(|s| matches!(s, Step::Open { .. }))
    }
    pub fn preview(&self) -> Vec<String> {
        self.steps.iter().map(preview_step).collect()
    }
}

// ---- constructors for common steps ----------------------------------------

pub fn run(argv: &[&str]) -> Step {
    Step::Run { argv: argv.iter().map(|s| s.to_string()).collect(), allow_fail: false }
}
pub fn run_lenient(argv: &[&str]) -> Step {
    Step::Run { argv: argv.iter().map(|s| s.to_string()).collect(), allow_fail: true }
}
pub fn admin(script: impl Into<String>) -> Step {
    Step::Admin { script: script.into() }
}
pub fn open(target: &str, instruction: &str) -> Step {
    Step::Open { target: target.into(), instruction: instruction.into() }
}
/// A fix that only opens a System Settings pane.
pub fn settings_fix(label: &str, url: &str, instruction: &str) -> Fix {
    Fix::new(label)
        .change(format!("Opens System Settings. {instruction}"))
        .step(open(url, instruction))
}

/// Well-known System Settings deep links (macOS 13+).
pub mod pane {
    pub const PRIVACY: &str = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension";
    pub const FILEVAULT: &str = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?FileVault";
    pub const LOCKDOWN: &str = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?LockdownMode";
    pub const FDA: &str = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles";
    pub const SHARING: &str = "x-apple.systempreferences:com.apple.Sharing-Settings.extension";
    pub const NETWORK: &str = "x-apple.systempreferences:com.apple.Network-Settings.extension";
    pub const FIREWALL: &str = "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall";
    pub const WIFI: &str = "x-apple.systempreferences:com.apple.wifi-settings-extension";
    pub const LOCK_SCREEN: &str = "x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension";
    pub const USERS: &str = "x-apple.systempreferences:com.apple.Users-Groups-Settings.extension";
    pub const UPDATE: &str = "x-apple.systempreferences:com.apple.Software-Update-Settings.extension";
    pub const LOGIN_ITEMS: &str = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension";
    pub const AIRDROP: &str = "x-apple.systempreferences:com.apple.AirDrop-Handoff-Settings.extension";
    pub const BLUETOOTH: &str = "x-apple.systempreferences:com.apple.BluetoothSettings";
    pub const PROFILES: &str = "x-apple.systempreferences:com.apple.Profiles-Settings.extension";
    pub const APPLE_ID: &str = "x-apple.systempreferences:com.apple.systempreferences.AppleIDSettings";
    pub const EXTENSIONS: &str = "x-apple.systempreferences:com.apple.ExtensionsPreferences";
    pub const KEYCHAIN_APP: &str = "bundle:com.apple.keychainaccess";
}

// ---- preview ----------------------------------------------------------------

pub fn preview_step(s: &Step) -> String {
    match s {
        Step::Run { argv, allow_fail } => {
            format!("{}{}", sh_join(argv), if *allow_fail { "   (errors ignored)" } else { "" })
        }
        Step::Admin { script } => format!("[admin — macOS password dialog] {script}"),
        Step::Open { target, instruction } => format!("open {}   → {instruction}", sh_quote(target)),
        Step::Chmod { path, mode } => format!("chmod {mode:o} {}", sh_quote(path)),
        Step::Move { from, to } => format!("mkdir -p {} && mv {} {}", sh_quote(&parent(to)), sh_quote(from), sh_quote(to)),
        Step::CopyFile { from, to } => format!("cp -p {} {}", sh_quote(from), sh_quote(to)),
        Step::WriteFile { path, content } => format!("write {} ({} lines, staged copy)", sh_quote(path), content.lines().count()),
        Step::AppendLine { path, line } => format!("append line {} to {}", sh_quote(line), sh_quote(path)),
        Step::RemoveLine { path, line } => format!("remove line {} from {}", sh_quote(line), sh_quote(path)),
        Step::JsonRemove { path, keys, backup } => format!(
            "cp -p {} {} && remove key(s) {} from {}",
            sh_quote(path),
            sh_quote(backup),
            keys.iter().map(|k| k.join(".")).collect::<Vec<_>>().join(", "),
            sh_quote(path)
        ),
        Step::KeychainImport { file, keys, service } => format!(
            "for each of {}: security add-generic-password -U -s {} -a <NAME> -w <value read from {}, sent over stdin, never shown>",
            keys.join(", "),
            sh_quote(service),
            sh_quote(file)
        ),
        Step::RcToKeychain { file, keys, service, backup } => format!(
            "store {k} in Keychain service {s} (values via stdin, never shown); cp -p {f} {b}; chmod 600 {b}; rewrite those lines in {f} to: export NAME=\"$(security find-generic-password -s {s} -a NAME -w)\"",
            f = sh_quote(file),
            b = sh_quote(backup),
            k = keys.join(", "),
            s = sh_quote(service)
        ),
    }
}

fn parent(p: &str) -> String {
    Path::new(p).parent().map(|x| x.display().to_string()).unwrap_or_else(|| "/".into())
}

// ---- execution ----------------------------------------------------------------

/// AppleScript string literal for `do shell script`.
pub fn applescript_admin(script: &str) -> String {
    let esc = script.replace('\\', "\\\\").replace('"', "\\\"");
    format!("do shell script \"{esc}\" with administrator privileges")
}

/// Apply steps. With `dry_run` nothing runs; the preview lines are returned.
pub fn apply_steps(steps: &[Step], dry_run: bool) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    for s in steps {
        let p = preview_step(s);
        if dry_run {
            log.push(format!("[dry run] {p}"));
            continue;
        }
        apply_step(s)?;
        log.push(format!("done: {p}"));
    }
    Ok(log)
}

fn apply_step(s: &Step) -> Result<(), String> {
    match s {
        Step::Run { argv, allow_fail } => {
            let (prog, args) = argv.split_first().ok_or("empty command")?;
            let args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let o = crate::cmd::run_timeout(prog, &args, Duration::from_secs(120)).map_err(|e| e.to_string())?;
            if !o.success() && !allow_fail {
                return Err(format!("{} failed: {}", prog, o.combined().trim()));
            }
            Ok(())
        }
        Step::Admin { script } => {
            // Long timeout: installing updates can take a while.
            let o = crate::cmd::run_timeout("osascript", &["-e", &applescript_admin(script)], Duration::from_secs(4 * 3600))
                .map_err(|e| e.to_string())?;
            if o.success() {
                Ok(())
            } else if o.stderr.contains("-128") {
                Err("cancelled in the macOS password dialog — nothing was changed".into())
            } else {
                Err(format!("admin command failed: {}", o.combined().trim()))
            }
        }
        Step::Open { target, .. } => {
            let o = if let Some(b) = target.strip_prefix("bundle:") {
                crate::cmd::run("open", &["-b", b])
            } else {
                crate::cmd::run("open", &[target])
            }
            .map_err(|e| e.to_string())?;
            if o.success() { Ok(()) } else { Err(o.combined()) }
        }
        Step::Chmod { path, mode } => {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                return Err("refusing to chmod a symlink".into());
            }
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode)).map_err(|e| e.to_string())
        }
        Step::Move { from, to } => {
            if Path::new(to).exists() {
                return Err(format!("destination already exists: {to}"));
            }
            std::fs::create_dir_all(parent(to)).map_err(|e| e.to_string())?;
            std::fs::rename(from, to).map_err(|e| e.to_string())
        }
        Step::CopyFile { from, to } => std::fs::copy(from, to).map(|_| ()).map_err(|e| e.to_string()),
        Step::WriteFile { path, content } => {
            std::fs::create_dir_all(parent(path)).map_err(|e| e.to_string())?;
            std::fs::write(path, content).map_err(|e| e.to_string())
        }
        Step::AppendLine { path, line } => {
            let cur = std::fs::read_to_string(path).unwrap_or_default();
            if cur.lines().any(|l| l.trim() == line.trim()) {
                return Ok(());
            }
            let mut new = cur;
            if !new.is_empty() && !new.ends_with('\n') {
                new.push('\n');
            }
            new.push_str(line);
            new.push('\n');
            std::fs::write(path, new).map_err(|e| e.to_string())
        }
        Step::RemoveLine { path, line } => {
            let cur = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let new = remove_line(&cur, line);
            std::fs::write(path, new).map_err(|e| e.to_string())
        }
        Step::JsonRemove { path, keys, backup } => {
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let new = json_remove_keys(&text, keys)?;
            std::fs::create_dir_all(parent(backup)).map_err(|e| e.to_string())?;
            std::fs::copy(path, backup).map_err(|e| e.to_string())?;
            std::fs::write(path, new).map_err(|e| e.to_string())
        }
        Step::KeychainImport { file, keys, service } => {
            let text = std::fs::read_to_string(file).map_err(|e| e.to_string())?;
            keychain_store(&text, keys, service)
        }
        Step::RcToKeychain { file, keys, service, backup } => {
            let text = std::fs::read_to_string(file).map_err(|e| e.to_string())?;
            keychain_store(&text, keys, service)?;
            std::fs::create_dir_all(parent(backup)).map_err(|e| e.to_string())?;
            std::fs::copy(file, backup).map_err(|e| e.to_string())?;
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(backup, std::fs::Permissions::from_mode(0o600));
            }
            std::fs::write(file, rc_rewrite(&text, keys, service)).map_err(|e| e.to_string())
        }
    }
}

/// Quote a value for `security -i` (its parser understands double quotes with
/// backslash escapes).
pub fn security_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Build the `security -i` script that stores the given keys (contains secret
/// values — only ever sent over a pipe, never logged or returned to the UI).
pub fn keychain_script(text: &str, keys: &[String], service: &str) -> (String, usize) {
    let mut script = String::new();
    let mut n = 0;
    for a in super::checks::secrets::parse_assignments(text) {
        if keys.contains(&a.name) {
            script.push_str(&format!(
                "add-generic-password -U -s {} -a {} -w {}\n",
                security_quote(service),
                security_quote(&a.name),
                security_quote(&a.value)
            ));
            n += 1;
        }
    }
    (script, n)
}

fn keychain_store(text: &str, keys: &[String], service: &str) -> Result<(), String> {
    let (script, n) = keychain_script(text, keys, service);
    if n == 0 {
        return Err("none of the variables were found in the file any more".into());
    }
    let o = crate::cmd::run_opts("security", &["-i"], Duration::from_secs(60), Some(script.as_bytes()))
        .map_err(|e| e.to_string())?;
    // Never echo security's output: it could in theory include the input line.
    if o.success() { Ok(()) } else { Err("the security tool reported an error while saving to the Keychain".into()) }
}

/// Rewrite `[export ]NAME=value` lines for the given names to fetch from Keychain.
pub fn rc_rewrite(text: &str, keys: &[String], service: &str) -> String {
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        let (body, nl) = match line.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (line, ""),
        };
        let replaced = super::checks::secrets::parse_assignment_line(body).and_then(|a| {
            if keys.contains(&a.name) {
                let indent: String = body.chars().take_while(|c| c.is_whitespace()).collect();
                let export = if body.trim_start().starts_with("export ") { "export " } else { "" };
                Some(format!(
                    "{indent}{export}{n}=\"$(security find-generic-password -s {s} -a {n} -w 2>/dev/null)\"",
                    n = a.name,
                    s = sh_quote(service)
                ))
            } else {
                None
            }
        });
        out.push_str(&replaced.unwrap_or_else(|| body.to_string()));
        out.push_str(nl);
    }
    out
}

pub fn remove_line(text: &str, line: &str) -> String {
    text.split_inclusive('\n').filter(|l| l.trim_end_matches('\n').trim() != line.trim()).collect()
}

/// Remove keys (paths of object keys) from a JSON document, preserving order.
pub fn json_remove_keys(text: &str, keys: &[Vec<String>]) -> Result<String, String> {
    let mut v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    for path in keys {
        let Some((last, parents)) = path.split_last() else { continue };
        let mut cur = Some(&mut v);
        for p in parents {
            cur = cur.and_then(|c| c.get_mut(p));
        }
        if let Some(obj) = cur.and_then(|c| c.as_object_mut()) {
            obj.shift_remove(last);
        }
    }
    let mut s = serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?;
    s.push('\n');
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applescript_escaping() {
        let s = applescript_admin(r#"echo "a\b""#);
        assert_eq!(s, r#"do shell script "echo \"a\\b\"" with administrator privileges"#);
    }

    #[test]
    fn dry_run_runs_nothing() {
        let tmp = std::env::temp_dir().join(format!("mcp-dry-{}", std::process::id()));
        std::fs::write(&tmp, "x").unwrap();
        let steps = vec![
            Step::Chmod { path: tmp.display().to_string(), mode: 0o600 },
            Step::Move { from: tmp.display().to_string(), to: format!("{}.moved", tmp.display()) },
            admin("/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"),
        ];
        let log = apply_steps(&steps, true).unwrap();
        assert_eq!(log.len(), 3);
        assert!(log.iter().all(|l| l.starts_with("[dry run]")));
        assert!(tmp.exists());
        std::fs::remove_file(&tmp).unwrap();
    }

    #[test]
    fn chmod_and_move_really_work_on_temp_files() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("mcp-fix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("key");
        std::fs::write(&f, "x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let to = d.join("q/sub/key");
        let steps = vec![
            Step::Chmod { path: f.display().to_string(), mode: 0o600 },
            Step::Move { from: f.display().to_string(), to: to.display().to_string() },
        ];
        apply_steps(&steps, false).unwrap();
        assert_eq!(std::fs::metadata(&to).unwrap().permissions().mode() & 0o777, 0o600);
        // undo
        apply_steps(&[Step::Move { from: to.display().to_string(), to: f.display().to_string() }], false).unwrap();
        assert!(f.exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn preview_never_contains_values() {
        let s = Step::KeychainImport { file: "/p/.env".into(), keys: vec!["API_KEY".into()], service: "svc".into() };
        let p = preview_step(&s);
        assert!(p.contains("API_KEY"));
        assert!(p.contains("never shown"));
    }

    #[test]
    fn keychain_script_quotes_and_selects() {
        let text = "API_KEY=\"ab\\\"c d\"\nOTHER_TOKEN=zzz\nPLAIN=1\n";
        let (s, n) = keychain_script(text, &["API_KEY".into()], "svc");
        assert_eq!(n, 1);
        assert!(s.starts_with("add-generic-password -U -s \"svc\" -a \"API_KEY\" -w "));
        assert!(!s.contains("zzz"));
    }

    #[test]
    fn rc_rewrite_only_named_lines() {
        let text = "# hi\nexport OPENAI_API_KEY=sk-fake123\n  GH_TOKEN='fake'\nexport PATH=/x:$PATH\n";
        let out = rc_rewrite(text, &["OPENAI_API_KEY".into(), "GH_TOKEN".into()], "mcp:zshrc");
        assert!(!out.contains("sk-fake123"));
        assert!(!out.contains("'fake'"));
        assert!(out.contains("export OPENAI_API_KEY=\"$(security find-generic-password -s mcp:zshrc -a OPENAI_API_KEY -w 2>/dev/null)\""));
        assert!(out.contains("  GH_TOKEN=\"$(security"));
        assert!(out.contains("export PATH=/x:$PATH\n"));
        assert!(out.starts_with("# hi\n"));
    }

    #[test]
    fn json_remove_preserves_rest() {
        let t = r#"{"theme":"dark","skipDangerousModePermissionPrompt":true,"permissions":{"defaultMode":"bypassPermissions","allow":["Read"]}}"#;
        let out = json_remove_keys(
            t,
            &[vec!["skipDangerousModePermissionPrompt".into()], vec!["permissions".into(), "defaultMode".into()]],
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("skipDangerousModePermissionPrompt").is_none());
        assert!(v["permissions"].get("defaultMode").is_none());
        assert_eq!(v["permissions"]["allow"][0], "Read");
        assert!(out.find("theme").unwrap() < out.find("permissions").unwrap());
    }

    #[test]
    fn append_and_remove_line() {
        let p = std::env::temp_dir().join(format!("mcp-gi-{}", std::process::id()));
        std::fs::write(&p, "target/").unwrap();
        let ps = p.display().to_string();
        apply_steps(&[Step::AppendLine { path: ps.clone(), line: ".env".into() }], false).unwrap();
        apply_steps(&[Step::AppendLine { path: ps.clone(), line: ".env".into() }], false).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "target/\n.env\n");
        apply_steps(&[Step::RemoveLine { path: ps, line: ".env".into() }], false).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "target/\n");
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn fix_serde_roundtrip() {
        let f = Fix::new("x").step(run(&["true"])).undo(vec![admin("true")]);
        let j = serde_json::to_string(&f.undo).unwrap();
        let back: Option<Vec<Step>> = serde_json::from_str(&j).unwrap();
        assert_eq!(back, f.undo);
    }
}
