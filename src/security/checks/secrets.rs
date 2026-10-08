//! Plaintext secrets in shell rc files, home credential files, launch agent
//! environments and ~/Projects. Only file paths and variable/key NAMES are
//! ever reported — values are read into memory to decide "is this a real
//! value?" and then dropped.

use super::super::fix::{Fix, Step, run, run_lenient};
use super::super::{Category::Secrets, Ctx, Finding, Status};
use crate::cmd;
use crate::util::tilde;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub name: String,
    pub value: String,
}

fn valid_name(n: &str) -> bool {
    let mut c = n.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
        && n.chars().all(|ch| ch.is_ascii_alphanumeric() || "_-.".contains(ch))
}

fn unquote(v: &str) -> String {
    let v = v.trim().trim_end_matches(',').trim();
    if v.len() >= 2 && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\''))) {
        let inner = &v[1..v.len() - 1];
        if v.starts_with('"') {
            return inner.replace("\\\"", "\"").replace("\\\\", "\\");
        }
        return inner.to_string();
    }
    // Unquoted: drop trailing " # comment".
    match v.find(" #") {
        Some(i) => v[..i].trim().to_string(),
        None => v.to_string(),
    }
}

/// Parse one `NAME=value`, `export NAME=value`, `name = value`, `name: value`
/// or `"name": "value"` line.
pub fn parse_assignment_line(line: &str) -> Option<Assignment> {
    let l = line.trim();
    if l.is_empty() || l.starts_with('#') || l.starts_with("//") || l.starts_with(';') {
        return None;
    }
    let l = l.strip_prefix("export ").map(|s| s.trim_start()).unwrap_or(l);
    // Pick the earliest separator among '=' and ':'.
    let eq = l.find('=');
    let colon = l.find(':');
    let (idx, sep) = match (eq, colon) {
        (Some(e), Some(c)) if c < e => (c, ':'),
        (Some(e), _) => (e, '='),
        (None, Some(c)) => (c, ':'),
        _ => return None,
    };
    let raw_name = l[..idx].trim().trim_matches('"').trim_matches('\'');
    let _ = sep;
    if !valid_name(raw_name) {
        return None;
    }
    let value = unquote(&l[idx + 1..]);
    Some(Assignment { name: raw_name.to_string(), value })
}

pub fn parse_assignments(text: &str) -> Vec<Assignment> {
    text.lines().filter_map(parse_assignment_line).collect()
}

fn segments(name: &str) -> Vec<String> {
    // camelCase → snake, then split on _ - .
    let mut s = String::new();
    let mut prev_lower = false;
    for ch in name.chars() {
        if ch.is_ascii_uppercase() && prev_lower {
            s.push('_');
        }
        prev_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        s.push(ch.to_ascii_uppercase());
    }
    s.split(['_', '-', '.']).filter(|x| !x.is_empty()).map(String::from).collect()
}

/// Does a variable/key name look like it holds a secret?
pub fn is_secret_name(name: &str) -> bool {
    let seg = segments(name);
    if seg.is_empty() {
        return false;
    }
    const NOT: [&str; 14] = ["FILE", "PATH", "URL", "URI", "ENDPOINT", "DIR", "NAME", "TYPE", "LENGTH", "LEN", "ID", "HEADER", "PROMPT", "FIELD"];
    if NOT.contains(&seg.last().unwrap().as_str()) {
        return false;
    }
    if seg.iter().any(|s| ["MAX", "MIN", "NUM", "COUNT", "LIMIT"].contains(&s.as_str())) {
        return false;
    }
    const WORDS: [&str; 12] = [
        "TOKEN", "SECRET", "SECRETS", "PASSWORD", "PASSWD", "PASS", "PASSPHRASE", "APIKEY", "CREDENTIAL", "CREDENTIALS", "PRIVATEKEY", "AUTHTOKEN",
    ];
    const KEY_PREFIX: [&str; 9] = ["API", "ACCESS", "PRIVATE", "SECRET", "AUTH", "SIGNING", "ENCRYPTION", "CLIENT", "MASTER"];
    for (i, s) in seg.iter().enumerate() {
        if WORDS.contains(&s.as_str()) {
            return true;
        }
        if s == "KEY" && i > 0 && KEY_PREFIX.contains(&seg[i - 1].as_str()) {
            return true;
        }
    }
    false
}

/// Values that are clearly not real secrets (empty, references, placeholders).
pub fn is_placeholder(v: &str) -> bool {
    let t = v.trim();
    let l = t.to_lowercase();
    if t.chars().count() < 4 {
        return true;
    }
    if t.starts_with('$') || t.contains("${") || t.contains("$(") || t.starts_with('%') || t.starts_with("{{") {
        return true;
    }
    if (t.starts_with('<') && t.ends_with('>')) || (t.starts_with('[') && t.ends_with(']')) || t.starts_with('{') {
        return true;
    }
    const WORDS: [&str; 16] = [
        "changeme", "change_me", "change-me", "xxxx", "todo", "none", "null", "false", "true", "placeholder", "example", "redacted", "secret", "password", "undefined", "dummy",
    ];
    if WORDS.contains(&l.as_str()) {
        return true;
    }
    if l.starts_with("your") || l.contains("your_") || l.contains("your-") || l.ends_with("_here") || l.ends_with("-here") || l.contains("example") {
        return true;
    }
    if l.contains("process.env") || l.contains("os.environ") || l.contains("getenv") || l.contains("keychain") {
        return true;
    }
    let first = t.chars().next().unwrap();
    t.chars().all(|c| c == first) || t.chars().all(|c| c == '*' || c == 'x' || c == 'X' || c == '.')
}

/// Secret-looking names with a real-looking value (names only are returned).
pub fn secret_names_in_text(text: &str) -> Vec<String> {
    let mut v: Vec<String> = vec![];
    for a in parse_assignments(text) {
        if is_secret_name(&a.name) && !is_placeholder(&a.value) && !v.contains(&a.name) {
            v.push(a.name);
        }
    }
    // npm style: //registry.npmjs.org/:_authToken=...
    for l in text.lines() {
        for k in ["_authToken=", "_auth=", "_password="] {
            if let Some(i) = l.find(k) {
                let val = &l[i + k.len()..];
                let n = k.trim_end_matches('=').to_string();
                if !is_placeholder(val) && !v.contains(&n) {
                    v.push(n);
                }
            }
        }
    }
    v
}

/// Walk JSON and collect dotted key paths whose name is secret-like and value non-placeholder.
pub fn secret_names_in_json(text: &str) -> Option<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut out = vec![];
    fn walk(v: &serde_json::Value, path: &str, out: &mut Vec<String>, parent_is_auths: bool) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, val) in m {
                    let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                    let leaf = match val {
                        serde_json::Value::String(s) => Some(s.clone()),
                        serde_json::Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    };
                    if let Some(s) = leaf {
                        let docker_auth = parent_is_auths && k == "auth";
                        if (is_secret_name(k) || docker_auth) && !is_placeholder(&s) && !out.contains(&p) {
                            out.push(p.clone());
                        }
                    }
                    walk(val, &p, out, path.ends_with("auths") || path.contains("auths."));
                }
            }
            serde_json::Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(x, &format!("{path}[{i}]"), out, false);
                }
            }
            _ => {}
        }
    }
    walk(&v, "", &mut out, false);
    Some(out)
}

pub fn contains_private_key(text: &str) -> bool {
    text.contains("PRIVATE KEY-----")
}

/// ~/.netrc `password`/`account` tokens → names like "password (machine example.com)".
pub fn netrc_names(text: &str) -> Vec<String> {
    let toks: Vec<&str> = text.split_whitespace().collect();
    let mut out = vec![];
    let mut machine = String::from("default");
    let mut i = 0;
    while i < toks.len() {
        match toks[i] {
            "machine" if i + 1 < toks.len() => {
                machine = toks[i + 1].to_string();
                i += 1;
            }
            "password" if i + 1 < toks.len() && !is_placeholder(toks[i + 1]) => {
                out.push(format!("password (machine {machine})"));
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// ~/.git-credentials lines `https://user:token@host` → "credential for host".
pub fn git_credential_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let rest = l.trim().split_once("://")?.1;
            let (userinfo, host) = rest.split_once('@')?;
            (!userinfo.is_empty()).then(|| format!("credential for {}", host.split('/').next().unwrap_or(host)))
        })
        .collect()
}

/// Is a project file worth scanning by name?
pub fn is_candidate_file(name: &str) -> bool {
    let n = name.to_lowercase();
    n.starts_with(".env") || n == "config.json" || n.contains("credentials") || n.ends_with(".pem") || n.ends_with(".key")
}

pub const SKIP_DIRS: [&str; 14] = [
    "target", "node_modules", ".git", "venv", ".venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".next", ".cache", "DerivedData", "Pods", ".build",
];

/// Walk a directory tree (never following symlinks) collecting candidate files
/// and git repo roots.
pub fn walk_projects(root: &Path, max_files: usize) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut files = vec![];
    let mut repos = vec![];
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            seen += 1;
            if seen > max_files {
                return (files, repos);
            }
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if ft.is_dir() {
                if name == ".git" {
                    repos.push(dir.clone());
                    continue;
                }
                if SKIP_DIRS.contains(&name.as_str()) || depth >= 10 {
                    continue;
                }
                stack.push((p, depth + 1));
            } else if ft.is_file() && is_candidate_file(&name) {
                files.push(p);
            }
        }
    }
    files.sort();
    repos.sort();
    (files, repos)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Remote {
    pub github: Option<String>,
    pub has_credentials: bool,
}

/// Parse a git remote URL (credentials are detected, never kept).
pub fn parse_remote(url: &str) -> Remote {
    let u = url.trim();
    let mut has_credentials = false;
    let mut hostpath = u.to_string();
    if let Some((_, rest)) = u.split_once("://") {
        if let Some((userinfo, hp)) = rest.split_once('@') {
            // "git@" style user is fine; a password/token is not.
            has_credentials = userinfo.contains(':') || userinfo.len() > 20;
            hostpath = hp.to_string();
        } else {
            hostpath = rest.to_string();
        }
    } else if let Some((_, hp)) = u.split_once('@') {
        hostpath = hp.replacen(':', "/", 1);
    }
    let github = hostpath.strip_prefix("github.com/").map(|p| p.trim_end_matches('/').trim_end_matches(".git").to_string()).filter(|p| p.split('/').count() == 2);
    Remote { github, has_credentials }
}

/// Remote URLs from a .git/config file.
pub fn git_config_urls(text: &str) -> Vec<String> {
    text.lines().filter_map(|l| l.trim().strip_prefix("url = ").or_else(|| l.trim().strip_prefix("url=")).map(|s| s.trim().to_string())).collect()
}

#[derive(Default)]
struct GitCache {
    visibility: HashMap<String, Option<String>>,
}

impl GitCache {
    fn visibility(&mut self, slug: &str) -> Option<String> {
        if let Some(v) = self.visibility.get(slug) {
            return v.clone();
        }
        let v = cmd::which("gh").and_then(|_| {
            let o = cmd::run("gh", &["repo", "view", slug, "--json", "visibility", "-q", ".visibility"]).ok()?;
            o.success().then(|| o.stdout.trim().to_uppercase()).filter(|s| !s.is_empty())
        });
        self.visibility.insert(slug.to_string(), v.clone());
        v
    }
}

fn repo_root(path: &Path, stop: &Path) -> Option<PathBuf> {
    let mut d = path.parent()?;
    loop {
        if d.join(".git").exists() {
            return Some(d.to_path_buf());
        }
        if d == stop {
            return None;
        }
        d = d.parent()?;
    }
}

fn mode_of(p: &Path) -> u32 {
    std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777).unwrap_or(0)
}

fn chmod_fix(p: &Path) -> Option<Fix> {
    let m = mode_of(p);
    if m & 0o077 == 0 {
        return None;
    }
    let ps = p.display().to_string();
    Some(
        Fix::new("Restrict file permissions to you only (600)")
            .change(format!("{}: mode {:o} → 600", tilde(p), m))
            .step(Step::Chmod { path: ps.clone(), mode: 0o600 })
            .undo(vec![Step::Chmod { path: ps, mode: m }]),
    )
}

fn keychain_fixes(p: &Path, names: &[String], rc: bool, ctx: &Ctx) -> Option<Fix> {
    let simple: Vec<String> = names.iter().filter(|n| valid_name(n) && !n.contains('.')).cloned().collect();
    if simple.is_empty() {
        return None;
    }
    let service = format!("mac-cleaner-pro:{}", tilde(p));
    let ps = p.display().to_string();
    let delete_steps: Vec<Step> = simple.iter().map(|n| run_lenient(&["security", "delete-generic-password", "-s", &service, "-a", n])).collect();
    if rc {
        let backup = ctx
            .backup_dir()
            .join(format!("{}.{}.bak", p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), ctx.stamp))
            .display()
            .to_string();
        let mut undo = vec![Step::CopyFile { from: backup.clone(), to: ps.clone() }];
        undo.extend(delete_steps);
        Some(
            Fix::new("Move these variables into the Keychain")
                .change(format!("Store {} in your login Keychain (service \"{service}\")", simple.join(", ")))
                .change(format!("Rewrite those lines in {} to read the value from the Keychain at shell start-up", tilde(p)))
                .change(format!("Original file backed up to {} (permissions 600) for undo — delete it once you're happy", tilde(Path::new(&backup))))
                .step(Step::RcToKeychain { file: ps, keys: simple, service, backup })
                .undo(undo)
                .warn("New terminal windows will read the values from the Keychain; macOS may ask once to allow `security` access. Values are never shown or logged."),
        )
    } else {
        Some(
            Fix::new("Copy these secrets into the Keychain")
                .change(format!("Store {} in your login Keychain (service \"{service}\"). The file itself is NOT changed (programs may still read it).", simple.join(", ")))
                .change(format!("Then load them with: export NAME=\"$(security find-generic-password -s '{service}' -a NAME -w)\" and remove them from the file yourself"))
                .step(Step::KeychainImport { file: ps, keys: simple, service })
                .undo(delete_steps),
        )
    }
}

fn names_ev(names: &[String]) -> String {
    format!("names: {} (values hidden)", names.join(", "))
}

pub fn secrets(ctx: &Ctx) -> Vec<Finding> {
    let mut out = vec![];
    let why_rc = "Secrets exported in shell start-up files are readable by every program you run, end up in backups and dotfile repos, and are easy to leak in screen shares.";

    // 1. Shell rc files
    for f in [".zshrc", ".zprofile", ".zshenv", ".bash_profile", ".bashrc", ".profile"] {
        let p = ctx.home.join(f);
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let names = secret_names_in_text(&text);
        if names.is_empty() {
            continue;
        }
        let mut fd = Finding::new(Secrets, format!("Secrets in ~/{f}"), Status::Warning, format!("{} secret variable(s) stored in plain text.", names.len()))
            .evidence(format!("file: ~/{f}"))
            .evidence(names_ev(&names))
            .explain(why_rc)
            .fix_text("Store the values in the macOS Keychain and read them at start-up, e.g. export NAME=\"$(security find-generic-password -s my-service -a NAME -w)\".");
        if let Some(k) = keychain_fixes(&p, &names, true, ctx) {
            fd = fd.with_fix(k);
        }
        if let Some(c) = chmod_fix(&p) {
            fd = fd.with_fix(c);
        }
        out.push(fd);
    }

    // 2. Well-known credential files in home
    let cred_files: [(&str, &str); 8] = [
        (".netrc", "netrc"),
        (".git-credentials", "gitcred"),
        (".npmrc", "text"),
        (".pypirc", "text"),
        (".aws/credentials", "text"),
        (".docker/config.json", "json"),
        (".config/gh/hosts.yml", "text"),
        (".m2/settings.xml", "xml"),
    ];
    for (rel, kind) in cred_files {
        let p = ctx.home.join(rel);
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let names = match kind {
            "netrc" => netrc_names(&text),
            "gitcred" => git_credential_names(&text),
            "json" => secret_names_in_json(&text).unwrap_or_default(),
            "xml" => {
                if text.contains("<password>") { vec!["<password>".into()] } else { vec![] }
            }
            _ => secret_names_in_text(&text),
        };
        if names.is_empty() {
            continue;
        }
        let m = mode_of(&p);
        let loose = m & 0o077 != 0;
        let mut fd = Finding::new(
            Secrets,
            format!("Credentials in ~/{rel}"),
            if loose { Status::Warning } else { Status::Info },
            if loose { format!("Credentials stored with loose permissions ({m:o}).") } else { "Standard credential file, readable only by you.".to_string() },
        )
        .evidence(format!("file: ~/{rel} (mode {m:o})"))
        .evidence(names_ev(&names))
        .explain("This is the tool's normal place for credentials, but it is plain text. Keep it readable only by you, and prefer a credential helper/Keychain where the tool supports one (git credential-osxkeychain, aws sso, gh auth).");
        if let Some(c) = chmod_fix(&p) {
            fd = fd.with_fix(c).fix_text("Restrict to mode 600.").command(format!("chmod 600 ~/{rel}"));
        }
        out.push(fd);
    }

    // 3. Launch agent environment variables
    let la = ctx.home.join("Library/LaunchAgents");
    if let Ok(rd) = std::fs::read_dir(&la) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_none_or(|x| x != "plist") {
                continue;
            }
            let Ok(o) = cmd::run("plutil", &["-convert", "json", "-o", "-", &p.display().to_string()]) else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&o.stdout) else { continue };
            let Some(env) = v.get("EnvironmentVariables").and_then(|x| x.as_object()) else { continue };
            let names: Vec<String> = env
                .iter()
                .filter(|(k, val)| is_secret_name(k) && val.as_str().is_some_and(|s| !is_placeholder(s)))
                .map(|(k, _)| k.clone())
                .collect();
            if names.is_empty() {
                continue;
            }
            let mut fd = Finding::new(Secrets, format!("Secrets in launch agent {}", p.file_name().unwrap_or_default().to_string_lossy()), Status::Warning, "Secret environment variables stored in a launch agent plist.")
                .evidence(format!("file: {}", tilde(&p)))
                .evidence(names_ev(&names))
                .explain("Launch agent plists are plain text and often copied into backups or dotfile repos. Have the program read the secret from the Keychain or a 600-mode file instead.");
            if let Some(c) = chmod_fix(&p) {
                fd = fd.with_fix(c);
            }
            out.push(fd);
        }
    }

    // 4. ~/Projects
    let mut cache = GitCache::default();
    let (files, repos) = walk_projects(&ctx.projects, 400_000);
    for r in &repos {
        if let Ok(cfg) = std::fs::read_to_string(r.join(".git/config")) {
            for url in git_config_urls(&cfg) {
                if parse_remote(&url).has_credentials {
                    out.push(
                        Finding::new(Secrets, format!("Token in git remote URL: {}", tilde(r)), Status::Critical, "A git remote URL has a password/token embedded in it.")
                            .evidence(format!("repo: {} (.git/config)", tilde(r)))
                            .explain("Tokens in remote URLs are stored in plain text, shown by `git remote -v`, and copied with the repo.")
                            .fix_text("Switch to a credential helper or SSH: `git remote set-url origin https://github.com/OWNER/REPO.git` then `gh auth setup-git`. Rotate the token.")
                            .command("git remote -v   # then: git remote set-url origin <url without token>"),
                    );
                }
            }
        }
    }
    let mut clean_files = 0usize;
    for p in files {
        let Ok(meta) = std::fs::metadata(&p) else { continue };
        if meta.len() > 2_000_000 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&p) else { continue };
        if bytes.contains(&0) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let lower = p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        let is_pem = lower.ends_with(".pem") || lower.ends_with(".key");
        let names: Vec<String> = if is_pem {
            if contains_private_key(&text) { vec!["PRIVATE KEY (PEM block)".into()] } else { vec![] }
        } else if lower.ends_with(".json") {
            secret_names_in_json(&text).unwrap_or_else(|| secret_names_in_text(&text))
        } else {
            secret_names_in_text(&text)
        };
        drop(text);
        if names.is_empty() {
            clean_files += 1;
            continue;
        }
        out.push(project_finding(&p, &names, is_pem, ctx, &mut cache));
    }
    if out.is_empty() {
        out.push(
            Finding::new(Secrets, "Plaintext secrets", Status::Ok, format!("No plaintext secrets found in shell files, credential files or ~/Projects ({clean_files} candidate files checked)."))
                .explain("Checked shell rc files, common credential files, launch agents and .env*/config.json/*credentials*/*.pem/*.key files under ~/Projects. Only names are ever reported."),
        );
    } else {
        out.push(
            Finding::new(Secrets, "Scan coverage", Status::Info, format!("Also checked {clean_files} other candidate file(s) under ~/Projects with no secrets."))
                .explain("Only names are reported, never values. ~/Desktop, ~/Documents and ~/Downloads are deliberately not scanned (privacy-protected)."),
        );
    }
    out
}

fn project_finding(p: &Path, names: &[String], is_pem: bool, ctx: &Ctx, cache: &mut GitCache) -> Finding {
    let title = format!("Secrets in {}", tilde(p));
    let mut ev = vec![format!("file: {}", tilde(p)), names_ev(names)];
    let mut fixes = vec![];
    let status;
    let summary;
    if let Some(root) = repo_root(p, &ctx.projects) {
        let rel = p.strip_prefix(&root).unwrap_or(p).display().to_string();
        let rs = root.display().to_string();
        let tracked = cmd::run("git", &["-C", &rs, "ls-files", "--error-unmatch", "--", &rel]).map(|o| o.success()).unwrap_or(false);
        let ignored = !tracked && cmd::run("git", &["-C", &rs, "check-ignore", "-q", "--", &rel]).map(|o| o.success()).unwrap_or(false);
        let remote = cmd::run("git", &["-C", &rs, "remote", "get-url", "origin"]).ok().filter(|o| o.success()).map(|o| parse_remote(&o.stdout));
        let vis = remote.as_ref().and_then(|r| r.github.clone()).and_then(|slug| cache.visibility(&slug).map(|v| (slug, v)));
        ev.push(format!("git repo: {}", tilde(&root)));
        ev.push(format!("tracked by git: {tracked}; ignored by .gitignore: {ignored}"));
        match &vis {
            Some((slug, v)) => ev.push(format!("GitHub repo {slug}: {v}")),
            None => ev.push(format!("GitHub visibility: {}", if remote.is_some() { "unknown (not GitHub or gh unavailable)" } else { "no remote" })),
        }
        let public = vis.as_ref().is_some_and(|(_, v)| v == "PUBLIC");
        if tracked {
            status = if public || is_pem { Status::Critical } else { Status::Warning };
            summary = if public {
                "Committed to a PUBLIC GitHub repo — treat these secrets as leaked and rotate them.".to_string()
            } else {
                "Committed to git — anyone with access to the repo (or a future leak) can read them.".to_string()
            };
            fixes.push(
                Fix::new("Stop tracking this file in git (keeps your copy)")
                    .change(format!("git rm --cached {rel} in {}", tilde(&root)))
                    .change(format!("Add {rel} to .gitignore"))
                    .step(run(&["git", "-C", &rs, "rm", "--cached", "--quiet", "--", &rel]))
                    .step(Step::AppendLine { path: root.join(".gitignore").display().to_string(), line: rel.clone() })
                    .undo(vec![
                        Step::RemoveLine { path: root.join(".gitignore").display().to_string(), line: rel.clone() },
                        run(&["git", "-C", &rs, "add", "-f", "--", &rel]),
                    ])
                    .warn("This does not erase it from earlier commits or from GitHub. Rotate (regenerate) the secrets, and commit the change."),
            );
        } else if !ignored {
            status = Status::Warning;
            summary = "Not ignored by git — one `git add .` away from being committed.".to_string();
            fixes.push(
                Fix::new("Add to .gitignore")
                    .change(format!("Append \"{rel}\" to {}", tilde(&root.join(".gitignore"))))
                    .step(Step::AppendLine { path: root.join(".gitignore").display().to_string(), line: rel.clone() })
                    .undo(vec![Step::RemoveLine { path: root.join(".gitignore").display().to_string(), line: rel.clone() }]),
            );
        } else {
            status = Status::Info;
            summary = "Plain-text secrets, but ignored by git.".to_string();
        }
    } else {
        ev.push("not inside a git repo".into());
        status = Status::Info;
        summary = "Plain-text secrets (not in a git repo).".to_string();
    }
    if !is_pem && let Some(k) = keychain_fixes(p, names, false, ctx) {
        fixes.push(k);
    }
    if let Some(c) = chmod_fix(p) {
        fixes.push(c);
    }
    let mut f = Finding::new(Secrets, title, status, summary)
        .evidence_all(ev)
        .explain("Plain-text secrets in project folders get committed, copied to backups and shared by accident.")
        .fix_text("Keep secret files out of git (.gitignore), restrict them to mode 600, and prefer the Keychain. If a secret was ever pushed, rotate it.");
    for x in fixes {
        f = f.with_fix(x);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for n in ["API_KEY", "OPENAI_API_KEY", "apiKey", "clientSecret", "GITHUB_TOKEN", "DB_PASSWORD", "aws_secret_access_key", "BYBIT_API_SECRET", "privateKey", "DB_PASS"] {
            assert!(is_secret_name(n), "{n}");
        }
        for n in ["MAX_TOKENS", "TOKENIZER", "PATH", "TOKEN_URL", "PASSWORD_FILE", "AWS_ACCESS_KEY_ID", "max_token", "KEYBOARD", "MONKEY", "num_tokens", "SECRET_NAME"] {
            assert!(!is_secret_name(n), "{n}");
        }
    }

    #[test]
    fn placeholders() {
        for v in ["", "  ", "${API_KEY}", "$TOKEN", "<your-key>", "changeme", "your_api_key_here", "xxxxxxxx", "********", "os.environ['X']", "abc", "$(security find-generic-password -s a -w)"] {
            assert!(is_placeholder(v), "{v:?}");
        }
        for v in ["sk-proj-abc123def456", "hunter2hunter2", "8f14e45fceea167a5a36dedd4bea2543"] {
            assert!(!is_placeholder(v), "{v:?}");
        }
    }

    #[test]
    fn assignment_lines() {
        let a = parse_assignment_line("export OPENAI_API_KEY=\"sk-fake-123\"").unwrap();
        assert_eq!((a.name.as_str(), a.value.as_str()), ("OPENAI_API_KEY", "sk-fake-123"));
        let a = parse_assignment_line("aws_secret_access_key = abcdEFGH1234").unwrap();
        assert_eq!(a.name, "aws_secret_access_key");
        assert_eq!(a.value, "abcdEFGH1234");
        let a = parse_assignment_line("  \"apiKey\": \"zzzz-yyyy\",").unwrap();
        assert_eq!((a.name.as_str(), a.value.as_str()), ("apiKey", "zzzz-yyyy"));
        let a = parse_assignment_line("token: abcd1234 # note").unwrap();
        assert_eq!(a.value, "abcd1234");
        assert!(parse_assignment_line("# API_KEY=x").is_none());
        assert!(parse_assignment_line("echo hello").is_none());
        assert!(parse_assignment_line("alias ll='ls -l'").is_none());
    }

    #[test]
    fn text_scan_reports_names_only() {
        let t = "export PATH=/usr/bin\nexport GITHUB_TOKEN=ghp_FAKEFAKEFAKE1234\nAPI_KEY=\nSECRET=${OTHER}\nMAX_TOKENS=4096\n//registry.npmjs.org/:_authToken=npm_FAKE12345\n";
        let n = secret_names_in_text(t);
        assert_eq!(n, vec!["GITHUB_TOKEN", "_authToken"]);
        for name in &n {
            assert!(!name.contains("FAKE"));
        }
    }

    #[test]
    fn json_scan() {
        let j = r#"{"api":{"apiKey":"real-looking-key-1234","baseUrl":"https://x"},"auths":{"ghcr.io":{"auth":"dXNlcjpwYXNzd29yZA=="}},"password":"","model":{"max_tokens":100}}"#;
        let n = secret_names_in_json(j).unwrap();
        assert_eq!(n, vec!["api.apiKey", "auths.ghcr.io.auth"]);
        assert!(secret_names_in_json("not json").is_none());
    }

    #[test]
    fn netrc_gitcred() {
        assert_eq!(netrc_names("machine api.example.com login me password s3cr3tpass\n"), vec!["password (machine api.example.com)"]);
        assert_eq!(git_credential_names("https://user:ghp_FAKE@github.com\n"), vec!["credential for github.com"]);
    }

    #[test]
    fn candidates() {
        for n in [".env", ".env.local", "config.json", "aws_credentials.txt", "server.pem", "id.key", "Credentials.json"] {
            assert!(is_candidate_file(n), "{n}");
        }
        for n in ["main.rs", "config.yaml", "env.rs", "keys.txt"] {
            assert!(!is_candidate_file(n), "{n}");
        }
    }

    #[test]
    fn remotes() {
        assert_eq!(parse_remote("git@github.com:owner/repo.git"), Remote { github: Some("owner/repo".into()), has_credentials: false });
        assert_eq!(parse_remote("https://github.com/owner/repo"), Remote { github: Some("owner/repo".into()), has_credentials: false });
        let r = parse_remote("https://user:ghp_FAKE@github.com/owner/repo.git");
        assert!(r.has_credentials);
        assert_eq!(r.github.as_deref(), Some("owner/repo"));
        assert!(parse_remote("https://ghp_ABCDEFGHIJKLMNOPQRSTUV@github.com/o/r").has_credentials);
        assert_eq!(parse_remote("https://gitlab.com/o/r").github, None);
        assert_eq!(git_config_urls("[remote \"origin\"]\n\turl = https://github.com/o/r.git\n"), vec!["https://github.com/o/r.git"]);
    }

    #[test]
    fn walk_skips_and_finds() {
        let d = std::env::temp_dir().join(format!("mcp-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("app/.git")).unwrap();
        std::fs::create_dir_all(d.join("app/node_modules/x")).unwrap();
        std::fs::create_dir_all(d.join("app/sub")).unwrap();
        std::fs::write(d.join("app/.env"), "API_KEY=fakefakefake\n").unwrap();
        std::fs::write(d.join("app/node_modules/x/.env"), "API_KEY=fakefakefake\n").unwrap();
        std::fs::write(d.join("app/sub/config.json"), "{}").unwrap();
        std::os::unix::fs::symlink("/etc", d.join("app/link")).unwrap();
        let (files, repos) = walk_projects(&d, 10_000);
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|f| !f.to_string_lossy().contains("node_modules")));
        assert_eq!(repos, vec![d.join("app")]);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn full_check_on_fake_home_never_leaks_values() {
        let home = std::env::temp_dir().join(format!("mcp-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("Projects/p")).unwrap();
        std::fs::write(home.join(".zshrc"), "export OPENAI_API_KEY=sk-LEAKCHECK-0001\n").unwrap();
        std::fs::write(home.join("Projects/p/.env"), "STRIPE_SECRET=LEAKCHECK-0002\nDEBUG=1\n").unwrap();
        std::fs::write(home.join("Projects/p/server.key"), "-----BEGIN PRIVATE KEY-----\nLEAKCHECK0003\n-----END PRIVATE KEY-----\n").unwrap();
        let ctx = Ctx::with_home(home.clone());
        let f = secrets(&ctx);
        let md = crate::security::report::markdown(&f, "t");
        let fixes: String = f.iter().flat_map(|x| x.fixes.iter()).map(|x| format!("{:?}{:?}", x, x.preview())).collect();
        assert!(!md.contains("LEAKCHECK"), "{md}");
        assert!(!fixes.contains("LEAKCHECK"));
        assert!(md.contains("OPENAI_API_KEY"));
        assert!(md.contains("STRIPE_SECRET"));
        assert!(md.contains("PRIVATE KEY"));
        std::fs::remove_dir_all(&home).unwrap();
    }
}
