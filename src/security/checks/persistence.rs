//! Launch agents/daemons (with code signatures), login items, cron, periodic,
//! login hooks — the places software uses to start automatically.

use super::super::fix::{Fix, Step, admin, pane, run_lenient, settings_fix};
use super::super::{Category::Persistence, Ctx, Finding, Status};
use crate::cmd;
use crate::util::{sh_quote, tilde};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum Sig {
    Unsigned,
    AdHoc,
    Apple,
    DeveloperId(String),
    Other(String),
    Unknown(String),
}

impl Sig {
    pub fn describe(&self) -> String {
        match self {
            Sig::Unsigned => "not code-signed".into(),
            Sig::AdHoc => "ad-hoc signed (no developer identity)".into(),
            Sig::Apple => "signed by Apple".into(),
            Sig::DeveloperId(s) => format!("signed: {s}"),
            Sig::Other(s) => format!("signed: {s}"),
            Sig::Unknown(s) => format!("signature unknown ({s})"),
        }
    }
}

/// Parse `codesign -dvv <path>` output (stderr).
pub fn parse_codesign(out: &str) -> Sig {
    if out.contains("not signed at all") {
        return Sig::Unsigned;
    }
    if out.contains("Signature=adhoc") {
        return Sig::AdHoc;
    }
    let auth: Vec<&str> = out.lines().filter_map(|l| l.strip_prefix("Authority=")).collect();
    if let Some(first) = auth.first() {
        if *first == "Software Signing" || first.starts_with("Apple Mac OS Application Signing") || first.starts_with("Apple iPhone OS Application Signing") {
            return Sig::Apple;
        }
        if first.starts_with("Developer ID Application:") {
            return Sig::DeveloperId(first.to_string());
        }
        return Sig::Other(first.to_string());
    }
    Sig::Unknown(out.lines().next().unwrap_or("").to_string())
}

/// `TeamIdentifier=` from `codesign -dvv` output; None if missing or "not set".
pub fn parse_team(out: &str) -> Option<String> {
    let t = out.lines().find_map(|l| l.strip_prefix("TeamIdentifier="))?.trim();
    (!t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric())).then(|| t.to_string())
}

/// `Executable=` (main executable path) from `codesign -dvv` output.
pub fn parse_executable(out: &str) -> Option<String> {
    out.lines().find_map(|l| l.strip_prefix("Executable=")).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Parse `spctl -a -vv` output → (accepted, source).
pub fn parse_spctl(out: &str) -> (bool, String) {
    let accepted = out.lines().next().map(|l| l.trim_end().ends_with(": accepted")).unwrap_or(false);
    let source = out.lines().find_map(|l| l.strip_prefix("source=")).unwrap_or("").to_string();
    (accepted, source)
}

#[derive(Debug, Clone, PartialEq)]
pub struct LaunchTarget {
    /// The executable launchd starts.
    pub exec: String,
    /// The program that matters for review (script/binary run by a wrapper).
    pub target: String,
    pub inline_shell: bool,
}

const WRAPPERS: [&str; 16] = [
    "sh", "bash", "zsh", "dash", "env", "nohup", "caffeinate", "python", "python3", "node", "ruby", "perl", "osascript", "arch", "open", "exec",
];

/// Work out what a launch item actually runs. Arguments other than file paths
/// are never returned (they could contain tokens).
pub fn resolve_target(program: Option<&str>, args: &[String]) -> Option<LaunchTarget> {
    let exec = program.map(|s| s.to_string()).or_else(|| args.first().cloned())?;
    let base = Path::new(&exec).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let is_wrapper = WRAPPERS.contains(&base.as_str()) || base.starts_with("python");
    if !is_wrapper {
        return Some(LaunchTarget { target: exec.clone(), exec, inline_shell: false });
    }
    // ProgramArguments[0] is argv[0] (the launcher itself) in both forms.
    let rest: &[String] = args.get(1..).unwrap_or(&[]);
    let mut inline = false;
    for (i, a) in rest.iter().enumerate() {
        if a == "-c" {
            inline = true;
            if let Some(cmdline) = rest.get(i + 1)
                && let Some(p) = cmdline.split_whitespace().map(|t| t.trim_matches(|c| c == '"' || c == '\'')).find(|t| t.starts_with('/'))
            {
                return Some(LaunchTarget { exec: exec.clone(), target: p.to_string(), inline_shell: true });
            }
            break;
        }
        if a.starts_with('/') || a.starts_with("~/") {
            return Some(LaunchTarget { exec: exec.clone(), target: a.clone(), inline_shell: false });
        }
    }
    Some(LaunchTarget { target: exec.clone(), exec, inline_shell: inline })
}

#[derive(Debug, Clone)]
pub struct LaunchItem {
    pub plist: PathBuf,
    pub label: String,
    pub target: Option<LaunchTarget>,
    pub env_names: Vec<String>,
    pub disabled: bool,
}

pub fn parse_launch_plist_json(path: &Path, json: &str) -> Option<LaunchItem> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let label = v.get("Label").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let program = v.get("Program").and_then(|x| x.as_str());
    let args: Vec<String> = v
        .get("ProgramArguments")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let env_names = v
        .get("EnvironmentVariables")
        .and_then(|x| x.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    Some(LaunchItem {
        plist: path.to_path_buf(),
        label,
        target: resolve_target(program, &args),
        env_names,
        disabled: v.get("Disabled").and_then(|x| x.as_bool()).unwrap_or(false),
    })
}

pub fn read_launch_item(path: &Path) -> Option<LaunchItem> {
    let p = path.display().to_string();
    let o = cmd::run("plutil", &["-convert", "json", "-o", "-", &p]).ok()?;
    if !o.success() {
        return None;
    }
    parse_launch_plist_json(path, &o.stdout)
}

pub fn launch_dirs(home: &Path) -> Vec<(PathBuf, bool)> {
    vec![
        (home.join("Library/LaunchAgents"), false),
        (PathBuf::from("/Library/LaunchAgents"), true),
        (PathBuf::from("/Library/LaunchDaemons"), true),
    ]
}

fn expand(p: &str, home: &Path) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(r) => home.join(r),
        None => PathBuf::from(p),
    }
}

fn is_script(p: &Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 2];
    std::fs::File::open(p).and_then(|mut f| f.read_exact(&mut b)).map(|_| &b == b"#!").unwrap_or(false)
}

pub fn quarantine_fix(item: &LaunchItem, system: bool, ctx: &Ctx) -> Fix {
    let name = item.plist.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let from = item.plist.display().to_string();
    if !system {
        let uid = std::fs::metadata(&ctx.home).map(|m| m.uid()).unwrap_or(501);
        let to = ctx.quarantine_dir().join(&name).display().to_string();
        let domain = format!("gui/{uid}");
        Fix::new(format!("Quarantine {name}"))
            .change(format!("Stop {} and move its plist to {} (reversible; nothing is deleted)", item.label, tilde(Path::new(&to))))
            .step(run_lenient(&["launchctl", "bootout", &domain, &from]))
            .step(Step::Move { from: from.clone(), to: to.clone() })
            .undo(vec![Step::Move { from: to, to: from.clone() }, run_lenient(&["launchctl", "bootstrap", &domain, &from])])
    } else {
        let qdir = format!("/Library/Application Support/MacCleanerPro/Quarantine/{}", ctx.stamp);
        let to = format!("{qdir}/{name}");
        Fix::new(format!("Quarantine {name}"))
            .change(format!("Stop {} and move its plist to {to} (reversible; nothing is deleted)", item.label))
            .step(admin(format!(
                "/bin/launchctl bootout system {f} 2>/dev/null; /bin/mkdir -p {q} && /bin/mv {f} {t}",
                f = sh_quote(&from),
                q = sh_quote(&qdir),
                t = sh_quote(&to)
            )))
            .undo(vec![admin(format!(
                "/bin/mv {t} {f} && /bin/launchctl bootstrap system {f} 2>/dev/null; true",
                f = sh_quote(&from),
                t = sh_quote(&to)
            ))])
    }
}

/// "Mark as trusted": records label + program + the SHA-256 seen in this audit.
pub fn trust_fix(item: &LaunchItem, program: &Path, sha256: &str, ctx: &Ctx) -> Fix {
    let file = ctx.trust_file().display().to_string();
    let program = program.display().to_string();
    Fix::new("Mark as trusted")
        .change(format!(
            "Records {} as trusted by you in {} (label + program path + SHA-256 of the program). If the program file changes, trust is dropped automatically. Nothing on the system is changed.",
            item.label,
            tilde(Path::new(&file))
        ))
        .step(Step::Trust { file: file.clone(), label: item.label.clone(), program: program.clone(), sha256: sha256.into() })
        .undo(vec![Step::Untrust { file, label: item.label.clone(), program }])
}

pub fn untrust_fix(item: &LaunchItem, program: &Path, sha256: &str, ctx: &Ctx) -> Fix {
    let file = ctx.trust_file().display().to_string();
    let program = program.display().to_string();
    Fix::new("Untrust")
        .change(format!("Removes {} from your trusted startup items; it will be flagged for review again.", item.label))
        .step(Step::Untrust { file: file.clone(), label: item.label.clone(), program: program.clone() })
        .undo(vec![Step::Trust { file, label: item.label.clone(), program, sha256: sha256.into() }])
}

/// Find an installed launch item by its label (for `--trust <label>`).
pub fn find_launch_item(home: &Path, label: &str) -> Option<LaunchItem> {
    for (dir, _) in launch_dirs(home) {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "plist") && p.is_file()).collect();
        paths.sort();
        for p in paths {
            if let Some(it) = read_launch_item(&p)
                && it.label == label
            {
                return Some(it);
            }
        }
    }
    None
}

/// The program file a launch item runs (absolute, `~/` expanded).
pub fn item_program(item: &LaunchItem, home: &Path) -> Option<PathBuf> {
    item.target.as_ref().map(|t| expand(&t.target, home))
}

/// Folders the audit must never read (they trigger macOS privacy prompts).
fn privacy_protected(p: &Path, home: &Path) -> bool {
    ["Desktop", "Documents", "Downloads"].iter().any(|d| p.starts_with(home.join(d)))
}

pub fn launch_items(ctx: &Ctx) -> Vec<Finding> {
    let mut out = vec![];
    let mut total = 0;
    for (dir, system) in launch_dirs(&ctx.home) {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                out.push(Finding::unknown(Persistence, format!("Launch items in {}", tilde(&dir)), e.to_string()));
                continue;
            }
        };
        let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "plist") && p.is_file()).collect();
        paths.sort();
        for p in paths {
            total += 1;
            out.push(analyse_item(&p, system, ctx));
        }
    }
    if total == 0 {
        out.push(Finding::new(Persistence, "Launch agents & daemons", Status::Ok, "No third-party launch agents or daemons."));
    }
    out
}

fn analyse_item(p: &Path, system: bool, ctx: &Ctx) -> Finding {
    let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let title = format!("Startup item: {name}");
    let Some(item) = read_launch_item(p) else {
        return Finding::unknown(Persistence, title, "plist could not be parsed");
    };
    let why = "Launch agents/daemons start a program automatically at login or boot — the most common way malware stays on a Mac. Unsigned or ad-hoc-signed programs are not necessarily bad (your own scripts and Homebrew tools are often unsigned), but review anything you don't recognise.";
    let mut ev = vec![format!("plist: {}", tilde(p)), format!("label: {}", item.label)];
    if item.disabled {
        ev.push("Disabled = true in plist".into());
    }
    if !item.env_names.is_empty() {
        ev.push(format!("sets environment variables (names only): {}", item.env_names.join(", ")));
    }
    let Some(t) = item.target.clone() else {
        return Finding::new(Persistence, title, Status::Warning, "No Program/ProgramArguments in plist.").evidence_all(ev).explain(why);
    };
    if item.label == crate::schedule::LABEL {
        ev.push(format!("runs: {}", tilde(Path::new(&t.target))));
        return Finding::new(Persistence, title, Status::Ok, "Mac Cleaner Pro's own weekly scan (scan + notify only).").evidence_all(ev).explain(why);
    }
    if t.exec != t.target {
        ev.push(format!("launcher: {}", tilde(Path::new(&t.exec))));
    }
    if t.inline_shell {
        ev.push("runs an inline shell command (not shown)".into());
    }
    let target = expand(&t.target, &ctx.home);
    ev.push(format!("program: {}", tilde(&target)));
    let qfix = quarantine_fix(&item, system, ctx);
    if !target.exists() {
        return Finding::new(Persistence, title, Status::Warning, "The program it runs does not exist (stale or broken entry).")
            .evidence_all(ev)
            .explain(why)
            .fix_text("If you no longer use this software, quarantine the entry (reversible).")
            .with_fix(qfix);
    }
    let ts = target.display().to_string();
    let sig = cmd::run("codesign", &["-dvv", &ts]).map(|o| parse_codesign(&o.combined())).unwrap_or_else(|e| Sig::Unknown(e.to_string()));
    let (accepted, source) = cmd::run_timeout("spctl", &["-a", "-vv", "-t", "exec", &ts], Duration::from_secs(30))
        .map(|o| parse_spctl(&o.combined()))
        .unwrap_or((false, String::new()));
    let script = is_script(&target);
    ev.push(format!("{}{}", if script { "script, " } else { "" }, sig.describe()));
    ev.push(format!("Gatekeeper assessment: {}{}", if accepted { "accepted" } else { "rejected" }, if source.is_empty() { String::new() } else { format!(" ({source})") }));
    let ok = matches!(sig, Sig::Apple) || (matches!(sig, Sig::DeveloperId(_)) && accepted);
    if ok {
        return Finding::new(Persistence, title, Status::Ok, format!("Runs a properly signed program ({}).", sig.describe())).evidence_all(ev).explain(why);
    }
    let what = format!("{} {}", if script { "a script," } else { "a program" }, sig.describe());
    // User trust: hash the program only if it is outside privacy-protected folders.
    let readable = !privacy_protected(&target, &ctx.home);
    let store = super::super::trusted::TrustStore::load(&ctx.trust_file());
    let state = if readable { store.state(&item.label, &target) } else { super::super::trusted::TrustState::NotTrusted };
    let sha = if readable { super::super::trusted::sha256_file(&target).ok() } else { None };
    use super::super::trusted::TrustState;
    match (state, sha) {
        (TrustState::Trusted, Some(h)) => {
            let trusted_at = store.lookup(&item.label, &ts).map(|e| e.trusted_at.clone()).unwrap_or_default();
            ev.push(format!("trusted by you on {trusted_at} (program SHA-256 unchanged: {})", &h[..16]));
            Finding::new(Persistence, title, Status::Info, format!("Trusted by you: runs {what}."))
                .evidence_all(ev)
                .explain(why)
                .fix_text("You marked this item as trusted. If the program file changes, it will be flagged for review again.")
                .with_fix(untrust_fix(&item, &target, &h, ctx))
                .with_fix(qfix)
        }
        (state, sha) => {
            let changed = state == TrustState::Changed;
            if changed {
                ev.push("was trusted by you, but the program file has changed since (SHA-256 differs)".into());
            }
            let mut f = Finding::new(
                Persistence,
                title,
                Status::Warning,
                if changed { format!("Review: trusted earlier, but the program changed — runs {what}.") } else { format!("Review: runs {what}.") },
            )
            .evidence_all(ev)
            .explain(why)
            .fix_text("If you installed or wrote this yourself, mark it as trusted (only you can do this; a changed program loses trust automatically). If you don't recognise it, quarantine it (moves the plist aside, reversible) and investigate the program.");
            if let Some(h) = sha {
                f = f.with_fix(trust_fix(&item, &target, &h, ctx));
            }
            f.with_fix(qfix)
        }
    }
}

pub fn parse_login_items(out: &str) -> Vec<String> {
    out.trim().split(", ").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

pub fn login_items(ctx: &Ctx) -> Vec<Finding> {
    let t = "Login items";
    let sfix = settings_fix("Open Login Items", pane::LOGIN_ITEMS, "Review \"Open at Login\" and \"Allow in the Background\"; remove anything you don't recognise.");
    if !ctx.include_login_items {
        return vec![Finding::new(Persistence, t, Status::Info, "Not listed automatically (reading them needs an Automation permission prompt). Enable \"Include login items\" to list them, or review in System Settings.")
            .explain("Login items open apps automatically when you log in; \"Allow in the Background\" items run helpers.")
            .with_fix(sfix)];
    }
    match cmd::run_timeout("osascript", &["-e", "tell application \"System Events\" to get the name of every login item"], Duration::from_secs(20)) {
        Ok(o) if o.success() => {
            let items = parse_login_items(&o.stdout);
            vec![Finding::new(Persistence, t, Status::Info, format!("{} login item(s).", items.len()))
                .evidence_all(items.iter().map(|i| format!("login item: {i}")))
                .explain("Login items open automatically when you log in. Remove any you don't recognise.")
                .with_fix(sfix)]
        }
        Ok(o) => vec![Finding::unknown(Persistence, t, format!("System Events not allowed ({})", o.stderr.trim()))],
        Err(e) => vec![Finding::unknown(Persistence, t, e.to_string())],
    }
}

/// Cron entries → (schedule, program) — the rest of the command is not kept
/// because it may contain tokens.
pub fn parse_crontab(out: &str) -> Vec<(String, String)> {
    out.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !l.split_whitespace().next().unwrap_or("").contains('='))
        .filter_map(|l| {
            let toks: Vec<&str> = l.split_whitespace().collect();
            let n = if toks.first()?.starts_with('@') { 1 } else { 5 };
            if toks.len() <= n {
                return None;
            }
            Some((toks[..n].join(" "), toks[n].to_string()))
        })
        .collect()
}

pub const DEFAULT_PERIODIC: [&str; 16] = [
    "110.clean-tmps", "130.clean-msgs", "140.clean-rwho", "199.rotate-fax", "310.accounting", "400.status-disks", "420.status-network", "430.status-rwho",
    "999.local", "310.locate", "320.whatis", "340.noid", "200.accounting", "500.daily", "600.weekly", "700.monthly",
];

pub fn cron_periodic_hooks(_: &Ctx) -> Vec<Finding> {
    let mut items: Vec<String> = vec![];
    match cmd::run("crontab", &["-l"]) {
        Ok(o) if o.success() => {
            for (sched, prog) in parse_crontab(&o.stdout) {
                items.push(format!("user crontab: [{sched}] {prog} …"));
            }
        }
        _ => {}
    }
    if Path::new("/etc/crontab").exists() {
        items.push("/etc/crontab exists".into());
    }
    for d in ["daily", "weekly", "monthly"] {
        if let Ok(rd) = std::fs::read_dir(format!("/etc/periodic/{d}")) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if !DEFAULT_PERIODIC.contains(&n.as_str()) {
                    items.push(format!("/etc/periodic/{d}/{n} (non-default)"));
                }
            }
        }
    }
    for f in ["/etc/periodic.conf.local", "/etc/daily.local", "/etc/weekly.local", "/etc/monthly.local", "/etc/launchd.conf", "/etc/rc.local"] {
        if Path::new(f).exists() {
            items.push(format!("{f} exists"));
        }
    }
    for (dom, key) in [
        ("com.apple.loginwindow", "LoginHook"),
        ("com.apple.loginwindow", "LogoutHook"),
        ("/Library/Preferences/com.apple.loginwindow", "LoginHook"),
        ("/Library/Preferences/com.apple.loginwindow", "LogoutHook"),
    ] {
        if let Some(v) = super::defaults_read(dom, key)
            && !v.is_empty()
        {
            items.push(format!("{key} set in {dom}: {}", v.split_whitespace().next().unwrap_or("")));
        }
    }
    let t = "Cron, periodic scripts, login hooks";
    let why = "Cron jobs, periodic scripts and login/logout hooks are older ways to run code automatically; malware still uses them because people rarely look there.";
    vec![if items.is_empty() {
        Finding::new(Persistence, t, Status::Ok, "No cron jobs, custom periodic scripts or login hooks.").explain(why)
    } else {
        Finding::new(Persistence, t, Status::Warning, format!("{} item(s) found — confirm you created them.", items.len()))
            .evidence_all(items)
            .explain(why)
            .fix_text("Edit your crontab with `crontab -e`; remove login hooks with `sudo defaults delete com.apple.loginwindow LoginHook`.")
            .command("crontab -l")
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codesign_parse() {
        assert_eq!(parse_codesign("/x: code object is not signed at all"), Sig::Unsigned);
        assert_eq!(parse_codesign("Executable=/opt/x\nIdentifier=a.out\nCodeDirectory v=20400 flags=0x20002(adhoc,linker-signed)\nSignature=adhoc\nTeamIdentifier=not set\n"), Sig::AdHoc);
        assert_eq!(parse_codesign("Identifier=com.apple.ls\nAuthority=Software Signing\nAuthority=Apple Code Signing Certification Authority\n"), Sig::Apple);
        assert_eq!(
            parse_codesign("Authority=Developer ID Application: Objective-See, LLC (VBG97UB4TA)\nAuthority=Developer ID Certification Authority\n"),
            Sig::DeveloperId("Developer ID Application: Objective-See, LLC (VBG97UB4TA)".into())
        );
        assert!(matches!(parse_codesign("/x: No such file or directory"), Sig::Unknown(_)));
    }

    #[test]
    fn team_and_executable() {
        let dv = "Executable=/Applications/eBay.app/Wrapper/eBay.app/eBay\nIdentifier=com.ebay.iphone\nTeamIdentifier=QYHMMGCMJR\n";
        assert_eq!(parse_team(dv), Some("QYHMMGCMJR".into()));
        assert_eq!(parse_executable(dv).as_deref(), Some("/Applications/eBay.app/Wrapper/eBay.app/eBay"));
        assert_eq!(parse_team("Signature=adhoc\nTeamIdentifier=not set\n"), None);
        assert_eq!(parse_team("Identifier=x\n"), None);
    }

    #[test]
    fn trust_fix_is_reversible_and_local() {
        let ctx = Ctx::with_home(PathBuf::from("/Users/x"));
        let item = LaunchItem { plist: "/Users/x/Library/LaunchAgents/com.a.plist".into(), label: "com.a".into(), target: None, env_names: vec![], disabled: false };
        let f = trust_fix(&item, Path::new("/Users/x/bin/a.sh"), "ab12", &ctx);
        assert!(f.is_trust_action());
        assert!(!f.needs_admin());
        assert!(matches!(&f.steps[0], Step::Trust { file, label, sha256, .. } if file == "/Users/x/Library/Application Support/Mac Cleaner Pro/trusted-startup-items.json" && label == "com.a" && sha256 == "ab12"));
        assert!(matches!(&f.undo.as_ref().unwrap()[0], Step::Untrust { .. }));
        let u = untrust_fix(&item, Path::new("/Users/x/bin/a.sh"), "ab12", &ctx);
        assert!(u.is_trust_action());
        assert!(matches!(&u.undo.as_ref().unwrap()[0], Step::Trust { .. }));
        assert!(privacy_protected(Path::new("/Users/x/Documents/a.sh"), Path::new("/Users/x")));
        assert!(!privacy_protected(Path::new("/Users/x/bin/a.sh"), Path::new("/Users/x")));
    }

    #[test]
    fn spctl_parse() {
        assert_eq!(parse_spctl("/Applications/LuLu.app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: X\n"), (true, "Notarized Developer ID".into()));
        assert_eq!(parse_spctl("/opt/homebrew/bin/ollama: rejected\n"), (false, String::new()));
        assert_eq!(parse_spctl("/tmp/t.sh: rejected\nsource=no usable signature\n").1, "no usable signature");
    }

    #[test]
    fn targets() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let t = resolve_target(None, &a(&["/usr/bin/caffeinate", "-i", "/Users/x/Projects/bot/bin/bot", "--token", "SECRET"])).unwrap();
        assert_eq!(t.target, "/Users/x/Projects/bot/bin/bot");
        let t = resolve_target(None, &a(&["/bin/bash", "-c", "cd /Users/x/p && ./run.sh --key abc"])).unwrap();
        assert_eq!(t.target, "/Users/x/p");
        assert!(t.inline_shell);
        let t = resolve_target(None, &a(&["/opt/homebrew/opt/ollama/bin/ollama", "serve"])).unwrap();
        assert_eq!(t.target, "/opt/homebrew/opt/ollama/bin/ollama");
        let t = resolve_target(Some("/usr/bin/python3"), &a(&["python3", "/Users/x/s.py"])).unwrap();
        assert_eq!(t.target, "/Users/x/s.py");
        assert!(resolve_target(None, &[]).is_none());
    }

    #[test]
    fn plist_json() {
        let j = r#"{"ProgramArguments":["/opt/homebrew/opt/dnscrypt-proxy/sbin/dnscrypt-proxy","-config","/opt/homebrew/etc/dnscrypt-proxy.toml"],"KeepAlive":true,"Label":"homebrew.mxcl.dnscrypt-proxy","EnvironmentVariables":{"API_TOKEN":"zzz"}}"#;
        let it = parse_launch_plist_json(Path::new("/Library/LaunchDaemons/x.plist"), j).unwrap();
        assert_eq!(it.label, "homebrew.mxcl.dnscrypt-proxy");
        assert_eq!(it.target.unwrap().target, "/opt/homebrew/opt/dnscrypt-proxy/sbin/dnscrypt-proxy");
        assert_eq!(it.env_names, vec!["API_TOKEN"]);
    }

    #[test]
    fn quarantine_is_reversible_move() {
        let ctx = Ctx::with_home(PathBuf::from("/Users/x"));
        let item = LaunchItem { plist: "/Users/x/Library/LaunchAgents/com.a.plist".into(), label: "com.a".into(), target: None, env_names: vec![], disabled: false };
        let f = quarantine_fix(&item, false, &ctx);
        assert!(!f.needs_admin());
        assert!(f.steps.iter().any(|s| matches!(s, Step::Move { .. })));
        assert!(f.undo.as_ref().unwrap().iter().any(|s| matches!(s, Step::Move { to, .. } if to.ends_with("com.a.plist") && to.contains("LaunchAgents"))));
        let sys = LaunchItem { plist: "/Library/LaunchDaemons/com.b.plist".into(), ..item };
        let f = quarantine_fix(&sys, true, &ctx);
        assert!(f.needs_admin());
        assert!(!f.preview().join(" ").contains("rm "));
    }

    #[test]
    fn crontab_parse() {
        let s = "# comment\nSHELL=/bin/sh\nAPI_KEY=secret\n*/5 * * * * /usr/local/bin/sync --token abc\n@reboot /Users/x/start.sh\n";
        let v = parse_crontab(s);
        assert_eq!(v, vec![("*/5 * * * *".into(), "/usr/local/bin/sync".into()), ("@reboot".into(), "/Users/x/start.sh".into())]);
    }

    #[test]
    fn login_items_parse() {
        assert_eq!(parse_login_items("LuLu, Rectangle\n"), vec!["LuLu", "Rectangle"]);
        assert!(parse_login_items("\n").is_empty());
    }
}
