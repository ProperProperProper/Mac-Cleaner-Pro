//! Security audit + actions.
//!
//! Audit rules:
//!   - Inspection is read-only. Nothing changes unless the user clicks a Fix
//!     button, reviews exactly what will change, and confirms.
//!   - Secret VALUES are never displayed, logged or exported — only file paths
//!     and variable/key NAMES.
//!   - No network calls of its own and no telemetry. (`softwareupdate` is
//!     Apple's tool and talks to Apple; `gh repo view` is used read-only to
//!     learn whether a repo holding a secret is public.)
//!   - No privacy-protected folders: never reads ~/Desktop, ~/Documents,
//!     ~/Downloads, Photos, Mail, Safari data. Scans home dotfiles, ~/Library
//!     launch agents/app-support of browsers, and ~/Projects only.
//!   - Every check degrades to "could not check" — never a crash.

pub mod checks;
pub mod fix;
pub mod report;
pub mod trusted;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::OnceLock;

pub use fix::{Fix, Step};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub enum Status {
    Ok,
    Info,
    Warning,
    Critical,
    Unknown,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Info => "INFO",
            Status::Warning => "WARNING",
            Status::Critical => "CRITICAL",
            Status::Unknown => "COULD NOT CHECK",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
pub enum Category {
    System,
    Updates,
    Firewall,
    Network,
    Sharing,
    Accounts,
    Persistence,
    Apps,
    Trust,
    Secrets,
    Files,
    DevTools,
}

impl Category {
    pub const ALL: [Category; 12] = [
        Category::System,
        Category::Updates,
        Category::Firewall,
        Category::Network,
        Category::Sharing,
        Category::Accounts,
        Category::Persistence,
        Category::Apps,
        Category::Trust,
        Category::Secrets,
        Category::Files,
        Category::DevTools,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Category::System => "System protection",
            Category::Updates => "Software updates",
            Category::Firewall => "Firewall",
            Category::Network => "Network",
            Category::Sharing => "Sharing services",
            Category::Accounts => "Accounts & device",
            Category::Persistence => "Startup items & persistence",
            Category::Apps => "Apps & extensions",
            Category::Trust => "Trust (certificates, sudo)",
            Category::Secrets => "Plaintext secrets",
            Category::Files => "Files, SSH & privacy",
            Category::DevTools => "Developer tools",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    /// Id of the check that produced it (set by the runner).
    pub check_id: &'static str,
    pub category: Category,
    pub title: String,
    pub status: Status,
    pub summary: String,
    pub evidence: Vec<String>,
    pub explanation: String,
    pub fix_text: String,
    pub fix_command: Option<String>,
    pub fixes: Vec<Fix>,
}

impl Finding {
    pub fn new(category: Category, title: impl Into<String>, status: Status, summary: impl Into<String>) -> Self {
        Finding {
            check_id: "",
            category,
            title: title.into(),
            status,
            summary: summary.into(),
            evidence: vec![],
            explanation: String::new(),
            fix_text: String::new(),
            fix_command: None,
            fixes: vec![],
        }
    }
    pub fn unknown(category: Category, title: impl Into<String>, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Finding::new(category, title, Status::Unknown, format!("Could not check: {reason}"))
            .explain("This check could not run (tool missing, timed out or permission denied). It is not counted as a problem.")
    }
    pub fn evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }
    pub fn evidence_all<I: IntoIterator<Item = String>>(mut self, e: I) -> Self {
        self.evidence.extend(e);
        self
    }
    pub fn explain(mut self, s: impl Into<String>) -> Self {
        self.explanation = s.into();
        self
    }
    pub fn fix_text(mut self, s: impl Into<String>) -> Self {
        self.fix_text = s.into();
        self
    }
    pub fn command(mut self, s: impl Into<String>) -> Self {
        self.fix_command = Some(s.into());
        self
    }
    pub fn with_fix(mut self, f: Fix) -> Self {
        self.fixes.push(f);
        self
    }
}

/// A listening socket (shared by the network and sharing checks).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Socket {
    pub proto: String, // "TCP" / "UDP"
    pub host: String,
    pub port: u16,
    pub process: String,
}

/// Shared context for one audit run.
pub struct Ctx {
    pub home: PathBuf,
    pub projects: PathBuf,
    pub include_login_items: bool,
    pub stamp: String,
    sockets: OnceLock<Result<Vec<Socket>, String>>,
}

impl Ctx {
    pub fn new(include_login_items: bool) -> Self {
        let home = crate::util::home();
        Ctx {
            projects: home.join("Projects"),
            home,
            include_login_items,
            stamp: crate::util::now_compact(),
            sockets: OnceLock::new(),
        }
    }
    pub fn with_home(home: PathBuf) -> Self {
        Ctx {
            projects: home.join("Projects"),
            home,
            include_login_items: false,
            stamp: "test".into(),
            sockets: OnceLock::new(),
        }
    }
    pub fn sockets(&self) -> Result<&Vec<Socket>, String> {
        self.sockets
            .get_or_init(checks::network::collect_sockets)
            .as_ref()
            .map_err(|e| e.clone())
    }
    pub fn port_listening(&self, port: u16) -> bool {
        self.sockets()
            .map(|s| s.iter().any(|x| x.proto == "TCP" && x.port == port))
            .unwrap_or(false)
    }
    /// Folder where quarantined startup items are moved (user-level items).
    pub fn quarantine_dir(&self) -> PathBuf {
        self.home
            .join("Library/Application Support/MacCleanerPro/Quarantine")
            .join(&self.stamp)
    }
    /// Startup items the user marked as trusted (see `trusted`).
    pub fn trust_file(&self) -> PathBuf {
        trusted::default_path(&self.home)
    }
    pub fn backup_dir(&self) -> PathBuf {
        self.home.join("Library/Application Support/MacCleanerPro/Backups")
    }
}

pub type CheckFn = fn(&Ctx) -> Vec<Finding>;

pub struct CheckDef {
    pub id: &'static str,
    pub name: &'static str,
    pub category: Category,
    /// Slow checks (network-bound or many subprocesses) — run in the background.
    pub slow: bool,
    pub run: CheckFn,
}

pub fn registry() -> Vec<CheckDef> {
    checks::registry()
}

/// Run one check, converting a panic into a "could not check" finding.
pub fn run_check(def: &CheckDef, ctx: &Ctx) -> Vec<Finding> {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (def.run)(ctx)));
    let mut out = r.unwrap_or_else(|_| vec![Finding::unknown(def.category, def.name, "internal error in this check")]);
    if out.is_empty() {
        out.push(Finding::unknown(def.category, def.name, "no result"));
    }
    for f in &mut out {
        f.check_id = def.id;
    }
    out
}

/// Run all checks in parallel; results in registry order.
pub fn run_all(ctx: &Ctx) -> Vec<Finding> {
    let defs = registry();
    let mut results: Vec<Vec<Finding>> = vec![vec![]; defs.len()];
    std::thread::scope(|s| {
        let handles: Vec<_> = defs.iter().map(|d| s.spawn(move || run_check(d, ctx))).collect();
        for (i, h) in handles.into_iter().enumerate() {
            results[i] = h.join().unwrap_or_default();
        }
    });
    results.into_iter().flatten().collect()
}

/// Result of applying (or previewing) a fix.
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    pub ok: bool,
    pub log: Vec<String>,
    pub after: String,
    pub history_id: Option<i64>,
    pub new_findings: Vec<Finding>,
}

fn state_of(findings: &[Finding], title: &str) -> String {
    findings
        .iter()
        .find(|f| f.title == title)
        .map(|f| format!("[{}] {}", f.status.label(), f.summary))
        .unwrap_or_else(|| "resolved (no longer reported)".into())
}

/// Apply a fix the user confirmed: run its steps, re-run the check, and log
/// the action (timestamp, commands, before/after, undo plan) in the history.
/// With `dry_run`, nothing is executed or logged.
pub fn execute_fix(finding: &Finding, fx: &Fix, dry_run: bool, include_login_items: bool) -> ActionOutcome {
    let before = format!("[{}] {}", finding.status.label(), finding.summary);
    let res = fix::apply_steps(&fx.steps, dry_run);
    if dry_run {
        return ActionOutcome { ok: res.is_ok(), log: res.unwrap_or_else(|e| vec![e]), after: before, history_id: None, new_findings: vec![] };
    }
    let (ok, log) = match res {
        Ok(l) => (true, l),
        Err(e) => (false, vec![format!("failed: {e}")]),
    };
    let ctx = Ctx::new(include_login_items);
    let new_findings = registry()
        .iter()
        .find(|d| d.id == finding.check_id)
        .map(|d| run_check(d, &ctx))
        .unwrap_or_default();
    let after = if fx.opens_settings() { "System Settings opened — use Re-check after changing it".to_string() } else { state_of(&new_findings, &finding.title) };
    let undo_json = if ok { fx.undo.as_ref().and_then(|u| serde_json::to_string(u).ok()) } else { None };
    let history_id = crate::history::History::open_default().ok().and_then(|h| {
        h.record_action(&finding.title, &fx.label, &fx.preview().join("\n"), &before, &after, &if ok { "ok".to_string() } else { log.join("; ") }, undo_json.as_deref())
            .ok()
    });
    ActionOutcome { ok, log, after, history_id, new_findings }
}

/// Undo a logged action (by history id) using its stored undo plan.
pub fn undo_action(id: i64, undo_json: &str, title: &str) -> Result<Vec<String>, String> {
    let steps: Vec<Step> = serde_json::from_str(undo_json).map_err(|e| e.to_string())?;
    let log = fix::apply_steps(&steps, false)?;
    if let Ok(h) = crate::history::History::open_default() {
        let _ = h.mark_undone(id);
        let cmds: Vec<String> = steps.iter().map(fix::preview_step).collect();
        let _ = h.record_action(title, "Undo", &cmds.join("\n"), "", "undone", "ok", None);
    }
    Ok(log)
}
