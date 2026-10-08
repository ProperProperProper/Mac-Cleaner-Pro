//! Pending updates (softwareupdate -l) and automatic-update settings.

use super::super::fix::{Fix, admin, pane, settings_fix};
use super::super::{Category::Updates, Ctx, Finding, Status};
use crate::cmd;
use crate::util::sh_quote;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct Update {
    pub label: String,
    pub title: String,
    pub version: String,
    pub recommended: bool,
    pub restart: bool,
}

pub fn parse_softwareupdate(out: &str) -> Vec<Update> {
    let mut v: Vec<Update> = vec![];
    for line in out.lines() {
        let l = line.trim();
        if let Some(label) = l.strip_prefix("* Label:") {
            v.push(Update {
                label: label.trim().to_string(),
                title: String::new(),
                version: String::new(),
                recommended: false,
                restart: false,
            });
        } else if l.starts_with("Title:")
            && let Some(u) = v.last_mut()
        {
            for part in l.split(',') {
                let (k, val) = match part.split_once(':') {
                    Some((k, val)) => (k.trim(), val.trim()),
                    None => continue,
                };
                match k {
                    "Title" => u.title = val.to_string(),
                    "Version" => u.version = val.to_string(),
                    "Recommended" => u.recommended = val.eq_ignore_ascii_case("YES"),
                    "Action" => u.restart = val.eq_ignore_ascii_case("restart"),
                    _ => {}
                }
            }
        }
    }
    v
}

fn major(v: &str) -> Option<u32> {
    v.split('.').next()?.trim().parse().ok()
}

/// A full macOS major upgrade (e.g. 26 → 27) is optional; same-major updates are patches.
pub fn is_major_upgrade(u: &Update, current: &str) -> bool {
    u.title.starts_with("macOS") && matches!((major(&u.version), major(current)), (Some(a), Some(b)) if a > b)
}

pub fn pending(_: &Ctx) -> Vec<Finding> {
    let t = "Pending software updates";
    let cur = cmd::run("sw_vers", &["-productVersion"]).map(|o| o.stdout.trim().to_string()).unwrap_or_default();
    let o = match cmd::run_timeout("softwareupdate", &["-l"], Duration::from_secs(300)) {
        Ok(o) => o,
        Err(e) => return vec![Finding::unknown(Updates, t, e.to_string())],
    };
    let out = o.combined();
    if out.contains("No new software available") {
        return vec![Finding::new(Updates, t, Status::Ok, format!("macOS {cur} is up to date."))
            .evidence("softwareupdate -l: No new software available.")];
    }
    let ups = parse_softwareupdate(&out);
    if ups.is_empty() {
        let first = out.lines().last().unwrap_or("").trim().to_string();
        return vec![Finding::unknown(Updates, t, format!("could not list updates ({first})"))];
    }
    let (majors, patches): (Vec<&Update>, Vec<&Update>) = ups.iter().partition(|u| is_major_upgrade(u, &cur));
    let ev: Vec<String> = ups
        .iter()
        .map(|u| {
            format!(
                "{} {}{}{}",
                u.title,
                u.version,
                if u.restart { " — RESTART REQUIRED" } else { "" },
                if is_major_upgrade(u, &cur) { " (optional major upgrade)" } else { "" }
            )
        })
        .collect();
    let why = "Updates fix actively exploited security holes. Patch releases for your current macOS version should be installed promptly; a new major version is optional.";
    if patches.is_empty() {
        return vec![Finding::new(Updates, t, Status::Info, format!("Up to date for macOS {cur}; a major upgrade is available ({}).", majors.len()))
            .evidence_all(ev)
            .explain(why)
            .with_fix(settings_fix("Open Software Update", pane::UPDATE, "Upgrade when convenient."))];
    }
    let restart = patches.iter().any(|u| u.restart);
    let labels: Vec<String> = patches.iter().map(|u| sh_quote(&u.label)).collect();
    let mut fx = Fix::new(format!("Install {} update(s)", patches.len()))
        .step(admin(format!("/usr/sbin/softwareupdate -i {}", labels.join(" "))))
        .warn(if restart {
            "One or more updates need a RESTART to finish. This app does not restart the Mac — macOS will ask you. Save your work first. Downloading can take a long time."
        } else {
            "Downloading and installing can take a while."
        });
    for u in &patches {
        fx = fx.change(format!("Install {} {}{}", u.title, u.version, if u.restart { " (restart required)" } else { "" }));
    }
    vec![Finding::new(
        Updates,
        t,
        Status::Warning,
        format!("{} update(s) pending for macOS {cur}{}.", patches.len(), if restart { " — restart required" } else { "" }),
    )
    .evidence_all(ev)
    .explain(why)
    .fix_text("System Settings → General → Software Update → Update Now.")
    .command(format!("sudo softwareupdate -i {}", labels.join(" ")))
    .with_fix(fx)
    .with_fix(settings_fix("Open Software Update", pane::UPDATE, "Click Update Now."))]
}

/// Parse `defaults read <domain>` dictionary output into key → raw value.
pub fn parse_defaults_dict(out: &str) -> BTreeMap<String, String> {
    out.lines()
        .filter_map(|l| {
            let l = l.trim().trim_end_matches(';');
            let (k, v) = l.split_once(" = ")?;
            Some((k.trim().trim_matches('"').to_string(), v.trim().trim_matches('"').to_string()))
        })
        .collect()
}

pub struct AutoKey {
    pub key: &'static str,
    pub name: &'static str,
    pub security: bool,
}

pub const AUTO_KEYS: [AutoKey; 5] = [
    AutoKey { key: "AutomaticCheckEnabled", name: "Check for updates automatically", security: true },
    AutoKey { key: "AutomaticDownload", name: "Download new updates when available", security: false },
    AutoKey { key: "CriticalUpdateInstall", name: "Install Security Responses (Rapid Security Responses)", security: true },
    AutoKey { key: "ConfigDataInstall", name: "Install system data files (XProtect/malware definitions)", security: true },
    AutoKey { key: "AutomaticallyInstallMacOSUpdates", name: "Install macOS updates automatically", security: false },
];

pub const SU_PLIST: &str = "/Library/Preferences/com.apple.SoftwareUpdate";

/// Returns (key, name, security, current value: Some(bool) or None = not set → macOS default on).
pub fn evaluate_auto(map: &BTreeMap<String, String>) -> Vec<(&'static AutoKey, Option<bool>)> {
    AUTO_KEYS
        .iter()
        .map(|k| (k, super::truthy(map.get(k.key).map(|s| s.as_str()))))
        .collect()
}

pub fn auto_settings(_: &Ctx) -> Vec<Finding> {
    let t = "Automatic update settings";
    let o = match cmd::run("defaults", &["read", SU_PLIST]) {
        Ok(o) => o,
        Err(e) => return vec![Finding::unknown(Updates, t, e.to_string())],
    };
    let map = parse_defaults_dict(&o.stdout);
    let vals = evaluate_auto(&map);
    let mut ev = vec![];
    let mut off_sec = vec![];
    let mut off_other = vec![];
    for (k, v) in &vals {
        let on = v.unwrap_or(k.key != "AutomaticallyInstallMacOSUpdates");
        ev.push(format!("{} ({}): {}{}", k.name, k.key, if on { "on" } else { "OFF" }, if v.is_none() { " (default)" } else { "" }));
        if !on {
            if k.security { off_sec.push((*k, *v)) } else { off_other.push((*k, *v)) }
        }
    }
    let app_store = super::defaults_read("/Library/Preferences/com.apple.commerce", "AutoUpdate");
    ev.push(format!("App Store app updates (com.apple.commerce AutoUpdate): {}", match super::truthy(app_store.as_deref()) {
        Some(true) => "on",
        Some(false) => "OFF",
        None => "default",
    }));
    let why = "Security Responses and system data files deliver urgent fixes and XProtect malware definitions in the background, without a full macOS update. With them off, malware protection silently goes stale.";
    let all_off: Vec<(&AutoKey, Option<bool>)> = off_sec.iter().chain(off_other.iter()).cloned().collect();
    let make_fix = |items: &[(&AutoKey, Option<bool>)]| {
        let mut f = Fix::new("Turn on automatic security updates");
        let mut script = vec![];
        let mut undo = vec![];
        for (k, prev) in items {
            f = f.change(format!("{}: off → on", k.name));
            script.push(format!("/usr/bin/defaults write {SU_PLIST} {} -bool true", k.key));
            undo.push(match prev {
                Some(b) => format!("/usr/bin/defaults write {SU_PLIST} {} -bool {}", k.key, b),
                None => format!("/usr/bin/defaults delete {SU_PLIST} {}", k.key),
            });
        }
        f.step(admin(script.join(" && "))).undo(vec![admin(undo.join("; "))])
    };
    let status = if !off_sec.is_empty() {
        Status::Critical
    } else if !off_other.is_empty() {
        Status::Info
    } else {
        Status::Ok
    };
    let summary = match status {
        Status::Critical => format!("Security auto-updates are OFF: {}.", off_sec.iter().map(|(k, _)| k.name).collect::<Vec<_>>().join("; ")),
        Status::Info => "Security updates are automatic; some optional auto-installs are off.".to_string(),
        _ => "All automatic update options are on.".to_string(),
    };
    let mut f = Finding::new(Updates, t, status, summary).evidence_all(ev).explain(why);
    if !all_off.is_empty() {
        f = f
            .fix_text("System Settings → General → Software Update → (i) next to Automatic Updates → turn everything on, especially \"Install Security Responses and system files\".")
            .command(all_off.iter().map(|(k, _)| format!("sudo defaults write {SU_PLIST} {} -bool true", k.key)).collect::<Vec<_>>().join("\n"))
            .with_fix(make_fix(if off_sec.is_empty() { &all_off } else { &off_sec }))
            .with_fix(settings_fix("Open Software Update", pane::UPDATE, "Click (i) next to Automatic Updates and turn the options on."));
    }
    vec![f]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n* Label: Safari27.0TahoeAuto-27.0\n\tTitle: Safari, Version: 27.0, Size: 249465KiB, Recommended: YES, \n* Label: macOS Tahoe 26.7.1-25G241\n\tTitle: macOS Tahoe 26.7.1, Version: 26.7.1, Size: 3852307KiB, Recommended: YES, Action: restart, \n* Label: macOS 27.0.1-26A434\n\tTitle: macOS 27.0.1, Version: 27.0.1, Size: 11853549KiB, Recommended: YES, Action: restart,\n";

    #[test]
    fn parse_updates() {
        let u = parse_softwareupdate(SAMPLE);
        assert_eq!(u.len(), 3);
        assert_eq!(u[0].title, "Safari");
        assert!(!u[0].restart);
        assert_eq!(u[1].label, "macOS Tahoe 26.7.1-25G241");
        assert!(u[1].restart && u[1].recommended);
        assert!(!is_major_upgrade(&u[1], "26.5"));
        assert!(is_major_upgrade(&u[2], "26.5"));
        assert!(!is_major_upgrade(&u[0], "26.5"));
        assert!(parse_softwareupdate("No new software available.\n").is_empty());
    }

    #[test]
    fn parse_su_prefs() {
        let s = "{\n    AutomaticDownload = 1;\n    AutomaticallyInstallMacOSUpdates = 0;\n    ConfigDataInstall = 0;\n    CriticalUpdateInstall = 0;\n    LastResultCode = 2;\n}\n";
        let m = parse_defaults_dict(s);
        assert_eq!(m.get("ConfigDataInstall").map(|s| s.as_str()), Some("0"));
        let e = evaluate_auto(&m);
        let get = |k: &str| e.iter().find(|(a, _)| a.key == k).unwrap().1;
        assert_eq!(get("AutomaticCheckEnabled"), None);
        assert_eq!(get("CriticalUpdateInstall"), Some(false));
        assert_eq!(get("AutomaticDownload"), Some(true));
    }
}
