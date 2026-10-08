//! macOS application firewall + third-party firewalls (LuLu, Little Snitch…).

use super::super::fix::{Fix, admin, pane, settings_fix};
use super::super::{Category::Firewall, Ctx, Finding, Status};
use crate::cmd;

const FW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// Global state: 0 off, 1 on, 2 on + block all non-essential.
pub fn parse_global_state(out: &str) -> Option<u8> {
    if let Some(i) = out.find("State = ") {
        return out[i + 8..].chars().next()?.to_digit(10).map(|d| d as u8);
    }
    let l = out.to_lowercase();
    if l.contains("firewall is disabled") {
        Some(0)
    } else if l.contains("firewall is enabled") {
        Some(1)
    } else {
        None
    }
}

pub fn parse_stealth(out: &str) -> Option<bool> {
    let l = out.to_lowercase();
    if l.contains("stealth mode is on") || l.contains("stealth mode enabled") {
        Some(true)
    } else if l.contains("stealth mode is off") || l.contains("stealth mode disabled") {
        Some(false)
    } else {
        None
    }
}

pub fn parse_blockall(out: &str) -> Option<bool> {
    let l = out.to_lowercase();
    if l.contains("disabled") {
        Some(false)
    } else if l.contains("blocking all") || l.contains("enabled") {
        Some(true)
    } else {
        None
    }
}

fn fw(arg: &str) -> Result<String, String> {
    cmd::run(FW, &[arg]).map(|o| o.combined()).map_err(|e| e.to_string())
}

pub fn app_firewall(_: &Ctx) -> Vec<Finding> {
    let mut out = vec![];
    let t = "Firewall";
    match fw("--getglobalstate") {
        Err(e) => out.push(Finding::unknown(Firewall, t, e)),
        Ok(s) => {
            let ev = s.trim().to_string();
            let why = "The application firewall blocks unsolicited incoming connections to apps and services on this Mac — important on public/hotel/café Wi-Fi.";
            out.push(match parse_global_state(&s) {
                Some(0) => Finding::new(Firewall, t, Status::Warning, "The macOS firewall is OFF.")
                    .evidence(ev)
                    .explain(why)
                    .fix_text("System Settings → Network → Firewall → turn on.")
                    .command(format!("sudo {FW} --setglobalstate on"))
                    .with_fix(
                        Fix::new("Turn on the firewall")
                            .change("Firewall: off → on")
                            .step(admin(format!("{FW} --setglobalstate on")))
                            .undo(vec![admin(format!("{FW} --setglobalstate off"))]),
                    ),
                Some(1) => Finding::new(Firewall, t, Status::Ok, "The firewall is on.").evidence(ev).explain(why),
                Some(_) => Finding::new(Firewall, t, Status::Ok, "The firewall is on and blocking all non-essential incoming connections.").evidence(ev).explain(why),
                None => Finding::unknown(Firewall, t, format!("unrecognised output: {ev}")),
            });
        }
    }
    let t = "Firewall stealth mode";
    match fw("--getstealthmode") {
        Err(e) => out.push(Finding::unknown(Firewall, t, e)),
        Ok(s) => {
            let ev = s.trim().to_string();
            let why = "Stealth mode makes the Mac ignore pings and probes on closed ports, so it is harder to discover on a network.";
            out.push(match parse_stealth(&s) {
                Some(true) => Finding::new(Firewall, t, Status::Ok, "Stealth mode is on.").evidence(ev).explain(why),
                Some(false) => Finding::new(Firewall, t, Status::Warning, "Stealth mode is off.")
                    .evidence(ev)
                    .explain(why)
                    .fix_text("System Settings → Network → Firewall → Options → Enable stealth mode.")
                    .command(format!("sudo {FW} --setstealthmode on"))
                    .with_fix(
                        Fix::new("Turn on stealth mode")
                            .change("Stealth mode: off → on")
                            .step(admin(format!("{FW} --setstealthmode on")))
                            .undo(vec![admin(format!("{FW} --setstealthmode off"))]),
                    ),
                None => Finding::unknown(Firewall, t, format!("unrecognised output: {ev}")),
            });
        }
    }
    let t = "Firewall block-all mode";
    match fw("--getblockall") {
        Err(e) => out.push(Finding::unknown(Firewall, t, e)),
        Ok(s) => {
            let ev = s.trim().to_string();
            let why = "Block-all is the strictest setting: only essential services (DHCP, Bonjour, IPSec) may receive connections. It can break AirDrop, AirPlay and sharing.";
            out.push(match parse_blockall(&s) {
                Some(true) => Finding::new(Firewall, t, Status::Ok, "Block all incoming connections: on.").evidence(ev).explain(why),
                Some(false) => Finding::new(Firewall, t, Status::Info, "Block all incoming connections: off (optional hardening).")
                    .evidence(ev)
                    .explain(why)
                    .fix_text("Optional: System Settings → Network → Firewall → Options → Block all incoming connections.")
                    .command(format!("sudo {FW} --setblockall on"))
                    .with_fix(
                        Fix::new("Block all incoming connections")
                            .change("Block-all: off → on")
                            .step(admin(format!("{FW} --setblockall on")))
                            .undo(vec![admin(format!("{FW} --setblockall off"))])
                            .warn("AirDrop, AirPlay receiving, Screen/File Sharing and local dev servers reachable from other devices may stop working."),
                    ),
                None => Finding::unknown(Firewall, t, format!("unrecognised output: {ev}")),
            });
        }
    }
    out
}

pub const KNOWN_FIREWALLS: [(&str, &str); 4] = [
    ("com.objective-see.lulu", "LuLu"),
    ("at.obdev.littlesnitch", "Little Snitch"),
    ("com.radiosilenceapp", "Radio Silence"),
    ("com.vallumapp", "Vallum"),
];

/// Names of known third-party firewalls among active system extensions.
pub fn detect_firewalls(sysext_out: &str) -> Vec<String> {
    let mut v = vec![];
    for line in sysext_out.lines() {
        if !line.contains("activated enabled") {
            continue;
        }
        for (id, name) in KNOWN_FIREWALLS {
            if line.contains(id) && !v.contains(&name.to_string()) {
                v.push(name.to_string());
            }
        }
    }
    v
}

pub fn third_party(_: &Ctx) -> Vec<Finding> {
    let t = "Third-party firewall";
    let sx = cmd::run("systemextensionsctl", &["list"]).map(|o| o.combined());
    let mut names = sx.as_ref().map(|s| detect_firewalls(s)).unwrap_or_default();
    for (proc_name, name) in [("LuLu", "LuLu"), ("Little Snitch Agent", "Little Snitch")] {
        if let Ok(o) = cmd::run("pgrep", &["-x", proc_name])
            && o.success()
            && !names.contains(&name.to_string())
        {
            names.push(format!("{name} (app running)"));
        }
    }
    let why = "An outbound firewall such as LuLu alerts you when an app tries to connect out — useful for spotting malware or apps phoning home. Optional.";
    vec![if !names.is_empty() {
        Finding::new(Firewall, t, Status::Ok, format!("Active: {}", names.join(", "))).evidence_all(names.clone()).explain(why)
    } else if sx.is_err() {
        Finding::unknown(Firewall, t, "systemextensionsctl unavailable")
    } else {
        Finding::new(Firewall, t, Status::Info, "No outbound firewall (e.g. LuLu) detected — optional.")
            .explain(why)
            .fix_text("Optional: install LuLu (free, open source, objective-see.org).")
            .with_fix(settings_fix("Open Network settings", pane::FIREWALL, "Review firewall options."))
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_state() {
        assert_eq!(parse_global_state("Firewall is blocking all non-essential incoming connections. (State = 2)"), Some(2));
        assert_eq!(parse_global_state("Firewall is enabled. (State = 1)"), Some(1));
        assert_eq!(parse_global_state("Firewall is disabled. (State = 0)"), Some(0));
        assert_eq!(parse_global_state("Firewall is disabled."), Some(0));
        assert_eq!(parse_global_state("??"), None);
    }

    #[test]
    fn stealth_blockall() {
        assert_eq!(parse_stealth("Firewall stealth mode is on"), Some(true));
        assert_eq!(parse_stealth("Firewall stealth mode is off"), Some(false));
        assert_eq!(parse_blockall("Firewall is blocking all non-essential incoming connections."), Some(true));
        assert_eq!(parse_blockall("Firewall has block all state set to disabled."), Some(false));
    }

    #[test]
    fn firewalls() {
        let s = "*\t*\tVBG97UB4TA\tcom.objective-see.lulu.extension (4.3.2/4.3.2)\tLuLu\t[activated enabled]\n";
        assert_eq!(detect_firewalls(s), vec!["LuLu"]);
        assert!(detect_firewalls("*\t*\tX\tcom.objective-see.lulu.extension (1)\tLuLu\t[terminated waiting to uninstall on reboot]").is_empty());
    }
}
