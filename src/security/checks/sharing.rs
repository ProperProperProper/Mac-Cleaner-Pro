//! Sharing services: Remote Login, Screen Sharing, File Sharing, Remote
//! Management, Remote Apple Events, Printer/Internet Sharing, AirPlay
//! Receiver, Bluetooth.

use super::super::fix::{Fix, admin, pane, run, settings_fix};
use super::super::{Category::Sharing, Ctx, Finding, Status};
use super::{defaults_read, defaults_read_host, launchd_system_loaded, truthy};
use crate::cmd;

/// Standard fix for a launchd-backed sharing service: disable + stop it
/// (what the System Settings toggle does), undo re-enables it.
fn launchd_fix(name: &str, label: &str, plist: &str) -> Fix {
    Fix::new(format!("Turn off {name}"))
        .change(format!("{name}: on → off (service {label} disabled and stopped)"))
        .step(admin(format!("/bin/launchctl disable system/{label}; /bin/launchctl bootout system/{label} 2>/dev/null; true")))
        .undo(vec![admin(format!(
            "/bin/launchctl enable system/{label}; /bin/launchctl bootstrap system {plist} 2>/dev/null; true"
        ))])
}

struct Svc {
    title: &'static str,
    why: &'static str,
    settings_hint: &'static str,
}

fn on_finding(s: &Svc, evidence: Vec<String>) -> Finding {
    Finding::new(Sharing, s.title, Status::Warning, format!("{} is ON.", s.title))
        .evidence_all(evidence)
        .explain(s.why)
        .fix_text(format!("System Settings → General → Sharing → turn off {}. {}", s.title, s.settings_hint))
}

fn off_finding(s: &Svc, evidence: Vec<String>) -> Finding {
    Finding::new(Sharing, s.title, Status::Ok, format!("{} is off.", s.title)).evidence_all(evidence).explain(s.why)
}

/// Parse `cupsctl` output → printer sharing on?
pub fn parse_cupsctl_share(out: &str) -> Option<bool> {
    out.lines().find_map(|l| l.trim().strip_prefix("_share_printers=").map(|v| v.trim() == "1"))
}

/// Parse `defaults read …/com.apple.nat NAT` (Internet Sharing) → Enabled?
pub fn parse_nat_enabled(out: &str) -> Option<bool> {
    out.lines().find_map(|l| {
        let l = l.trim().trim_end_matches(';');
        l.strip_prefix("Enabled = ").map(|v| v.trim() == "1")
    })
}

pub fn sharing(ctx: &Ctx) -> Vec<Finding> {
    let mut out = vec![];

    // Remote Login (SSH)
    let s = Svc {
        title: "Remote Login (SSH)",
        why: "Remote Login lets anyone who knows (or guesses) an account password, or holds an authorized key, get a shell on this Mac over the network.",
        settings_hint: "",
    };
    let loaded = launchd_system_loaded("com.openssh.sshd");
    let p22 = ctx.port_listening(22);
    let ev = vec![format!("launchd com.openssh.sshd loaded: {}", fmt_res(&loaded)), format!("TCP port 22 listening: {p22}")];
    out.push(match (loaded, p22) {
        (Ok(true), _) | (_, true) => on_finding(&s, ev)
            .command("sudo systemsetup -setremotelogin off")
            .with_fix(launchd_fix("Remote Login", "com.openssh.sshd", "/System/Library/LaunchDaemons/ssh.plist"))
            .with_fix(settings_fix("Open Sharing settings", pane::SHARING, "Turn off Remote Login.")),
        (Ok(false), false) => off_finding(&s, ev),
        (Err(e), false) => Finding::unknown(Sharing, s.title, e),
    });

    // Screen Sharing
    let s = Svc {
        title: "Screen Sharing",
        why: "Screen Sharing (VNC) lets others view and control this Mac remotely.",
        settings_hint: "",
    };
    let loaded = launchd_system_loaded("com.apple.screensharing");
    let p = ctx.port_listening(5900);
    let ev = vec![format!("launchd com.apple.screensharing loaded: {}", fmt_res(&loaded)), format!("TCP port 5900 listening: {p}")];
    out.push(match (loaded, p) {
        (Ok(true), _) | (_, true) => on_finding(&s, ev)
            .with_fix(launchd_fix("Screen Sharing", "com.apple.screensharing", "/System/Library/LaunchDaemons/com.apple.screensharing.plist"))
            .with_fix(settings_fix("Open Sharing settings", pane::SHARING, "Turn off Screen Sharing.")),
        (Ok(false), false) => off_finding(&s, ev),
        (Err(e), false) => Finding::unknown(Sharing, s.title, e),
    });

    // File Sharing
    let s = Svc {
        title: "File Sharing (SMB/AFP)",
        why: "File Sharing exposes shared folders to the local network; weak passwords or guest access can leak files.",
        settings_hint: "",
    };
    let loaded = launchd_system_loaded("com.apple.smbd");
    let p = ctx.port_listening(445) || ctx.port_listening(548);
    let ev = vec![format!("launchd com.apple.smbd loaded: {}", fmt_res(&loaded)), format!("TCP 445/548 listening: {p}")];
    out.push(match (loaded, p) {
        (Ok(true), _) | (_, true) => on_finding(&s, ev)
            .with_fix(launchd_fix("File Sharing", "com.apple.smbd", "/System/Library/LaunchDaemons/com.apple.smbd.plist"))
            .with_fix(settings_fix("Open Sharing settings", pane::SHARING, "Turn off File Sharing.")),
        (Ok(false), false) => off_finding(&s, ev),
        (Err(e), false) => Finding::unknown(Sharing, s.title, e),
    });

    // Remote Management (ARD)
    let s = Svc {
        title: "Remote Management (ARD)",
        why: "Remote Management gives Apple Remote Desktop full control of this Mac — normally only used on company-managed Macs.",
        settings_hint: "",
    };
    let ard_proc = cmd::run("pgrep", &["-x", "ARDAgent"]).map(|o| o.success()).unwrap_or(false);
    let ard_file = std::path::Path::new("/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd").exists();
    let p = ctx.port_listening(3283);
    let ev = vec![format!("ARDAgent running: {ard_proc}"), format!("RemoteManagement.launchd present: {ard_file}"), format!("port 3283 listening: {p}")];
    let kick = "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart";
    out.push(if ard_file || p || ard_proc {
        on_finding(&s, ev)
            .command(format!("sudo {kick} -deactivate -configure -access -off"))
            .with_fix(
                Fix::new("Turn off Remote Management")
                    .change("Remote Management: on → off")
                    .step(admin(format!("{kick} -deactivate -configure -access -off")))
                    .warn("No automatic undo: re-enable it in System Settings → Sharing if you need it."),
            )
            .with_fix(settings_fix("Open Sharing settings", pane::SHARING, "Turn off Remote Management."))
    } else {
        off_finding(&s, ev)
    });

    // Remote Apple Events
    let s = Svc {
        title: "Remote Apple Events",
        why: "Remote Apple Events let other computers send AppleScript commands to apps on this Mac.",
        settings_hint: "",
    };
    let loaded = launchd_system_loaded("com.apple.AEServer");
    let p = ctx.port_listening(3031);
    let ev = vec![format!("launchd com.apple.AEServer loaded: {}", fmt_res(&loaded)), format!("TCP 3031 listening: {p}")];
    out.push(match (loaded, p) {
        (Ok(true), _) | (_, true) => on_finding(&s, ev)
            .command("sudo systemsetup -setremoteappleevents off")
            .with_fix(launchd_fix("Remote Apple Events", "com.apple.AEServer", "/System/Library/LaunchDaemons/com.apple.AEServer.plist"))
            .with_fix(settings_fix("Open Sharing settings", pane::SHARING, "Turn off Remote Application Scripting.")),
        (Ok(false), false) => off_finding(&s, ev),
        (Err(e), false) => Finding::unknown(Sharing, s.title, e),
    });

    // Printer Sharing
    let s = Svc { title: "Printer Sharing", why: "Printer Sharing exposes the CUPS print service (port 631) to the network.", settings_hint: "" };
    out.push(match cmd::run("cupsctl", &[]) {
        Err(e) => Finding::unknown(Sharing, s.title, e.to_string()),
        Ok(o) => match parse_cupsctl_share(&o.stdout) {
            Some(true) => on_finding(&s, vec!["cupsctl: _share_printers=1".into()])
                .command("cupsctl --no-share-printers")
                .with_fix(
                    Fix::new("Turn off Printer Sharing")
                        .change("Printer Sharing: on → off")
                        .step(admin("/usr/sbin/cupsctl --no-share-printers"))
                        .undo(vec![admin("/usr/sbin/cupsctl --share-printers")]),
                ),
            Some(false) => off_finding(&s, vec!["cupsctl: _share_printers=0".into()]),
            None => Finding::unknown(Sharing, s.title, "cupsctl output not recognised"),
        },
    });

    // Internet Sharing
    let s = Svc {
        title: "Internet Sharing",
        why: "Internet Sharing turns this Mac into a router for other devices, bridging networks.",
        settings_hint: "",
    };
    let nat = cmd::run("defaults", &["read", "/Library/Preferences/SystemConfiguration/com.apple.nat", "NAT"])
        .ok()
        .filter(|o| o.success())
        .and_then(|o| parse_nat_enabled(&o.stdout));
    out.push(if nat == Some(true) {
        on_finding(&s, vec!["com.apple.nat NAT Enabled = 1".into()])
            .with_fix(settings_fix("Open Sharing settings", pane::SHARING, "Turn off Internet Sharing."))
    } else {
        off_finding(&s, vec![format!("com.apple.nat NAT Enabled: {}", if nat.is_none() { "not configured" } else { "0" })])
    });

    // AirPlay Receiver (Apple's own key spells it "Reciever")
    let s = Svc {
        title: "AirPlay Receiver",
        why: "AirPlay Receiver listens on ports 5000/7000 so nearby devices can stream to this Mac. It has had remotely exploitable bugs; turn it off if you don't use it.",
        settings_hint: "",
    };
    let key = truthy(defaults_read("com.apple.controlcenter", "AirplayRecieverEnabled").as_deref());
    let listening = ctx
        .sockets()
        .map(|v| v.iter().any(|x| x.proto == "TCP" && (x.port == 5000 || x.port == 7000) && x.process.starts_with("ControlCe")))
        .unwrap_or(false);
    let ev = vec![
        format!("defaults com.apple.controlcenter AirplayRecieverEnabled: {}", key.map(|b| if b { "1" } else { "0" }).unwrap_or("not set (macOS default: on)")),
        format!("ControlCenter listening on 5000/7000: {listening}"),
    ];
    out.push(if listening || key == Some(true) {
        Finding::new(Sharing, s.title, Status::Warning, "AirPlay Receiver is ON.")
            .evidence_all(ev)
            .explain(s.why)
            .fix_text("System Settings → General → AirDrop & Handoff → AirPlay Receiver → off. (Changing the defaults key alone does not stop it on current macOS.)")
            .with_fix(settings_fix("Open AirDrop & Handoff", pane::AIRDROP, "Turn off AirPlay Receiver."))
    } else {
        off_finding(&s, ev)
    });

    // Bluetooth Sharing / discoverability
    let bt = truthy(defaults_read_host("com.apple.Bluetooth", "PrefKeyServicesEnabled").as_deref());
    out.push(if bt == Some(true) {
        Finding::new(Sharing, "Bluetooth Sharing", Status::Warning, "Bluetooth Sharing is ON.")
            .evidence("PrefKeyServicesEnabled = 1")
            .explain("Bluetooth Sharing lets nearby devices send or browse files.")
            .with_fix(
                Fix::new("Turn off Bluetooth Sharing")
                    .change("Bluetooth Sharing: on → off")
                    .step(run(&["defaults", "-currentHost", "write", "com.apple.Bluetooth", "PrefKeyServicesEnabled", "-bool", "false"]))
                    .undo(vec![run(&["defaults", "-currentHost", "write", "com.apple.Bluetooth", "PrefKeyServicesEnabled", "-bool", "true"])]),
            )
    } else {
        Finding::new(Sharing, "Bluetooth Sharing", Status::Ok, "Bluetooth Sharing is off.")
            .evidence(format!("PrefKeyServicesEnabled: {}", if bt.is_none() { "not set" } else { "0" }))
            .explain("macOS is only discoverable over Bluetooth while the Bluetooth settings pane is open; Bluetooth file sharing is off.")
            .with_fix(settings_fix("Open Bluetooth settings", pane::BLUETOOTH, "Turn Bluetooth off when not needed."))
    });
    out
}

fn fmt_res(r: &Result<bool, String>) -> String {
    match r {
        Ok(b) => b.to_string(),
        Err(e) => format!("unknown ({e})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cups() {
        assert_eq!(parse_cupsctl_share("_debug_logging=0\n_share_printers=0\n_user_cancel_any=0\n"), Some(false));
        assert_eq!(parse_cupsctl_share("_share_printers=1\n"), Some(true));
        assert_eq!(parse_cupsctl_share(""), None);
    }

    #[test]
    fn nat() {
        assert_eq!(parse_nat_enabled("{\n    Enabled = 1;\n    PrimaryInterface = { Device = en0; };\n}\n"), Some(true));
        assert_eq!(parse_nat_enabled("{\n    Enabled = 0;\n}\n"), Some(false));
    }

    #[test]
    fn launchd_fix_has_undo() {
        let f = launchd_fix("Remote Login", "com.openssh.sshd", "/System/Library/LaunchDaemons/ssh.plist");
        assert!(f.needs_admin());
        assert!(f.preview()[0].contains("launchctl disable system/com.openssh.sshd"));
        assert!(f.undo.is_some());
    }
}
