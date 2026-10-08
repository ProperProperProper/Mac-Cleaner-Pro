//! Custom-trusted certificates (possible HTTPS interception) and sudo config.

use super::super::fix::{pane, settings_fix};
use super::super::{Category::Trust, Ctx, Finding, Status};
use crate::cmd;

/// Certificate names from `security dump-trust-settings [-d]`.
pub fn parse_trust_settings(out: &str) -> Vec<String> {
    if out.contains("No Trust Settings were found") {
        return vec![];
    }
    out.lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("Cert ")?;
            let (idx, name) = rest.split_once(':')?;
            idx.trim().parse::<u32>().ok()?;
            Some(name.trim().to_string())
        })
        .collect()
}

pub fn certificates(_: &Ctx) -> Vec<Finding> {
    let t = "Custom trusted certificates";
    let user = cmd::run("security", &["dump-trust-settings"]);
    let admin = cmd::run("security", &["dump-trust-settings", "-d"]);
    if user.is_err() && admin.is_err() {
        return vec![Finding::unknown(Trust, t, "security tool unavailable")];
    }
    let mut ev = vec![];
    for (scope, r) in [("login (user)", user), ("system (admin)", admin)] {
        if let Ok(o) = r {
            for n in parse_trust_settings(&o.combined()) {
                ev.push(format!("{scope}: {n}"));
            }
        }
    }
    let why = "A certificate you (or software) marked as trusted can be used to impersonate any website and read your HTTPS traffic. Debugging proxies (Charles, mitmproxy, Proxyman), corporate VPNs and some antivirus tools add these — malware does too.";
    vec![if ev.is_empty() {
        Finding::new(Trust, t, Status::Ok, "No certificates with custom trust settings (only Apple's built-in roots are trusted).").explain(why)
    } else {
        Finding::new(Trust, t, Status::Warning, format!("{} certificate(s) have custom trust — confirm you added them.", ev.len()))
            .evidence_all(ev)
            .explain(why)
            .fix_text("Open Keychain Access → System / login keychain → Certificates; for any you don't recognise, double-click → Trust → \"Use System Defaults\", or delete it.")
            .with_fix(settings_fix("Open Keychain Access", pane::KEYCHAIN_APP, "Find the certificate, double-click it, set Trust to \"Use System Defaults\" or delete it."))
    }]
}

pub fn parse_sudo_l(out: &str) -> Vec<String> {
    out.lines().filter(|l| l.contains("NOPASSWD")).map(|l| l.trim().to_string()).collect()
}

pub fn sudoers(_: &Ctx) -> Vec<Finding> {
    let t = "sudo configuration";
    let mut ev = vec![];
    let mut warn = false;
    match std::fs::read_dir("/etc/sudoers.d") {
        Ok(rd) => {
            let names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
            if names.is_empty() {
                ev.push("/etc/sudoers.d: empty".into());
            } else {
                warn = true;
                ev.extend(names.iter().map(|n| format!("/etc/sudoers.d/{n}")));
            }
        }
        Err(e) => ev.push(format!("/etc/sudoers.d: {e}")),
    }
    if let Ok(m) = std::fs::metadata("/etc/sudoers")
        && let Ok(mt) = m.modified()
    {
        let dt: chrono::DateTime<chrono::Local> = mt.into();
        ev.push(format!("/etc/sudoers last modified {}", dt.format("%Y-%m-%d")));
    }
    // -n: never prompts. Only shows rules if no password is needed.
    if let Ok(o) = cmd::run("sudo", &["-n", "-l"]) {
        let nopw = parse_sudo_l(&o.combined());
        if !nopw.is_empty() {
            warn = true;
            ev.extend(nopw.into_iter().map(|r| format!("passwordless sudo rule: {r}")));
        }
    }
    let why = "sudo rules decide who can run commands as root. Extra files in /etc/sudoers.d or NOPASSWD rules let programs (or malware running as you) become root without a password.";
    vec![if warn {
        Finding::new(Trust, t, Status::Warning, "Custom sudo rules found — confirm you added them.")
            .evidence_all(ev)
            .explain(why)
            .fix_text("Review with `sudo visudo` and `sudo ls -l /etc/sudoers.d`; remove rules you don't need.")
            .command("sudo visudo")
    } else {
        Finding::new(Trust, t, Status::Ok, "No custom sudoers.d files or passwordless sudo rules visible.").evidence_all(ev).explain(why)
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_parse() {
        assert!(parse_trust_settings("SecTrustSettingsCopyCertificates: No Trust Settings were found.").is_empty());
        let s = "Number of trusted certs = 2\nCert 0: Charles Proxy CA (8 Oct 2026)\n   Number of trust settings : 1\nCert 1: Corp Root\n   Number of trust settings : 0\n";
        assert_eq!(parse_trust_settings(s), vec!["Charles Proxy CA (8 Oct 2026)", "Corp Root"]);
    }

    #[test]
    fn sudo_parse() {
        assert!(parse_sudo_l("sudo: a password is required").is_empty());
        let s = "User me may run the following commands:\n    (ALL) NOPASSWD: /usr/bin/true\n    (ALL) ALL\n";
        assert_eq!(parse_sudo_l(s), vec!["(ALL) NOPASSWD: /usr/bin/true"]);
    }
}
