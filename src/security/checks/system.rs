//! FileVault, SIP, Gatekeeper, XProtect, macOS version, profiles, extensions.

use super::super::fix::{Fix, admin, pane, settings_fix};
use super::super::{Category::System, Ctx, Finding, Status};
use crate::cmd;

#[derive(Debug, PartialEq)]
pub enum OnOff {
    On,
    Off,
    InProgress(String),
    Other(String),
}

pub fn parse_fdesetup(out: &str) -> OnOff {
    let t = out.trim();
    if t.contains("FileVault is On") {
        OnOff::On
    } else if t.contains("FileVault is Off") {
        OnOff::Off
    } else if t.contains("in progress") {
        OnOff::InProgress(t.lines().next().unwrap_or("").to_string())
    } else {
        OnOff::Other(t.lines().next().unwrap_or("").to_string())
    }
}

pub fn filevault(_: &Ctx) -> Vec<Finding> {
    let t = "FileVault disk encryption";
    let o = match cmd::run("fdesetup", &["status"]) {
        Ok(o) => o,
        Err(e) => return vec![Finding::unknown(System, t, e.to_string())],
    };
    let out = o.combined();
    let ev = out.lines().next().unwrap_or("").to_string();
    let why = "FileVault encrypts the whole disk. Without it, anyone with physical access to the Mac (theft, repair shop) can read every file.";
    let fixf = settings_fix(
        "Open FileVault settings",
        pane::FILEVAULT,
        "Privacy & Security → FileVault → Turn On. Store the recovery key safely.",
    );
    vec![match parse_fdesetup(&out) {
        OnOff::On => Finding::new(System, t, Status::Ok, "FileVault is on.").evidence(ev).explain(why),
        OnOff::Off => Finding::new(System, t, Status::Critical, "FileVault is OFF — the disk is not encrypted.")
            .evidence(ev)
            .explain(why)
            .fix_text("System Settings → Privacy & Security → FileVault → Turn On.")
            .command("sudo fdesetup enable")
            .with_fix(fixf),
        OnOff::InProgress(s) => Finding::new(System, t, Status::Warning, format!("FileVault change in progress: {s}")).evidence(ev).explain(why),
        OnOff::Other(s) => Finding::unknown(System, t, format!("unrecognised output: {s}")),
    }]
}

pub fn parse_csrutil(out: &str) -> OnOff {
    let l = out.to_lowercase();
    if l.contains("status: enabled.") {
        OnOff::On
    } else if l.contains("status: disabled") {
        OnOff::Off
    } else {
        OnOff::Other(out.trim().lines().next().unwrap_or("").to_string())
    }
}

pub fn sip(_: &Ctx) -> Vec<Finding> {
    let t = "System Integrity Protection";
    let o = match cmd::run("csrutil", &["status"]) {
        Ok(o) => o,
        Err(e) => return vec![Finding::unknown(System, t, e.to_string())],
    };
    let out = o.combined();
    let ev = out.lines().next().unwrap_or("").to_string();
    let why = "SIP stops even admin/root processes from modifying macOS system files — a core defence against rootkits.";
    vec![match parse_csrutil(&out) {
        OnOff::On => Finding::new(System, t, Status::Ok, "SIP is enabled.").evidence(ev).explain(why),
        OnOff::Off => Finding::new(System, t, Status::Critical, "SIP is DISABLED.")
            .evidence(ev)
            .explain(why)
            .fix_text("Restart into Recovery (hold the power button on Apple silicon), open Terminal there and run `csrutil enable`, then restart. This cannot be done from inside macOS.")
            .command("csrutil enable   # run in Recovery Terminal"),
        _ if !ev.is_empty() => Finding::new(System, t, Status::Warning, "SIP is in a custom/partial configuration.")
            .evidence(ev)
            .explain(why)
            .fix_text("Restart into Recovery and run `csrutil enable` to restore the full protection.")
            .command("csrutil enable   # run in Recovery Terminal"),
        _ => Finding::unknown(System, t, "no output from csrutil"),
    }]
}

pub fn gatekeeper(_: &Ctx) -> Vec<Finding> {
    let t = "Gatekeeper";
    let o = match cmd::run("spctl", &["--status"]) {
        Ok(o) => o,
        Err(e) => return vec![Finding::unknown(System, t, e.to_string())],
    };
    let out = o.combined().trim().to_string();
    let why = "Gatekeeper blocks apps that are not signed by an identified developer and notarized by Apple.";
    vec![if out.contains("assessments enabled") {
        Finding::new(System, t, Status::Ok, "Gatekeeper is enabled.").evidence(out).explain(why)
    } else if out.contains("assessments disabled") {
        Finding::new(System, t, Status::Critical, "Gatekeeper is DISABLED — any downloaded app can run unchecked.")
            .evidence(out)
            .explain(why)
            .fix_text("Re-enable Gatekeeper (admin).")
            .command("sudo spctl --global-enable")
            .with_fix(
                Fix::new("Re-enable Gatekeeper")
                    .change("Gatekeeper: disabled → enabled")
                    .step(admin("/usr/sbin/spctl --global-enable"))
                    .undo(vec![admin("/usr/sbin/spctl --global-disable")]),
            )
    } else {
        Finding::unknown(System, t, format!("unrecognised output: {out}"))
    }]
}

/// Parse `xprotect version` → (version, installed date "YYYY-MM-DD").
pub fn parse_xprotect_version(out: &str) -> Option<(String, String)> {
    let line = out.lines().find(|l| l.contains("Version:"))?;
    let ver = line.split("Version:").nth(1)?.split_whitespace().next()?.to_string();
    let date = line
        .split("Installed:")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or("")
        .to_string();
    Some((ver, date))
}

pub fn days_since(date_ymd: &str) -> Option<i64> {
    let d = chrono::NaiveDate::parse_from_str(date_ymd, "%Y-%m-%d").ok()?;
    Some((chrono::Local::now().date_naive() - d).num_days())
}

fn plist_version(path: &str) -> Option<String> {
    let o = cmd::run("plutil", &["-extract", "CFBundleShortVersionString", "raw", "-o", "-", path]).ok()?;
    o.success().then(|| o.stdout.trim().to_string())
}

pub fn xprotect(_: &Ctx) -> Vec<Finding> {
    let t = "XProtect / malware definitions";
    let base = "/Library/Apple/System/Library/CoreServices";
    let mut ev = vec![];
    let mut age: Option<i64> = None;
    if let Ok(o) = cmd::run("xprotect", &["version"])
        && let Some((v, d)) = parse_xprotect_version(&o.combined())
    {
        ev.push(format!("XProtect definitions version {v}, installed {d}"));
        age = days_since(&d);
    } else if let Some(v) = plist_version(&format!("{base}/XProtect.bundle/Contents/Info.plist")) {
        ev.push(format!("XProtect.bundle version {v}"));
        if let Ok(m) = std::fs::metadata(format!("{base}/XProtect.bundle/Contents/Info.plist"))
            && let Ok(mt) = m.modified()
            && let Ok(el) = mt.elapsed()
        {
            age = Some((el.as_secs() / 86_400) as i64);
        }
    }
    if let Some(v) = plist_version(&format!("{base}/XProtect.app/Contents/Info.plist")) {
        ev.push(format!("XProtect Remediator (XProtect.app) version {v}"));
    }
    if let Some(v) = plist_version(&format!("{base}/MRT.app/Contents/Info.plist")) {
        ev.push(format!("MRT.app version {v} (legacy; replaced by XProtect Remediator)"));
    }
    if ev.is_empty() {
        return vec![Finding::unknown(System, t, "XProtect not found or not readable")];
    }
    let why = "XProtect is macOS's built-in malware scanner. Apple pushes new definitions silently — but only if \"Install Security Responses and system files\" is on.";
    let upd = Fix::new("Update XProtect now")
        .change("Downloads and installs the latest XProtect definitions from Apple")
        .step(admin("/usr/bin/xprotect update"));
    let f = match age {
        Some(a) if a > 60 => Finding::new(System, t, Status::Warning, format!("Malware definitions are {a} days old."))
            .fix_text("Turn on System Settings → General → Software Update → Automatic Updates → \"Install Security Responses and system files\", or update now.")
            .command("sudo xprotect update")
            .with_fix(upd),
        Some(a) => Finding::new(System, t, Status::Ok, format!("XProtect present, definitions {a} days old.")),
        None => Finding::new(System, t, Status::Info, "XProtect present (age unknown)."),
    };
    vec![f.evidence_all(ev).explain(why)]
}

pub fn macos_version(_: &Ctx) -> Vec<Finding> {
    let t = "macOS version";
    let v = cmd::run("sw_vers", &["-productVersion"]).map(|o| o.stdout.trim().to_string());
    let b = cmd::run("sw_vers", &["-buildVersion"]).map(|o| o.stdout.trim().to_string()).unwrap_or_default();
    match v {
        Ok(v) if !v.is_empty() => vec![Finding::new(System, t, Status::Info, format!("macOS {v} ({b})"))
            .evidence(format!("sw_vers: {v} build {b}"))
            .explain("See the Software updates section for pending patches.")],
        Ok(_) => vec![Finding::unknown(System, t, "sw_vers printed nothing")],
        Err(e) => vec![Finding::unknown(System, t, e.to_string())],
    }
}

/// Profile identifiers from `profiles list` output.
pub fn parse_profiles(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split("profileIdentifier:").nth(1))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn parse_enrollment(out: &str) -> (Option<bool>, Option<bool>) {
    let get = |k: &str| {
        out.lines()
            .find(|l| l.trim_start().starts_with(k))
            .map(|l| l.to_lowercase().contains("yes"))
    };
    (get("Enrolled via DEP"), get("MDM enrollment"))
}

pub fn profiles(_: &Ctx) -> Vec<Finding> {
    let t = "Configuration profiles / MDM";
    let enr = cmd::run("profiles", &["status", "-type", "enrollment"]);
    let lst = cmd::run("profiles", &["list"]);
    let (Ok(enr), Ok(lst)) = (enr, lst) else {
        return vec![Finding::unknown(System, t, "the profiles tool could not run")];
    };
    let (dep, mdm) = parse_enrollment(&enr.combined());
    let ids = parse_profiles(&lst.combined());
    let mut ev = vec![
        format!("Enrolled via DEP: {}", dep.map(|b| if b { "Yes" } else { "No" }).unwrap_or("?")),
        format!("MDM enrollment: {}", mdm.map(|b| if b { "Yes" } else { "No" }).unwrap_or("?")),
    ];
    ev.extend(ids.iter().map(|i| format!("profile: {i}")));
    let why = "Configuration profiles and MDM can install certificates, VPNs/proxies and restrictions. Unknown profiles are a classic way to intercept traffic or control a Mac.";
    let mut out = vec![];
    if ids.is_empty() && mdm != Some(true) {
        out.push(Finding::new(System, t, Status::Ok, "No MDM enrollment and no user configuration profiles.").evidence_all(ev).explain(why));
    } else {
        let mut f = Finding::new(
            System,
            t,
            Status::Warning,
            format!("{} profile(s) installed{} — review that you recognise them.", ids.len(), if mdm == Some(true) { ", Mac is MDM-enrolled" } else { "" }),
        )
        .evidence_all(ev)
        .explain(why)
        .fix_text("System Settings → General → Device Management (Profiles). Remove any profile you don't recognise. Work/school-managed Macs: ask IT first.")
        .with_fix(settings_fix("Open Device Management", pane::PROFILES, "Select a profile you don't recognise and click −."));
        for id in &ids {
            f = f.with_fix(
                Fix::new(format!("Remove profile {id}"))
                    .change(format!("Configuration profile {id}: installed → removed"))
                    .step(admin(format!("/usr/bin/profiles remove -identifier {}", crate::util::sh_quote(id))))
                    .warn("This cannot be undone from this app — you'd need the original profile file to reinstall it. Only remove profiles you are sure are not from your employer/school."),
            );
        }
        out.push(f);
    }
    out
}

/// (teamID, bundleID, state) for each extension in `systemextensionsctl list`.
pub fn parse_sysext(out: &str) -> Vec<(String, String, String)> {
    out.lines()
        .filter(|l| l.contains('\t') && l.contains('[') && !l.starts_with("enabled"))
        .filter_map(|l| {
            let cols: Vec<&str> = l.split('\t').collect();
            if cols.len() < 5 {
                return None;
            }
            let bundle = cols[3].split_whitespace().next()?.to_string();
            let state = l.rsplit('[').next()?.trim_end_matches(']').to_string();
            Some((cols[2].to_string(), bundle, state))
        })
        .collect()
}

/// Non-Apple kext names from `kextstat` output.
pub fn parse_kextstat(out: &str) -> Vec<String> {
    out.lines()
        .skip_while(|l| !l.trim_start().starts_with("Index"))
        .skip(1)
        .filter_map(|l| l.split_whitespace().nth(5).map(|s| s.to_string()))
        .filter(|n| !n.starts_with("com.apple."))
        .collect()
}

pub fn extensions(_: &Ctx) -> Vec<Finding> {
    let t = "System & kernel extensions";
    let sx = cmd::run("systemextensionsctl", &["list"]).map(|o| parse_sysext(&o.combined()));
    let kx = cmd::run("kextstat", &["-l"]).map(|o| parse_kextstat(&format!("Index\n{}", o.stdout)));
    if sx.is_err() && kx.is_err() {
        return vec![Finding::unknown(System, t, "systemextensionsctl/kextstat unavailable")];
    }
    let sx = sx.unwrap_or_default();
    let kx = kx.unwrap_or_default();
    let mut ev: Vec<String> = sx.iter().map(|(team, b, s)| format!("system extension {b} (team {team}) [{s}]")).collect();
    ev.extend(kx.iter().map(|k| format!("kernel extension {k}")));
    let why = "System extensions (network filters, endpoint security) and kernel extensions run with deep privileges. Make sure each one belongs to software you installed on purpose.";
    vec![if kx.is_empty() && sx.is_empty() {
        Finding::new(System, t, Status::Ok, "No third-party system or kernel extensions.").explain(why)
    } else if !kx.is_empty() {
        Finding::new(System, t, Status::Warning, format!("{} third-party kernel extension(s) loaded — review.", kx.len()))
            .evidence_all(ev)
            .explain(why)
            .fix_text("Remove kexts you don't need via their vendor's uninstaller; System Settings → General → Login Items & Extensions shows extensions.")
            .with_fix(settings_fix("Open Extensions settings", pane::LOGIN_ITEMS, "Scroll to Extensions and review each one."))
    } else {
        Finding::new(System, t, Status::Info, format!("{} third-party system extension(s).", sx.len())).evidence_all(ev).explain(why)
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdesetup() {
        assert_eq!(parse_fdesetup("FileVault is On.\n"), OnOff::On);
        assert_eq!(parse_fdesetup("FileVault is Off.\n"), OnOff::Off);
        assert!(matches!(parse_fdesetup("Encryption in progress: Percent completed = 10"), OnOff::InProgress(_)));
    }

    #[test]
    fn csrutil() {
        assert_eq!(parse_csrutil("System Integrity Protection status: enabled.\n"), OnOff::On);
        assert_eq!(parse_csrutil("System Integrity Protection status: disabled.\n"), OnOff::Off);
        assert!(matches!(parse_csrutil("System Integrity Protection status: unknown (Custom Configuration)."), OnOff::Other(_)));
    }

    #[test]
    fn xprotect_version() {
        let (v, d) = parse_xprotect_version("Version: 5347 Installed: 2026-06-03 01:41:26 +0000\n").unwrap();
        assert_eq!(v, "5347");
        assert_eq!(d, "2026-06-03");
        assert!(days_since("2000-01-01").unwrap() > 9000);
        assert!(parse_xprotect_version("garbage").is_none());
    }

    #[test]
    fn profiles_parse() {
        assert!(parse_profiles("There are no configuration profiles installed for user 'x'").is_empty());
        let s = "_computerlevel[1] attribute: profileIdentifier: com.corp.wifi\n_computerlevel[2] attribute: profileIdentifier: com.evil.proxy\n";
        assert_eq!(parse_profiles(s), vec!["com.corp.wifi", "com.evil.proxy"]);
        assert_eq!(parse_enrollment("Enrolled via DEP: No\nMDM enrollment: No\n"), (Some(false), Some(false)));
        assert_eq!(parse_enrollment("Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\n"), (Some(true), Some(true)));
    }

    #[test]
    fn sysext_parse() {
        let s = "1 extension(s)\n--- com.apple.system_extension.network_extension (Go to 'System Settings > General')\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tVBG97UB4TA\tcom.objective-see.lulu.extension (4.3.2/4.3.2)\tLuLu\t[activated enabled]\n";
        let v = parse_sysext(s);
        assert_eq!(v, vec![("VBG97UB4TA".into(), "com.objective-see.lulu.extension".into(), "activated enabled".into())]);
    }

    #[test]
    fn kextstat_parse() {
        let s = "Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>\n    1  150 0                  0          0          com.apple.kpi.bsd (25.5.0) X\n  200    0 0xfff 0x1000 0x1000 com.vendor.driver (1.0) Y <1 2>\n";
        assert_eq!(parse_kextstat(s), vec!["com.vendor.driver"]);
        assert!(parse_kextstat("Index Refs Address Size Wired Name\n").is_empty());
    }
}
