//! Admin users, guest, auto-login, screen lock, Find My, Lockdown Mode.

use super::super::fix::{Fix, admin, pane, run, settings_fix};
use super::super::{Category::Accounts, Ctx, Finding, Status};
use super::{defaults_read, defaults_read_host, truthy};
use crate::cmd;
use std::time::Duration;

pub fn parse_admins(out: &str) -> Vec<String> {
    out.lines()
        .find_map(|l| l.strip_prefix("GroupMembership:"))
        .map(|s| s.split_whitespace().filter(|u| *u != "root" && !u.starts_with('_')).map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

pub fn admins(_: &Ctx) -> Vec<Finding> {
    let t = "Administrator accounts";
    let o = match cmd::run("dscl", &[".", "-read", "/Groups/admin", "GroupMembership"]) {
        Ok(o) if o.success() => o,
        Ok(o) => return vec![Finding::unknown(Accounts, t, o.combined().trim().to_string())],
        Err(e) => return vec![Finding::unknown(Accounts, t, e.to_string())],
    };
    let a = parse_admins(&o.stdout);
    let me = std::env::var("USER").unwrap_or_default();
    let why = "Admin accounts can install software and change system settings (after a password prompt). Malware that tricks an admin into typing their password gets full control. A separate standard account for daily use is the most cautious setup.";
    let status = if a.len() > 2 { Status::Warning } else { Status::Info };
    vec![Finding::new(Accounts, t, status, format!("{} admin account(s){}.", a.len(), if a.contains(&me) { "; your account is an admin" } else { "" }))
        .evidence_all(a.iter().map(|u| format!("admin: {u}")))
        .explain(why)
        .fix_text("Remove admin rights from accounts that don't need them: System Settings → Users & Groups.")
        .with_fix(settings_fix("Open Users & Groups", pane::USERS, "Click (i) next to a user to change \"Allow this user to administer this computer\"."))]
}

pub fn parse_guest(out: &str) -> Option<bool> {
    let l = out.to_lowercase();
    if l.contains("guest account disabled") {
        Some(false)
    } else if l.contains("guest account enabled") {
        Some(true)
    } else {
        None
    }
}

pub fn guest(_: &Ctx) -> Vec<Finding> {
    let t = "Guest account";
    let mut state = cmd::run("sysadminctl", &["-guestAccount", "status"]).ok().and_then(|o| parse_guest(&o.combined()));
    let mut ev = vec![];
    if let Some(s) = state {
        ev.push(format!("sysadminctl: guest account {}", if s { "enabled" } else { "disabled" }));
    } else if let Some(v) = truthy(defaults_read("/Library/Preferences/com.apple.loginwindow", "GuestEnabled").as_deref()) {
        state = Some(v);
        ev.push(format!("loginwindow GuestEnabled = {}", v as u8));
    }
    let why = "The guest account lets anyone log in without a password. Data is wiped on logout, but it still gives physical attackers a foothold.";
    vec![match state {
        Some(true) => Finding::new(Accounts, t, Status::Warning, "Guest account is enabled.")
            .evidence_all(ev)
            .explain(why)
            .command("sudo sysadminctl -guestAccount off")
            .fix_text("System Settings → Users & Groups → Guest User → off.")
            .with_fix(
                Fix::new("Disable the guest account")
                    .change("Guest account: enabled → disabled")
                    .step(admin("/usr/sbin/sysadminctl -guestAccount off"))
                    .undo(vec![admin("/usr/sbin/sysadminctl -guestAccount on")]),
            ),
        Some(false) => Finding::new(Accounts, t, Status::Ok, "Guest account is disabled.").evidence_all(ev).explain(why),
        None => Finding::unknown(Accounts, t, "sysadminctl/defaults gave no answer"),
    }]
}

pub fn autologin(_: &Ctx) -> Vec<Finding> {
    let t = "Automatic login";
    let o = match cmd::run("defaults", &["read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]) {
        Ok(o) => o,
        Err(e) => return vec![Finding::unknown(Accounts, t, e.to_string())],
    };
    let why = "With automatic login, anyone who turns the Mac on is logged straight into your account. (FileVault disables it.)";
    vec![if o.success() && !o.stdout.trim().is_empty() {
        Finding::new(Accounts, t, Status::Critical, "Automatic login is ON.")
            .evidence("loginwindow autoLoginUser is set")
            .explain(why)
            .fix_text("System Settings → Users & Groups → Automatically log in as → Off.")
            .command("sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser && sudo rm -f /etc/kcpassword")
            .with_fix(
                Fix::new("Turn off automatic login")
                    .change("Automatic login: on → off (removes the stored auto-login password /etc/kcpassword)")
                    .step(admin("/usr/bin/defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser; /bin/rm -f /etc/kcpassword"))
                    .warn("No undo: turning it back on requires re-entering the password in System Settings."),
            )
    } else {
        Finding::new(Accounts, t, Status::Ok, "Automatic login is off.").evidence("loginwindow autoLoginUser not set").explain(why)
    }]
}

/// `sysadminctl -screenLock status` → Some(seconds) (0 = immediate), None = off.
pub fn parse_screenlock(out: &str) -> Result<Option<u64>, String> {
    let l = out.to_lowercase();
    if l.contains("screenlock is immediate") {
        return Ok(Some(0));
    }
    if l.contains("screenlock is off") {
        return Ok(None);
    }
    if let Some(i) = l.find("screenlock delay is ") {
        let n: String = l[i + 20..].chars().take_while(|c| c.is_ascii_digit()).collect();
        return n.parse().map(Some).map_err(|_| "unparsable delay".into());
    }
    Err("unrecognised output".into())
}

pub fn parse_pmset_displaysleep(out: &str) -> Option<u64> {
    out.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == "displaysleep").then(|| it.next()?.parse().ok())?
    })
}

pub fn screen_lock(_: &Ctx) -> Vec<Finding> {
    let mut out = vec![];
    let t = "Password after sleep / screensaver";
    let why = "If no password is required right after the screen locks, anyone at your desk can use the Mac during the grace period.";
    match cmd::run("sysadminctl", &["-screenLock", "status"]) {
        Err(e) => out.push(Finding::unknown(Accounts, t, e.to_string())),
        Ok(o) => {
            let txt = o.combined();
            let ev = txt.lines().last().unwrap_or("").split("] ").last().unwrap_or("").trim().to_string();
            let sfix = settings_fix(
                "Open Lock Screen settings",
                pane::LOCK_SCREEN,
                "Set \"Require password after screen saver begins or display is turned off\" to Immediately.",
            );
            out.push(match parse_screenlock(&txt) {
                Ok(Some(s)) if s <= 5 => Finding::new(Accounts, t, Status::Ok, "Password required immediately.").evidence(ev).explain(why),
                Ok(Some(s)) => Finding::new(Accounts, t, Status::Warning, format!("Password only required {} after the screen locks.", fmt_secs(s)))
                    .evidence(ev)
                    .explain(why)
                    .fix_text("System Settings → Lock Screen → Require password … → Immediately. (macOS only allows this change from System Settings or with your password typed in Terminal.)")
                    .command("sysadminctl -screenLock immediate -password -")
                    .with_fix(sfix),
                Ok(None) => Finding::new(Accounts, t, Status::Critical, "No password is required after sleep/screensaver.")
                    .evidence(ev)
                    .explain(why)
                    .fix_text("System Settings → Lock Screen → Require password … → Immediately.")
                    .command("sysadminctl -screenLock immediate -password -")
                    .with_fix(sfix),
                Err(e) => Finding::unknown(Accounts, t, e),
            });
        }
    }

    let t = "Screensaver / display sleep";
    let idle: Option<u64> = defaults_read_host("com.apple.screensaver", "idleTime").and_then(|s| s.parse().ok());
    let disp = cmd::run("pmset", &["-g"]).ok().and_then(|o| parse_pmset_displaysleep(&o.stdout));
    let ev = vec![
        format!("screensaver idleTime: {}", idle.map(|s| if s == 0 { "never".into() } else { fmt_secs(s) }).unwrap_or_else(|| "not set (default 20 min)".into())),
        format!("display sleep: {}", disp.map(|m| if m == 0 { "never".into() } else { format!("{m} min") }).unwrap_or_else(|| "unknown".into())),
    ];
    let idle_eff = idle.unwrap_or(1200);
    let lock_after = match (idle_eff, disp) {
        (0, Some(0)) | (0, None) => None,
        (0, Some(d)) => Some(d * 60),
        (i, Some(0)) | (i, None) => Some(i),
        (i, Some(d)) => Some(i.min(d * 60)),
    };
    let why = "The screen only locks when the screensaver starts or the display sleeps. If that never happens (or takes very long), an unattended Mac stays unlocked.";
    let mut fx = Fix::new("Start screensaver after 10 minutes")
        .change(format!("Screensaver start: {} → 10 min", idle.map(fmt_secs).unwrap_or_else(|| "default".into())))
        .step(run(&["defaults", "-currentHost", "write", "com.apple.screensaver", "idleTime", "-int", "600"]));
    fx = fx.undo(vec![match idle {
        Some(v) => run(&["defaults", "-currentHost", "write", "com.apple.screensaver", "idleTime", "-int", &v.to_string()]),
        None => run(&["defaults", "-currentHost", "delete", "com.apple.screensaver", "idleTime"]),
    }]);
    out.push(match lock_after {
        None => Finding::new(Accounts, t, Status::Warning, "Screensaver and display sleep are both off — the screen never auto-locks.")
            .evidence_all(ev)
            .explain(why)
            .with_fix(fx),
        Some(s) if s > 1200 => Finding::new(Accounts, t, Status::Warning, format!("Screen auto-locks only after {}.", fmt_secs(s)))
            .evidence_all(ev)
            .explain(why)
            .with_fix(fx),
        Some(s) => Finding::new(Accounts, t, Status::Ok, format!("Screen locks after about {} idle.", fmt_secs(s))).evidence_all(ev).explain(why),
    });
    out
}

fn fmt_secs(s: u64) -> String {
    if s == 0 {
        "0 s".into()
    } else if s.is_multiple_of(60) {
        format!("{} min", s / 60)
    } else {
        format!("{s} s")
    }
}

pub fn parse_activation_lock(out: &str) -> Option<bool> {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("Activation Lock Status:"))
        .map(|v| v.trim().eq_ignore_ascii_case("enabled"))
}

pub fn find_my(_: &Ctx) -> Vec<Finding> {
    let t = "Find My / Activation Lock";
    let o = match cmd::run_timeout("system_profiler", &["SPHardwareDataType"], Duration::from_secs(60)) {
        Ok(o) => o,
        Err(e) => return vec![Finding::unknown(Accounts, t, e.to_string())],
    };
    let chip = o
        .stdout
        .lines()
        .find(|l| l.contains("Chip:") || l.contains("Processor Name:"))
        .map(|l| l.trim().to_string())
        .unwrap_or_default();
    let why = "Find My lets you locate, lock or erase a lost Mac; Activation Lock stops a thief from erasing and reusing it.";
    vec![match parse_activation_lock(&o.stdout) {
        Some(true) => Finding::new(Accounts, t, Status::Ok, "Activation Lock is enabled (Find My Mac is on).")
            .evidence("Activation Lock Status: Enabled")
            .evidence(chip)
            .explain(why),
        Some(false) => Finding::new(Accounts, t, Status::Warning, "Activation Lock is disabled — Find My Mac is probably off.")
            .evidence("Activation Lock Status: Disabled")
            .evidence(chip)
            .explain(why)
            .fix_text("System Settings → [your name] → iCloud → Find My Mac → On.")
            .with_fix(settings_fix("Open Apple Account settings", pane::APPLE_ID, "iCloud → Find My Mac → turn on.")),
        None => Finding::new(Accounts, t, Status::Info, "Activation Lock status not reported (Intel Mac without T2, or not readable).")
            .evidence(chip)
            .explain(why),
    }]
}

pub fn lockdown(_: &Ctx) -> Vec<Finding> {
    let t = "Lockdown Mode";
    let v = truthy(defaults_read(".GlobalPreferences", "LDMGlobalEnabled").as_deref());
    let why = "Lockdown Mode is an extreme, optional protection for people who may be personally targeted by sophisticated spyware. It disables many features.";
    vec![if v == Some(true) {
        Finding::new(Accounts, t, Status::Ok, "Lockdown Mode is on.").evidence("LDMGlobalEnabled = 1").explain(why)
    } else {
        Finding::new(Accounts, t, Status::Info, "Lockdown Mode is off (only needed if you may be personally targeted).")
            .evidence("LDMGlobalEnabled not set")
            .explain(why)
            .with_fix(settings_fix("Open Lockdown Mode settings", pane::LOCKDOWN, "Privacy & Security → Lockdown Mode → Turn On (restart required)."))
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admins_parse() {
        assert_eq!(parse_admins("GroupMembership: root alice _mbsetupuser bob\n"), vec!["alice", "bob"]);
        assert!(parse_admins("nothing").is_empty());
    }

    #[test]
    fn guest_parse() {
        assert_eq!(parse_guest("2026-10-08 11:44:39.590 sysadminctl[8995:3976685] Guest account disabled."), Some(false));
        assert_eq!(parse_guest("... Guest account enabled."), Some(true));
        assert_eq!(parse_guest("?"), None);
    }

    #[test]
    fn screenlock_parse() {
        assert_eq!(parse_screenlock("2026-10-08 sysadminctl[1:2] screenLock delay is 300 seconds"), Ok(Some(300)));
        assert_eq!(parse_screenlock("x screenLock is immediate"), Ok(Some(0)));
        assert_eq!(parse_screenlock("x screenLock is off"), Ok(None));
        assert!(parse_screenlock("weird").is_err());
    }

    #[test]
    fn pmset_parse() {
        let s = "System-wide power settings:\nCurrently in use:\n sleep                1 (sleep prevented by powerd)\n displaysleep         10\n disksleep            10\n";
        assert_eq!(parse_pmset_displaysleep(s), Some(10));
    }

    #[test]
    fn activation_lock() {
        assert_eq!(parse_activation_lock("      Chip: Apple M4\n      Activation Lock Status: Enabled\n"), Some(true));
        assert_eq!(parse_activation_lock("Activation Lock Status: Disabled"), Some(false));
        assert_eq!(parse_activation_lock("Chip: x"), None);
    }
}
