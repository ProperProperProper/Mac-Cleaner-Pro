//! All audit checks. Each module has pure parsers (unit-tested against captured
//! sample outputs) plus a check function that runs the real system tool.

pub mod accounts;
pub mod apps;
pub mod devtools;
pub mod files;
pub mod firewall;
pub mod network;
pub mod persistence;
pub mod secrets;
pub mod sharing;
pub mod system;
pub mod trust;
pub mod updates;

use super::{Category, CheckDef};
use crate::cmd;

pub fn registry() -> Vec<CheckDef> {
    use Category::*;
    let d = |id, name, category, slow, run| CheckDef { id, name, category, slow, run };
    vec![
        d("filevault", "FileVault disk encryption", System, false, system::filevault),
        d("sip", "System Integrity Protection", System, false, system::sip),
        d("gatekeeper", "Gatekeeper", System, false, system::gatekeeper),
        d("xprotect", "XProtect / malware definitions", System, false, system::xprotect),
        d("macos", "macOS version", System, false, system::macos_version),
        d("profiles", "Configuration profiles / MDM", System, false, system::profiles),
        d("extensions", "System & kernel extensions", System, false, system::extensions),
        d("updates_pending", "Pending software updates", Updates, true, updates::pending),
        d("updates_auto", "Automatic update settings", Updates, false, updates::auto_settings),
        d("firewall", "Application firewall", Firewall, false, firewall::app_firewall),
        d("firewall_3p", "Third-party firewall", Firewall, false, firewall::third_party),
        d("listeners", "Listening network services", Network, false, network::listeners),
        d("dns", "DNS servers", Network, false, network::dns),
        d("proxies", "Web/SOCKS proxies", Network, false, network::proxies),
        d("hosts", "/etc/hosts", Network, false, network::hosts),
        d("wifi", "Wi-Fi security", Network, true, network::wifi),
        d("sharing", "Sharing services", Sharing, false, sharing::sharing),
        d("admins", "Administrator accounts", Accounts, false, accounts::admins),
        d("guest", "Guest account", Accounts, false, accounts::guest),
        d("autologin", "Automatic login", Accounts, false, accounts::autologin),
        d("screenlock", "Screen lock & screensaver", Accounts, false, accounts::screen_lock),
        d("findmy", "Find My / Activation Lock", Accounts, true, accounts::find_my),
        d("lockdown", "Lockdown Mode", Accounts, false, accounts::lockdown),
        d("launch_items", "Launch agents & daemons", Persistence, false, persistence::launch_items),
        d("login_items", "Login items", Persistence, false, persistence::login_items),
        d("cron", "Cron, periodic scripts, login hooks", Persistence, false, persistence::cron_periodic_hooks),
        d("app_signatures", "App signatures", Apps, true, apps::app_signatures),
        d("browser_ext", "Browser extensions", Apps, false, apps::browser_extensions),
        d("certs", "Custom trusted certificates", Trust, false, trust::certificates),
        d("sudoers", "sudo configuration", Trust, false, trust::sudoers),
        d("secrets", "Plaintext secrets", Secrets, true, secrets::secrets),
        d("ssh", "SSH keys", Files, false, files::ssh),
        d("perms", "File permissions", Files, false, files::permissions),
        d("fda", "Full Disk Access", Files, false, files::full_disk_access),
        d("claude", "Claude Code permissions", DevTools, false, devtools::claude_settings),
    ]
}

/// `defaults read <domain> <key>` → trimmed value, None if missing/unreadable.
pub fn defaults_read(domain: &str, key: &str) -> Option<String> {
    let o = cmd::run("defaults", &["read", domain, key]).ok()?;
    o.success().then(|| o.stdout.trim().to_string())
}

pub fn defaults_read_host(domain: &str, key: &str) -> Option<String> {
    let o = cmd::run("defaults", &["-currentHost", "read", domain, key]).ok()?;
    o.success().then(|| o.stdout.trim().to_string())
}

/// Is a launchd service loaded in the system domain? (No root needed.)
pub fn launchd_system_loaded(label: &str) -> Result<bool, String> {
    let o = cmd::run("launchctl", &["print", &format!("system/{label}")]).map_err(|e| e.to_string())?;
    Ok(o.success())
}

pub fn truthy(v: Option<&str>) -> Option<bool> {
    match v?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_ids_unique() {
        let r = registry();
        let mut ids: Vec<_> = r.iter().map(|d| d.id).collect();
        ids.sort();
        let n = ids.len();
        ids.dedup();
        assert_eq!(n, ids.len());
        assert!(n >= 30);
    }

    #[test]
    fn truthy_values() {
        assert_eq!(truthy(Some("1")), Some(true));
        assert_eq!(truthy(Some("0\n")), Some(false));
        assert_eq!(truthy(Some("maybe")), None);
        assert_eq!(truthy(None), None);
    }
}
