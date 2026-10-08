//! Weekly background scan via a user launchd agent (same label and schedule as
//! the original app: Mondays 10:00). It only scans and posts a local
//! notification — it never deletes or fixes anything unattended.

use std::path::{Path, PathBuf};

pub const LABEL: &str = "com.maccleanerpro.weeklyscan";

pub fn plist_path() -> PathBuf {
    crate::util::home().join(format!("Library/LaunchAgents/{LABEL}.plist"))
}

/// The binary launchd should run: the installed app if present, else this executable.
pub fn program_path() -> String {
    let installed = "/Applications/Mac Cleaner Pro.app/Contents/MacOS/mac-cleaner-pro";
    if Path::new(installed).exists() {
        return installed.to_string();
    }
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| installed.to_string())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub fn plist_xml(program: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--background-scan</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key>
        <integer>1</integer>
        <key>Hour</key>
        <integer>10</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
"#,
        xml_escape(program)
    )
}

pub fn enabled() -> bool {
    plist_path().exists()
}

pub fn enable() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let p = plist_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(&p, plist_xml(&program_path())).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    let ps = p.display().to_string();
    let _ = crate::cmd::run("launchctl", &["unload", &ps]);
    let _ = crate::cmd::run("launchctl", &["load", &ps]);
    Ok(())
}

pub fn disable() -> Result<(), String> {
    let p = plist_path();
    if p.exists() {
        let _ = crate::cmd::run("launchctl", &["unload", &p.display().to_string()]);
        std::fs::remove_file(&p).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Headless weekly check: totals reclaimable space and runs the read-only
/// security audit, then posts one local notification. Never deletes or fixes.
pub fn run_background_scan() -> String {
    let home = crate::util::home();
    let now = std::time::SystemTime::now();
    let total: u64 = crate::cleaner::categories(&home)
        .iter()
        .filter(|c| !c.opt_in)
        .flat_map(|c| crate::cleaner::scan_category(c, now))
        .map(|i| i.size)
        .sum();
    let ctx = crate::security::Ctx::new(false);
    let findings = crate::security::run_all(&ctx);
    let s = crate::security::report::Summary::of(&findings);
    let msg = format!(
        "{} of junk found. Security: {} critical, {} warnings (score {}). Open Mac Cleaner Pro to review.",
        crate::util::human(total),
        s.critical,
        s.warning,
        s.score
    );
    let script = format!(
        "display notification \"{}\" with title \"Mac Cleaner Pro\"",
        msg.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let _ = crate::cmd::run("osascript", &["-e", &script]);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_has_label_and_args() {
        let x = plist_xml("/Applications/Mac Cleaner Pro.app/Contents/MacOS/mac-cleaner-pro");
        assert!(x.contains("<string>com.maccleanerpro.weeklyscan</string>"));
        assert!(x.contains("<string>--background-scan</string>"));
        assert!(x.contains("<integer>10</integer>"));
        assert!(!x.contains("python"));
    }
}
