//! App signatures/notarization and browser extensions.

use super::super::fix::{Fix, run};
use super::super::{Category::Apps, Ctx, Finding, Status};
use super::persistence::parse_spctl;
use crate::cmd;
use crate::util::tilde;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn list_apps(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut v = vec![];
    for d in dirs {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "app") && !p.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(true) {
                    v.push(p);
                }
            }
        }
    }
    v.sort();
    v
}

pub fn app_signatures(ctx: &Ctx) -> Vec<Finding> {
    let t = "App signatures & notarization";
    let apps = list_apps(&[PathBuf::from("/Applications"), ctx.home.join("Applications")]);
    if apps.is_empty() {
        return vec![Finding::unknown(Apps, t, "no apps found in /Applications")];
    }
    // Assess in parallel (spctl can take ~0.5 s per app).
    let results: Vec<(PathBuf, bool, String)> = std::thread::scope(|s| {
        let chunks: Vec<Vec<PathBuf>> = apps.chunks(apps.len().div_ceil(8)).map(|c| c.to_vec()).collect();
        let hs: Vec<_> = chunks
            .into_iter()
            .map(|c| {
                s.spawn(move || {
                    c.into_iter()
                        .map(|p| {
                            let ps = p.display().to_string();
                            let (ok, src) = cmd::run_timeout("spctl", &["-a", "-vv", &ps], Duration::from_secs(60))
                                .map(|o| parse_spctl(&o.combined()))
                                .unwrap_or((false, "could not assess".into()));
                            (p, ok, src)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    let mut out = vec![];
    let own = |p: &Path| p.file_name().is_some_and(|n| n == "Mac Cleaner Pro.app");
    let rejected: Vec<&(PathBuf, bool, String)> = results.iter().filter(|(p, ok, _)| !ok && !own(p)).collect();
    let mut by_src: std::collections::BTreeMap<String, usize> = Default::default();
    for (_, ok, s) in &results {
        if *ok {
            *by_src.entry(if s.is_empty() { "accepted".into() } else { s.clone() }).or_default() += 1;
        }
    }
    let summary_ev: Vec<String> = by_src.iter().map(|(s, n)| format!("{n} app(s): {s}")).collect();
    let why = "Gatekeeper rejects apps that are unsigned, not notarized by Apple, or whose signature is broken (possibly modified after signing). Such apps are not necessarily malicious (open-source builds often are unsigned) but deserve a second look.";
    out.push(if rejected.is_empty() {
        Finding::new(Apps, t, Status::Ok, format!("All {} apps pass Gatekeeper.", results.len())).evidence_all(summary_ev).explain(why)
    } else {
        Finding::new(Apps, t, Status::Info, format!("{} of {} apps pass Gatekeeper; {} need review (listed separately).", results.len() - rejected.len(), results.len(), rejected.len()))
            .evidence_all(summary_ev)
            .explain(why)
    });
    for (p, _, src) in rejected {
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let ps = p.display().to_string();
        let quarantined = cmd::run("xattr", &["-p", "com.apple.quarantine", &ps]).map(|o| o.success()).unwrap_or(false);
        out.push(
            Finding::new(Apps, format!("App: {name}"), Status::Warning, format!("{name} is rejected by Gatekeeper{}.", if src.is_empty() { String::new() } else { format!(" ({src})") }))
                .evidence(format!("path: {}", tilde(p)))
                .evidence(format!("quarantine attribute present: {quarantined}{}", if quarantined { "" } else { " (removed or never downloaded via a browser)" }))
                .explain(why)
                .fix_text("If you don't recognise it or no longer need it, quit it and move it to the Trash. Re-download apps from the developer's official site or the App Store.")
                .with_fix(Fix::new("Show in Finder").change("Opens a Finder window with the app selected (changes nothing)").step(run(&["open", "-R", &ps]))),
        );
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct Extension {
    pub browser: String,
    pub name: String,
    pub id: String,
    pub risky: Vec<String>,
}

pub const RISKY_PERMS: [&str; 10] = [
    "<all_urls>", "*://*/*", "http://*/*", "https://*/*", "nativeMessaging", "debugger", "proxy", "webRequestBlocking", "management", "declarativeNetRequestWithHostAccess",
];

pub fn risky_of(perms: &[String]) -> Vec<String> {
    perms.iter().filter(|p| RISKY_PERMS.contains(&p.as_str())).cloned().collect()
}

fn str_list(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// Parse a Chromium extension manifest; `messages` resolves `__MSG_x__` names.
pub fn parse_chromium_manifest(json: &str, messages: Option<&str>) -> Option<(String, Vec<String>)> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let mut name = v.get("name")?.as_str()?.to_string();
    if let Some(key) = name.strip_prefix("__MSG_").and_then(|s| s.strip_suffix("__"))
        && let Some(m) = messages.and_then(|m| serde_json::from_str::<serde_json::Value>(m).ok())
        && let Some(obj) = m.as_object()
        && let Some((_, val)) = obj.iter().find(|(k, _)| k.eq_ignore_ascii_case(key))
        && let Some(msg) = val.get("message").and_then(|x| x.as_str())
    {
        name = msg.to_string();
    }
    let mut perms = str_list(v.get("permissions"));
    perms.extend(str_list(v.get("host_permissions")));
    if let Some(cs) = v.get("content_scripts").and_then(|x| x.as_array()) {
        for c in cs {
            perms.extend(str_list(c.get("matches")));
        }
    }
    Some((name, perms))
}

/// Parse Firefox `extensions.json` → (name, id, permissions) of user-installed extensions.
pub fn parse_firefox_extensions(json: &str) -> Vec<(String, String, Vec<String>)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return vec![] };
    v.get("addons")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter(|x| x.get("type").and_then(|t| t.as_str()) == Some("extension") && x.get("location").and_then(|t| t.as_str()) == Some("app-profile"))
                .map(|x| {
                    let name = x.pointer("/defaultLocale/name").and_then(|n| n.as_str()).unwrap_or("?").to_string();
                    let id = x.get("id").and_then(|n| n.as_str()).unwrap_or("?").to_string();
                    let mut perms = str_list(x.pointer("/userPermissions/permissions"));
                    perms.extend(str_list(x.pointer("/userPermissions/origins")));
                    (name, id, perms)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn chromium_extensions(browser: &str, root: &Path) -> Vec<Extension> {
    let mut v = vec![];
    let Ok(profiles) = std::fs::read_dir(root) else { return v };
    for prof in profiles.flatten() {
        let ext_dir = prof.path().join("Extensions");
        let Ok(ids) = std::fs::read_dir(&ext_dir) else { continue };
        for id in ids.flatten() {
            let Ok(vers) = std::fs::read_dir(id.path()) else { continue };
            let Some(ver) = vers.flatten().map(|e| e.path()).filter(|p| p.join("manifest.json").exists()).max() else { continue };
            let Ok(m) = std::fs::read_to_string(ver.join("manifest.json")) else { continue };
            let default_locale = serde_json::from_str::<serde_json::Value>(&m)
                .ok()
                .and_then(|x| x.get("default_locale").and_then(|l| l.as_str()).map(String::from))
                .unwrap_or_else(|| "en".into());
            let msgs = std::fs::read_to_string(ver.join("_locales").join(&default_locale).join("messages.json")).ok();
            if let Some((name, perms)) = parse_chromium_manifest(&m, msgs.as_deref()) {
                let idn = id.file_name().to_string_lossy().to_string();
                if v.iter().any(|e: &Extension| e.id == idn) {
                    continue;
                }
                v.push(Extension { browser: browser.into(), name, id: idn, risky: risky_of(&perms) });
            }
        }
    }
    v
}

pub fn browser_extensions(ctx: &Ctx) -> Vec<Finding> {
    let t = "Browser extensions";
    let support = ctx.home.join("Library/Application Support");
    let mut exts = vec![];
    for (name, rel) in [
        ("Chrome", "Google/Chrome"),
        ("Brave", "BraveSoftware/Brave-Browser"),
        ("Edge", "Microsoft Edge"),
        ("Chromium", "Chromium"),
        ("Vivaldi", "Vivaldi"),
        ("Arc", "Arc/User Data"),
    ] {
        exts.extend(chromium_extensions(name, &support.join(rel)));
    }
    if let Ok(rd) = std::fs::read_dir(support.join("Firefox/Profiles")) {
        for p in rd.flatten() {
            if let Ok(j) = std::fs::read_to_string(p.path().join("extensions.json")) {
                for (name, id, perms) in parse_firefox_extensions(&j) {
                    exts.push(Extension { browser: "Firefox".into(), name, id, risky: risky_of(&perms) });
                }
            }
        }
    }
    let why = "Extensions with access to all websites can read passwords, cookies and everything you type on every page. Malicious or sold-off extensions are a common way accounts get hijacked. (Safari extensions are not inspected, to avoid a privacy prompt.)";
    let risky: Vec<&Extension> = exts.iter().filter(|e| !e.risky.is_empty()).collect();
    let ev: Vec<String> = exts
        .iter()
        .map(|e| format!("{}: {} ({}){}", e.browser, e.name, e.id, if e.risky.is_empty() { String::new() } else { format!(" — broad access: {}", e.risky.join(", ")) }))
        .collect();
    vec![if exts.is_empty() {
        Finding::new(Apps, t, Status::Ok, "No Chrome/Brave/Edge/Firefox extensions found.").explain(why)
    } else if risky.is_empty() {
        Finding::new(Apps, t, Status::Info, format!("{} extension(s), none with all-sites access.", exts.len())).evidence_all(ev).explain(why)
    } else {
        Finding::new(Apps, t, Status::Warning, format!("{} of {} extension(s) can access all websites or native apps — review.", risky.len(), exts.len()))
            .evidence_all(ev)
            .explain(why)
            .fix_text("Open the browser's extensions page (chrome://extensions, about:addons) and remove extensions you don't use or recognise.")
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_manifest() {
        let m = r#"{"name":"__MSG_appName__","default_locale":"en","permissions":["storage","tabs"],"host_permissions":["<all_urls>"]}"#;
        let msgs = r#"{"appName":{"message":"Ad Blocker"}}"#;
        let (n, p) = parse_chromium_manifest(m, Some(msgs)).unwrap();
        assert_eq!(n, "Ad Blocker");
        assert_eq!(risky_of(&p), vec!["<all_urls>"]);
        let (n, p) = parse_chromium_manifest(r#"{"name":"Dark","content_scripts":[{"matches":["https://*/*"]}]}"#, None).unwrap();
        assert_eq!(n, "Dark");
        assert_eq!(risky_of(&p), vec!["https://*/*"]);
        assert!(parse_chromium_manifest("{}", None).is_none());
    }

    #[test]
    fn firefox() {
        let j = r#"{"addons":[{"id":"ublock@x","type":"extension","location":"app-profile","defaultLocale":{"name":"uBlock"},"userPermissions":{"permissions":["nativeMessaging"],"origins":["<all_urls>"]}},{"id":"sys@moz","type":"extension","location":"app-system-defaults","defaultLocale":{"name":"Sys"}}]}"#;
        let v = parse_firefox_extensions(j);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "uBlock");
        assert_eq!(risky_of(&v[0].2).len(), 2);
        assert!(parse_firefox_extensions("bad").is_empty());
    }
}
