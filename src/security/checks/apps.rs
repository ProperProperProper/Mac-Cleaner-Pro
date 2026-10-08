//! App signatures/notarization and browser extensions.

use super::super::fix::{Fix, run};
use super::super::{Category::Apps, Ctx, Finding, Status};
use super::persistence::{Sig, parse_codesign, parse_executable, parse_spctl, parse_team};
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

/// App Store iPhone/iPad app wrapped for Apple silicon: no `Contents/Info.plist`,
/// but a `Wrapper/` folder and/or a `WrappedBundle` link. Gatekeeper (`spctl`)
/// rejects these by design. Never follows symlinks.
pub fn is_wrapped_ios(app: &Path) -> bool {
    if app.join("Contents").join("Info.plist").symlink_metadata().is_ok() {
        return false;
    }
    let wrapper = app.join("Wrapper").symlink_metadata().map(|m| m.is_dir()).unwrap_or(false);
    let link = app.join("WrappedBundle").symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false);
    wrapper || link
}

/// `codesign --verify` message for App Store iOS bundles, which use iOS-style
/// resource rules; strict verification always reports it for them.
pub const IOS_OBSOLETE_ENVELOPE: &str = "resource envelope is obsolete (custom omit rules)";
/// `codesign --verify` message when a correctly signed standalone executable is
/// used as a bundle's main executable (e.g. Claude Code's URL handler).
pub const NO_RESOURCES: &str = "code has no resources but signature indicates they must be present";

/// True if `out` (codesign --verify stderr) reports failures, and every one of them is `reason`.
pub fn only_reason(out: &str, reason: &str) -> bool {
    let lines: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("In architecture")).collect();
    !lines.is_empty() && lines.iter().all(|l| l.contains(reason))
}

/// Facts gathered about an app Gatekeeper rejected.
#[derive(Debug, Clone, Default)]
pub struct RejectedApp {
    pub wrapped_ios: bool,
    /// `codesign -dvv <app>` output.
    pub codesign_dv: String,
    /// `codesign --verify --deep --strict <app>`: passed?, output.
    pub verify_strict: (bool, String),
    /// Second verification, run only when the strict one failed solely with a
    /// known benign reason: `--deep --no-strict` on the bundle for
    /// [`IOS_OBSOLETE_ENVELOPE`] (still checks every hash and the designated
    /// requirement), `--strict` on the main executable for [`NO_RESOURCES`].
    pub verify_fallback: Option<bool>,
    /// `spctl -a -vv <app>` output.
    pub spctl: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppVerdict {
    /// Signed by Apple for App Store distribution, signature verified.
    IosAppStore { team: String },
    /// Valid Developer ID signature; Gatekeeper rejects it only for lack of notarization.
    SignedNotNotarized { signer: String },
    Rejected,
}

pub fn signature_verified(r: &RejectedApp, benign: &str) -> bool {
    r.verify_strict.0 || (only_reason(&r.verify_strict.1, benign) && r.verify_fallback == Some(true))
}

pub fn classify_rejected(r: &RejectedApp) -> AppVerdict {
    let Some(team) = parse_team(&r.codesign_dv) else { return AppVerdict::Rejected };
    let revoked = r.spctl.to_ascii_lowercase().contains("revoked");
    if revoked {
        return AppVerdict::Rejected;
    }
    let iphone_signed = r.codesign_dv.lines().any(|l| l.starts_with("Authority=Apple iPhone OS Application Signing"));
    if r.wrapped_ios && iphone_signed && signature_verified(r, IOS_OBSOLETE_ENVELOPE) {
        return AppVerdict::IosAppStore { team };
    }
    if !r.wrapped_ios
        && let Sig::DeveloperId(auth) = parse_codesign(&r.codesign_dv)
        && auth.contains(&format!("({team})"))
        && signature_verified(r, NO_RESOURCES)
    {
        let signer = auth.strip_prefix("Developer ID Application: ").unwrap_or(&auth).to_string();
        return AppVerdict::SignedNotNotarized { signer };
    }
    AppVerdict::Rejected
}

fn gather_rejected(app: &Path, spctl: String) -> RejectedApp {
    let ps = app.display().to_string();
    let run = |args: &[&str]| cmd::run_timeout("codesign", args, Duration::from_secs(120)).map(|o| (o.success(), o.combined())).unwrap_or((false, String::new()));
    let codesign_dv = run(&["-dvv", &ps]).1;
    let wrapped_ios = is_wrapped_ios(app);
    let verify_strict = run(&["--verify", "--deep", "--strict", &ps]);
    let mut verify_fallback = None;
    if !verify_strict.0 {
        if wrapped_ios && only_reason(&verify_strict.1, IOS_OBSOLETE_ENVELOPE) {
            verify_fallback = Some(run(&["--verify", "--deep", "--no-strict", &ps]).0);
        } else if only_reason(&verify_strict.1, NO_RESOURCES)
            && let Some(exe) = parse_executable(&codesign_dv)
        {
            verify_fallback = Some(run(&["--verify", "--strict", &exe]).0);
        }
    }
    RejectedApp { wrapped_ios, codesign_dv, verify_strict, verify_fallback, spctl }
}

pub fn app_signatures(ctx: &Ctx) -> Vec<Finding> {
    let t = "App signatures & notarization";
    let apps = list_apps(&[PathBuf::from("/Applications"), ctx.home.join("Applications")]);
    if apps.is_empty() {
        return vec![Finding::unknown(Apps, t, "no apps found in /Applications")];
    }
    let own = |p: &Path| p.file_name().is_some_and(|n| n == "Mac Cleaner Pro.app");
    // Assess in parallel (spctl can take ~0.5 s per app).
    type Assessed = (PathBuf, bool, String, Option<RejectedApp>);
    let results: Vec<Assessed> = std::thread::scope(|s| {
        let chunks: Vec<Vec<PathBuf>> = apps.chunks(apps.len().div_ceil(8)).map(|c| c.to_vec()).collect();
        let hs: Vec<_> = chunks
            .into_iter()
            .map(|c| {
                s.spawn(move || {
                    c.into_iter()
                        .map(|p| {
                            let ps = p.display().to_string();
                            let raw = cmd::run_timeout("spctl", &["-a", "-vv", &ps], Duration::from_secs(60)).map(|o| o.combined()).unwrap_or_default();
                            let (ok, src) = if raw.is_empty() { (false, "could not assess".into()) } else { parse_spctl(&raw) };
                            let extra = (!ok && !own(&p)).then(|| gather_rejected(&p, raw));
                            (p, ok, src, extra)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    let mut by_src: std::collections::BTreeMap<String, usize> = Default::default();
    for (_, ok, s, _) in &results {
        if *ok {
            *by_src.entry(if s.is_empty() { "accepted".into() } else { s.clone() }).or_default() += 1;
        }
    }
    let why = "Gatekeeper rejects apps that are unsigned, not notarized by Apple, or whose signature is broken (possibly modified after signing). Such apps are not necessarily malicious (open-source builds often are unsigned) but deserve a second look. App Store iPhone/iPad apps running on Apple silicon are always rejected by Gatekeeper's check by design; their Apple App Store signature is verified separately.";
    let mut items = vec![];
    let (mut n_ios, mut n_unnot, mut n_rej) = (0, 0, 0);
    for (p, _, src, extra) in &results {
        let Some(r) = extra else { continue };
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let ps = p.display().to_string();
        let title = format!("App: {name}");
        let ident = r.codesign_dv.lines().find_map(|l| l.strip_prefix("Identifier=")).unwrap_or("?").to_string();
        let gk = format!("Gatekeeper (spctl): rejected{}", if src.is_empty() { String::new() } else { format!(" ({src})") });
        let finder = Fix::new("Show in Finder").change("Opens a Finder window with the app selected (changes nothing)").step(run(&["open", "-R", &ps]));
        match classify_rejected(r) {
            AppVerdict::IosAppStore { team } => {
                n_ios += 1;
                items.push(
                    Finding::new(Apps, title, Status::Ok, format!("App Store iPhone/iPad app, signed by team {team}."))
                        .evidence(format!("path: {}", tilde(p)))
                        .evidence(format!("identifier: {ident}, team: {team}, signed by Apple iPhone OS Application Signing"))
                        .evidence(if r.verify_strict.0 {
                            "codesign --verify --deep --strict: valid".to_string()
                        } else {
                            format!("codesign --verify --deep: valid, satisfies its designated requirement (strict mode only reports \"{IOS_OBSOLETE_ENVELOPE}\", normal for App Store iOS apps)")
                        })
                        .evidence(format!("{gk} — expected: Gatekeeper does not assess wrapped iOS apps"))
                        .explain(why),
                );
            }
            AppVerdict::SignedNotNotarized { signer } => {
                n_unnot += 1;
                let mut f = Finding::new(Apps, title, Status::Info, format!("{name} is signed by {signer}, not notarized."))
                    .evidence(format!("path: {}", tilde(p)))
                    .evidence(format!("identifier: {ident}, Developer ID signature verified (codesign)"));
                if !r.verify_strict.0 {
                    f = f.evidence(format!("bundle check reports \"{NO_RESOURCES}\"; the main executable's own signature is valid"));
                }
                if let Some(exe) = parse_executable(&r.codesign_dv)
                    && let Ok(link) = std::fs::read_link(&exe)
                {
                    f = f.evidence(format!("main executable is a link to {}", tilde(&link)));
                }
                items.push(f.evidence(gk).explain(why).fix_text("The developer is identified by Apple's Developer ID. Keep it if you installed it on purpose.").with_fix(finder));
            }
            AppVerdict::Rejected => {
                n_rej += 1;
                let quarantined = cmd::run("xattr", &["-p", "com.apple.quarantine", &ps]).map(|o| o.success()).unwrap_or(false);
                items.push(
                    Finding::new(Apps, title, Status::Warning, format!("{name} is rejected by Gatekeeper{}.", if src.is_empty() { String::new() } else { format!(" ({src})") }))
                        .evidence(format!("path: {}", tilde(p)))
                        .evidence(format!("signature: {}", parse_codesign(&r.codesign_dv).describe()))
                        .evidence(format!("quarantine attribute present: {quarantined}{}", if quarantined { "" } else { " (removed or never downloaded via a browser)" }))
                        .explain(why)
                        .fix_text("If you don't recognise it or no longer need it, quit it and move it to the Trash. Re-download apps from the developer's official site or the App Store.")
                        .with_fix(finder),
                );
            }
        }
    }
    let mut summary_ev: Vec<String> = by_src.iter().map(|(s, n)| format!("{n} app(s): {s}")).collect();
    if n_ios > 0 {
        summary_ev.push(format!("{n_ios} app(s): App Store iPhone/iPad apps (signature verified)"));
    }
    if n_unnot > 0 {
        summary_ev.push(format!("{n_unnot} app(s): Developer ID signed, not notarized"));
    }
    let accepted = results.iter().filter(|(_, ok, _, _)| *ok).count();
    let mut out = vec![if n_rej == 0 && n_unnot == 0 {
        Finding::new(Apps, t, Status::Ok, format!("All {} apps pass Gatekeeper or are verified App Store iPhone/iPad apps.", results.len())).evidence_all(summary_ev).explain(why)
    } else {
        Finding::new(
            Apps,
            t,
            Status::Info,
            format!("{accepted} of {} apps pass Gatekeeper; {n_ios} verified App Store iPhone/iPad app(s), {n_unnot} signed but not notarized, {n_rej} need review (listed separately).", results.len()),
        )
        .evidence_all(summary_ev)
        .explain(why)
    }];
    out.extend(items);
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

    const IOS_DV: &str = "Executable=/Applications/Grays.app/Wrapper/Runner.app/Runner\nIdentifier=grays.GraysOnline\nFormat=app bundle with Mach-O thin (arm64)\nAuthority=Apple iPhone OS Application Signing\nAuthority=Apple iPhone Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=7C9N6X87GL\n";
    const DEVID_DV: &str = "Executable=/Users/x/Applications/Claude Code URL Handler.app/Contents/MacOS/claude\nIdentifier=com.anthropic.claude-code\nAuthority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)\nAuthority=Developer ID Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=Q6L2SF6YDW\n";

    fn tmp_app(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mcp-apps-{}-{name}", std::process::id())).join(format!("{name}.app"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn wrapped_ios_detection() {
        // eBay-style: Wrapper/ folder + WrappedBundle link, no Contents/Info.plist.
        let a = tmp_app("eBay");
        std::fs::create_dir_all(a.join("Wrapper/eBay.app")).unwrap();
        std::os::unix::fs::symlink("Wrapper/eBay.app", a.join("WrappedBundle")).unwrap();
        assert!(is_wrapped_ios(&a));
        // Only a Wrapper folder.
        let b = tmp_app("OnlyWrapper");
        std::fs::create_dir_all(b.join("Wrapper/X.app")).unwrap();
        assert!(is_wrapped_ios(&b));
        // A normal Mac app is not wrapped, even if it happens to contain a Wrapper folder.
        let c = tmp_app("Mac");
        std::fs::create_dir_all(c.join("Contents/MacOS")).unwrap();
        std::fs::write(c.join("Contents/Info.plist"), "<plist/>").unwrap();
        assert!(!is_wrapped_ios(&c));
        std::fs::create_dir_all(c.join("Wrapper")).unwrap();
        assert!(!is_wrapped_ios(&c));
        // An empty bundle is not.
        assert!(!is_wrapped_ios(&tmp_app("Empty")));
        for p in [a, b, c] {
            let _ = std::fs::remove_dir_all(p.parent().unwrap());
        }
    }

    #[test]
    fn ios_app_store_classification() {
        let strict_fail = (false, format!("/Applications/Grays.app: {IOS_OBSOLETE_ENVELOPE}\n"));
        let r = RejectedApp { wrapped_ios: true, codesign_dv: IOS_DV.into(), verify_strict: strict_fail.clone(), verify_fallback: Some(true), spctl: "/Applications/Grays.app: rejected\norigin=Apple iPhone OS Application Signing\n".into() };
        assert_eq!(classify_rejected(&r), AppVerdict::IosAppStore { team: "7C9N6X87GL".into() });
        assert_eq!(classify_rejected(&RejectedApp { verify_strict: (true, String::new()), verify_fallback: None, ..r.clone() }), AppVerdict::IosAppStore { team: "7C9N6X87GL".into() });
        // Hashes/designated requirement don't verify → still a warning.
        assert_eq!(classify_rejected(&RejectedApp { verify_fallback: Some(false), ..r.clone() }), AppVerdict::Rejected);
        // Any other verification failure → warning.
        assert_eq!(classify_rejected(&RejectedApp { verify_strict: (false, "/A.app: a sealed resource is missing or invalid\n".into()), ..r.clone() }), AppVerdict::Rejected);
        // No real team → warning.
        assert_eq!(classify_rejected(&RejectedApp { codesign_dv: IOS_DV.replace("TeamIdentifier=7C9N6X87GL", "TeamIdentifier=not set"), ..r.clone() }), AppVerdict::Rejected);
        // Not signed by Apple's App Store identity (e.g. ad-hoc) → warning.
        assert_eq!(classify_rejected(&RejectedApp { codesign_dv: "Identifier=x\nSignature=adhoc\nTeamIdentifier=ABCDE12345\n".into(), ..r.clone() }), AppVerdict::Rejected);
        // Not a wrapped bundle → not treated as an iOS app.
        assert_eq!(classify_rejected(&RejectedApp { wrapped_ios: false, ..r }), AppVerdict::Rejected);
    }

    #[test]
    fn developer_id_not_notarized_classification() {
        let r = RejectedApp {
            wrapped_ios: false,
            codesign_dv: DEVID_DV.into(),
            verify_strict: (true, String::new()),
            verify_fallback: None,
            spctl: "/Users/x/Applications/Some.app: rejected\nsource=Unnotarized Developer ID\norigin=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)\n".into(),
        };
        let want = AppVerdict::SignedNotNotarized { signer: "Anthropic PBC (Q6L2SF6YDW)".into() };
        assert_eq!(classify_rejected(&r), want);
        // Claude Code URL Handler: bundle check only complains about missing resources; the executable verifies.
        let handler = RejectedApp { verify_strict: (false, format!("/Users/x/Applications/Claude Code URL Handler.app: {NO_RESOURCES}\n")), verify_fallback: Some(true), ..r.clone() };
        assert_eq!(classify_rejected(&handler), want);
        assert_eq!(classify_rejected(&RejectedApp { verify_fallback: Some(false), ..handler }), AppVerdict::Rejected);
        // Tampered bundle → warning.
        assert_eq!(classify_rejected(&RejectedApp { verify_strict: (false, "/A.app: a sealed resource is missing or invalid\n".into()), ..r.clone() }), AppVerdict::Rejected);
        // Revoked certificate → warning.
        assert_eq!(classify_rejected(&RejectedApp { spctl: "/A.app: CSSMERR_TP_CERT_REVOKED\n".into(), ..r.clone() }), AppVerdict::Rejected);
        // Unsigned / ad-hoc stay warnings.
        assert_eq!(classify_rejected(&RejectedApp { codesign_dv: "/A.app: code object is not signed at all\n".into(), ..r.clone() }), AppVerdict::Rejected);
        assert_eq!(classify_rejected(&RejectedApp { codesign_dv: "Identifier=a\nSignature=adhoc\nTeamIdentifier=not set\n".into(), ..r.clone() }), AppVerdict::Rejected);
        // Team must match the Developer ID certificate.
        assert_eq!(classify_rejected(&RejectedApp { codesign_dv: DEVID_DV.replace("TeamIdentifier=Q6L2SF6YDW", "TeamIdentifier=ZZZZZZZZZZ"), ..r }), AppVerdict::Rejected);
    }

    #[test]
    fn only_reason_parse() {
        assert!(only_reason(&format!("/A.app: {IOS_OBSOLETE_ENVELOPE}\n"), IOS_OBSOLETE_ENVELOPE));
        assert!(!only_reason(&format!("/A.app: {IOS_OBSOLETE_ENVELOPE}\n/A.app: a sealed resource is missing or invalid\n"), IOS_OBSOLETE_ENVELOPE));
        assert!(!only_reason("", IOS_OBSOLETE_ENVELOPE));
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
