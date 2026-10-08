//! The disk cleaner (port of the original cleaner.py).
//!
//! Design rules (what keeps this from being "that shady cleaner app"):
//!   - Only ever touches well-known, regenerable cache/log/junk locations.
//!   - Never deletes anything without the user reviewing an itemised list and
//!     confirming in the app first.
//!   - Never asks for admin/root privileges.
//!   - Never phones home — purely local filesystem operations.
//!   - No duplicate-file scanning (deliberately excluded — too risky for dev
//!     workflows where generated build artifacts legitimately duplicate).
//!   - Never touches ~/Pictures or the Photos library.

use crate::util::path_size;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Chat-app media: only items older than this are offered.
pub const CHAT_MEDIA_AGE_DAYS: u64 = 30;
pub const OLD_INSTALLER_AGE_DAYS: u64 = 30;
pub const OLD_INSTALLER_EXTS: [&str; 2] = ["dmg", "pkg"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    /// Remove every top-level entry inside the folder (the folder itself stays —
    /// apps expect it to exist).
    AllEntries,
    /// Only .dmg/.pkg files older than OLD_INSTALLER_AGE_DAYS.
    OldInstallers,
    /// Only entries whose modification time is older than CHAT_MEDIA_AGE_DAYS.
    OlderThanChatCutoff,
}

#[derive(Debug, Clone)]
pub struct CleanCategory {
    pub label: &'static str,
    pub description: &'static str,
    pub paths: Vec<PathBuf>,
    pub kind: ScanKind,
    /// Opt-in categories start unchecked — the user includes them deliberately.
    pub opt_in: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub path: PathBuf,
    pub size: u64,
}

pub const CHAT_LABEL: &str = "Chat App Media (30+ days old) — opt-in";

/// Chat-app media caches: messaging apps quietly accumulate every photo/video
/// you've ever received into a local cache that grows forever. This is
/// DELIBERATELY scoped to known *cache* folders inside each app's own
/// container — never ~/Pictures, never the Photos Library, never anything that
/// holds your own photos. Only items older than the age cutoff are considered.
pub fn chat_media_paths(home: &Path) -> Vec<PathBuf> {
    [
        "Library/Containers/net.whatsapp.WhatsApp/Data/Library/Caches/ChatMedia",
        "Library/Containers/net.whatsapp.WhatsApp/Data/Library/Caches/AsyncMediaProcessingCache",
        "Library/Containers/net.whatsapp.WhatsApp/Data/tmp/MediaCache",
        "Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/media_cache",
        "Library/Application Support/Signal/attachments.noindex",
        "Library/Application Support/discord/Cache",
        "Library/Application Support/Slack/Cache",
    ]
    .iter()
    .map(|p| home.join(p))
    .collect()
}

/// Every path here is a regenerable cache/log/temp location — nothing that holds
/// unique user data. macOS and apps recreate these automatically as needed.
pub fn categories(home: &Path) -> Vec<CleanCategory> {
    let h = |p: &str| home.join(p);
    vec![
        CleanCategory {
            label: "User App Caches",
            description: "Per-app cache files (~/Library/Caches) — rebuilt automatically on next launch",
            paths: vec![h("Library/Caches")],
            kind: ScanKind::AllEntries,
            opt_in: false,
        },
        CleanCategory {
            label: "App & Crash Logs",
            description: "Old log files and crash reports (~/Library/Logs)",
            paths: vec![h("Library/Logs")],
            kind: ScanKind::AllEntries,
            opt_in: false,
        },
        CleanCategory {
            label: "Mail Attachments Cache",
            description: "Downloaded email attachments cached locally — Mail re-downloads them on demand",
            paths: vec![h("Library/Containers/com.apple.mail/Data/Library/Mail Downloads")],
            kind: ScanKind::AllEntries,
            opt_in: false,
        },
        CleanCategory {
            label: "Trash",
            description: "Items already in the Trash (~/.Trash)",
            paths: vec![h(".Trash")],
            kind: ScanKind::AllEntries,
            opt_in: false,
        },
        CleanCategory {
            label: "Xcode Derived Data",
            description: "Build intermediates Xcode regenerates on the next build",
            paths: vec![h("Library/Developer/Xcode/DerivedData")],
            kind: ScanKind::AllEntries,
            opt_in: false,
        },
        CleanCategory {
            label: "Xcode Device Support / Simulator Caches",
            description: "Cached simulator runtimes and device-support files Xcode re-downloads as needed",
            paths: vec![
                h("Library/Developer/Xcode/iOS DeviceSupport"),
                h("Library/Developer/CoreSimulator/Caches"),
            ],
            kind: ScanKind::AllEntries,
            opt_in: false,
        },
        CleanCategory {
            label: "Browser Caches",
            description: "Cached pages/assets for Safari, Chrome, and Firefox — sites reload fresh",
            paths: vec![
                h("Library/Caches/com.apple.Safari"),
                h("Library/Caches/Google/Chrome"),
                h("Library/Caches/Firefox"),
            ],
            kind: ScanKind::AllEntries,
            opt_in: false,
        },
        CleanCategory {
            label: "Old Installers in Downloads",
            description: "Disk images and installer packages in ~/Downloads older than 30 days",
            paths: vec![h("Downloads")],
            kind: ScanKind::OldInstallers,
            opt_in: false,
        },
        CleanCategory {
            label: CHAT_LABEL,
            description: "Photos/videos auto-saved by WhatsApp, Telegram, Signal, Discord, Slack — \
                cache folders only, never your Photos library or ~/Pictures. Off by default; \
                tick to include items older than 30 days.",
            paths: chat_media_paths(home),
            kind: ScanKind::OlderThanChatCutoff,
            opt_in: true,
        },
    ]
}

fn older_than(path: &Path, days: u64, now: SystemTime) -> bool {
    let cutoff = now
        .checked_sub(Duration::from_secs(days * 86_400))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    path.symlink_metadata()
        .and_then(|m| m.modified())
        .map(|t| t < cutoff)
        .unwrap_or(false)
}

/// Guard: refuse anything that is not strictly inside one of the category's
/// base folders, and anything under ~/Pictures or a Photos library.
pub fn is_safe_target(path: &Path, bases: &[PathBuf]) -> bool {
    let s = path.to_string_lossy();
    if s.contains("/Pictures/") || s.ends_with("/Pictures") || s.contains(".photoslibrary") {
        return false;
    }
    if path.components().any(|c| c.as_os_str() == "..") {
        return false;
    }
    bases
        .iter()
        .any(|b| path.parent() == Some(b.as_path()) && path != b.as_path())
}

/// Returns the entries this category would remove (nothing is touched).
pub fn scan_category(cat: &CleanCategory, now: SystemTime) -> Vec<Item> {
    let mut items = Vec::new();
    for base in &cat.paths {
        // Missing or permission-protected locations are skipped quietly —
        // nothing this app touches requires elevated permissions.
        let Ok(rd) = std::fs::read_dir(base) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if !is_safe_target(&path, &cat.paths) {
                continue;
            }
            let Ok(meta) = path.symlink_metadata() else {
                continue;
            };
            match cat.kind {
                ScanKind::OldInstallers => {
                    let ext = path
                        .extension()
                        .map(|e| e.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    if meta.is_file()
                        && OLD_INSTALLER_EXTS.contains(&ext.as_str())
                        && older_than(&path, OLD_INSTALLER_AGE_DAYS, now)
                    {
                        items.push(Item { size: meta.len(), path });
                    }
                }
                ScanKind::OlderThanChatCutoff => {
                    if older_than(&path, CHAT_MEDIA_AGE_DAYS, now) {
                        items.push(Item { size: path_size(&path), path });
                    }
                }
                ScanKind::AllEntries => {
                    items.push(Item { size: path_size(&path), path });
                }
            }
        }
    }
    items
}

/// Remove one item. Directories are removed recursively without following
/// symlinks; a symlink is removed itself, never its target.
/// Returns true if the item no longer exists afterwards.
pub fn remove_path(path: &Path) -> bool {
    match path.symlink_metadata() {
        Ok(m) if m.is_dir() => {
            let _ = std::fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(path);
        }
        Err(_) => return true,
    }
    path.symlink_metadata().is_err()
}

/// Clean the given items (already reviewed and confirmed by the user).
/// Returns (label, removed_count, bytes_freed) per category.
pub fn clean(
    selected: &[(String, Vec<PathBuf>, Vec<Item>)],
    mut progress: impl FnMut(&str),
) -> Vec<(String, u64, u64)> {
    let mut summary = Vec::new();
    for (label, bases, items) in selected {
        let (mut count, mut freed) = (0u64, 0u64);
        for it in items {
            if !is_safe_target(&it.path, bases) {
                continue;
            }
            progress(&format!(
                "Removing {}…",
                it.path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
            ));
            if remove_path(&it.path) {
                count += 1;
                freed += it.size;
            }
        }
        summary.push((label.clone(), count, freed));
    }
    summary
}

/// Top-level locations the Disk Usage tab measures — purely informational,
/// nothing here is ever deleted by this tool.
pub fn disk_usage_roots(home: &Path) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("Home folder", home.to_path_buf()),
        ("Applications", PathBuf::from("/Applications")),
        ("Library", home.join("Library")),
        ("Downloads", home.join("Downloads")),
        ("Documents", home.join("Documents")),
        ("Desktop", home.join("Desktop")),
        ("Movies", home.join("Movies")),
        ("Pictures", home.join("Pictures")),
    ]
}

/// Measure disk usage roots, sorted largest first.
pub fn measure_disk_usage(home: &Path, mut progress: impl FnMut(&str)) -> Vec<(String, PathBuf, u64)> {
    let mut out: Vec<(String, PathBuf, u64)> = disk_usage_roots(home)
        .into_iter()
        .map(|(label, p)| {
            progress(&format!("Measuring {label}…"));
            let size = if p.exists() { crate::util::dir_size(&p) } else { 0 };
            (label.to_string(), p, size)
        })
        .collect();
    out.sort_by_key(|r| std::cmp::Reverse(r.2));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mcp-clean-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn set_old(p: &Path, days: u64) {
        let t = SystemTime::now() - Duration::from_secs(days * 86_400);
        fs::File::options()
            .write(true)
            .open(p)
            .or_else(|_| fs::File::open(p))
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    #[test]
    fn categories_match_original_app() {
        let cats = categories(Path::new("/Users/x"));
        assert_eq!(cats.len(), 9);
        let opt_in: Vec<_> = cats.iter().filter(|c| c.opt_in).map(|c| c.label).collect();
        assert_eq!(opt_in, vec![CHAT_LABEL]);
        for c in &cats {
            for p in &c.paths {
                let s = p.to_string_lossy();
                assert!(!s.contains("Pictures"), "{s}");
                assert!(!s.contains("Documents"), "{s}");
                assert!(!s.contains("Desktop"), "{s}");
            }
        }
    }

    #[test]
    fn all_entries_scan_lists_top_level_items_only() {
        let d = tmp("all");
        fs::create_dir_all(d.join("Caches/app1/deep")).unwrap();
        fs::write(d.join("Caches/app1/deep/f"), [0u8; 10]).unwrap();
        fs::write(d.join("Caches/file"), [0u8; 5]).unwrap();
        let cat = CleanCategory {
            label: "t",
            description: "",
            paths: vec![d.join("Caches"), d.join("missing")],
            kind: ScanKind::AllEntries,
            opt_in: false,
        };
        let mut items = scan_category(&cat, SystemTime::now());
        items.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].size, 10);
        assert_eq!(items[1].size, 5);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn old_installers_filter_by_ext_and_age() {
        let d = tmp("dl");
        let dl = d.join("Downloads");
        fs::create_dir_all(&dl).unwrap();
        for f in ["old.dmg", "new.dmg", "old.PKG", "old.zip"] {
            fs::write(dl.join(f), [0u8; 7]).unwrap();
        }
        set_old(&dl.join("old.dmg"), 40);
        set_old(&dl.join("old.PKG"), 40);
        set_old(&dl.join("old.zip"), 40);
        let cat = CleanCategory {
            label: "Old Installers in Downloads",
            description: "",
            paths: vec![dl.clone()],
            kind: ScanKind::OldInstallers,
            opt_in: false,
        };
        let mut names: Vec<String> = scan_category(&cat, SystemTime::now())
            .into_iter()
            .map(|i| i.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["old.PKG", "old.dmg"]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn chat_media_age_filter() {
        let d = tmp("chat");
        fs::write(d.join("recent.jpg"), [0u8; 3]).unwrap();
        fs::write(d.join("old.jpg"), [0u8; 3]).unwrap();
        set_old(&d.join("old.jpg"), 31);
        let cat = CleanCategory {
            label: CHAT_LABEL,
            description: "",
            paths: vec![d.clone()],
            kind: ScanKind::OlderThanChatCutoff,
            opt_in: true,
        };
        let items = scan_category(&cat, SystemTime::now());
        assert_eq!(items.len(), 1);
        assert!(items[0].path.ends_with("old.jpg"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn safety_guard() {
        let base = vec![PathBuf::from("/Users/x/Library/Caches")];
        assert!(is_safe_target(Path::new("/Users/x/Library/Caches/foo"), &base));
        assert!(!is_safe_target(Path::new("/Users/x/Library/Caches"), &base));
        assert!(!is_safe_target(Path::new("/Users/x/Library/Caches/a/b"), &base));
        assert!(!is_safe_target(Path::new("/Users/x/Documents/foo"), &base));
        let pics = vec![PathBuf::from("/Users/x/Pictures")];
        assert!(!is_safe_target(Path::new("/Users/x/Pictures/foo"), &pics));
    }

    #[test]
    fn clean_removes_dirs_and_symlinks_not_targets() {
        let d = tmp("rm");
        let base = d.join("Caches");
        fs::create_dir_all(base.join("dir/sub")).unwrap();
        fs::write(base.join("dir/sub/f"), [0u8; 4]).unwrap();
        let outside = d.join("keep.txt");
        fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, base.join("link")).unwrap();
        let cat = CleanCategory {
            label: "t",
            description: "",
            paths: vec![base.clone()],
            kind: ScanKind::AllEntries,
            opt_in: false,
        };
        let items = scan_category(&cat, SystemTime::now());
        let summary = clean(&[("t".into(), vec![base.clone()], items)], |_| {});
        assert_eq!(summary[0].1, 2);
        assert!(base.exists(), "container folder must stay");
        assert!(fs::read_dir(&base).unwrap().next().is_none());
        assert!(outside.exists(), "symlink target must not be deleted");
        fs::remove_dir_all(&d).unwrap();
    }
}
