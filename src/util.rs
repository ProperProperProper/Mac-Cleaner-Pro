//! Small shared helpers: paths, sizes, quoting, timestamps.

use std::path::{Path, PathBuf};

/// The user's home directory (falls back to `/` so nothing ever panics).
pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Where the app keeps its own data (history database, quarantine, backups).
pub fn app_support() -> PathBuf {
    home().join("Library/Application Support/MacCleanerPro")
}

/// Human-readable byte size, same format as the original Python app ("12.3 MB").
pub fn human(num_bytes: u64) -> String {
    let mut n = num_bytes as f64;
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if n < 1024.0 {
            return format!("{n:.1} {unit}");
        }
        n /= 1024.0;
    }
    format!("{n:.1} PB")
}

/// Local timestamp in the history-log format.
pub fn now_string() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Timestamp usable inside file names.
pub fn now_compact() -> String {
    chrono::Local::now().format("%Y%m%d-%H%M%S").to_string()
}

/// POSIX shell single-quote a string so it can be pasted into a terminal safely.
pub fn sh_quote(s: &str) -> String {
    if !s.is_empty()
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Join argv into a copy-pasteable shell command.
pub fn sh_join(argv: &[String]) -> String {
    argv.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" ")
}

/// Show a path relative to home as `~/...` (shorter and avoids printing the user name).
pub fn tilde(path: &Path) -> String {
    let h = home();
    if h != Path::new("/")
        && let Ok(rest) = path.strip_prefix(&h)
    {
        if rest.as_os_str().is_empty() {
            return "~".into();
        }
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

/// Recursive directory size; never follows symlinks, skips unreadable entries.
pub fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let Ok(rd) = std::fs::read_dir(path) else {
        return 0;
    };
    for entry in rd.flatten() {
        let Ok(meta) = entry.path().symlink_metadata() else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        } else if meta.is_dir() {
            total += dir_size(&entry.path());
        } else {
            total += meta.len();
        }
    }
    total
}

/// Size of a file or directory (directories recursively), without following symlinks.
pub fn path_size(path: &Path) -> u64 {
    match path.symlink_metadata() {
        Ok(m) if m.is_dir() => dir_size(path),
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_sizes() {
        assert_eq!(human(0), "0.0 B");
        assert_eq!(human(1023), "1023.0 B");
        assert_eq!(human(1024), "1.0 KB");
        assert_eq!(human(1536 * 1024), "1.5 MB");
        assert_eq!(human(5 * 1024 * 1024 * 1024), "5.0 GB");
    }

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("/usr/bin/true"), "/usr/bin/true");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
        assert_eq!(sh_quote(""), "''");
        assert_eq!(
            sh_join(&["chmod".into(), "600".into(), "/x y/z".into()]),
            "chmod 600 '/x y/z'"
        );
    }

    #[test]
    fn dir_size_counts_files_not_symlinks() {
        let d = std::env::temp_dir().join(format!("mcp-size-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("a"), [0u8; 100]).unwrap();
        std::fs::write(d.join("sub/b"), [0u8; 50]).unwrap();
        std::os::unix::fs::symlink(d.join("a"), d.join("link")).unwrap();
        assert_eq!(dir_size(&d), 150);
        assert_eq!(path_size(&d.join("a")), 100);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
