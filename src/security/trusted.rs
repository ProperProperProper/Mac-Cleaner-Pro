//! Startup items the user explicitly marked as trusted.
//!
//! Stored in `~/Library/Application Support/Mac Cleaner Pro/trusted-startup-items.json`.
//! An entry is keyed by the launchd label, the program path and a SHA-256 of
//! the program file, so a changed binary or script loses trust automatically.
//! Entries are only ever written by an explicit user action ("Mark as trusted"
//! in the Security tab, or `--trust <label>`); the audit itself only reads.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const FILE_NAME: &str = "trusted-startup-items.json";

pub fn default_path(home: &Path) -> PathBuf {
    home.join("Library/Application Support/Mac Cleaner Pro").join(FILE_NAME)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    pub label: String,
    pub program: String,
    pub sha256: String,
    pub trusted_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TrustStore {
    pub version: u32,
    pub items: Vec<Entry>,
}

impl Default for TrustStore {
    fn default() -> Self {
        TrustStore { version: 1, items: vec![] }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustState {
    NotTrusted,
    Trusted,
    /// Trusted earlier, but the program file's hash no longer matches.
    Changed,
}

impl TrustStore {
    /// Missing or unreadable file → empty store (nothing trusted).
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    /// Write atomically (temp file + rename), mode 600; creates the folder.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let dir = path.parent().ok_or("trust file has no parent folder")?;
        std::fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json + "\n").map_err(|e| e.to_string())?;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    pub fn lookup(&self, label: &str, program: &str) -> Option<&Entry> {
        self.items.iter().find(|e| e.label == label && e.program == program)
    }

    /// Add or replace the entry for (label, program).
    pub fn trust(&mut self, label: &str, program: &str, sha256: &str) {
        self.untrust(label, program);
        self.items.push(Entry { label: label.into(), program: program.into(), sha256: sha256.into(), trusted_at: crate::util::now_string() });
        self.items.sort_by(|a, b| (&a.label, &a.program).cmp(&(&b.label, &b.program)));
    }

    /// Remove the entry for (label, program); true if one was removed.
    pub fn untrust(&mut self, label: &str, program: &str) -> bool {
        let n = self.items.len();
        self.items.retain(|e| !(e.label == label && e.program == program));
        n != self.items.len()
    }

    /// Trust state of a program; hashes the file only if an entry exists.
    pub fn state(&self, label: &str, program: &Path) -> TrustState {
        let Some(e) = self.lookup(label, &program.display().to_string()) else { return TrustState::NotTrusted };
        match sha256_file(program) {
            Ok(h) if h == e.sha256 => TrustState::Trusted,
            _ => TrustState::Changed,
        }
    }
}

/// SHA-256 (hex) of a regular file (symlinks are followed to the real file).
pub fn sha256_file(path: &Path) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Record trust for (label, program) — only if the program still has the hash
/// the user reviewed (`expected`). Used by the GUI action and `--trust`.
pub fn apply_trust(file: &Path, label: &str, program: &str, expected: &str) -> Result<(), String> {
    let now = sha256_file(Path::new(program))?;
    if now != expected {
        return Err(format!("{program} changed since it was reviewed; re-run the audit and check it again"));
    }
    let mut s = TrustStore::load(file);
    s.trust(label, program, &now);
    s.save(file)
}

pub fn apply_untrust(file: &Path, label: &str, program: &str) -> Result<(), String> {
    let mut s = TrustStore::load(file);
    if s.untrust(label, program) { s.save(file) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mcp-trust-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sha256_known_value() {
        let d = tmpdir("sha");
        let f = d.join("x");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(sha256_file(&f).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert!(sha256_file(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn round_trip_and_hash_invalidation() {
        let d = tmpdir("rt");
        // The store's folder does not exist yet: save must create it.
        let file = d.join("Mac Cleaner Pro").join(FILE_NAME);
        let prog = d.join("bot.sh");
        std::fs::write(&prog, "#!/bin/sh\necho v1\n").unwrap();
        let ps = prog.display().to_string();
        let h = sha256_file(&prog).unwrap();

        assert_eq!(TrustStore::load(&file).state("com.x.bot", &prog), TrustState::NotTrusted);
        apply_trust(&file, "com.x.bot", &ps, &h).unwrap();
        assert!(file.exists());
        let s = TrustStore::load(&file);
        assert_eq!(s.items.len(), 1);
        assert_eq!(s.items[0].label, "com.x.bot");
        assert_eq!(s.state("com.x.bot", &prog), TrustState::Trusted);
        // Same program under a different label is not trusted.
        assert_eq!(s.state("com.other", &prog), TrustState::NotTrusted);
        // Trusting again does not duplicate.
        apply_trust(&file, "com.x.bot", &ps, &h).unwrap();
        assert_eq!(TrustStore::load(&file).items.len(), 1);

        // Changing the script removes trust automatically.
        std::fs::write(&prog, "#!/bin/sh\necho v2\n").unwrap();
        assert_eq!(TrustStore::load(&file).state("com.x.bot", &prog), TrustState::Changed);
        // And it can't be re-trusted with the stale reviewed hash.
        assert!(apply_trust(&file, "com.x.bot", &ps, &h).is_err());

        apply_untrust(&file, "com.x.bot", &ps).unwrap();
        assert!(TrustStore::load(&file).items.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn corrupt_file_trusts_nothing() {
        let d = tmpdir("bad");
        let file = d.join(FILE_NAME);
        std::fs::write(&file, "not json").unwrap();
        assert!(TrustStore::load(&file).items.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
