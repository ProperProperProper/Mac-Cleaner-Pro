//! ~/.ssh, file permissions, Full Disk Access.

use super::super::fix::{Fix, Step, pane, settings_fix};
use super::super::{Category::Files, Ctx, Finding, Status};
use crate::util::tilde;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn mode(p: &Path) -> Option<u32> {
    std::fs::symlink_metadata(p).ok().map(|m| m.permissions().mode() & 0o7777)
}

fn chmod_step_pair(p: &Path, new: u32, old: u32) -> (Step, Step) {
    let s = p.display().to_string();
    (Step::Chmod { path: s.clone(), mode: new }, Step::Chmod { path: s, mode: old })
}

/// Does this file start like a private key? (Reads only the first bytes; never shown.)
pub fn looks_like_private_key(head: &[u8]) -> bool {
    let s = String::from_utf8_lossy(head);
    s.starts_with("-----BEGIN") && s.contains("PRIVATE KEY")
}

fn read_head(p: &Path) -> Vec<u8> {
    use std::io::Read;
    let mut b = vec![0u8; 64];
    match std::fs::File::open(p).and_then(|mut f| f.read(&mut b)) {
        Ok(n) => {
            b.truncate(n);
            b
        }
        Err(_) => vec![],
    }
}

pub fn ssh(ctx: &Ctx) -> Vec<Finding> {
    let dir = ctx.home.join(".ssh");
    let Some(dm) = mode(&dir) else {
        return vec![Finding::new(Files, "SSH keys", Status::Ok, "No ~/.ssh folder.")];
    };
    let mut out = vec![];
    let mut bad: Vec<(PathBuf, u32, u32)> = vec![];
    if dm & 0o077 != 0 {
        bad.push((dir.clone(), dm, 0o700));
    }
    let mut keys = 0;
    let mut auth_keys = None;
    let mut ev = vec![format!("~/.ssh mode {:o}", dm)];
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = p.symlink_metadata() else { continue };
            if !m.is_file() {
                continue;
            }
            let fm = m.permissions().mode() & 0o7777;
            let name = e.file_name().to_string_lossy().to_string();
            if name == "authorized_keys" {
                let n = std::fs::read_to_string(&p).map(|t| t.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).count()).unwrap_or(0);
                auth_keys = Some(n);
                if fm & 0o022 != 0 {
                    bad.push((p.clone(), fm, 0o600));
                }
            } else if name == "config" {
                if fm & 0o022 != 0 {
                    bad.push((p.clone(), fm, 0o600));
                }
            } else if !name.ends_with(".pub") && looks_like_private_key(&read_head(&p)) {
                keys += 1;
                ev.push(format!("private key ~/.ssh/{name} mode {:o}", fm));
                if fm & 0o077 != 0 {
                    bad.push((p.clone(), fm, 0o600));
                }
            }
        }
    }
    let t = "SSH key permissions";
    let why = "Private keys readable by other users (or group) can be copied and used to log in to your servers and GitHub. ssh itself refuses keys with loose permissions.";
    out.push(if bad.is_empty() {
        Finding::new(Files, t, Status::Ok, format!("~/.ssh and {keys} private key(s) have safe permissions.")).evidence_all(ev).explain(why)
    } else {
        let mut f = Fix::new("Fix SSH permissions");
        let mut undo = vec![];
        for (p, old, new) in &bad {
            let (a, b) = chmod_step_pair(p, *new, *old);
            f = f.change(format!("{}: {:o} → {:o}", tilde(p), old, new)).step(a);
            undo.push(b);
        }
        Finding::new(Files, t, Status::Critical, format!("{} SSH item(s) have unsafe permissions.", bad.len()))
            .evidence_all(ev)
            .evidence_all(bad.iter().map(|(p, o, n)| format!("{} is {:o}, should be {:o}", tilde(p), o, n)))
            .explain(why)
            .fix_text("chmod 700 ~/.ssh and chmod 600 each private key.")
            .command("chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_*[!.pub]")
            .with_fix(f.undo(undo))
    });
    let remote_login = ctx.port_listening(22);
    let t = "SSH authorized_keys";
    out.push(match auth_keys {
        None => Finding::new(Files, t, Status::Ok, "No ~/.ssh/authorized_keys (nobody can log in to this Mac with a key)."),
        Some(n) if remote_login => Finding::new(Files, t, Status::Warning, format!("{n} key(s) can log in to this Mac over SSH (Remote Login is on)."))
            .evidence(format!("~/.ssh/authorized_keys: {n} key(s)"))
            .explain("Each line in authorized_keys is a key that can open a shell on this Mac without your password. Remove keys you don't recognise.")
            .fix_text("Review ~/.ssh/authorized_keys, or turn off Remote Login if unused.")
            .command("cat ~/.ssh/authorized_keys"),
        Some(n) => Finding::new(Files, t, Status::Info, format!("{n} authorized key(s) present; Remote Login is off so they can't be used right now."))
            .evidence(format!("~/.ssh/authorized_keys: {n} key(s)")),
    });
    out
}

/// World-writable entries (not symlinks, not sticky dirs) up to `depth` levels.
pub fn world_writable(root: &Path, depth: usize) -> Vec<(PathBuf, u32)> {
    let mut v = vec![];
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((d, lvl)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = p.symlink_metadata() else { continue };
            if m.file_type().is_symlink() {
                continue;
            }
            let md = m.permissions().mode() & 0o7777;
            if md & 0o002 != 0 && !(m.is_dir() && md & 0o1000 != 0) {
                v.push((p.clone(), md));
            }
            if m.is_dir() && lvl + 1 < depth {
                let n = e.file_name();
                if !super::secrets::SKIP_DIRS.contains(&n.to_string_lossy().as_ref()) {
                    stack.push((p, lvl + 1));
                }
            }
        }
    }
    v.sort();
    v
}

pub fn permissions(ctx: &Ctx) -> Vec<Finding> {
    let mut out = vec![];
    // Home folder
    let t = "Home folder permissions";
    match mode(&ctx.home) {
        None => out.push(Finding::unknown(Files, t, "cannot stat home")),
        Some(m) => {
            let why = "If your home folder is writable by others, any local user or process could plant files (e.g. shell start-up scripts) in it.";
            out.push(if m & 0o002 != 0 {
                let (a, b) = chmod_step_pair(&ctx.home, m & !0o002, m);
                Finding::new(Files, t, Status::Critical, format!("Home folder is world-writable ({m:o})."))
                    .explain(why)
                    .command("chmod o-w ~")
                    .with_fix(Fix::new("Remove world-write from home").change(format!("~: {m:o} → {:o}", m & !0o002)).step(a).undo(vec![b]))
            } else if m & 0o005 != 0 {
                Finding::new(Files, t, Status::Info, format!("Home folder mode {m:o}: other users can list it (macOS default is 750 or 700)."))
                    .evidence(format!("~ mode {m:o}"))
                    .explain(why)
            } else {
                Finding::new(Files, t, Status::Ok, format!("Home folder mode {m:o}.")).evidence(format!("~ mode {m:o}")).explain(why)
            });
        }
    }
    // World-writable files in ~/Projects and LaunchAgents (group-writable too for agents)
    let mut ww = world_writable(&ctx.projects, 2);
    for d in [ctx.home.join("Library/LaunchAgents"), PathBuf::from("/Library/LaunchAgents"), PathBuf::from("/Library/LaunchDaemons")] {
        if let Some(m) = mode(&d)
            && m & 0o022 != 0
        {
            ww.push((d.clone(), m));
        }
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                if let Some(m) = mode(&e.path())
                    && m & 0o022 != 0
                    && !e.path().symlink_metadata().map(|x| x.file_type().is_symlink()).unwrap_or(true)
                {
                    ww.push((e.path(), m));
                }
            }
        }
    }
    let t = "World-writable files";
    let why = "Files anyone can write to can be modified by any process or user — dangerous for scripts, configs and especially launch agent plists (code that runs at login).";
    out.push(if ww.is_empty() {
        Finding::new(Files, t, Status::Ok, "No world-writable files in ~/Projects (top 2 levels) or in launch agent folders.").explain(why)
    } else {
        let user_owned: Vec<&(PathBuf, u32)> = ww.iter().filter(|(p, _)| p.starts_with(&ctx.home)).collect();
        let mut f = Finding::new(Files, t, Status::Warning, format!("{} world/group-writable item(s).", ww.len()))
            .evidence_all(ww.iter().take(40).map(|(p, m)| format!("{} mode {:o}", tilde(p), m)))
            .explain(why)
            .fix_text("Remove the write bit for others: chmod go-w <file>.")
            .command("chmod go-w <path>");
        if !user_owned.is_empty() {
            let mut fx = Fix::new("Remove group/world write permission");
            let mut undo = vec![];
            for (p, m) in user_owned {
                let (a, b) = chmod_step_pair(p, m & !0o022, *m);
                fx = fx.change(format!("{}: {:o} → {:o}", tilde(p), m, m & !0o022)).step(a);
                undo.push(b);
            }
            f = f.with_fix(fx.undo(undo));
        }
        f
    });
    out
}

pub fn full_disk_access(_: &Ctx) -> Vec<Finding> {
    let t = "Full Disk Access";
    let db = "/Library/Application Support/com.apple.TCC/TCC.db";
    let who = if std::env::var("TERM").is_ok() { "this Terminal session" } else { "Mac Cleaner Pro" };
    match std::fs::File::open(db) {
        Ok(_) => vec![Finding::new(Files, t, Status::Info, format!("{who} has Full Disk Access."))
            .evidence(format!("could open {db}"))
            .explain("Full Disk Access lets a program read all your data, including Mail, Messages and Safari. Every program started from a Terminal that has it inherits it. Grant it only to apps that need it.")
            .with_fix(settings_fix("Open Full Disk Access", pane::FDA, "Remove apps that don't need Full Disk Access."))],
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1) => vec![Finding::new(Files, t, Status::Ok, format!("{who} does not have Full Disk Access (not required)."))
            .evidence(format!("{db}: permission denied"))
            .explain("This audit does not need Full Disk Access; a few checks just report less without it.")],
        Err(e) => vec![Finding::unknown(Files, t, e.to_string())],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_detection() {
        assert!(looks_like_private_key(b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl"));
        assert!(looks_like_private_key(b"-----BEGIN RSA PRIVATE KEY-----"));
        assert!(!looks_like_private_key(b"ssh-ed25519 AAAA"));
        assert!(!looks_like_private_key(b""));
    }

    #[test]
    fn ssh_on_fake_home() {
        let h = std::env::temp_dir().join(format!("mcp-ssh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&h);
        std::fs::create_dir_all(h.join(".ssh")).unwrap();
        std::fs::set_permissions(h.join(".ssh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(h.join(".ssh/id_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n").unwrap();
        std::fs::set_permissions(h.join(".ssh/id_ed25519"), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(h.join(".ssh/id_ed25519.pub"), "ssh-ed25519 AAAA").unwrap();
        let ctx = Ctx::with_home(h.clone());
        let f = ssh(&ctx);
        assert_eq!(f[0].status, Status::Critical);
        let fx = &f[0].fixes[0];
        assert_eq!(fx.steps.len(), 2);
        assert!(fx.preview().iter().any(|p| p.starts_with("chmod 600") && p.contains("id_ed25519")));
        assert!(fx.preview().iter().any(|p| p.starts_with("chmod 700")));
        assert!(!format!("{:?}", f).contains("FAKE"));
        std::fs::remove_dir_all(&h).unwrap();
    }

    #[test]
    fn world_writable_detection() {
        let d = std::env::temp_dir().join(format!("mcp-ww-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("a/b")).unwrap();
        std::fs::write(d.join("a/f"), "x").unwrap();
        std::fs::set_permissions(d.join("a/f"), std::fs::Permissions::from_mode(0o666)).unwrap();
        std::fs::write(d.join("a/b/deep"), "x").unwrap();
        std::fs::set_permissions(d.join("a/b/deep"), std::fs::Permissions::from_mode(0o666)).unwrap();
        let v = world_writable(&d, 2);
        assert_eq!(v.len(), 1);
        assert!(v[0].0.ends_with("a/f"));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
