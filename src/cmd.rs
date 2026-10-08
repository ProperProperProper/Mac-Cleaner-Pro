//! Running external macOS tools safely: absolute paths, timeouts, no shell,
//! and errors turned into values (a missing tool must never crash a check).

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
    /// stdout followed by stderr (many Apple tools print results on stderr).
    pub fn combined(&self) -> String {
        let mut s = self.stdout.clone();
        if !self.stderr.is_empty() {
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&self.stderr);
        }
        s
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CmdError {
    NotFound(String),
    Timeout(String),
    Io(String),
}

impl std::fmt::Display for CmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CmdError::NotFound(p) => write!(f, "command not found: {p}"),
            CmdError::Timeout(p) => write!(f, "timed out: {p}"),
            CmdError::Io(e) => write!(f, "could not run command: {e}"),
        }
    }
}

/// PATH used for child processes. Apps launched from Finder get a minimal PATH,
/// so Homebrew locations are added for tools like `gh`.
const CHILD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec:/opt/homebrew/bin:/usr/local/bin";

/// Find an executable by name in the standard locations.
pub fn which(name: &str) -> Option<String> {
    if name.starts_with('/') {
        return std::path::Path::new(name).exists().then(|| name.to_string());
    }
    CHILD_PATH
        .split(':')
        .map(|d| format!("{d}/{name}"))
        .find(|p| std::path::Path::new(p).is_file())
}

pub fn run(program: &str, args: &[&str]) -> Result<Output, CmdError> {
    run_opts(program, args, Duration::from_secs(30), None)
}

pub fn run_timeout(program: &str, args: &[&str], timeout: Duration) -> Result<Output, CmdError> {
    run_opts(program, args, timeout, None)
}

/// Run a program with an optional stdin payload (never logged) and a timeout.
pub fn run_opts(
    program: &str,
    args: &[&str],
    timeout: Duration,
    stdin: Option<&[u8]>,
) -> Result<Output, CmdError> {
    let path = which(program).ok_or_else(|| CmdError::NotFound(program.to_string()))?;
    let mut child = Command::new(&path)
        .args(args)
        .env("PATH", CHILD_PATH)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CmdError::Io(format!("{program}: {e}")))?;

    if let Some(data) = stdin
        && let Some(mut si) = child.stdin.take()
    {
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = si.write_all(&data);
        });
    }
    let mut so = child.stdout.take();
    let mut se = child.stderr.take();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = so.as_mut() {
            let _ = s.read_to_end(&mut b);
        }
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = se.as_mut() {
            let _ = s.read_to_end(&mut b);
        }
        b
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CmdError::Timeout(program.to_string()));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(CmdError::Io(e.to_string())),
        }
    };
    let stdout = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned();
    Ok(Output {
        code: status.code(),
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_command_is_an_error_not_a_panic() {
        assert!(matches!(
            run("definitely-not-a-real-tool-xyz", &[]),
            Err(CmdError::NotFound(_))
        ));
    }

    #[test]
    fn runs_and_captures() {
        let o = run("echo", &["hi"]).unwrap();
        assert!(o.success());
        assert_eq!(o.stdout.trim(), "hi");
    }

    #[test]
    fn stdin_payload() {
        let o = run_opts("cat", &[], Duration::from_secs(5), Some(b"abc")).unwrap();
        assert_eq!(o.stdout, "abc");
    }

    #[test]
    fn timeout_kills() {
        let r = run_timeout("sleep", &["5"], Duration::from_millis(200));
        assert!(matches!(r, Err(CmdError::Timeout(_))));
    }
}
