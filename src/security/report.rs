//! Summary score and the Markdown report (used by CLI, export and GUI).

use super::{Category, Finding, Status};

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Summary {
    pub ok: usize,
    pub info: usize,
    pub warning: usize,
    pub critical: usize,
    pub unknown: usize,
    pub score: u32,
}

impl Summary {
    /// Score = share of checked findings that are fine; warnings count half.
    /// "Could not check" results are excluded.
    pub fn of(findings: &[Finding]) -> Self {
        let mut s = Summary::default();
        for f in findings {
            match f.status {
                Status::Ok => s.ok += 1,
                Status::Info => s.info += 1,
                Status::Warning => s.warning += 1,
                Status::Critical => s.critical += 1,
                Status::Unknown => s.unknown += 1,
            }
        }
        let checked = s.ok + s.info + s.warning + s.critical;
        s.score = if checked == 0 {
            0
        } else {
            (((s.ok + s.info) as f64 + 0.5 * s.warning as f64) / checked as f64 * 100.0).round() as u32
        };
        s
    }
}

pub fn markdown(findings: &[Finding], timestamp: &str) -> String {
    let s = Summary::of(findings);
    let mut md = String::new();
    md.push_str("# Mac Cleaner Pro — Security Audit\n\n");
    md.push_str(&format!("- Run: {timestamp}\n"));
    md.push_str(&format!(
        "- Score: **{}/100** — {} OK, {} info, {} warning, {} critical, {} could not check\n",
        s.score, s.ok, s.info, s.warning, s.critical, s.unknown
    ));
    md.push_str("- The audit is read-only. Secret values are never shown — only file and variable names.\n\n");

    let attention: Vec<&Finding> = findings
        .iter()
        .filter(|f| matches!(f.status, Status::Critical | Status::Warning))
        .collect();
    if !attention.is_empty() {
        md.push_str("## Needs attention\n\n");
        let mut sorted = attention.clone();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.status));
        for f in sorted {
            md.push_str(&format!("- **{}** {} — {}\n", f.status.label(), f.title, f.summary));
        }
        md.push('\n');
    }

    for cat in Category::ALL {
        let in_cat: Vec<&Finding> = findings.iter().filter(|f| f.category == cat).collect();
        if in_cat.is_empty() {
            continue;
        }
        md.push_str(&format!("## {}\n\n", cat.label()));
        for f in in_cat {
            md.push_str(&format!("### [{}] {}\n\n{}\n\n", f.status.label(), f.title, f.summary));
            if !f.evidence.is_empty() {
                md.push_str("Evidence:\n\n");
                for e in &f.evidence {
                    md.push_str(&format!("- `{}`\n", e.replace('`', "'")));
                }
                md.push('\n');
            }
            if !f.explanation.is_empty() {
                md.push_str(&format!("Why it matters: {}\n\n", f.explanation));
            }
            if !f.fix_text.is_empty() && !matches!(f.status, Status::Ok) {
                md.push_str(&format!("How to fix: {}\n\n", f.fix_text));
            }
            if let Some(c) = &f.fix_command
                && !matches!(f.status, Status::Ok)
            {
                md.push_str(&format!("```sh\n{c}\n```\n\n"));
            }
            for fx in &f.fixes {
                md.push_str(&format!("In-app action available: **{}**{}\n\n", fx.label, if fx.needs_admin() { " (asks for your admin password via macOS)" } else { "" }));
            }
        }
    }
    md
}

/// Short plain-text summary (CLI header, notifications).
pub fn summary_line(findings: &[Finding]) -> String {
    let s = Summary::of(findings);
    format!(
        "Score {}/100 — OK {}, Info {}, Warning {}, Critical {}, Could not check {}",
        s.score, s.ok, s.info, s.warning, s.critical, s.unknown
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::Finding;

    #[test]
    fn score_and_counts() {
        let f = vec![
            Finding::new(Category::System, "a", Status::Ok, ""),
            Finding::new(Category::System, "b", Status::Warning, ""),
            Finding::new(Category::System, "c", Status::Critical, ""),
            Finding::new(Category::System, "d", Status::Unknown, ""),
        ];
        let s = Summary::of(&f);
        assert_eq!((s.ok, s.warning, s.critical, s.unknown), (1, 1, 1, 1));
        assert_eq!(s.score, 50);
        assert_eq!(Summary::of(&[]).score, 0);
    }

    #[test]
    fn markdown_has_sections() {
        let f = vec![Finding::new(Category::Firewall, "Firewall", Status::Warning, "off")
            .fix_text("turn on")
            .command("sudo x")];
        let md = markdown(&f, "now");
        assert!(md.contains("## Firewall"));
        assert!(md.contains("Needs attention"));
        assert!(md.contains("```sh\nsudo x\n```"));
    }
}
