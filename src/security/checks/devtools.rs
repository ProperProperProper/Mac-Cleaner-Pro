//! Developer tools: Claude Code permission settings.

use super::super::fix::{Fix, Step};
use super::super::{Category::DevTools, Ctx, Finding, Status};
use crate::util::tilde;

#[derive(Debug, Default, PartialEq)]
pub struct ClaudeRisk {
    pub skip_prompt: bool,
    pub bypass_default: bool,
    pub unrestricted_bash: bool,
}

pub fn parse_claude_settings(text: &str) -> Option<ClaudeRisk> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let allow: Vec<String> = v
        .pointer("/permissions/allow")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default();
    Some(ClaudeRisk {
        skip_prompt: v.get("skipDangerousModePermissionPrompt").and_then(|x| x.as_bool()) == Some(true),
        bypass_default: v.pointer("/permissions/defaultMode").and_then(|x| x.as_str()) == Some("bypassPermissions"),
        unrestricted_bash: allow.iter().any(|a| a == "Bash" || a == "Bash(*)" || a == "Bash(*:*)"),
    })
}

pub fn claude_settings(ctx: &Ctx) -> Vec<Finding> {
    let mut out = vec![];
    for rel in [".claude/settings.json", ".claude/settings.local.json"] {
        let p = ctx.home.join(rel);
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let t = format!("Claude Code: ~/{rel}");
        let Some(r) = parse_claude_settings(&text) else {
            out.push(Finding::unknown(DevTools, t, "not valid JSON"));
            continue;
        };
        let mut ev = vec![];
        let mut keys = vec![];
        if r.skip_prompt {
            ev.push("skipDangerousModePermissionPrompt: true".to_string());
            keys.push(vec!["skipDangerousModePermissionPrompt".to_string()]);
        }
        if r.bypass_default {
            ev.push("permissions.defaultMode: bypassPermissions".to_string());
            keys.push(vec!["permissions".to_string(), "defaultMode".to_string()]);
        }
        if r.unrestricted_bash {
            ev.push("permissions.allow contains unrestricted Bash".to_string());
        }
        let why = "With bypass-permissions mode (and its confirmation prompt skipped) Claude Code can run any shell command and edit any file without asking — convenient for autonomous work, but a prompt-injection in a web page, README or dependency could then run commands as you.";
        if ev.is_empty() {
            out.push(Finding::new(DevTools, t, Status::Ok, "Claude Code asks before running commands.").explain(why));
            continue;
        }
        let mut f = Finding::new(DevTools, t, Status::Warning, "Claude Code can run commands without asking.")
            .evidence_all(ev)
            .explain(why)
            .fix_text(format!("Remove these keys from {} (or keep them deliberately if you rely on autonomous runs).", tilde(&p)));
        if !keys.is_empty() {
            let ps = p.display().to_string();
            let backup = ctx.backup_dir().join(format!("claude-{}.{}.json", rel.replace(['/', '.'], "_"), ctx.stamp)).display().to_string();
            let mut fx = Fix::new("Make Claude Code ask again")
                .step(Step::JsonRemove { path: ps.clone(), keys: keys.clone(), backup: backup.clone() })
                .undo(vec![Step::CopyFile { from: backup.clone(), to: ps }])
                .warn("Running Claude Code sessions keep their current mode until restarted.");
            for k in &keys {
                fx = fx.change(format!("Remove \"{}\" from ~/{rel}", k.join(".")));
            }
            fx = fx.change(format!("Backup saved to {}", tilde(std::path::Path::new(&backup))));
            f = f.with_fix(fx);
        }
        out.push(f);
    }
    if out.is_empty() {
        out.push(Finding::new(DevTools, "Claude Code permissions", Status::Ok, "No Claude Code settings file (or nothing risky)."));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let r = parse_claude_settings(r#"{"skipDangerousModePermissionPrompt":true,"theme":"x","permissions":{"allow":["Read","Bash"]}}"#).unwrap();
        assert_eq!(r, ClaudeRisk { skip_prompt: true, bypass_default: false, unrestricted_bash: true });
        let r = parse_claude_settings(r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#).unwrap();
        assert!(r.bypass_default);
        assert_eq!(parse_claude_settings("{}").unwrap(), ClaudeRisk::default());
        assert!(parse_claude_settings("nope").is_none());
    }
}
