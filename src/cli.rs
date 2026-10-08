//! Command-line modes (no GUI). None of these delete or change anything,
//! except `--background-scan`, which only posts a notification.

use crate::security::{self, report};
use crate::util::human;

pub const HELP: &str = "Mac Cleaner Pro — disk cleaner + macOS security audit

USAGE:
  mac-cleaner-pro                     open the app
  mac-cleaner-pro --audit [--output FILE] [--with-login-items]
                                      print the security audit report (Markdown); read-only
  mac-cleaner-pro --cli               same as --audit
  mac-cleaner-pro --fix-preview       list every available fix and the exact commands it
                                      would run (dry run: nothing is executed)
  mac-cleaner-pro --dry-run-clean     show what the cleaner would remove, with sizes
                                      (deletes nothing)
  mac-cleaner-pro --background-scan   weekly job: scan + audit, post one notification
  mac-cleaner-pro --update-schedule   point an enabled weekly job at this binary
  mac-cleaner-pro --trust LABEL       mark an installed startup item as trusted by you
                                      (label + program path + SHA-256 of the program)
  mac-cleaner-pro --untrust LABEL     remove that trust entry
  mac-cleaner-pro --help
";

/// Returns Some(exit code) if a CLI mode handled the args, None to start the GUI.
pub fn run(args: &[String]) -> Option<i32> {
    let has = |f: &str| args.iter().any(|a| a == f);
    if has("--help") || has("-h") {
        print!("{HELP}");
        return Some(0);
    }
    if has("--background-scan") {
        println!("{}", crate::schedule::run_background_scan());
        return Some(0);
    }
    if has("--update-schedule") {
        // Re-point an existing weekly job at this binary (used by build_app.sh).
        if crate::schedule::enabled() {
            match crate::schedule::enable() {
                Ok(()) => println!("weekly job now runs {}", crate::schedule::program_path()),
                Err(e) => {
                    eprintln!("could not update weekly job: {e}");
                    return Some(1);
                }
            }
        } else {
            println!("weekly job not enabled; nothing to update");
        }
        return Some(0);
    }
    for (flag, trust) in [("--trust", true), ("--untrust", false)] {
        if let Some(i) = args.iter().position(|a| a == flag) {
            let Some(label) = args.get(i + 1).filter(|l| !l.starts_with("--")) else {
                eprintln!("{flag} needs a launchd label, e.g. {flag} com.example.agent");
                return Some(2);
            };
            return Some(match trust_cli(label, trust) {
                Ok(msg) => {
                    println!("{msg}");
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            });
        }
    }
    if has("--dry-run-clean") {
        dry_run_clean();
        return Some(0);
    }
    if has("--audit") || has("--cli") || has("--fix-preview") {
        let ctx = security::Ctx::new(has("--with-login-items"));
        let findings = security::run_all(&ctx);
        if has("--fix-preview") {
            print_fix_preview(&findings);
        } else {
            let md = report::markdown(&findings, &crate::util::now_string());
            if let Some(i) = args.iter().position(|a| a == "--output")
                && let Some(path) = args.get(i + 1)
            {
                if let Err(e) = std::fs::write(path, &md) {
                    eprintln!("could not write {path}: {e}");
                    return Some(1);
                }
                eprintln!("report written to {path}");
            }
            print!("{md}");
            eprintln!("{}", report::summary_line(&findings));
        }
        return Some(0);
    }
    if let Some(a) = args.iter().skip(1).find(|a| a.starts_with("--")) {
        // Ignore macOS-provided args like -psn_…; unknown flags get help.
        eprintln!("unknown option {a}\n\n{HELP}");
        return Some(2);
    }
    None
}

/// `--trust` / `--untrust`: same steps as the GUI's "Mark as trusted" / "Untrust".
fn trust_cli(label: &str, trust: bool) -> Result<String, String> {
    use security::checks::persistence::{find_launch_item, item_program, trust_fix, untrust_fix};
    let ctx = security::Ctx::new(false);
    let item = find_launch_item(&ctx.home, label).ok_or_else(|| format!("no startup item with label {label} in ~/Library/LaunchAgents, /Library/LaunchAgents or /Library/LaunchDaemons"))?;
    let program = item_program(&item, &ctx.home).ok_or_else(|| format!("{label} has no Program/ProgramArguments"))?;
    let sha = security::trusted::sha256_file(&program)?;
    let fx = if trust { trust_fix(&item, &program, &sha, &ctx) } else { untrust_fix(&item, &program, &sha, &ctx) };
    let log = security::fix::apply_steps(&fx.steps, false)?;
    Ok(log.join("\n"))
}

fn dry_run_clean() {
    let home = crate::util::home();
    let now = std::time::SystemTime::now();
    println!("DRY RUN — nothing will be deleted.\n");
    let mut total = 0u64;
    for c in crate::cleaner::categories(&home) {
        let items = crate::cleaner::scan_category(&c, now);
        let size: u64 = items.iter().map(|i| i.size).sum();
        if !c.opt_in {
            total += size;
        }
        println!(
            "{:<45} {:>10}  {:>5} items{}",
            c.label,
            human(size),
            items.len(),
            if c.opt_in { "   (opt-in, not selected by default)" } else { "" }
        );
    }
    println!("\nReclaimable with default selection: {}", human(total));
}

fn print_fix_preview(findings: &[security::Finding]) {
    println!("FIX PREVIEW — dry run, nothing is executed.\n");
    let mut n = 0;
    for f in findings {
        for fx in &f.fixes {
            n += 1;
            println!("[{}] {} — {}", f.status.label(), f.title, fx.label);
            for c in &fx.changes {
                println!("    change: {c}");
            }
            if let Some(w) = &fx.warning {
                println!("    caution: {w}");
            }
            match security::fix::apply_steps(&fx.steps, true) {
                Ok(lines) => lines.iter().for_each(|l| println!("    {l}")),
                Err(e) => println!("    preview error: {e}"),
            }
            match &fx.undo {
                Some(u) => u.iter().for_each(|s| println!("    undo: {}", security::fix::preview_step(s))),
                None => println!("    undo: not available"),
            }
            println!();
        }
    }
    println!("{n} fix(es) available.");
}
