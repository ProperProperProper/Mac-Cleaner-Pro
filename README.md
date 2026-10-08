# Mac Cleaner Pro

A small, transparent macOS utility written in **pure Rust** (eframe/egui GUI) with two parts:

1. **Cleaner**: does what the popular "Mac cleaner" apps do, without the bloat, upsells or trust issues.
2. **Security**: a full macOS security audit. Every finding explains the risk in plain English, and where possible it has a **Fix** button. You review the exact commands, confirm, and the action is logged with undo.

No Python is needed to build or run it. The app makes no network calls of its own and has no telemetry.

## Cleaner: what it cleans

| Category | What it is | Why it's safe to remove |
|---|---|---|
| User App Caches | `~/Library/Caches/*` | Apps rebuild their caches automatically on next launch |
| App & Crash Logs | `~/Library/Logs/*` | Historical logs, not needed for apps to keep running |
| Mail Attachments Cache | Mail's `Mail Downloads` cache | Mail re-downloads attachments on demand |
| Trash | `~/.Trash/*` | You already chose to delete these |
| Xcode Derived Data | `~/Library/Developer/Xcode/DerivedData` | Xcode regenerates build intermediates from source |
| Xcode Device Support / Simulator Caches | Simulator runtimes & device-support files | Re-downloaded by Xcode as needed |
| Browser Caches | Safari / Chrome / Firefox cache dirs | Pages reload fresh; bookmarks/history are not touched |
| Old Installers in Downloads | `.dmg`/`.pkg` in `~/Downloads` older than 30 days | One-time installers you've already used |
| Chat App Media (opt-in) | WhatsApp/Telegram/Signal/Discord/Slack **cache** folders, items older than 30 days | Off by default; never `~/Pictures` or the Photos library |

How it works: **Scan** (background, touches nothing) → **Review** (sizes and item counts per category, with an expandable list of items) → **Confirm** (an in-app dialog shows how many items and how much space) → **Clean**. Opt-in categories start unticked. Every cleanup is recorded in the local **History** tab (SQLite at `~/Library/Application Support/MacCleanerPro/history.db`; history from the old Python version is kept).

The **Disk Usage** tab is a read-only map of where your space is going. **Weekly reminders** (launchd job `com.maccleanerpro.weeklyscan`, Mondays 10:00) run a silent scan plus the read-only security audit and post one notification. They never delete or fix anything.

The cleaner will never:

- ask for admin rights
- touch anything outside the well-known cache/log/temp paths above
- run a duplicate-file scan

## Security: what it checks

| Area | Checks |
|---|---|
| System protection | FileVault, SIP, Gatekeeper, XProtect / XProtect Remediator definitions and their age, macOS version, configuration profiles & MDM enrollment, third-party system/kernel extensions |
| Software updates | Pending updates (`softwareupdate -l`, runs in the background, restart-required flagged, major upgrades shown as optional); automatic update settings (check, download, Security Responses, system data files/XProtect, macOS auto-install, App Store) |
| Firewall | Application firewall on/off, stealth mode, block-all; third-party firewall (LuLu, Little Snitch…) |
| Network | Listening TCP/UDP sockets (`lsof` + `netstat`), split into local-only vs reachable from the network, with known services identified; DNS servers; web/SOCKS/PAC proxies; `/etc/hosts` overrides of sensitive domains; current Wi-Fi security type (the network name is never read) |
| Sharing | Remote Login (SSH), Screen Sharing, File Sharing, Remote Management (ARD), Remote Apple Events, Printer Sharing, Internet Sharing, AirPlay Receiver (`AirplayRecieverEnabled`, Apple's spelling, plus ports 5000/7000), Bluetooth Sharing |
| Accounts & device | Admin users, guest account, automatic login, password required after sleep/screensaver, screensaver/display-sleep timeout, Find My / Activation Lock, Lockdown Mode |
| Startup items | `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`: the program each one runs, whether it exists, its code signature (`codesign`, `spctl`). Unsigned items are flagged for *review*, not called malware. Also login items (opt-in, because listing them needs an Automation prompt), cron, periodic scripts, login/logout hooks |
| Apps & extensions | Apps in `/Applications` and `~/Applications` that Gatekeeper rejects; Chrome/Brave/Edge/Chromium/Vivaldi/Arc/Firefox extensions with all-site or native access (Safari is not inspected, to avoid a privacy prompt) |
| Trust | Certificates with custom trust settings (possible HTTPS interception); `/etc/sudoers.d` and passwordless sudo rules (`sudo -n -l`, never prompts) |
| Plaintext secrets | Shell rc files, common credential files (`.netrc`, `.aws/credentials`, `.npmrc`, `.docker/config.json`…), launch-agent environment variables, and `.env*` / `config.json` / `*credentials*` / `*.pem` / `*.key` under `~/Projects` (skipping `target/`, `node_modules/`, `.git/`, venvs). For each file it reports whether git tracks or ignores it, and whether the GitHub repo is public (read-only `gh repo view`). It also flags tokens embedded in git remote URLs |
| Files, SSH & privacy | `~/.ssh` and private-key permissions, `authorized_keys`, world-writable files in `~/Projects` and launch-agent folders, home folder mode, whether this app/Terminal has Full Disk Access |
| Developer tools | Claude Code `skipDangerousModePermissionPrompt` / `bypassPermissions` / unrestricted Bash |

Rules the audit follows:

- **Inspection is read-only.** Nothing changes until you click a Fix button and confirm.
- **Secret values are never displayed, logged or exported.** Only file paths and variable/key names are shown. A unit test checks that the report and the fix plans never contain test values.
- **No privacy prompts.** The audit never reads `~/Desktop`, `~/Documents`, `~/Downloads`, Photos, Mail or Safari data, and never follows symlinks.
- If a check can't run (tool missing, permission denied, timeout), it shows "could not check" instead of crashing.

## Security: fixing things

Each fixable finding has a **Fix** button. Before anything runs, a confirmation dialog shows:

- exactly what will change (before → after)
- the exact commands
- any caution (for example, a restart is needed)
- whether undo is available

After you apply a fix, the app re-runs the check. Every action goes into the History tab with:

- timestamp
- the commands
- the state before and after
- an **Undo** button where possible

How each kind of fix runs:

- **Admin fixes** run through macOS's own administrator dialog (`osascript … with administrator privileges`). The app never asks for, stores or logs your password.
- **User-level fixes** (file permissions, `.gitignore`, the screensaver timeout) run directly.
- **Settings that only System Settings can change** (FileVault, AirPlay Receiver, Lockdown Mode, the lock-screen password delay…) open the exact System Settings pane, with a one-line instruction and a **Re-check** button.
- **Suspicious startup items** are *quarantined*. The plist is moved to `~/Library/Application Support/MacCleanerPro/Quarantine/` (or `/Library/…` for system items) and can be moved back. Nothing is deleted.
- **Plaintext secrets** can be copied into the login Keychain. Values go to `security` over stdin, never as command-line arguments, never logged. For shell rc files, the lines can also be rewritten to read from the Keychain, with a 600-mode backup for undo.

Examples of available fixes:

- firewall, stealth mode and block-all on
- turning off Remote Login, Screen Sharing, File Sharing, Printer Sharing, Remote Apple Events, Remote Management or the guest account
- turning on automatic security updates
- installing pending updates (warns about the restart; the app never restarts the Mac itself)
- updating XProtect
- removing a configuration profile (explicit warning, no undo)
- cleaning `/etc/hosts` (backup kept)
- fixing `~/.ssh` and world-writable permissions
- untracking a committed secret file
- making Claude Code ask before running commands again

**Preview only (dry run)** in the Security tab, or `--fix-preview` on the command line, shows every fix's commands without running anything.

## Build & install

Requires Rust (stable) and Xcode Command Line Tools.

```bash
./build_app.sh            # release build → target/bundle/Mac Cleaner Pro.app,
                          # installs to /Applications (or ~/Applications), keeps a backup
                          # of the previous bundle in backup/, re-points the weekly job
./build_app.sh --no-install
```

The bundle is ad-hoc signed with the stable identifier `com.local.mac-cleaner-pro`, so firewall rules (LuLu) keep matching across rebuilds.

## Command line

```bash
mac-cleaner-pro --audit [--output report.md] [--with-login-items]   # security report (Markdown), read-only
mac-cleaner-pro --fix-preview      # every available fix + exact commands; executes nothing
mac-cleaner-pro --dry-run-clean    # what the cleaner would remove, with sizes; deletes nothing
mac-cleaner-pro --background-scan  # what the weekly job runs
```

Inside the app bundle the binary is `/Applications/Mac Cleaner Pro.app/Contents/MacOS/mac-cleaner-pro`.

## Development

```bash
cargo test --release
cargo clippy --all-targets -- -D warnings
```

Every parser (fdesetup, csrutil, socketfilterfw, softwareupdate, lsof, netstat, scutil, codesign, spctl, profiles, systemextensionsctl, kextstat, sysadminctl, pmset, system_profiler, cupsctl, dump-trust-settings, crontab, plists, manifests, env/JSON secret files…) is unit-tested against captured sample output.

Layout:

- `src/cleaner.rs`: scan/clean/disk usage
- `src/history.rs`: SQLite log
- `src/schedule.rs`: weekly launchd job
- `src/security/`: audit checks (`checks/*.rs`), fix plans and execution (`fix.rs`), report (`report.rs`)
- `src/gui.rs`: GUI
- `src/cli.rs`: command line
- `icon.icns`: static app icon
