# Mac Cleaner Pro

A small, transparent disk-cleanup utility for macOS — built to do exactly what
the popular "Mac cleaner" apps do, minus the bloat, the upsells, and the trust
issues.

## What it cleans

| Category | What it is | Why it's safe to remove |
|---|---|---|
| User App Caches | `~/Library/Caches/*` | Apps rebuild their caches automatically on next launch |
| App & Crash Logs | `~/Library/Logs/*` | Historical logs — not needed for apps to keep running |
| Trash | `~/.Trash/*` | You already chose to delete these |
| Xcode Derived Data | `~/Library/Developer/Xcode/DerivedData` | Xcode regenerates build intermediates from source |
| Xcode Device Support / Simulator Caches | Simulator runtimes & device-support files | Re-downloaded by Xcode as needed |
| Browser Caches | Safari / Chrome / Firefox cache dirs | Pages reload fresh; no bookmarks/history touched |
| Old Installers in Downloads | `.dmg`/`.pkg` files in `~/Downloads` older than 30 days | One-time installers you've already used |

**Deliberately excluded:** duplicate-file scanning. Dev workflows legitimately
generate near-identical build artifacts, and a generic duplicate finder is one
of the easiest ways for a "cleaner" to delete something you actually need.

## How it works

1. **Scan** — walks the categories above on a background thread and totals up
   how much space each one is using. Nothing is touched during a scan.
2. **Review** — every category is listed with its size and item count, with a
   checkbox so you can include/exclude any of them.
3. **Confirm** — clicking "Clean Selected" shows exactly how many items and
   how much space will be freed before anything is deleted.
4. **Clean** — only then are the selected items removed, on a background
   thread so the UI stays responsive.

## What it will never do

- Ask for admin/root privileges
- Touch anything outside the well-known cache/log/temp paths listed above
- Delete your documents, photos, projects, or anything containing unique data
- Send any data anywhere — it's a purely local filesystem tool
- Run a "duplicate file" scan that could flag your own work as junk

## Running it

```bash
pip3 install PyQt6
python3 cleaner.py
```

## Building a standalone .app

```bash
pip3 install pyinstaller
pyinstaller --windowed --name "Mac Cleaner Pro" cleaner.py
```
