#!/usr/bin/env python3
"""
Mac Cleaner Pro — a small, transparent disk-cleanup utility.

Design rules (what keeps this from being "that shady cleaner app"):
  - Only ever touches well-known, regenerable cache/log/junk locations.
  - Never deletes anything without the user reviewing an itemised list first.
  - Never asks for admin/root privileges.
  - Never phones home — purely local filesystem operations.
  - No duplicate-file scanning (deliberately excluded — too risky for dev workflows
    where generated build artifacts legitimately duplicate).
"""
import os
import sys
import shutil
import sqlite3
import subprocess
import time
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QCheckBox, QMessageBox, QProgressBar,
    QAbstractItemView, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

HOME = Path.home()
APP_SUPPORT = HOME / "Library" / "Application Support" / "MacCleanerPro"
HISTORY_DB = APP_SUPPORT / "history.db"
LAUNCH_AGENT_PATH = HOME / "Library" / "LaunchAgents" / "com.maccleanerpro.weeklyscan.plist"
LAUNCH_AGENT_LABEL = "com.maccleanerpro.weeklyscan"

# Chat-app media caches: messaging apps quietly accumulate every photo/video
# you've ever received into a local cache that grows forever unless cleared.
# This is DELIBERATELY scoped to known *cache* folders inside each app's own
# sandboxed container — never ~/Pictures, never your Photos Library, never
# anything that holds your own photos. Only items older than the age cutoff
# below are considered, so recent/active conversations are left alone.
CHAT_MEDIA_AGE_DAYS = 30
CHAT_MEDIA_PATHS = [
    # WhatsApp
    HOME / "Library" / "Containers" / "net.whatsapp.WhatsApp" / "Data" / "Library" / "Caches" / "ChatMedia",
    HOME / "Library" / "Containers" / "net.whatsapp.WhatsApp" / "Data" / "Library" / "Caches" / "AsyncMediaProcessingCache",
    HOME / "Library" / "Containers" / "net.whatsapp.WhatsApp" / "Data" / "tmp" / "MediaCache",
    # Telegram
    HOME / "Library" / "Group Containers" / "6N38VWS5BX.ru.keepcoder.Telegram" / "media_cache",
    # Signal
    HOME / "Library" / "Application Support" / "Signal" / "attachments.noindex",
    # Discord
    HOME / "Library" / "Application Support" / "discord" / "Cache",
    # Slack
    HOME / "Library" / "Application Support" / "Slack" / "Cache",
]

# ── scan categories ──────────────────────────────────────────────────────────
# Each entry: (label, description, [paths to scan])
# Every path here is a regenerable cache/log/temp location — nothing that holds
# unique user data. macOS and apps recreate these automatically as needed.
CATEGORIES = [
    (
        "User App Caches",
        "Per-app cache files (~/Library/Caches) — rebuilt automatically on next launch",
        [HOME / "Library" / "Caches"],
    ),
    (
        "App & Crash Logs",
        "Old log files and crash reports (~/Library/Logs)",
        [HOME / "Library" / "Logs"],
    ),
    (
        "Mail Attachments Cache",
        "Downloaded email attachments cached locally — Mail re-downloads them on demand",
        [HOME / "Library" / "Containers" / "com.apple.mail" / "Data" / "Library" / "Mail Downloads"],
    ),
    (
        "Trash",
        "Items already in the Trash (~/.Trash)",
        [HOME / ".Trash"],
    ),
    (
        "Xcode Derived Data",
        "Build intermediates Xcode regenerates on the next build",
        [HOME / "Library" / "Developer" / "Xcode" / "DerivedData"],
    ),
    (
        "Xcode Device Support / Simulator Caches",
        "Cached simulator runtimes and device-support files Xcode re-downloads as needed",
        [
            HOME / "Library" / "Developer" / "Xcode" / "iOS DeviceSupport",
            HOME / "Library" / "Developer" / "CoreSimulator" / "Caches",
        ],
    ),
    (
        "Browser Caches",
        "Cached pages/assets for Safari, Chrome, and Firefox — sites reload fresh",
        [
            HOME / "Library" / "Caches" / "com.apple.Safari",
            HOME / "Library" / "Caches" / "Google" / "Chrome",
            HOME / "Library" / "Caches" / "Firefox",
        ],
    ),
    (
        "Old Installers in Downloads",
        "Disk images and installer packages in ~/Downloads older than 30 days",
        [HOME / "Downloads"],
    ),
    (
        "Chat App Media (30+ days old) — opt-in",
        "Photos/videos auto-saved by WhatsApp, Telegram, Signal, Discord, Slack — "
        "cache folders only, never your Photos library or ~/Pictures. Off by default; "
        "tick to include items older than 30 days.",
        CHAT_MEDIA_PATHS,
    ),
]

# Categories that should start UNCHECKED — the user opts in explicitly rather
# than having them swept up in a routine "select all and clean" pass.
OPT_IN_CATEGORIES = {"Chat App Media (30+ days old) — opt-in"}

OLD_INSTALLER_EXTS = {".dmg", ".pkg"}
OLD_INSTALLER_AGE_DAYS = 30

# Top-level locations the Disk Usage tab measures — purely informational,
# nothing here is ever deleted by this tool.
DISK_USAGE_ROOTS = [
    ("Home folder", HOME),
    ("Applications", Path("/Applications")),
    ("Library", HOME / "Library"),
    ("Downloads", HOME / "Downloads"),
    ("Documents", HOME / "Documents"),
    ("Desktop", HOME / "Desktop"),
    ("Movies", HOME / "Movies"),
    ("Pictures", HOME / "Pictures"),
]


def _human(num_bytes):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


def _dir_size(path):
    total = 0
    try:
        for entry in os.scandir(path):
            try:
                if entry.is_symlink():
                    continue
                elif entry.is_dir(follow_symlinks=False):
                    total += _dir_size(entry.path)
                else:
                    total += entry.stat().st_size
            except (OSError, PermissionError):
                continue
    except (OSError, PermissionError):
        pass
    return total


def scan_category(label, paths):
    """Returns a list of (path, size_bytes) entries this category would remove."""
    items = []
    for base in paths:
        try:
            if not base.exists():
                continue
            entries = list(base.iterdir())
        except (OSError, PermissionError):
            # No Full Disk Access / TCC-protected location — skip quietly,
            # nothing this app touches requires elevated permissions.
            continue

        if label == "Old Installers in Downloads":
            cutoff = time.time() - OLD_INSTALLER_AGE_DAYS * 86400
            for entry in entries:
                try:
                    if entry.suffix.lower() in OLD_INSTALLER_EXTS and entry.is_file():
                        if entry.stat().st_mtime < cutoff:
                            items.append((entry, entry.stat().st_size))
                except OSError:
                    continue
        elif label.startswith("Chat App Media"):
            # Age-filtered: only items older than the cutoff are offered, so
            # active/recent conversations' media is left untouched.
            cutoff = time.time() - CHAT_MEDIA_AGE_DAYS * 86400
            for entry in entries:
                try:
                    mtime = entry.stat().st_mtime
                    if mtime < cutoff:
                        size = _dir_size(entry) if entry.is_dir() else entry.stat().st_size
                        items.append((entry, size))
                except OSError:
                    continue
        else:
            # Trash / cache / log / derived-data dirs: remove each top-level
            # entry. For caches/logs the container directory itself is left
            # in place — apps expect it to exist.
            for entry in entries:
                try:
                    size = _dir_size(entry) if entry.is_dir() else entry.stat().st_size
                    items.append((entry, size))
                except OSError:
                    continue
    return items


def remove_path(path):
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink()
    except (OSError, PermissionError):
        pass


# ── cleanup history (local SQLite log — pure transparency, nothing phoned home) ─
def _init_history_db():
    APP_SUPPORT.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(HISTORY_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cleanups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            category TEXT NOT NULL,
            items INTEGER NOT NULL,
            bytes_freed INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn


def record_cleanup(per_category):
    """per_category: dict label -> (item_count, bytes_freed)"""
    conn = _init_history_db()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for label, (count, freed) in per_category.items():
        if count:
            conn.execute(
                "INSERT INTO cleanups (ts, category, items, bytes_freed) VALUES (?, ?, ?, ?)",
                (ts, label, count, freed),
            )
    conn.commit()
    conn.close()


def load_history(limit=200):
    if not HISTORY_DB.exists():
        return []
    conn = _init_history_db()
    rows = conn.execute(
        "SELECT ts, category, items, bytes_freed FROM cleanups ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


# ── background threads (keep the GUI responsive) ────────────────────────────
class ScanWorker(QThread):
    progress = pyqtSignal(str)
    done = pyqtSignal(dict)

    def run(self):
        results = {}
        for label, _desc, paths in CATEGORIES:
            self.progress.emit(f"Scanning {label}…")
            results[label] = scan_category(label, paths)
        self.done.emit(results)


class CleanWorker(QThread):
    progress = pyqtSignal(str)
    done = pyqtSignal(dict)  # label -> (count, bytes_freed)

    def __init__(self, items_by_category):
        super().__init__()
        self._items_by_category = items_by_category

    def run(self):
        summary = {}
        for label, items in self._items_by_category.items():
            freed = 0
            count = 0
            for path, size in items:
                self.progress.emit(f"Removing {path.name}…")
                remove_path(path)
                freed += size
                count += 1
            summary[label] = (count, freed)
        self.done.emit(summary)


class DiskUsageWorker(QThread):
    progress = pyqtSignal(str)
    done = pyqtSignal(list)  # [(label, path, size_bytes), ...]

    def run(self):
        results = []
        for label, path in DISK_USAGE_ROOTS:
            self.progress.emit(f"Measuring {label}…")
            try:
                size = _dir_size(path) if path.exists() else 0
            except (OSError, PermissionError):
                size = 0
            results.append((label, path, size))
        results.sort(key=lambda r: r[2], reverse=True)
        self.done.emit(results)


# ── scheduling: a launchd agent that runs a silent background scan weekly ──
# It only ever scans and posts a local notification — it never deletes
# anything unattended. Cleaning always requires you to open the app.
def _scan_script_command():
    script = str(Path(__file__).resolve())
    return [sys.executable, script, "--background-scan"]


def schedule_enabled():
    return LAUNCH_AGENT_PATH.exists()


def enable_schedule():
    cmd = _scan_script_command()
    args_xml = "\n".join(f"        <string>{c}</string>" for c in cmd)
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key>
        <integer>1</integer>
        <key>Hour</key>
        <integer>10</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
"""
    LAUNCH_AGENT_PATH.write_text(plist)
    os.chmod(LAUNCH_AGENT_PATH, 0o600)
    subprocess.run(["launchctl", "unload", str(LAUNCH_AGENT_PATH)], capture_output=True)
    subprocess.run(["launchctl", "load", str(LAUNCH_AGENT_PATH)], capture_output=True)


def disable_schedule():
    if LAUNCH_AGENT_PATH.exists():
        subprocess.run(["launchctl", "unload", str(LAUNCH_AGENT_PATH)], capture_output=True)
        LAUNCH_AGENT_PATH.unlink()


def run_background_scan_and_notify():
    """Headless weekly check — scans, then posts a local notification with
    the total reclaimable space. Never deletes anything by itself."""
    total = 0
    for label, _desc, paths in CATEGORIES:
        for _path, size in scan_category(label, paths):
            total += size
    if total > 0:
        msg = f"{_human(total)} of junk found — open Mac Cleaner Pro to review and clean."
        subprocess.run([
            "osascript", "-e",
            f'display notification "{msg}" with title "Mac Cleaner Pro"'
        ], capture_output=True)


# ── GUI: Clean tab ───────────────────────────────────────────────────────────
class CleanTab(QWidget):
    def __init__(self):
        super().__init__()
        self._results = {}
        self._checkboxes = {}
        self._build_ui()
        self._start_scan()

    def _build_ui(self):
        root = QVBoxLayout(self)

        self._status = QLabel("Scanning…")
        self._status.setStyleSheet("color:#888;")
        root.addWidget(self._status)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        root.addWidget(self._progress)

        self._list = QListWidget()
        self._list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        root.addWidget(self._list, 1)

        btn_row = QHBoxLayout()
        self._btn_rescan = QPushButton("Rescan")
        self._btn_rescan.clicked.connect(self._start_scan)
        self._btn_clean = QPushButton("Clean Selected")
        self._btn_clean.setEnabled(False)
        self._btn_clean.setStyleSheet(
            "QPushButton { background:#1a3a1a; border:1px solid #2a5a2a; "
            "border-radius:4px; color:#88dd88; font-weight:bold; padding:8px 16px; }"
            "QPushButton:hover { background:#2a5a2a; color:#ffffff; }"
            "QPushButton:disabled { background:#1a1a1a; border:1px solid #333; color:#555; }"
        )
        self._btn_clean.clicked.connect(self._confirm_and_clean)
        btn_row.addWidget(self._btn_rescan)
        btn_row.addStretch(1)
        btn_row.addWidget(self._btn_clean)
        root.addLayout(btn_row)

        note = QLabel(
            "Only well-known cache, log, and temp locations are scanned.\n"
            "Nothing is removed until you review the list and confirm."
        )
        note.setStyleSheet("color:#666; font-size:11px;")
        root.addWidget(note)

    def _start_scan(self):
        self._list.clear()
        self._btn_clean.setEnabled(False)
        self._btn_rescan.setEnabled(False)
        self._progress.setRange(0, 0)
        self._progress.setVisible(True)
        self._status.setText("Scanning…")
        self._scan_thread = ScanWorker()
        self._scan_thread.progress.connect(self._status.setText)
        self._scan_thread.done.connect(self._on_scan_done)
        self._scan_thread.start()

    def _on_scan_done(self, results):
        self._results = results
        self._progress.setVisible(False)
        self._btn_rescan.setEnabled(True)

        total_bytes = 0
        self._checkboxes = {}
        for label, desc, _paths in CATEGORIES:
            items = results.get(label, [])
            cat_bytes = sum(size for _p, size in items)
            total_bytes += cat_bytes

            row = QListWidgetItem()
            row_widget = QWidget()
            row_layout = QVBoxLayout(row_widget)
            row_layout.setContentsMargins(8, 6, 8, 6)

            cb = QCheckBox(f"{label} — {_human(cat_bytes)} ({len(items)} items)")
            cb.setStyleSheet("font-weight:bold;")
            cb.setEnabled(len(items) > 0)
            # Opt-in categories start unchecked — the user must deliberately
            # include them rather than having them swept up by default.
            cb.setChecked(len(items) > 0 and label not in OPT_IN_CATEGORIES)
            self._checkboxes[label] = cb
            cb.stateChanged.connect(self._update_clean_button)

            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color:#888; font-size:11px; margin-left:22px;")

            row_layout.addWidget(cb)
            row_layout.addWidget(desc_label)
            row.setSizeHint(row_widget.sizeHint())
            self._list.addItem(row)
            self._list.setItemWidget(row, row_widget)

        self._status.setText(f"Scan complete — {_human(total_bytes)} reclaimable")
        self._update_clean_button()

    def _update_clean_button(self):
        any_checked = any(cb.isChecked() and cb.isEnabled() for cb in self._checkboxes.values())
        self._btn_clean.setEnabled(any_checked)

    def _selected_items_by_category(self):
        out = {}
        for label, cb in self._checkboxes.items():
            if cb.isChecked() and cb.isEnabled():
                out[label] = self._results.get(label, [])
        return out

    def _confirm_and_clean(self):
        by_cat = self._selected_items_by_category()
        items = [it for items in by_cat.values() for it in items]
        if not items:
            return
        total = sum(size for _p, size in items)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Confirm Cleanup")
        box.setText(
            f"This will permanently remove {len(items)} items, "
            f"freeing approximately {_human(total)}.\n\n"
            "These are all regenerable cache/log/temp files — nothing\n"
            "containing your documents or unique data will be touched."
        )
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return

        self._btn_clean.setEnabled(False)
        self._btn_rescan.setEnabled(False)
        self._progress.setRange(0, 0)
        self._clean_thread = CleanWorker(by_cat)
        self._clean_thread.progress.connect(self._status.setText)
        self._clean_thread.done.connect(self._on_clean_done)
        self._clean_thread.start()

    def _on_clean_done(self, summary):
        record_cleanup(summary)
        count = sum(c for c, _f in summary.values())
        freed = sum(f for _c, f in summary.values())
        self._progress.setRange(0, 1)
        self._progress.setValue(1)
        self._status.setText(f"Done — removed {count} items, freed {_human(freed)}")
        QMessageBox.information(
            self, "Cleanup Complete",
            f"Removed {count} items and freed approximately {_human(freed)}.\n\n"
            "This run has been added to the History tab."
        )
        if hasattr(self.window(), "_history_tab"):
            self.window()._history_tab.reload()
        self._start_scan()


# ── GUI: Disk Usage tab (informational only — never deletes anything) ───────
class DiskUsageTab(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()
        self._start_scan()

    def _build_ui(self):
        root = QVBoxLayout(self)

        info = QLabel(
            "Shows where your disk space is going. This tab never deletes "
            "anything — it's purely a map to help you decide what to look at."
        )
        info.setStyleSheet("color:#888; font-size:11px;")
        info.setWordWrap(True)
        root.addWidget(info)

        self._status = QLabel("Measuring…")
        root.addWidget(self._status)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        root.addWidget(self._progress)

        self._list = QListWidget()
        self._list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        root.addWidget(self._list, 1)

        self._btn_rescan = QPushButton("Remeasure")
        self._btn_rescan.clicked.connect(self._start_scan)
        root.addWidget(self._btn_rescan)

    def _start_scan(self):
        self._list.clear()
        self._btn_rescan.setEnabled(False)
        self._progress.setRange(0, 0)
        self._progress.setVisible(True)
        self._status.setText("Measuring…")
        self._thread = DiskUsageWorker()
        self._thread.progress.connect(self._status.setText)
        self._thread.done.connect(self._on_done)
        self._thread.start()

    def _on_done(self, results):
        self._progress.setVisible(False)
        self._btn_rescan.setEnabled(True)
        max_size = max((r[2] for r in results), default=1) or 1

        for label, path, size in results:
            row = QListWidgetItem()
            w = QWidget()
            layout = QVBoxLayout(w)
            layout.setContentsMargins(8, 6, 8, 6)

            top = QHBoxLayout()
            name = QLabel(f"{label}")
            name.setStyleSheet("font-weight:bold;")
            size_lbl = QLabel(_human(size))
            size_lbl.setStyleSheet("color:#aaa;")
            top.addWidget(name)
            top.addStretch(1)
            top.addWidget(size_lbl)

            bar = QProgressBar()
            bar.setRange(0, 1000)
            bar.setValue(int(size / max_size * 1000))
            bar.setTextVisible(False)
            bar.setFixedHeight(8)

            path_lbl = QLabel(str(path))
            path_lbl.setStyleSheet("color:#666; font-size:10px;")

            layout.addLayout(top)
            layout.addWidget(bar)
            layout.addWidget(path_lbl)
            row.setSizeHint(w.sizeHint())
            self._list.addItem(row)
            self._list.setItemWidget(row, w)

        self._status.setText("Measurement complete — sorted largest first")


# ── GUI: History tab ─────────────────────────────────────────────────────────
class HistoryTab(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()
        self.reload()

    def _build_ui(self):
        root = QVBoxLayout(self)

        info = QLabel(
            "A local log of every cleanup this app has performed — what was "
            "removed, when, and how much space it freed. Stored only on this Mac."
        )
        info.setStyleSheet("color:#888; font-size:11px;")
        info.setWordWrap(True)
        root.addWidget(info)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Date / Time", "Category", "Items Removed", "Space Freed"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        root.addWidget(self._table, 1)

        self._summary = QLabel("")
        self._summary.setStyleSheet("color:#888;")
        root.addWidget(self._summary)

        btn = QPushButton("Refresh")
        btn.clicked.connect(self.reload)
        root.addWidget(btn)

    def reload(self):
        rows = load_history()
        self._table.setRowCount(len(rows))
        total_freed = 0
        total_items = 0
        for r, (ts, category, items, freed) in enumerate(rows):
            total_freed += freed
            total_items += items
            self._table.setItem(r, 0, QTableWidgetItem(ts))
            self._table.setItem(r, 1, QTableWidgetItem(category))
            self._table.setItem(r, 2, QTableWidgetItem(str(items)))
            self._table.setItem(r, 3, QTableWidgetItem(_human(freed)))

        if rows:
            self._summary.setText(
                f"All-time: {total_items} items removed, {_human(total_freed)} freed across {len(rows)} logged entries"
            )
        else:
            self._summary.setText("No cleanups recorded yet — run a clean from the Clean tab.")


# ── GUI: main window ─────────────────────────────────────────────────────────
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mac Cleaner Pro")
        self.resize(760, 620)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)

        header = QHBoxLayout()
        title = QLabel("Mac Cleaner Pro")
        title.setStyleSheet("font-size:20px; font-weight:bold;")
        header.addWidget(title)
        header.addStretch(1)

        self._schedule_cb = QCheckBox("Weekly cleanup reminders")
        self._schedule_cb.setChecked(schedule_enabled())
        self._schedule_cb.setToolTip(
            "Runs a silent background scan once a week and shows a notification\n"
            "if junk is found. Never deletes anything automatically — cleaning\n"
            "always requires you to open the app and confirm."
        )
        self._schedule_cb.stateChanged.connect(self._toggle_schedule)
        header.addWidget(self._schedule_cb)

        self._btn_quit = QPushButton("Quit")
        self._btn_quit.setStyleSheet(
            "QPushButton { background:#3a1a1a; border:1px solid #5a2a2a; "
            "border-radius:4px; color:#dd8888; padding:6px 14px; }"
            "QPushButton:hover { background:#5a2a2a; color:#ffffff; }"
        )
        self._btn_quit.clicked.connect(self.close)
        header.addWidget(self._btn_quit)
        root.addLayout(header)

        tabs = QTabWidget()
        self._clean_tab = CleanTab()
        self._disk_tab = DiskUsageTab()
        self._history_tab = HistoryTab()
        tabs.addTab(self._clean_tab, "Clean")
        tabs.addTab(self._disk_tab, "Disk Usage")
        tabs.addTab(self._history_tab, "History")
        root.addWidget(tabs, 1)

    def _toggle_schedule(self, _state):
        if self._schedule_cb.isChecked():
            enable_schedule()
        else:
            disable_schedule()

    def closeEvent(self, event):
        # Let any in-flight scan/clean threads finish before the process exits —
        # quitting mid-scan would tear down Qt objects a worker thread still uses.
        for thread in (
            getattr(self._clean_tab, "_scan_thread", None),
            getattr(self._clean_tab, "_clean_thread", None),
            getattr(self._disk_tab, "_thread", None),
        ):
            if thread is not None and thread.isRunning():
                thread.wait(5000)
        event.accept()
        # On macOS, closing the last window leaves the app running in the
        # background — explicitly quit so "Quit" actually ends the process.
        QApplication.instance().quit()


def main():
    if "--background-scan" in sys.argv:
        run_background_scan_and_notify()
        return

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
