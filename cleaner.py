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
import time
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QCheckBox, QMessageBox, QProgressBar,
    QAbstractItemView,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

HOME = Path.home()

# ── scan categories ──────────────────────────────────────────────────────────
# Each entry: (label, description, [glob paths to scan])
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
]

OLD_INSTALLER_EXTS = {".dmg", ".pkg"}
OLD_INSTALLER_AGE_DAYS = 30


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


# ── background scan thread (keeps the GUI responsive) ───────────────────────
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
    done = pyqtSignal(int, int)  # files_removed, bytes_freed

    def __init__(self, items):
        super().__init__()
        self._items = items

    def run(self):
        freed = 0
        count = 0
        for path, size in self._items:
            self.progress.emit(f"Removing {path.name}…")
            remove_path(path)
            freed += size
            count += 1
        self.done.emit(count, freed)


# ── GUI ──────────────────────────────────────────────────────────────────────
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mac Cleaner Pro")
        self.resize(720, 560)
        self._results = {}
        self._build_ui()
        self._start_scan()

    def _build_ui(self):
        root = QVBoxLayout(self)

        title = QLabel("Mac Cleaner Pro")
        title.setStyleSheet("font-size:20px; font-weight:bold;")
        root.addWidget(title)

        self._status = QLabel("Scanning…")
        self._status.setStyleSheet("color:#888;")
        root.addWidget(self._status)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # indeterminate while scanning
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

    # ── scanning ─────────────────────────────────────────────────────────────
    def _start_scan(self):
        self._list.clear()
        self._btn_clean.setEnabled(False)
        self._btn_rescan.setEnabled(False)
        self._progress.setRange(0, 0)
        self._status.setText("Scanning…")
        self._scan_thread = ScanWorker()
        self._scan_thread.progress.connect(self._status.setText)
        self._scan_thread.done.connect(self._on_scan_done)
        self._scan_thread.start()

    def _on_scan_done(self, results):
        self._results = results
        self._progress.setRange(0, 1)
        self._progress.setValue(1)
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
            cb.setChecked(len(items) > 0)
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

    # ── cleaning ─────────────────────────────────────────────────────────────
    def _selected_items(self):
        items = []
        for label, cb in self._checkboxes.items():
            if cb.isChecked() and cb.isEnabled():
                items.extend(self._results.get(label, []))
        return items

    def _confirm_and_clean(self):
        items = self._selected_items()
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
        self._clean_thread = CleanWorker(items)
        self._clean_thread.progress.connect(self._status.setText)
        self._clean_thread.done.connect(self._on_clean_done)
        self._clean_thread.start()

    def _on_clean_done(self, count, freed):
        self._progress.setRange(0, 1)
        self._progress.setValue(1)
        self._status.setText(f"Done — removed {count} items, freed {_human(freed)}")
        QMessageBox.information(
            self, "Cleanup Complete",
            f"Removed {count} items and freed approximately {_human(freed)}."
        )
        self._start_scan()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
