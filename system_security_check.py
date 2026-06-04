"""
System Security Check — PyQt6 GUI
Run as Administrator for full functionality.
Scans installed packages, services, scheduled tasks, startup items,
network connections, browser extensions, and proxy settings.
Flags known PUPs, adware, bandwidth sellers, and crypto miners.
"""

import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QIcon, QTextCursor, QFont, QColor, QAction
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    QFileDialog,
    QHeaderView,
    QStatusBar,
)

# ─── Icon boilerplate ───────────────────────────────────────────────
APP_ICON_FILE = "SystemSecurityCheck.ico"


def get_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def get_resource_path(filename: str) -> Path:
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass) / filename
    return get_app_dir() / filename


def apply_app_icon(app_or_window) -> None:
    icon_path = get_resource_path(APP_ICON_FILE)
    if icon_path.exists():
        app_or_window.setWindowIcon(QIcon(str(icon_path)))


# ─── Suspicious patterns ────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    # Proxy / bandwidth sellers
    "infatica", "p2b network", "honeygain", "peer2profit", "packetstream",
    "pawns.app", "iproyal", "bright data", "luminati", "oxylabs",
    "smartproxy", "webshare",
    # Adware / PUPs
    "webadvisor", "webcompanion", "web companion", "segurazo",
    "searchprotect", "conduit", "mindspark", "ask toolbar",
    "babylon", "delta toolbar", "coupon", "shopathome",
    "pricemeter", "savesense", "superfish", "wajam",
    "crossrider", "opencandy", "installcore", "softonic",
    "downloadhelper", "speedupmypc", "driver booster",
    "driver updater", "slimcleaner", "pc cleaner", "regclean",
    "systweak", "auslogics", "glarysoft", "iobit",
    # Crypto miners
    "coinhive", "xmrig", "minergate", "nicehash",
    # Remote access (flag, not necessarily bad)
    "anydesk", "ultraviewer", "ammyy", "rustdesk",
    # Misc
    "hola vpn", "hotspot shield free", "psiphon",
]

SUSPICIOUS_TASK_PATTERNS = [
    "infatica", "p2b", "honeygain", "peer2profit", "miner",
    "chromium", "svchost_",
]

COLOR_SUSPICIOUS = QColor(240, 80, 80)


# ─── PowerShell runner ──────────────────────────────────────────────
def run_ps(command: str, timeout: int = 90) -> str:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT — command took too long]"
    except Exception as e:
        return f"[ERROR: {e}]"


# ─── Data collection functions ──────────────────────────────────────
def scan_packages() -> list[dict]:
    raw = run_ps(
        "Get-Package | Where-Object { $_.Name -notlike '*Microsoft*' -and "
        "$_.Name -notlike '*Windows*' } | "
        "Select-Object Name, Version | ConvertTo-Json -Compress"
    )
    return _parse_json_list(raw)


def scan_services() -> list[dict]:
    raw = run_ps(
        "Get-Service | Where-Object { $_.Status -eq 'Running' -and "
        "$_.DisplayName -notlike '*Microsoft*' -and "
        "$_.DisplayName -notlike '*Windows*' } | "
        "Select-Object DisplayName, Name, Status | ConvertTo-Json -Compress"
    )
    return _parse_json_list(raw)


def scan_tasks() -> list[dict]:
    raw = run_ps(
        "Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -and "
        "$_.Author -notlike '*Microsoft*' } | "
        "Select-Object TaskName, Author, State | ConvertTo-Json -Compress"
    )
    return _parse_json_list(raw)


def scan_startup() -> list[dict]:
    raw = run_ps(
        "Get-CimInstance Win32_StartupCommand | "
        "Select-Object Name, Command, Location | ConvertTo-Json -Compress"
    )
    return _parse_json_list(raw)


def scan_connections() -> list[dict]:
    raw = run_ps(
        "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
        "Select-Object RemoteAddress, RemotePort, OwningProcess, "
        "@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction "
        "SilentlyContinue).ProcessName}} | ConvertTo-Json -Compress",
        timeout=30,
    )
    return _parse_json_list(raw)


def scan_chrome_extensions() -> list[dict]:
    ext_path = (
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "Google" / "Chrome" / "User Data" / "Default" / "Extensions"
    )
    if not ext_path.exists():
        return []
    extensions = []
    for ext_dir in ext_path.iterdir():
        if ext_dir.is_dir() and ext_dir.name != "Temp":
            name = ext_dir.name
            for version_dir in ext_dir.iterdir():
                manifest = version_dir / "manifest.json"
                if manifest.exists():
                    try:
                        with open(manifest, "r", encoding="utf-8", errors="ignore") as f:
                            data = json.load(f)
                            n = data.get("name", ext_dir.name)
                            name = n if not n.startswith("__MSG_") else f"{n} ({ext_dir.name})"
                    except Exception:
                        pass
                    break
            extensions.append({"Name": name, "ID": ext_dir.name})
    return extensions


def scan_firefox_extensions() -> list[dict]:
    profiles_path = Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles"
    if not profiles_path.exists():
        return []
    extensions = []
    seen = set()
    for profile in profiles_path.iterdir():
        ext_file = profile / "extensions.json"
        if ext_file.exists():
            try:
                with open(ext_file, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    for addon in data.get("addons", []):
                        aid = addon.get("id", "unknown")
                        if aid in seen:
                            continue
                        seen.add(aid)
                        name = addon.get("defaultLocale", {}).get("name", aid)
                        active = addon.get("active", False)
                        extensions.append({
                            "Name": name,
                            "ID": aid,
                            "Status": "enabled" if active else "disabled",
                        })
            except Exception:
                pass
    return extensions


def scan_proxy() -> str:
    return run_ps(
        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion"
        "\\Internet Settings' | Select-Object ProxyEnable, ProxyServer, "
        "ProxyOverride, AutoConfigURL | Format-List"
    )


def _parse_json_list(raw: str) -> list[dict]:
    if not raw or raw.startswith("[TIMEOUT") or raw.startswith("[ERROR"):
        return [{"_error": raw or "No data returned"}]
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return [{"_raw": raw}]


def is_suspicious(text: str, patterns: list[str] | None = None) -> str | None:
    patterns = patterns or SUSPICIOUS_PATTERNS
    lower = text.lower()
    for p in patterns:
        if p in lower:
            return p
    return None


# ─── Scan thread ────────────────────────────────────────────────────
class ScanThread(QThread):
    progress = pyqtSignal(str)
    section_done = pyqtSignal(str, list)
    text_section = pyqtSignal(str, str)
    finished_all = pyqtSignal(int, int)

    def run(self):
        total = 0
        flagged = 0

        scans = [
            ("Installed Packages", scan_packages, SUSPICIOUS_PATTERNS),
            ("Running Services", scan_services, SUSPICIOUS_PATTERNS),
            ("Scheduled Tasks", scan_tasks, SUSPICIOUS_TASK_PATTERNS),
            ("Startup Items", scan_startup, SUSPICIOUS_PATTERNS),
            ("Active Connections", scan_connections, None),
            ("Chrome Extensions", scan_chrome_extensions, SUSPICIOUS_PATTERNS),
            ("Firefox Extensions", scan_firefox_extensions, SUSPICIOUS_PATTERNS),
        ]

        for i, (name, func, patterns) in enumerate(scans, 1):
            self.progress.emit(f"[{i}/8] Scanning {name}...")
            data = func()
            if patterns:
                for item in data:
                    vals = " ".join(str(v) for v in item.values())
                    if is_suspicious(vals, patterns):
                        item["_flagged"] = True
                        flagged += 1
            total += len(data)
            self.section_done.emit(name, data)

        self.progress.emit("[8/8] Checking proxy settings...")
        proxy_text = scan_proxy()
        self.text_section.emit("Proxy Settings", proxy_text)

        self.progress.emit("Scan complete.")
        self.finished_all.emit(total, flagged)


# ─── Action thread ──────────────────────────────────────────────────
class ActionThread(QThread):
    result = pyqtSignal(str, bool)

    def __init__(self, action: str, target: str, parent=None):
        super().__init__(parent)
        self.action = action
        self.target = target

    def run(self):
        if self.action == "uninstall":
            # Step 1: Try normal uninstall
            run_ps(f'Get-Package -Name "*{self.target}*" | Uninstall-Package -Force')
            verify = run_ps(
                f'Get-Package -Name "*{self.target}*" -ErrorAction SilentlyContinue '
                f'| Measure-Object | Select-Object -ExpandProperty Count'
            )

            if verify.strip() not in ("0", ""):
                # Step 2: Normal uninstall failed — try the package's own uninstaller
                run_ps(
                    f'Get-Package -Name "*{self.target}*" | ForEach-Object {{ '
                    f'$u = $_.Meta.Attributes["UninstallString"]; '
                    f'if ($u) {{ $u = $u.Trim(\'"\'); if (Test-Path $u) {{ Start-Process $u -ArgumentList "/S","/SILENT","/VERYSILENT" -Wait -ErrorAction SilentlyContinue }} }} }}'
                )

            # Step 3: Clean ghost registry entries regardless
            registry_script = (
                f'$paths = @('
                f'"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",'
                f'"HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",'
                f'"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"'
                f'); $removed = 0; '
                f'foreach ($p in $paths) {{ '
                f'Get-ChildItem $p -EA SilentlyContinue | ForEach-Object {{ '
                f'$n = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).DisplayName; '
                f'if ($n -like "*{self.target}*") {{ '
                f'Remove-Item $_.PSPath -Recurse -Force; $removed++ }} }} }}; '
                f'Write-Output $removed'
            )
            reg_removed = run_ps(registry_script).strip()

            # Step 4: Clean leftover folders in Program Files
            folder_script = (
                f'$dirs = @("C:\\Program Files","C:\\Program Files (x86)",'
                f'"$env:APPDATA","$env:LOCALAPPDATA","$env:PROGRAMDATA"); '
                f'foreach ($d in $dirs) {{ '
                f'Get-ChildItem $d -Filter "*{self.target}*" -Directory -EA SilentlyContinue | '
                f'ForEach-Object {{ Remove-Item $_.FullName -Recurse -Force -EA SilentlyContinue; '
                f'Write-Output "Deleted: $($_.FullName)" }} }}'
            )
            folders_out = run_ps(folder_script).strip()

            # Step 5: Kill any related scheduled tasks
            task_script = (
                f'Get-ScheduledTask | Where-Object {{ $_.TaskName -like "*{self.target}*" }} | '
                f'ForEach-Object {{ '
                f'Stop-ScheduledTask -InputObject $_ -EA SilentlyContinue; '
                f'Unregister-ScheduledTask -InputObject $_ -Confirm:$false -EA SilentlyContinue; '
                f'Write-Output "Removed task: $($_.TaskName)" }}'
            )
            tasks_out = run_ps(task_script).strip()

            # Final verify
            final = run_ps(
                f'Get-Package -Name "*{self.target}*" -ErrorAction SilentlyContinue '
                f'| Measure-Object | Select-Object -ExpandProperty Count'
            )

            details = []
            if reg_removed and reg_removed != "0":
                details.append(f"{reg_removed} registry entries removed")
            if folders_out:
                details.append("leftover folders deleted")
            if tasks_out:
                details.append("scheduled tasks removed")

            if final.strip() in ("0", ""):
                msg = f"Fully removed: {self.target}"
                if details:
                    msg += f" ({', '.join(details)})"
                self.result.emit(msg, True)
            else:
                self.result.emit(
                    f"Partially removed: {self.target}. "
                    f"Try uninstalling from Settings → Apps manually.",
                    False,
                )

        elif self.action == "kill_task":
            run_ps(f'Stop-ScheduledTask -TaskName "{self.target}" -ErrorAction SilentlyContinue')
            out = run_ps(f'Unregister-ScheduledTask -TaskName "{self.target}" -Confirm:$false')
            if "Access is denied" in out:
                self.result.emit(
                    f"Access denied — run as Administrator to remove: {self.target}", False
                )
            else:
                self.result.emit(f"Removed scheduled task: {self.target}", True)

        elif self.action == "delete_folder":
            run_ps(f'Remove-Item "{self.target}" -Recurse -Force')
            if not Path(self.target).exists():
                self.result.emit(f"Deleted: {self.target}", True)
            else:
                self.result.emit(f"Failed to delete: {self.target}", False)


# ─── Stylesheet ─────────────────────────────────────────────────────
STYLE = """
QMainWindow, QWidget {
    background-color: #1a1d23;
    color: #d0d4dc;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}
QTabWidget::pane {
    border: 1px solid #2a2e38;
    border-radius: 4px;
    background: #1e2128;
}
QTabBar::tab {
    background: #252830;
    color: #808590;
    padding: 8px 18px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    min-width: 100px;
}
QTabBar::tab:selected {
    background: #1e2128;
    color: #e0e4ec;
    border-bottom: 2px solid #4a90d9;
}
QTabBar::tab:hover:!selected {
    background: #2c3040;
    color: #c0c4cc;
}
QTreeWidget {
    background-color: #16181e;
    border: 1px solid #2a2e38;
    border-radius: 4px;
    alternate-background-color: #1a1d24;
    outline: none;
}
QTreeWidget::item {
    padding: 4px 6px;
    border-bottom: 1px solid #22252c;
}
QTreeWidget::item:selected {
    background-color: #2a3a55;
    color: #e0e8f0;
}
QHeaderView::section {
    background-color: #22252d;
    color: #90949c;
    padding: 6px 10px;
    border: none;
    border-right: 1px solid #2a2e38;
    border-bottom: 1px solid #2a2e38;
    font-family: "Segoe UI", sans-serif;
    font-weight: bold;
    font-size: 12px;
}
QPushButton {
    background-color: #2d5a8a;
    color: #e0e8f0;
    border: none;
    border-radius: 4px;
    padding: 8px 20px;
    font-family: "Segoe UI", sans-serif;
    font-weight: bold;
    font-size: 13px;
}
QPushButton:hover {
    background-color: #3670a8;
}
QPushButton:pressed {
    background-color: #244a72;
}
QPushButton:disabled {
    background-color: #2a2e38;
    color: #555960;
}
QPushButton#dangerBtn {
    background-color: #8a2d2d;
}
QPushButton#dangerBtn:hover {
    background-color: #a83636;
}
QPlainTextEdit {
    background-color: #16181e;
    color: #c0c8d0;
    border: 1px solid #2a2e38;
    border-radius: 4px;
    font-family: "Consolas", monospace;
    font-size: 12px;
    padding: 6px;
}
QLineEdit {
    background-color: #16181e;
    color: #d0d4dc;
    border: 1px solid #2a2e38;
    border-radius: 4px;
    padding: 6px 10px;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}
QLineEdit:focus {
    border: 1px solid #4a90d9;
}
QStatusBar {
    background: #16181e;
    color: #707480;
    border-top: 1px solid #2a2e38;
    font-family: "Segoe UI", sans-serif;
    font-size: 12px;
}
"""


# ─── Main Window ────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("System Security Check")
        self.resize(960, 680)
        self.setMinimumSize(700, 450)

        self._scan_thread = None
        self._action_thread = None
        self._flagged_items: list[tuple[str, str]] = []

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 12, 16, 8)
        layout.setSpacing(10)

        # ── Header ──
        header = QHBoxLayout()
        title_col = QVBoxLayout()
        title = QLabel("System Security Check")
        title.setStyleSheet("font-family: 'Segoe UI', sans-serif; font-size: 18px; font-weight: bold; color: #e0e8f0;")
        subtitle = QLabel("Scan for suspicious software, PUPs, adware, and proxy hijackers")
        subtitle.setStyleSheet("font-family: 'Segoe UI', sans-serif; font-size: 12px; color: #707480;")
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        header.addLayout(title_col)
        header.addStretch()

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("font-family: 'Segoe UI', sans-serif; color: #64c878; font-weight: bold; font-size: 14px;")
        header.addWidget(self.status_label, alignment=Qt.AlignmentFlag.AlignRight)

        self.scan_btn = QPushButton("  Scan System")
        self.scan_btn.setFixedHeight(38)
        self.scan_btn.setMinimumWidth(140)
        self.scan_btn.clicked.connect(self.start_scan)
        header.addWidget(self.scan_btn)

        layout.addLayout(header)

        # ── Tabs ──
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, stretch=1)

        self._trees: dict[str, QTreeWidget] = {}
        tab_configs = [
            ("Packages", ["Name", "Version"]),
            ("Services", ["DisplayName", "Name", "Status"]),
            ("Tasks", ["TaskName", "Author", "State"]),
            ("Startup", ["Name", "Command", "Location"]),
            ("Connections", ["Process", "RemoteAddress", "RemotePort"]),
            ("Chrome Ext.", ["Name", "ID"]),
            ("Firefox Ext.", ["Name", "ID", "Status"]),
        ]
        section_map_keys = [
            "Installed Packages", "Running Services", "Scheduled Tasks",
            "Startup Items", "Active Connections", "Chrome Extensions",
            "Firefox Extensions",
        ]
        self._tab_section_map = {}
        for (tab_name, cols), section_key in zip(tab_configs, section_map_keys):
            tree = QTreeWidget()
            tree.setHeaderLabels(cols)
            tree.setAlternatingRowColors(True)
            tree.setRootIsDecorated(False)
            tree.setSelectionMode(QTreeWidget.SelectionMode.SingleSelection)
            header_view = tree.header()
            for i in range(len(cols)):
                header_view.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
            self._trees[section_key] = tree
            self._tab_section_map[section_key] = tab_name
            self.tabs.addTab(tree, tab_name)

            # Right-click: copy to action bar
            tree.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
            act = QAction("Copy name to action bar", tree)
            act.triggered.connect(lambda checked, t=tree: self._copy_selected(t))
            tree.addAction(act)

        # Proxy tab
        self.proxy_text = QPlainTextEdit()
        self.proxy_text.setReadOnly(True)
        self.tabs.addTab(self.proxy_text, "Proxy")

        # Log tab
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.tabs.addTab(self.log_text, "Log")

        # ── Bottom action bar ──
        bottom = QHBoxLayout()

        self.action_input = QLineEdit()
        self.action_input.setPlaceholderText(
            "Right-click an item → Copy name here, then Uninstall or Kill Task"
        )
        bottom.addWidget(self.action_input, stretch=1)

        self.uninstall_btn = QPushButton("Uninstall Package")
        self.uninstall_btn.setObjectName("dangerBtn")
        self.uninstall_btn.clicked.connect(lambda: self._run_action("uninstall"))
        bottom.addWidget(self.uninstall_btn)

        self.kill_task_btn = QPushButton("Kill Task")
        self.kill_task_btn.setObjectName("dangerBtn")
        self.kill_task_btn.clicked.connect(lambda: self._run_action("kill_task"))
        bottom.addWidget(self.kill_task_btn)

        self.export_btn = QPushButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        bottom.addWidget(self.export_btn)

        layout.addLayout(bottom)

        # Status bar
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready — click Scan System to begin")

    # ── Scan ────────────────────────────────────────────────────────
    def start_scan(self):
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("  Scanning...")
        self.status_label.setText("")
        self._flagged_items.clear()
        for tree in self._trees.values():
            tree.clear()
        self.proxy_text.clear()
        self.log_text.clear()
        self._log("Scan started...")

        self._scan_thread = ScanThread()
        self._scan_thread.progress.connect(self._on_progress)
        self._scan_thread.section_done.connect(self._on_section_done)
        self._scan_thread.text_section.connect(self._on_text_section)
        self._scan_thread.finished_all.connect(self._on_scan_finished)
        self._scan_thread.start()

    def _on_progress(self, msg: str):
        self.statusBar().showMessage(msg)
        self._log(msg)

    def _on_section_done(self, section: str, data: list[dict]):
        tree = self._trees.get(section)
        if not tree:
            return

        col_count = tree.columnCount()
        col_names = [tree.headerItem().text(i) for i in range(col_count)]

        for item_data in data:
            if "_error" in item_data:
                row = QTreeWidgetItem([item_data["_error"]])
                row.setForeground(0, QColor(180, 140, 60))
                tree.addTopLevelItem(row)
                continue
            if "_raw" in item_data:
                row = QTreeWidgetItem([item_data["_raw"]])
                tree.addTopLevelItem(row)
                continue

            values = []
            for col in col_names:
                v = item_data.get(col, "")
                values.append(str(v) if v is not None else "")

            row = QTreeWidgetItem(values)

            if item_data.get("_flagged"):
                for i in range(len(values)):
                    row.setForeground(i, COLOR_SUSPICIOUS)
                    f = row.font(i)
                    f.setBold(True)
                    row.setFont(i, f)
                self._flagged_items.append((section, values[0] if values else "?"))

            tree.addTopLevelItem(row)

        self._log(f"  {section}: {len(data)} items")

    def _on_text_section(self, section: str, text: str):
        if section == "Proxy Settings":
            self.proxy_text.setPlainText(text or "No proxy configured.")

    def _on_scan_finished(self, total: int, flagged: int):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("  Scan System")

        if flagged == 0:
            self.status_label.setStyleSheet(
                "font-family: 'Segoe UI', sans-serif; color: #64c878; font-weight: bold; font-size: 14px;"
            )
            self.status_label.setText(f"✓  Clean — {total} items scanned")
            self._log(f"\n✅ Scan complete: {total} items, no threats found.")
        else:
            self.status_label.setStyleSheet(
                "font-family: 'Segoe UI', sans-serif; color: #e05050; font-weight: bold; font-size: 14px;"
            )
            self.status_label.setText(
                f"⚠  {flagged} suspicious item{'s' if flagged != 1 else ''} found"
            )
            self._log(f"\n⚠️  Scan complete: {total} items, {flagged} flagged:")
            for section, name in self._flagged_items:
                self._log(f"   • [{section}] {name}")

            # Jump to the tab with first flagged item
            if self._flagged_items:
                first_section = self._flagged_items[0][0]
                tab_name = self._tab_section_map.get(first_section, "")
                for i in range(self.tabs.count()):
                    if self.tabs.tabText(i) == tab_name:
                        self.tabs.setCurrentIndex(i)
                        break

        self.statusBar().showMessage(
            f"Done — {total} items, {flagged} flagged  |  "
            f"Right-click → Copy to action bar → Uninstall / Kill Task"
        )

    # ── Actions ─────────────────────────────────────────────────────
    def _run_action(self, action: str):
        target = self.action_input.text().strip()
        if not target:
            QMessageBox.warning(
                self, "Input needed",
                "Enter a package name or task name in the action bar.\n"
                "Tip: right-click an item in the list to copy its name."
            )
            return

        label = {"uninstall": "Uninstall package", "kill_task": "Remove scheduled task"}
        reply = QMessageBox.question(
            self, "Confirm",
            f'{label.get(action, action)}: "{target}"\n\nProceed?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.uninstall_btn.setEnabled(False)
        self.kill_task_btn.setEnabled(False)
        self._log(f"\nRunning {action}: {target}...")

        self._action_thread = ActionThread(action, target)
        self._action_thread.result.connect(self._on_action_result)
        self._action_thread.start()

    def _on_action_result(self, msg: str, success: bool):
        self.uninstall_btn.setEnabled(True)
        self.kill_task_btn.setEnabled(True)
        self._log(f"  → {msg}")
        self.statusBar().showMessage(msg)
        if success:
            QMessageBox.information(self, "Done", msg)
        else:
            QMessageBox.warning(self, "Action result", msg)

    def _copy_selected(self, tree: QTreeWidget):
        item = tree.currentItem()
        if item:
            self.action_input.setText(item.text(0))

    # ── Export ──────────────────────────────────────────────────────
    def export_report(self):
        lines = [
            "=" * 70,
            "  SYSTEM SECURITY CHECK REPORT",
            f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Computer:  {os.environ.get('COMPUTERNAME', 'unknown')}",
            f"  User:      {os.environ.get('USERNAME', 'unknown')}",
            "=" * 70, "",
        ]

        for section_key, tree in self._trees.items():
            lines.append(f"── {section_key.upper()} ──")
            col_count = tree.columnCount()
            for i in range(tree.topLevelItemCount()):
                item = tree.topLevelItem(i)
                vals = [item.text(c) for c in range(col_count) if item.text(c)]
                prefix = "⚠️  " if item.font(0).bold() else "    "
                lines.append(prefix + "  |  ".join(vals))
            lines.append("")

        lines.append("── PROXY SETTINGS ──")
        lines.append(self.proxy_text.toPlainText())
        lines.extend([
            "", "=" * 70,
            '  Paste this into any AI chat and ask:',
            '  "Review this security report. Flag anything suspicious."',
            "=" * 70,
        ])

        export_dir = get_app_dir() / "DATA" / "AntiVirusLocal" / "Exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        default_path = str(export_dir / "security_report.txt")

        path, _ = QFileDialog.getSaveFileName(
            self, "Save report", default_path, "Text files (*.txt)"
        )
        if path:
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            self._log(f"\nReport saved to: {path}")
            self.statusBar().showMessage(f"Report saved: {path}")

    # ── Log helper ──────────────────────────────────────────────────
    def _log(self, msg: str):
        self.log_text.appendPlainText(msg)
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)


# ─── Entry point ────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("System Security Check")
    app.setStyleSheet(STYLE)
    apply_app_icon(app)

    window = MainWindow()
    apply_app_icon(window)
    window.show()

    raise SystemExit(app.exec())


if __name__ == "__main__":
    main()
