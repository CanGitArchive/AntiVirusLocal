"""
System Security Check — generates a report for AI-assisted review.
Run as Administrator in PowerShell:  python system_security_check.py
Outputs: security_report.txt (paste into any AI chat for analysis)

Optional flags:
  --delete PACKAGE_NAME   Attempt to uninstall a package by name
  --kill-task TASK_NAME   Stop + unregister a scheduled task
  --delete-folder PATH    Recursively delete a folder
"""

import subprocess
import sys
import argparse
import datetime
import os
import json
from pathlib import Path

REPORT_FILE = "security_report.txt"

# Known suspicious / PUP patterns (case-insensitive partial matches)
SUSPICIOUS_PATTERNS = [
    # Proxy / bandwidth sellers
    "infatica", "p2b", "honeygain", "peer2profit", "packetstream",
    "pawns.app", "iproyal", "bright data", "luminati", "oxylabs",
    "smartproxy", "spider", "webshare",
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
    # Remote access (legitimate but worth flagging)
    "anydesk", "ultraviewer", "ammyy", "rustdesk",
    # Misc
    "hola vpn", "hotspot shield free", "psiphon",
]

SUSPICIOUS_TASK_PATTERNS = [
    "infatica", "p2b", "honeygain", "peer2profit", "miner",
    "update_check", "chromium", "svchost_",
]


def run_ps(command: str, timeout: int = 60) -> str:
    """Run a PowerShell command and return stdout."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR: {e}]"


def get_installed_packages() -> str:
    return run_ps(
        "Get-Package | Sort-Object Name | Format-Table Name, Version -AutoSize"
    )


def get_non_microsoft_packages() -> str:
    return run_ps(
        "Get-Package | Where-Object { $_.Name -notlike '*Microsoft*' -and "
        "$_.Name -notlike '*Windows*' } | Sort-Object Name | "
        "Format-Table Name, Version -AutoSize"
    )


def get_services() -> str:
    return run_ps(
        "Get-Service | Where-Object { $_.Status -eq 'Running' -and "
        "$_.DisplayName -notlike '*Microsoft*' -and "
        "$_.DisplayName -notlike '*Windows*' } | "
        "Sort-Object DisplayName | Format-Table DisplayName, Name, Status -AutoSize"
    )


def get_scheduled_tasks() -> str:
    return run_ps(
        "Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -and "
        "$_.Author -notlike '*Microsoft*' } | "
        "Format-Table TaskName, Author, State -AutoSize"
    )


def get_startup_items() -> str:
    return run_ps(
        "Get-CimInstance Win32_StartupCommand | "
        "Format-Table Name, Command, Location -AutoSize"
    )


def get_established_connections() -> str:
    return run_ps(
        "Get-NetTCPConnection -State Established | "
        "Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, "
        "OwningProcess, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | "
        "Format-Table -AutoSize",
        timeout=30
    )


def get_browser_extensions_chrome() -> str:
    """List Chrome extension folder names (IDs)."""
    ext_path = Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "Extensions"
    if not ext_path.exists():
        return "[Chrome extensions folder not found]"
    
    extensions = []
    for ext_dir in ext_path.iterdir():
        if ext_dir.is_dir() and ext_dir.name != "Temp":
            # Try to read manifest for name
            name = ext_dir.name  # fallback to ID
            for version_dir in ext_dir.iterdir():
                manifest = version_dir / "manifest.json"
                if manifest.exists():
                    try:
                        with open(manifest, "r", encoding="utf-8", errors="ignore") as f:
                            data = json.load(f)
                            name = data.get("name", ext_dir.name)
                            if name.startswith("__MSG_"):
                                name = f"{name} (ID: {ext_dir.name})"
                    except Exception:
                        pass
                    break
            extensions.append(name)
    
    return "\n".join(sorted(extensions)) if extensions else "[No extensions found]"


def get_browser_extensions_firefox() -> str:
    """List Firefox extensions from profiles."""
    profiles_path = Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles"
    if not profiles_path.exists():
        return "[Firefox profiles folder not found]"
    
    extensions = []
    for profile in profiles_path.iterdir():
        ext_file = profile / "extensions.json"
        if ext_file.exists():
            try:
                with open(ext_file, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    for addon in data.get("addons", []):
                        name = addon.get("defaultLocale", {}).get("name", addon.get("id", "unknown"))
                        enabled = addon.get("active", False)
                        extensions.append(f"{name} [{'enabled' if enabled else 'disabled'}]")
            except Exception:
                pass
    
    return "\n".join(sorted(set(extensions))) if extensions else "[No extensions found]"


def get_proxy_settings() -> str:
    """Check system proxy configuration."""
    return run_ps(
        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | "
        "Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL | Format-List"
    )


def flag_suspicious(text: str, patterns: list[str]) -> list[str]:
    """Return lines from text that match any suspicious pattern."""
    flagged = []
    for line in text.splitlines():
        lower = line.lower()
        for pattern in patterns:
            if pattern in lower:
                flagged.append(f"  ⚠️  {line.strip()}  [matched: {pattern}]")
                break
    return flagged


def build_report() -> str:
    sections = []
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    sections.append(f"{'='*70}")
    sections.append(f"  SYSTEM SECURITY CHECK REPORT")
    sections.append(f"  Generated: {timestamp}")
    sections.append(f"  Computer: {os.environ.get('COMPUTERNAME', 'unknown')}")
    sections.append(f"  User: {os.environ.get('USERNAME', 'unknown')}")
    sections.append(f"{'='*70}\n")

    # 1. Installed packages (non-Microsoft)
    print("[1/8] Scanning installed packages...")
    pkgs = get_non_microsoft_packages()
    flags = flag_suspicious(pkgs, SUSPICIOUS_PATTERNS)
    sections.append("── INSTALLED PACKAGES (non-Microsoft/Windows) ──")
    sections.append(pkgs)
    if flags:
        sections.append("\n⚠️  SUSPICIOUS MATCHES:")
        sections.extend(flags)
    sections.append("")

    # 2. Running services
    print("[2/8] Scanning running services...")
    svcs = get_services()
    flags = flag_suspicious(svcs, SUSPICIOUS_PATTERNS)
    sections.append("── RUNNING SERVICES (non-Microsoft/Windows) ──")
    sections.append(svcs)
    if flags:
        sections.append("\n⚠️  SUSPICIOUS MATCHES:")
        sections.extend(flags)
    sections.append("")

    # 3. Scheduled tasks
    print("[3/8] Scanning scheduled tasks...")
    tasks = get_scheduled_tasks()
    flags = flag_suspicious(tasks, SUSPICIOUS_TASK_PATTERNS)
    sections.append("── SCHEDULED TASKS (non-Microsoft) ──")
    sections.append(tasks)
    if flags:
        sections.append("\n⚠️  SUSPICIOUS MATCHES:")
        sections.extend(flags)
    sections.append("")

    # 4. Startup items
    print("[4/8] Scanning startup items...")
    startup = get_startup_items()
    sections.append("── STARTUP ITEMS ──")
    sections.append(startup)
    sections.append("")

    # 5. Network connections
    print("[5/8] Scanning active connections...")
    conns = get_established_connections()
    sections.append("── ACTIVE NETWORK CONNECTIONS (ESTABLISHED) ──")
    sections.append(conns)
    sections.append("")

    # 6. Browser extensions
    print("[6/8] Scanning Chrome extensions...")
    chrome_ext = get_browser_extensions_chrome()
    sections.append("── CHROME EXTENSIONS ──")
    sections.append(chrome_ext)
    flags = flag_suspicious(chrome_ext, SUSPICIOUS_PATTERNS)
    if flags:
        sections.append("\n⚠️  SUSPICIOUS MATCHES:")
        sections.extend(flags)
    sections.append("")

    print("[7/8] Scanning Firefox extensions...")
    ff_ext = get_browser_extensions_firefox()
    sections.append("── FIREFOX EXTENSIONS ──")
    sections.append(ff_ext)
    flags = flag_suspicious(ff_ext, SUSPICIOUS_PATTERNS)
    if flags:
        sections.append("\n⚠️  SUSPICIOUS MATCHES:")
        sections.extend(flags)
    sections.append("")

    # 7. Proxy settings
    print("[8/8] Checking proxy settings...")
    proxy = get_proxy_settings()
    sections.append("── SYSTEM PROXY SETTINGS ──")
    sections.append(proxy)
    sections.append("")

    # Footer
    sections.append(f"{'='*70}")
    sections.append("  END OF REPORT")
    sections.append("  Paste this into an AI chat and ask:")
    sections.append('  "Review this security report. Flag anything suspicious."')
    sections.append(f"{'='*70}")

    return "\n".join(sections)


def delete_package(name: str):
    print(f"Attempting to uninstall: {name}")
    result = run_ps(f'Get-Package -Name "*{name}*" | Uninstall-Package -Force')
    print(result if result else "Uninstall command completed (no output = success)")


def kill_task(name: str):
    print(f"Stopping and removing scheduled task: {name}")
    run_ps(f'Stop-ScheduledTask -TaskName "{name}" -ErrorAction SilentlyContinue')
    result = run_ps(f'Unregister-ScheduledTask -TaskName "{name}" -Confirm:$false')
    print(result if result else "Task removed successfully")


def delete_folder(path: str):
    print(f"Deleting folder: {path}")
    result = run_ps(f'Remove-Item "{path}" -Recurse -Force')
    print(result if result else "Folder deleted successfully")


def main():
    parser = argparse.ArgumentParser(description="System Security Check Tool")
    parser.add_argument("--delete", metavar="PACKAGE", help="Uninstall a package by name")
    parser.add_argument("--kill-task", metavar="TASK", help="Remove a scheduled task")
    parser.add_argument("--delete-folder", metavar="PATH", help="Delete a folder recursively")
    args = parser.parse_args()

    # Action modes
    if args.delete:
        delete_package(args.delete)
        return
    if args.kill_task:
        kill_task(args.kill_task)
        return
    if args.delete_folder:
        delete_folder(args.delete_folder)
        return

    # Report mode
    print("Starting system security scan...\n")
    report = build_report()

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\n✅ Report saved to: {os.path.abspath(REPORT_FILE)}")
    print(f"   Paste it into any AI chat for review.\n")
    print(report)


if __name__ == "__main__":
    main()
