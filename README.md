# AntiVirusLocal — System Security Check

A single-file Windows desktop app that scans your PC for **bandwidth-selling
proxyware, PUPs, adware, and crypto miners** running quietly in the background —
then lets you export a plain-text report to paste into any AI chat for a second
opinion, and uninstall or kill what looks suspicious.

It was built after finding a real bandwidth-thief app (Infatica P2B) running
silently on a machine. The goal: surface that class of software fast, get an
outside read on it, and remove it.

![App icon](SystemSecurityCheck.png)

## Features

- **Read-only scan** of installed packages, running services, scheduled tasks,
  startup items, active TCP connections (remote IP + owning process), Chrome &
  Firefox extensions, and proxy settings — all off the UI thread.
- **Heuristic flagging** against a curated list of known proxyware (Honeygain,
  Peer2Profit, IPRoyal, Bright Data…), adware/PUPs, miners (xmrig, NiceHash…),
  and remote-access tools. Flagged rows render red and the UI jumps to them.
- **One-click export** to a `.txt` report that ends with a prompt asking an AI
  to review it — see [`sample_report.txt`](sample_report.txt) for the format.
- **Guided removal** behind a confirmation dialog: multi-step uninstall (normal
  → vendor uninstaller → ghost-registry cleanup → leftover folders → related
  tasks → verify), plus standalone *Kill Task* and folder deletion.

See [CHANGELOG.md](CHANGELOG.md) for the version history and engineering notes.

## Scope & trust model (by design)

This is a **single-operator local admin tool**, and that scope is deliberate:

- **Windows-only** — it drives everything through PowerShell, the Win32 registry,
  and `Get-ScheduledTask`.
- **Runs as Administrator** — uninstalling packages, editing HKLM, and
  unregistering tasks all require elevation. Without it, actions report
  "Access denied".
- **Removal is destructive and irreversible** — registry keys, folders, and
  scheduled tasks are deleted with `-Force`, only after a confirm dialog.
- **It interpolates the operator's input into PowerShell commands.** That is safe
  for its intended use — one trusted person acting on their own machine — but it
  is *not* hardened against untrusted input. Don't expose it to one.

Flagging is a **hint, not a verdict**: patterns are substring matches, and
legitimate tools (AnyDesk, RustDesk…) are flagged on purpose so you can decide.

## Run

```powershell
pip install -r requirements.txt
# Launch as Administrator for full scan/removal coverage
python system_security_check.py
```

## Build (optional)

A standalone executable is produced with [PyInstaller](https://pyinstaller.org/):

```powershell
pip install pyinstaller
pyinstaller --onefile --windowed --icon SystemSecurityCheck.ico system_security_check.py
```

The code resolves bundled resources via `sys.frozen` / `sys._MEIPASS`, so the
icon works both from source and in the packaged build.

## Tech stack

Python 3.12 · PyQt6 · PowerShell (system queries & actions) · PyInstaller (build)

## Layout

- `system_security_check.py` — the entire app (single file).
- `version_control/` — prior versions (V1.0 → V2.2) kept as plain snapshots.
- `sample_report.txt` — sanitized example of an exported report.
- `SystemSecurityCheck.ico` / `.png` — app icon.

## License

MIT — see [LICENSE](LICENSE).
