# AntiVirusLocal: System Security Check

A single-file Windows desktop app that scans your PC for **bandwidth-selling
proxyware, PUPs, adware, and crypto miners** running quietly in the background,
flags the suspects, and lets you remove them. Built after finding a real
bandwidth-thief app (Infatica P2B) running silently on a machine.

<img width="957" height="702" alt="AV_Main" src="https://github.com/user-attachments/assets/3be8e03b-dd66-4f9e-96e2-d4e5ee1bafda" />

**Tech:** Python 3.12 · PyQt6 · PowerShell · PyInstaller

## Run

```powershell
pip install -r requirements.txt
# Run as Administrator for full scan/removal coverage
python system_security_check.py
```

## What it does

- **Scans** (read-only, off the UI thread) installed packages, services,
  scheduled tasks, startup items, active TCP connections, browser extensions,
  and proxy settings.
- **Flags** matches against a curated list of known proxyware, adware/PUPs,
  miners, and remote-access tools. Suspect rows turn red and the UI jumps to them.
- **Exports** an AI-reviewable `.txt` report (see [`sample_report.txt`](sample_report.txt)).
- **Removes** suspects behind a confirm dialog: multi-step uninstall, *Kill Task*,
  and leftover-folder cleanup.

See [CHANGELOG.md](CHANGELOG.md) for the version history and engineering notes.

## Scope (by design)

A **single-operator local admin tool**: Windows-only, runs as Administrator, and
removal is destructive (registry/folders/tasks deleted with `-Force`). It
interpolates the operator's input into PowerShell, safe for one trusted user on
their own machine, not hardened against untrusted input. Flagging is a hint, not
a verdict (substring matches; legit tools like AnyDesk are flagged on purpose).

## License

MIT: see [LICENSE](LICENSE). Copyright (c) 2026 Can KADILAR.
