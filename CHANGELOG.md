# Changelog

All notable changes to AntiVirusLocal: System Security Check.

## V2.3: current

- Multi-step uninstall pipeline: normal uninstall → vendor uninstaller (silent
  flags) → ghost-registry cleanup across the three Uninstall hives → leftover
  folder deletion in Program Files / AppData / ProgramData → related scheduled
  task removal → final verify, with a per-step summary in the result message.
- Export report jumps the UI to the first flagged tab and lists every flagged
  item in the Log tab.
- Polished dark theme and per-category tabs (Packages, Services, Tasks, Startup,
  Connections, Chrome/Firefox extensions, Proxy, Log).

## V2.2

- Right-click "Copy name to action bar" on any row to stage it for Uninstall /
  Kill Task without retyping.
- Hardened the PowerShell runners with timeouts and structured error rows
  (`_error` / `_raw`) so a failed or slow query shows up in the UI instead of
  hanging the scan.

## V2.1

- Browser-extension scanning for Chrome and Firefox, read straight from the
  on-disk extension manifests / `extensions.json` (handles `__MSG_` localized
  names and de-duplicates Firefox add-ons across profiles).
- Active TCP connection scan resolves the owning process name per connection.

## V2.0: GUI rewrite

- Rewrote the V1.0 command-line script as a **PyQt6 desktop app**. Scans run in
  a background `QThread` and stream results into the UI per section; removal
  actions run in their own thread behind a confirmation dialog.
- Suspicious rows render red/bold against the `SUSPICIOUS_PATTERNS` /
  `SUSPICIOUS_TASK_PATTERNS` lists.

## V1.0: initial CLI

- Command-line script that scanned the system and wrote `security_report.txt`
  for AI-assisted review, with `--delete`, `--kill-task`, and `--delete-folder`
  flags for manual cleanup.
