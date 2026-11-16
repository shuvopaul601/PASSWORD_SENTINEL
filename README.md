# Password Sentinel 3.1

**A professional desktop password-assessment and authorized audit-preparation suite.**

Password Sentinel combines a password-strength analyzer, Have I Been Pwned Pwned Passwords lookup, custom candidate-list generator, batch assessment workflow, and local assessment history in a modern PyQt6 desktop interface. The analysis engine and command-line interface remain available independently of the GUI.

> **Authorized use only.** Assess passwords you own or systems for which you have explicit permission. Keep generated candidate lists within the approved audit scope.

## What's new in 3.1

- Fixed opaque label backgrounds that caused black text strips inside cards.
- Added resizable scroll containers to every workspace so content remains accessible when maximizing, restoring, or resizing the window.
- Improved input sizing and scrollbar styling for more consistent Windows display behavior.
- Reduced the minimum window size to support smaller displays.

## What's new in 3.0

- Modern PyQt6 interface with a dark navy / teal security-product design.
- Sidebar navigation and dedicated Overview, Password Analyzer, Wordlist Lab, Batch Audit, History, and Settings pages.
- Live password-strength feedback and detailed attack-scenario estimates.
- Optional Have I Been Pwned check using the Pwned Passwords k-anonymity range API.
- Background workers for network lookups, wordlist generation, and batch assessments so the interface remains responsive.
- Local SQLite assessment history. **Plaintext passwords are not stored**; history retains a truncated SHA-256 fingerprint and assessment metadata only.
- Exportable assessment text reports and batch CSV reports.
- Existing CLI commands and analysis / wordlist engines retained.

## Requirements

- Python 3.10 or newer recommended.
- PyQt6 for the desktop GUI.
- `zxcvbn` for pattern-aware strength estimation (the engine has an entropy fallback).
- `requests` for the optional breach lookup.

## Installation

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Linux / macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Launch the desktop application

```bash
python cli.py gui
```

Or launch directly:

```bash
python gui.py
```

## Desktop modules

### Overview

Displays assessment totals, average score, known breach-hit totals, and recent assessment metadata.

### Password Analyzer

- Live strength estimate while typing.
- Optional personal-context terms for dictionary matching.
- Full assessment with score, guessability-derived entropy estimate, and attack-scenario crack-time table.
- Optional breach lookup.
- Exportable text assessment report.

### Wordlist Lab

- Seed-based candidate generation.
- Configurable year, leetspeak, prefix/suffix, and pair-combination mutations.
- Minimum / maximum length and candidate-count cap.
- Preview and TXT export.

### Batch Audit

- Load a local newline-delimited text file.
- Assess each entry in a background worker.
- Mask values in the results table by default.
- Export CSV results.

### Assessment History

- Local SQLite record of assessment metadata.
- Stores a truncated SHA-256 fingerprint, not the plaintext password.
- Clear-history control.

## CLI usage

Analyze a password (prompts securely if `-p` is omitted):

```bash
python cli.py analyze
python cli.py analyze -p "Example-Passphrase" -u ExampleName
python cli.py analyze -p "Example-Passphrase" --check-pwned
```

Analyze many passwords from a file:

```bash
python cli.py batch passwords.txt --mask
```

Generate a candidate list for an authorized audit:

```bash
python cli.py wordlist -i "ExampleName" -i "ExamplePet" -o candidates.txt --stats
```

## Data and privacy

The GUI stores its local history database at:

```text
~/.password_sentinel/history.sqlite3
```

The database stores a truncated SHA-256 fingerprint and assessment metadata. It does not store plaintext passwords. Assessment reports and batch exports are written only when the user explicitly chooses an export path. The optional Pwned Passwords lookup sends only the first five hexadecimal characters of the password's SHA-1 hash to the service; the full password is not sent.

If a batch CSV is exported with masking disabled in the GUI, the export contains the original password values. Treat such exports as sensitive and store them securely.

## Estimation notes

Crack-time outputs are model-based estimates, not guarantees. Actual attack feasibility depends on the password-hashing algorithm, salts, rate limits, hardware, attacker resources, password reuse, and other controls. zxcvbn's guessability-derived estimate should not be interpreted as a direct measurement of random entropy.

## Project files

- `gui.py` — PyQt6 desktop interface.
- `strength.py` — password-strength analysis and breach lookup.
- `wordlist.py` — candidate-list generation and statistics.
- `cli.py` — command-line interface.
- `requirements.txt` — Python dependencies.

## Cross-platform support (Windows, Linux, macOS)

This release is **Password Sentinel only**. It does not modify or package SentryShield.

The Python/PyQt6 source is designed to run on Windows 10/11, current mainstream Linux desktop distributions, and macOS. Use Python 3.10+ and install dependencies separately on each operating system.

### Quick launchers

- **Windows:** double-click `launch_windows.bat` (or run it from Command Prompt).
- **Linux:** run `chmod +x launch_linux.sh` once, then `./launch_linux.sh`.
- **macOS:** right-click `launch_macos.command` → Open the first time if Gatekeeper asks, or run `chmod +x launch_macos.command && ./launch_macos.command` in Terminal.

Each launcher creates a project-local `.venv`, installs `requirements.txt`, and starts the GUI. A working Python 3.10+ installation is required. On Linux, a Qt platform plugin / display server is required; this is a desktop GUI, not a headless service.

### Build a native desktop app

The packaged desktop executable launches directly into the GUI; `cli.py` remains available for command-line use from Python. PyInstaller builds must be run on the target operating system (build Windows on Windows, Linux on Linux, and macOS on macOS). The packaging scripts are:

- Windows: `packaging\\build_windows.bat` — creates `dist\\PasswordSentinel\\PasswordSentinel.exe` and its supporting files.
- Linux: `bash packaging/build_linux.sh` — creates `dist/PasswordSentinel/PasswordSentinel` and its supporting files.
- macOS: `bash packaging/build_macos.sh` — creates `dist/PasswordSentinel.app`.

The `.github/workflows/build.yml` workflow can build all three platforms on GitHub Actions. Push a `v*` tag or manually run the workflow from the Actions tab; download the three platform artifacts from the workflow run. Builds are not code-signed or notarized; macOS may show Gatekeeper warnings until you sign/notarize the app with an Apple Developer identity.

### Per-user history location

The SQLite history database is stored in the standard per-user application-data location:

- Windows: `%LOCALAPPDATA%\\PasswordSentinel\\history.sqlite3`
- macOS: `~/Library/Application Support/PasswordSentinel/history.sqlite3`
- Linux: `$XDG_DATA_HOME/password-sentinel/history.sqlite3` (defaults to `~/.local/share/password-sentinel/history.sqlite3`)

The database remains local to the current OS user. Existing v3.1 Windows history in `~/.password_sentinel/history.sqlite3` is not automatically migrated; copy it manually only if you want to preserve it, and back it up first.
