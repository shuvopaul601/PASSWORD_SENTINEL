================================================================================
                         PASSWORD SENTINEL 3.2.0
             CROSS-PLATFORM PASSWORD ASSESSMENT TOOLKIT
================================================================================

PROJECT OVERVIEW
----------------
Password Sentinel is a desktop and command-line application for evaluating
password strength and preparing bounded candidate wordlists for authorized
password-audit exercises. It is a standalone project.

The application provides:
  1. A PyQt6 desktop interface with a dark navy / teal design.
  2. Password-strength analysis using zxcvbn when installed, with an entropy-
     based fallback when zxcvbn is unavailable.
  3. Optional Have I Been Pwned (HIBP) Pwned Passwords lookup using the
     k-anonymity range API.
  4. Custom candidate-wordlist generation from user-provided seed terms.
  5. Batch assessment of passwords loaded from a local text file.
  6. Local SQLite assessment history for single-password assessments.
  7. Text and CSV export options.
  8. A command-line interface (CLI), separate from the graphical interface.
  9. Launch scripts and PyInstaller build scripts for Windows, Linux and macOS.

IMPORTANT: The project source is cross-platform. The ZIP contains source code
and build scripts, not prebuilt, signed installers for all operating systems.
Native application packages must be built on their target operating system or
obtained as CI artifacts from the configured GitHub Actions workflow.


1. SYSTEM REQUIREMENTS
----------------------
Recommended:
  - Python 3.10 or newer.
  - Windows 10/11, a current mainstream Linux desktop distribution, or macOS.
  - Internet access only for installing dependencies and using the optional
    HIBP breach lookup.
  - A graphical desktop session for the PyQt6 GUI.

Python packages (listed in requirements.txt):
  - PyQt6       Desktop graphical interface.
  - zxcvbn      Pattern-aware password-strength estimator.
  - requests    HTTP client used by the optional HIBP lookup.

The analysis engine can fall back to a basic entropy estimator if zxcvbn is not
available. The GUI requires PyQt6. The optional HIBP lookup requires requests
and a working internet connection.

Linux note: This is a graphical desktop application, not a headless service.
A working display session and compatible Qt platform libraries are required.
If PyQt6 reports a missing Qt platform plugin, install the Qt/desktop runtime
packages recommended for your Linux distribution and Python installation.


2. PROJECT DIRECTORY STRUCTURE
-------------------------------
After extracting the ZIP, the project directory contains:

  cli.py
      Main command-line entry point. Supports analyze, batch, wordlist and gui.

  gui.py
      PyQt6 desktop application. Contains the navigation, workspaces, local
      history database integration, background workers and export workflows.

  gui_entry.py
      Small GUI-only entry point used by PyInstaller to package the desktop app.

  strength.py
      Password-strength analysis, attack-scenario estimates and HIBP lookup.

  wordlist.py
      Candidate generation, transformations, length filtering and export.

  requirements.txt
      Python package dependencies required by the application.

  launch_windows.bat
      Windows setup-and-launch script. Creates a local virtual environment,
      installs dependencies and starts the GUI.

  launch_linux.sh
      Linux setup-and-launch script. Creates a local virtual environment,
      installs dependencies and starts the GUI.

  launch_macos.command
      macOS setup-and-launch script. Creates a local virtual environment,
      installs dependencies and starts the GUI.

  packaging/build_windows.bat
      Builds a Windows GUI application folder with PyInstaller.

  packaging/build_linux.sh
      Builds a Linux GUI application folder with PyInstaller.

  packaging/build_macos.sh
      Builds a macOS .app bundle with PyInstaller.

  .github/workflows/build.yml
      GitHub Actions workflow that builds separate Windows, Linux and macOS
      artifacts when manually started or when a v* tag is pushed.

  CHANGELOG_3.1.0.txt
      Notes about the 3.1 UI changes included in this codebase.


3. INSTALLATION AND FIRST LAUNCH
---------------------------------
IMPORTANT: Extract the ZIP completely before running any launcher. Do not run
scripts from inside the ZIP preview window. Run the commands from the extracted
project directory so that the scripts can find cli.py and requirements.txt.

A. WINDOWS 10 / 11

Option 1 - Easy launcher:
  1. Install Python 3.10 or newer from https://www.python.org/downloads/windows/.
  2. During installation, enable the option to add Python to PATH.
  3. Extract the Password Sentinel ZIP to a normal folder, for example:
       C:\Tools\PasswordSentinel
  4. Open the extracted folder.
  5. Double-click launch_windows.bat.
  6. The script checks Python, creates a .venv folder if needed, activates it,
     upgrades pip, installs requirements.txt and launches the GUI.
  7. The first launch requires internet access to download Python packages.

Option 2 - Manual PowerShell installation:
  1. Open PowerShell in the extracted project folder.
  2. Create a virtual environment:
       py -3 -m venv .venv
  3. Activate it:
       .venv\Scripts\Activate.ps1
  4. Upgrade pip and install dependencies:
       python -m pip install --upgrade pip
       python -m pip install -r requirements.txt
  5. Start the GUI:
       python cli.py gui

If PowerShell blocks activation, you can use Command Prompt instead:
       .venv\Scripts\activate.bat
       python -m pip install -r requirements.txt
       python cli.py gui

B. LINUX

1. Install Python 3.10+, pip and the venv support package using your
   distribution's package manager. Package names differ by distribution.
2. Extract the ZIP and open a terminal in the ps_cross project directory.
3. Make the launcher executable:
       chmod +x launch_linux.sh
4. Run it:
       ./launch_linux.sh
5. The launcher creates .venv, installs requirements and starts the GUI.

Manual Linux installation:
       python3 -m venv .venv
       source .venv/bin/activate
       python -m pip install --upgrade pip
       python -m pip install -r requirements.txt
       python cli.py gui

If the system says that venv or ensurepip is unavailable, install the Python
venv package for your distribution and repeat the commands. If Qt cannot open
a display, confirm that you are running inside a graphical desktop session.

C. macOS

1. Install Python 3.10+ from https://www.python.org/downloads/macos/ or use a
   trusted package manager.
2. Extract the ZIP to a normal folder.
3. Open Terminal and change directory to the extracted ps_cross folder.
4. Make the launcher executable and run it:
       chmod +x launch_macos.command
       ./launch_macos.command
5. The script creates .venv, installs dependencies and starts the GUI.

If macOS Gatekeeper prevents the first launch of the .command file, open
Terminal and run the commands above from the extracted project directory.
You can also right-click the file and choose Open if macOS presents that option.

Manual macOS installation:
       python3 -m venv .venv
       source .venv/bin/activate
       python -m pip install --upgrade pip
       python -m pip install -r requirements.txt
       python cli.py gui


4. USING THE DESKTOP APPLICATION
---------------------------------
Start the application using the operating-system launcher or:
       python cli.py gui

The left sidebar contains six workspaces. Select a workspace to open it.

4.1 OVERVIEW

Purpose:
  The Overview page provides a summary of locally recorded assessments and
  quick navigation to the main tasks.

Typical information shown:
  - Assessments stored: number of single-password assessments in local history.
  - Average score: average score of the saved assessments, on a 0-4 scale.
  - Known breach hits: total breach occurrences recorded from completed HIBP
    checks in saved assessment history.
  - Last wordlist: number of candidates generated in the most recent wordlist
    generation during the current application session.

Quick actions:
  - Analyze a password: opens Password Analyzer.
  - Open Wordlist Lab: opens Wordlist Lab.
  - Start batch audit: opens Batch Audit.

The Overview is a dashboard. It does not itself scan files or network systems.

4.2 PASSWORD ANALYZER

Purpose:
  Assess one password and review its estimated strength and attack resistance.

Steps:
  1. Open Password Analyzer from the sidebar.
  2. Enter the password in the target credential field.
  3. Use the Show password control only when it is safe to reveal the value on
     your screen. Hide it again when finished.
  4. Optionally enter personal-context terms, separated by commas. Examples
     include a name, pet name, organization or memorable date. These terms are
     used as dictionary context by zxcvbn when that estimator is available.
  5. Select RUN FULL ASSESSMENT.
  6. Review the strength verdict, score, estimated entropy, fast-hash estimate,
     analysis method, strength profile, attack-scenario estimates and feedback.
  7. To check known breach exposure, select CHECK BREACH DATABASE. This action
     requires internet access.
  8. To save a text report, select EXPORT REPORT and choose a destination.

Score interpretation:
  0 = Very Weak
  1 = Weak
  2 = Fair
  3 = Strong
  4 = Very Strong

Analysis method:
  - zxcvbn: pattern-aware estimator that considers common passwords,
    dictionary patterns, sequences and other guessability patterns.
  - entropy fallback: used if zxcvbn is unavailable. It estimates from the
    character pool and password length; it is less pattern-aware.

Attack-scenario table:
  The tool displays modelled estimates for throttled online guessing,
  unthrottled online guessing, a slow offline hash scenario and a fast offline
  hash/GPU scenario. These are illustrative models, not predictions of a real
  attack against a particular service or hash database.

HIBP breach check:
  The optional Pwned Passwords range lookup uses the k-anonymity model. The
  application calculates the password's SHA-1 hash locally and sends only the
  first five hexadecimal characters of that hash to the service. The complete
  password and complete SHA-1 hash are not sent by this range-query design.
  The returned suffix list is checked locally. A match count indicates how
  often that hash appeared in the queried breach corpus; it does not prove that
  a particular account is currently compromised. A no-match result does not
  prove that a password has never been exposed.

4.3 WORDLIST LAB

Purpose:
  Generate a bounded text list of password candidates from seed terms for
  controlled, authorized password-audit exercises.

Steps:
  1. Open Wordlist Lab.
  2. Enter one or more seed values in the input field, separated by commas.
     Examples for a test lab might be a fictional user name, fictional pet name
     or a date created for the exercise. Avoid entering sensitive personal
     information unless you have a clear, authorized reason.
  3. Configure the generation options:
       Include year patterns:
         Adds year-based variations using a range ending at the current year.
       Include leetspeak:
         Adds bounded substitutions such as a->4/@, e->3 and o->0.
       Include prefixes/suffixes:
         Adds configured common symbols and number patterns before or after
         generated terms.
       Combine input pairs:
         Combines pairs of seed tokens in different orders and separators.
       Minimum length / Maximum length:
         Filters candidates by character count.
       Candidate limit:
         Caps the number of generated candidates. The default engine limit is
         200,000 candidates.
  4. Select GENERATE CANDIDATES.
  5. Review the candidate count, length range and preview list.
  6. Select SAVE WORDLIST (.TXT) and choose where to save the text file.

The generator cleans and tokenizes the supplied values, creates case variants,
optionally generates leetspeak substitutions, combines pairs, applies year and
prefix/suffix patterns, removes duplicates, filters by length and applies the
candidate cap. The output is a plain UTF-8 text file with one candidate per line.

Use this feature only for password-strength testing in a lab or against accounts
and systems for which you have explicit written authorization. Do not use the
output to attempt access to third-party accounts or services.

4.4 BATCH AUDIT

Purpose:
  Assess multiple password entries from a local text file.

Prepare the input file:
  - Create a UTF-8 .txt file.
  - Put one password on each line.
  - Remove entries that are blank or outside the approved test scope.
  - Protect the file because it contains credential material in plaintext.

Steps:
  1. Open Batch Audit.
  2. Select LOAD PASSWORD FILE.
  3. Choose the prepared .txt file.
  4. Confirm that the displayed filename and record count are expected.
  5. Leave the masking option enabled where possible.
  6. Select RUN BATCH AUDIT.
  7. Wait for the progress indicator to finish.
  8. Review the result table and summary counts for total, strong and weak
     entries.
  9. Select EXPORT CSV to save the results if required.

Masking:
  When masking is enabled, the table/export displays the first two characters
  followed by masking symbols. When masking is disabled, the original values
  can appear in the table and exported CSV. Treat unmasked output as highly
  sensitive and store it securely.

Batch assessments are held in the current application session for display and
CSV export. They are not automatically inserted into the single-assessment
SQLite history table by this workflow.

4.5 ASSESSMENT HISTORY

Purpose:
  Review metadata from saved single-password assessments.

The history table can display timestamp, truncated SHA-256 fingerprint,
password length, score, verdict, estimated entropy, estimated crack time,
analysis method and breach count. Use REFRESH to reload the table.

Use CLEAR HISTORY to delete all locally stored assessment metadata. The
application asks for confirmation before deletion. Clearing history cannot be
undone unless you have made a backup of the database.

Privacy detail:
  The application does not store the original plaintext password in this
  history database. It stores a 16-character prefix of the password's SHA-256
  fingerprint and assessment metadata. A hash fingerprint is not the password,
  but it is still derived from the password and should be treated as sensitive
  metadata. Do not publish or share the history database unnecessarily.

4.6 SETTINGS & ABOUT

Purpose:
  Provides application information, privacy notes and the current local
  history database path. Refer to this page to identify where local assessment
  history is stored on the current operating system.


5. COMMAND-LINE INTERFACE (CLI)
--------------------------------
The CLI can be used without opening the desktop GUI. Run commands from the
project directory with the virtual environment activated.

Show command help:
       python cli.py --help
       python cli.py analyze --help
       python cli.py batch --help
       python cli.py wordlist --help

5.1 ANALYZE ONE PASSWORD

Prompt securely (input is hidden while typing):
       python cli.py analyze

Analyze a supplied password:
       python cli.py analyze -p "Example-Passphrase"

Add personal context terms (repeat -u for each term):
       python cli.py analyze -p "Example-Passphrase" -u ExampleName -u ExamplePet

Also query the HIBP Pwned Passwords service:
       python cli.py analyze -p "Example-Passphrase" --check-pwned

Security note: Supplying a password with -p may expose it in shell history,
process listings or terminal logs depending on the operating system and shell.
For interactive use, prefer running analyze without -p so getpass can hide the
input.

5.2 BATCH ANALYSIS

Analyze a text file containing one password per line:
       python cli.py batch passwords.txt --mask

Add personal context terms:
       python cli.py batch passwords.txt --mask -u ExampleName

Request HIBP checks for each entry (requires network access):
       python cli.py batch passwords.txt --mask --check-pwned

The CLI prints a table with score, verdict, entropy estimate and fast-hash
crack-time estimate. Use --mask to avoid printing complete password values.
The CLI batch command does not automatically write a CSV file or save each
entry to the GUI's SQLite history.

5.3 GENERATE A WORDLIST

Generate candidates from seed terms and save them to a file:
       python cli.py wordlist -i "ExampleName" -i "ExamplePet" -o candidates.txt

Show summary statistics:
       python cli.py wordlist -i "ExampleName" -i "ExamplePet" -o candidates.txt --stats

Useful options:
       --no-years          Disable year patterns.
       --year-span 10      Use a 10-year range instead of the default 30.
       --no-leet           Disable leetspeak variants.
       --no-suffixes       Disable configured prefixes and suffixes.
       --no-combine        Disable pairwise seed combinations.
       --min-length 8      Set minimum candidate length.
       --max-length 24     Set maximum candidate length.
       --limit 50000       Limit output to 50,000 candidates.

Example with custom limits:
       python cli.py wordlist -i "ExampleName" -i "ExamplePet" \
         --min-length 8 --max-length 24 --limit 50000 \
         -o candidates.txt --stats


6. LOCAL DATA, PRIVACY AND FILES
---------------------------------
The GUI stores its SQLite history database in the current user's application
-data directory:

  Windows:
    %LOCALAPPDATA%\PasswordSentinel\history.sqlite3

  macOS:
    ~/Library/Application Support/PasswordSentinel/history.sqlite3

  Linux:
    $XDG_DATA_HOME/password-sentinel/history.sqlite3
    If XDG_DATA_HOME is not set, the default is:
    ~/.local/share/password-sentinel/history.sqlite3

The database is created automatically the first time the GUI starts.

Password handling summary:
  - Single-password assessment runs locally unless the optional HIBP lookup is
    requested.
  - The history database stores a truncated SHA-256 fingerprint and metadata,
    not the original plaintext password.
  - The optional HIBP range lookup sends only the first five characters of the
    SHA-1 hash, not the complete password.
  - The batch input file itself contains plaintext passwords and remains the
    user's responsibility.
  - Wordlist files, text reports and CSV exports are created only when the
    user chooses an export path. They may contain sensitive values.
  - Batch CSV exports can contain original password values if masking is off.

Protect input files, generated lists, reports, exports and database backups.
Delete sensitive temporary files securely according to your organization's
policy. Do not upload real credentials to public repositories or issue trackers.


7. BUILDING NATIVE DESKTOP APPLICATIONS
----------------------------------------
The packaging scripts use PyInstaller. Build on the operating system for which
you want to create the application. PyInstaller is not a universal cross-
compiler: a Windows build should be produced on Windows, a Linux build on Linux,
and a macOS build on macOS.

Before building, install Python 3.10+ and open a terminal in the project folder.

A. WINDOWS BUILD
  Run from Command Prompt:
       packaging\build_windows.bat
  The script installs the project dependencies and PyInstaller, then creates:
       dist\PasswordSentinel\PasswordSentinel.exe
  The folder contains supporting runtime files as well. Distribute the entire
  PasswordSentinel folder, not only the EXE.

B. LINUX BUILD
  Run:
       chmod +x packaging/build_linux.sh
       bash packaging/build_linux.sh
  Output:
       dist/PasswordSentinel/PasswordSentinel
  The output is a folder containing the executable and its supporting files.
  It is not an AppImage or DEB/RPM package in the current configuration.

C. macOS BUILD
  Run:
       bash packaging/build_macos.sh
  Output:
       dist/PasswordSentinel.app
  The app bundle is not signed or notarized by the provided script. Gatekeeper
  may warn when opening it. For public distribution, sign and notarize it using
  an appropriate Apple Developer identity and current Apple requirements.


8. AUTOMATED BUILDS WITH GITHUB ACTIONS
----------------------------------------
The repository includes .github/workflows/build.yml. It defines separate build
jobs for Windows, Ubuntu Linux and macOS.

To use it:
  1. Create a Git repository for this Password Sentinel project, if needed.
  2. Push the project files to GitHub.
  3. Open the repository's Actions tab and enable Actions if prompted.
  4. Select the "Build desktop apps" workflow.
  5. Select Run workflow for a manual build, or push a version tag beginning
     with v (for example v3.2.0) to trigger the workflow.
  6. Open the completed workflow run.
  7. Download the artifacts named PasswordSentinel-Windows,
     PasswordSentinel-Linux and PasswordSentinel-macOS.

These artifacts are build outputs, not signed/notarized releases. Review and
smoke-test each artifact on its target OS before distributing it. The workflow
uses GitHub-hosted runners and the dependency versions allowed by
requirements.txt at build time.


9. TROUBLESHOOTING
-------------------
"python" or "python3" not found:
  Install Python 3.10+ and ensure it is available in PATH. On Windows, try
  "py -3". On Linux/macOS, try "python3 --version".

Virtual environment creation fails:
  Confirm that Python's venv support is installed. On some Linux distributions
  it is provided as a separate system package.

Dependency installation fails:
  Confirm internet access, update pip, and retry:
       python -m pip install --upgrade pip
       python -m pip install -r requirements.txt

GUI does not open:
  Activate the project's virtual environment and run:
       python cli.py gui
  Read the terminal error. Confirm PyQt6 installed successfully and that the
  computer has a graphical desktop session. On Linux, check Qt platform plugin
  and display-server dependencies.

HIBP lookup fails:
  Confirm internet access and retry later. A firewall, proxy, DNS issue or
  service outage can prevent the request. A failed lookup is not the same as
  a clean breach result.

Application starts but history is empty:
  History is per operating-system user and stored in that user's application
  data directory. Previous history from an older release or a different OS
  location is not automatically migrated. Check the database path shown in
  Settings & About and back up any database before copying or replacing it.

Linux/macOS launcher permission denied:
       chmod +x launch_linux.sh
  or:
       chmod +x launch_macos.command

Native build cannot find PyInstaller:
  The packaging scripts install PyInstaller. If running manually, install it:
       python -m pip install pyinstaller


10. LIMITATIONS AND INTERPRETATION
-----------------------------------
  - Strength scores and crack-time estimates are heuristic/model outputs, not
    guarantees. Real attack feasibility depends on the hash algorithm, salt,
    rate limits, hardware, attacker resources, password reuse and other controls.
  - Entropy shown from zxcvbn is derived from its guessability estimate; it is
    not a direct measurement of independently generated random entropy.
  - The fallback entropy calculation is less capable of identifying human
    patterns than zxcvbn.
  - HIBP results refer to the queried breach corpus and do not establish the
    status of a specific account.
  - Wordlist generation creates candidate strings; it does not test logins,
    crack password hashes or validate whether a candidate is correct.
  - Batch audit reads a local text file; it is not a remote account scanner.
  - Cross-platform source support does not mean every OS build has been tested
    on every hardware configuration or Linux distribution.
  - Current PyInstaller scripts create application folders/bundles; they do
    not create a Windows installer, Linux AppImage/DEB/RPM, or signed macOS DMG.


11. RESPONSIBLE AND AUTHORIZED USE
-----------------------------------
Password Sentinel is intended for personal password hygiene, controlled
security education, and password-strength audits that you are authorized to
perform. Use it only with passwords you own or with explicit permission from
the relevant account owner or system owner. Do not use generated candidate
lists to attempt unauthorized access, credential stuffing or password attacks.
Follow applicable laws, contracts and organizational security policies.


12. VERSION AND PROJECT NOTES
------------------------------
Project name: Password Sentinel
Package edition: Cross-Platform source package
Package version label: 3.2.0
Desktop GUI version constant in this source: 3.1.0
Primary language: Python
Desktop framework: PyQt6
Local database: SQLite
Packaging: PyInstaller
Supported target platforms: Windows, Linux and macOS (source/build workflow)

The package version and the GUI's internal APP_VERSION constant are separate in
this codebase; the GUI title may therefore show 3.1.0 even though this archive
is the 3.2.0 cross-platform package. Update the GUI constant separately if a
unified displayed version is required in a future code change.

================================================================================
END OF README
================================================================================
