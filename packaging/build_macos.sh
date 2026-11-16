#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(realpath "$0")")/.."
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt pyinstaller
python3 -m PyInstaller --noconfirm --clean --windowed --name PasswordSentinel --osx-bundle-identifier com.passwordsentinel.desktop --collect-all zxcvbn gui_entry.py
echo "Build complete: dist/PasswordSentinel.app"
