#!/bin/bash
set -e
cd "$(dirname "$0")"
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python 3.10+ is required. Install it from https://www.python.org/downloads/macos/"
  read -r -p "Press Return to close..."
  exit 1
fi
if [ ! -d .venv ]; then "$PYTHON" -m venv .venv; fi
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python cli.py gui
