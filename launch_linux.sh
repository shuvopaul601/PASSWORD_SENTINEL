#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(realpath "$0")")"
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python 3 was not found. Install Python 3.10+ and try again." >&2
  exit 1
fi
if [[ ! -d .venv ]]; then "$PYTHON" -m venv .venv; fi
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python cli.py gui
