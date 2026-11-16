@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")
%PY% --version
if errorlevel 1 (
  echo Python 3.10 or newer is required.
  pause
  exit /b 1
)
if not exist .venv %PY% -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python cli.py gui
if errorlevel 1 pause
