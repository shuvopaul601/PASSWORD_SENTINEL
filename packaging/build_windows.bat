@echo off
setlocal
cd /d "%~dp0.."
py -3 -m pip install --upgrade pip
py -3 -m pip install -r requirements.txt pyinstaller
py -3 -m PyInstaller --noconfirm --clean --windowed --name "PasswordSentinel" --collect-all zxcvbn gui_entry.py
 echo Build complete: dist\PasswordSentinel\PasswordSentinel.exe
pause
