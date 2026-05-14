@echo off
setlocal
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller
pyinstaller --noconfirm --clean --windowed --onedir ^
  --name "EZSentinelWorkbench" ^
  --icon "assets\ez_sentinel.ico" ^
  --add-data "assets;assets" ^
  --add-data "config;config" ^
  --add-data "docs;docs" ^
  ez_sentinel_workbench.py

echo.
echo Build complete: dist\EZSentinelWorkbench\EZSentinelWorkbench.exe
pause
