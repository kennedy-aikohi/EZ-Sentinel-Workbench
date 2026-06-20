@echo off
setlocal
cd /d "%~dp0"

echo.
echo  ============================================================
echo   EZ Sentinel Workbench  -  Build Single-File Executable
echo  ============================================================
echo.

:: Step 1: ensure PyInstaller is current
echo  [1/3]  Upgrading PyInstaller...
python -m pip install --upgrade pyinstaller --quiet
if errorlevel 1 (
    echo.
    echo  ERROR: pip upgrade failed.
    echo  Make sure Python is on your PATH and pip is working.
    echo.
    pause & exit /b 1
)

:: Step 2: remove previous build artifacts
echo  [2/3]  Removing previous build artifacts...
if exist build  rmdir /s /q build
if exist dist   rmdir /s /q dist

:: Step 3: build
echo  [3/3]  Compiling...
echo.
pyinstaller --noconfirm --clean --windowed --onefile ^
  --name "EZSentinelWorkbench" ^
  --icon "assets\ez_sentinel.ico" ^
  --manifest "assets\app.manifest" ^
  --add-data "assets;assets" ^
  --add-data "config;config" ^
  --add-data "docs;docs" ^
  --add-data "tools;tools" ^
  ez_sentinel_workbench.py

if errorlevel 1 (
    echo.
    echo  BUILD FAILED  -  check the output above for details.
    echo.
    pause & exit /b 1
)

echo.
echo  ============================================================
echo   BUILD COMPLETE
echo   Output:  dist\EZSentinelWorkbench.exe
echo   Copy that single file anywhere - no other files needed.
echo  ============================================================
echo.
pause
