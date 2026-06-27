@echo off
REM ============================================================
REM  Build vtscan.exe for Windows.
REM  Double-click this file (or run it from cmd) inside apps\vtscan\.
REM  Requires Python 3.10+ installed with "Add Python to PATH".
REM ============================================================
cd /d "%~dp0"

echo [1/3] Installing dependencies (requests, colorama, pyinstaller)...
python -m pip install --upgrade pip
python -m pip install requests colorama pyinstaller
if errorlevel 1 goto error

echo.
echo [2/3] Building single .exe (may take a minute)...
pyinstaller --onefile --name vtscan --distpath "..\done" --workpath "build\work" --specpath "build" vtscan.py
if errorlevel 1 goto error

echo.
echo [3/3] Done! Built: ..\done\vtscan.exe
echo.
echo NOTE: put a .vtkey file with your VirusTotal key next to vtscan.exe,
echo       or set VT_API_KEY. On first run the app also asks for the key
echo       and saves it automatically.
echo.
pause
exit /b 0

:error
echo.
echo BUILD ERROR. Check that Python 3.10+ is installed (run: python --version)
echo and that you have internet access to download dependencies.
echo.
pause
exit /b 1
