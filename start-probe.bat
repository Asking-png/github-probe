@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal

set "PYW="
for /f "delims=" %%i in ('where pythonw.exe 2^>nul') do (
    echo %%i | findstr /i /c:"WindowsApps" >nul || (if not defined PYW set "PYW=%%i")
)
if not defined PYW (
    for /f "delims=" %%i in ('where python.exe 2^>nul') do (
        echo %%i | findstr /i /c:"WindowsApps" >nul || (if not defined PYW set "PYW=%%i")
    )
)
if not defined PYW (
    echo [ERROR] Python not found. Install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

start "" "%PYW%" -X utf8 "%~dp0probe_gui.py"
exit /b 0
