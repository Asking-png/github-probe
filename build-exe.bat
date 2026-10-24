@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal

rem ==== 把探测器打包成单个 exe，并更新桌面上的图标 ====

set "PY="
for /f "delims=" %%i in ('where python.exe 2^>nul') do (
    echo %%i | findstr /i /c:"WindowsApps" >nul || (if not defined PY set "PY=%%i")
)
if not defined PY (
    echo [错误] 未找到 Python。请安装 Python 3.10+（需含 tkinter）并加入 PATH。
    pause
    exit /b 1
)

set "VENV=%LOCALAPPDATA%\GitHubProbe-build"
if not exist "%VENV%\Scripts\pyinstaller.exe" (
    echo 首次打包：创建虚拟环境并安装 PyInstaller（约需 1 分钟）...
    "%PY%" -m venv "%VENV%" || (echo 创建虚拟环境失败 & pause & exit /b 1)
    "%VENV%\Scripts\python.exe" -m pip install -q pyinstaller || (echo 安装 PyInstaller 失败 & pause & exit /b 1)
)

echo 正在打包...
"%VENV%\Scripts\pyinstaller.exe" --noconsole --onefile --icon icon.ico --name GitHubProbe probe_gui.py

if not exist "dist\GitHubProbe.exe" (
    echo 打包失败，请看上面的输出。
    pause
    exit /b 1
)

copy /y "dist\GitHubProbe.exe" "%USERPROFILE%\Desktop\GitHub 实时探测.exe" >nul
echo.
echo 完成：dist\GitHubProbe.exe
echo 桌面图标已更新：GitHub 实时探测.exe
echo 验证方式：双击它；或在命令行运行  "GitHub 实时探测.exe" --selftest
echo （自检结果写在 %%LOCALAPPDATA%%\GitHubProbe\selftest.txt）
pause
