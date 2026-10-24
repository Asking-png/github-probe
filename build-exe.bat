@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal

rem ==== 把探测器打包成单个 exe（默认只输出到 dist\，不写桌面）====

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

set "OUT=dist\GitHubProbe.exe"
echo.
echo 完成：%OUT%
for %%A in ("%OUT%") do echo 产物大小：%%~zA 字节
echo.
echo 直接运行：
echo   "%OUT%"
echo 自检（无窗口探一轮，结果写入 %%LOCALAPPDATA%%\GitHubProbe\selftest.txt）：
echo   "%OUT%" --selftest
echo.

if /i "%~1"=="desktop" (
    copy /y "%OUT%" "%USERPROFILE%\Desktop\GitHubProbe.exe" >nul
    if errorlevel 1 (
        echo [警告] 复制到桌面失败，请手动复制 %OUT%
    ) else (
        echo 已复制到桌面：GitHubProbe.exe
    )
) else (
    echo 如需在桌面也放一份，重跑并加参数：  build-exe.bat desktop
)
pause
