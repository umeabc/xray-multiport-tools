@echo off
chcp 65001 >nul
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
    echo [错误] 未找到 Python，请安装 Python 3.8+ 并勾选 "Add python.exe to PATH"。
    pause
    exit /b 1
)
python xray_multi_port.py
if errorlevel 1 pause
