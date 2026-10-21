@echo off
chcp 65001 >nul
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
    echo [错误] 未找到 Python，请安装 Python 3.8+ 并勾选 "Add python.exe to PATH"。
    pause
    exit /b 1
)
python -m pip show pyinstaller >nul 2>nul || python -m pip install pyinstaller
python -m PyInstaller --noconfirm --onefile --noconsole --name XrayMultiPortLite --icon app.ico xray_multi_port.py
echo.
echo 构建完成: dist\XrayMultiPortLite.exe
pause
