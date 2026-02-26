@echo off
:: Windows Build Review - Launcher
:: Run this as Administrator for full results

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Not running as Administrator. Relaunching elevated...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs"
    exit /b
)

echo [*] Running Windows Build Review...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Windows-Build-Review.ps1"
echo.
echo [*] Done. Press any key to close.
pause >nul
