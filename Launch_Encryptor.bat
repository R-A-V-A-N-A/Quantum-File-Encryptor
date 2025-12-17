@echo off
title Quantum File Encryptor
cd /d "%~dp0"
echo.
echo ========================================
echo   Quantum File Encryptor
echo ========================================
echo.
py -3.14 encryptor_app.py
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to start. Trying alternative Python...
    python encryptor_app.py
)
pause
