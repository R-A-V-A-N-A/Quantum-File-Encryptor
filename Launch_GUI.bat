@echo off
title Quantum File Encryptor - GUI
echo.
echo ========================================
echo   Quantum File Encryptor - Web GUI
echo ========================================
echo.
echo Starting web interface...
echo.
py "%~dp0web_gui.py"
if errorlevel 1 (
    echo.
    echo Error! Trying alternative Python command...
    python "%~dp0web_gui.py"
)
pause
