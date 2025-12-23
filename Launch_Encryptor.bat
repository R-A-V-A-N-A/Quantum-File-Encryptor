@echo off
title Quantum File Encryptor

REM Handle UNC paths (WSL, network drives, etc.)
pushd "%~dp0"
if errorlevel 1 (
    echo [!] Cannot access folder. Copying to temp...
    xcopy /E /I /Y "%~dp0" "%TEMP%\QuantumEncryptor" >nul
    cd /d "%TEMP%\QuantumEncryptor"
)

echo.
echo ========================================
echo   Quantum File Encryptor
echo ========================================
echo.

REM IMPORTANT: Use py -3.14 (NOT -3.14t which is freethreaded and causes GIL errors)
py -3.14 encryptor_app.py

if errorlevel 1 (
    echo.
    echo [ERROR] Python not found or script failed.
    echo If you see a GIL error, you may need to install Python 3.12 LTS.
    echo Your Python 3.14t (freethreaded) has compatibility issues.
)

popd
pause
