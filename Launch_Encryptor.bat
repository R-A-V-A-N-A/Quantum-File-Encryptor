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

REM Try different Python versions
where py >nul 2>&1
if %errorlevel%==0 (
    py -3 encryptor_app.py
) else (
    python encryptor_app.py
)

if errorlevel 1 (
    echo.
    echo [ERROR] Python not found or script failed.
    echo Make sure Python 3.x is installed.
)

popd
pause
