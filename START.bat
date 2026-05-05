@echo off
setlocal
title Wazuh Home Lab

:: Prefer PowerShell 7 (pwsh.exe), fall back to Windows PowerShell 5.1
set "PS_EXE="
where /q pwsh.exe 2>nul && set "PS_EXE=pwsh.exe"
if not defined PS_EXE (
    where /q powershell.exe 2>nul && set "PS_EXE=powershell.exe"
)

if not defined PS_EXE (
    echo.
    echo  [ERROR] PowerShell is not installed or not on PATH.
    echo  Download it from: https://aka.ms/PSWindows
    echo.
    pause
    exit /b 1
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-WazuhLab.ps1" %*
set "EC=%ERRORLEVEL%"

echo.
if %EC% neq 0 (
    echo  Script exited with error code %EC%.
    echo.
)
echo  Press any key to close this window...
pause >nul
exit /b %EC%
