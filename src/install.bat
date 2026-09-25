@echo off
setlocal
REM ============================================================
REM  NetScan install launcher
REM  - Double-click to run. Extra arguments are passed to Install.ps1
REM    (e.g. install.bat -Force)
REM  - Relaunches itself as administrator when needed (UAC prompt).
REM  - Keep this file ASCII only (cmd cannot read UTF-8 BOM).
REM ============================================================

REM fltmc succeeds only in an elevated session
fltmc >nul 2>&1
if errorlevel 1 goto :elevate

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install.ps1" %*
set "RC=%errorlevel%"
echo.
if not "%RC%"=="0" echo [NetScan] install failed. (exit code %RC%)
pause
exit /b %RC%

:elevate
echo [NetScan] Administrator rights are required. Requesting elevation...
REM No parenthesized blocks here: a ')' in the path, e.g. "Program Files (x86)", would break them.
if "%~1"=="" goto :elevate_noargs
powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
goto :elevate_check
:elevate_noargs
powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
:elevate_check
if not errorlevel 1 exit /b 0
echo [NetScan] Elevation was cancelled or failed.
pause
exit /b 1
