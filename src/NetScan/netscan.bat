@echo off
REM ============================================================
REM  NetScan system launcher
REM  - Installed to %windir%\System32\netscan.bat by NetScan Setup
REM    (NetScan.iss) and removed by the NetScan uninstaller.
REM  - Loads the installed module by name and calls Start-NetScan.
REM    Calling "netscan" here would re-run this file forever when
REM    the module is missing, so the function name is used instead.
REM  - Keep this file ASCII only (cmd cannot read UTF-8 BOM).
REM ============================================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module NetScan -ErrorAction Stop; Start-NetScan"
