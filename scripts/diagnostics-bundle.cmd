@echo off
rem Double-click: a zip of Pathwarden numbers, safe to share, on your Desktop.
rem Drag a collection zip onto this file to also score it.
rem Instructions and what the zip holds: diagnostics-bundle.ps1.
if "%~1"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0diagnostics-bundle.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0diagnostics-bundle.ps1" -Collection "%~1"
)
echo.
pause
