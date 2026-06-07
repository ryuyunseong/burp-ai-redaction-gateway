@echo off
setlocal

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_local_real_export_smoke.ps1" %*
exit /b %errorlevel%
