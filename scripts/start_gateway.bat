@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_gateway.ps1" %*
exit /b %errorlevel%
