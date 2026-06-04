@echo off
setlocal

python -m compileall burp_ai_redaction_gateway tests
if errorlevel 1 exit /b 1

python -m unittest discover -s tests
if errorlevel 1 exit /b 1

if exist out (
  python -m burp_ai_redaction_gateway verify --input out
  if errorlevel 1 exit /b 1
)

where gitleaks >nul 2>nul
if %errorlevel%==0 (
  gitleaks dir -v --redact=100 --config .gitleaks.toml .
  if errorlevel 1 exit /b 1
)

echo Pre-commit checks passed.
exit /b 0
