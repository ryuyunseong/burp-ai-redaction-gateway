@echo off
setlocal

python scripts\make_safe_burp_export_sample.py
if errorlevel 1 exit /b 1

python -m burp_ai_redaction_gateway generate --input local_only\real_burp_history_sample.xml --output out\real_sample_check --project real_sample_alias
if errorlevel 1 exit /b 1

python -m burp_ai_redaction_gateway verify --input out\real_sample_check
if errorlevel 1 exit /b 1

call scripts\git_safety_check.bat
if errorlevel 1 exit /b 1

git -c safe.directory=C:/coding/burp-ai-redaction-gateway status --short --untracked-files=all
exit /b %errorlevel%

