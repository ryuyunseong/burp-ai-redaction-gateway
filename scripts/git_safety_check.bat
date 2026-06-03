@echo off
setlocal enabledelayedexpansion

set "REPO_SAFE=%CD:\=/%"
set "GIT_CMD=git -c safe.directory=%REPO_SAFE%"

%GIT_CMD% rev-parse --is-inside-work-tree >nul 2>nul
if errorlevel 1 (
  echo Not a Git repository yet. Skipping tracked/staged raw-data check.
  call scripts\pre_commit_check.bat
  exit /b !errorlevel!
)

echo Git status:
%GIT_CMD% status --short --untracked-files=all
if errorlevel 1 exit /b 1

set "SAFETY_LIST=%TEMP%\burp_ai_git_safety_%RANDOM%%RANDOM%.txt"
set "SAFETY_MATCHES=%TEMP%\burp_ai_git_safety_matches_%RANDOM%%RANDOM%.txt"

%GIT_CMD% ls-files > "%SAFETY_LIST%"
if errorlevel 1 exit /b 1
%GIT_CMD% diff --name-only --cached >> "%SAFETY_LIST%"
if errorlevel 1 exit /b 1

findstr /R /I /C:"^out/" /C:"^local_only/" /C:"^raw/" /C:"^raw_vault/" /C:"\.har$" /C:"\.burp$" /C:"\.burp-project$" /C:"_raw" /C:"raw_history" /C:"burp_history_raw" "%SAFETY_LIST%" > "%SAFETY_MATCHES%"
if not errorlevel 1 (
  echo Unsafe tracked or staged paths found:
  type "%SAFETY_MATCHES%"
  del "%SAFETY_LIST%" >nul 2>nul
  del "%SAFETY_MATCHES%" >nul 2>nul
  exit /b 1
)

del "%SAFETY_LIST%" >nul 2>nul
del "%SAFETY_MATCHES%" >nul 2>nul

call scripts\pre_commit_check.bat
exit /b !errorlevel!
