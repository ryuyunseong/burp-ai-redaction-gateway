$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$StateDir = Join-Path $RepoRoot "out\.launcher"
$LauncherLog = Join-Path $StateDir "launcher.log"

function Write-SafeLog {
    param(
        [string]$Event,
        [hashtable]$Fields = @{}
    )

    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $pairs = @("timestamp=$timestamp", "event=$Event")
    foreach ($key in ($Fields.Keys | Sort-Object)) {
        $safeKey = $key -replace "[^A-Za-z0-9_.-]", "_"
        $safeValue = [string]$Fields[$key]
        $safeValue = $safeValue -replace "[^A-Za-z0-9_.:/-]", "_"
        $pairs += "$safeKey=$safeValue"
    }
    Add-Content -Path $LauncherLog -Value ($pairs -join " ") -Encoding ascii
}

function Stop-ManagedGatewayProcess {
    param(
        [string]$Service,
        [string]$PidFile,
        [string]$ExpectedCommand
    )

    if (-not (Test-Path -LiteralPath $PidFile)) {
        Write-SafeLog -Event "process_not_running" -Fields @{ service = $Service; reason = "pid_file_missing" }
        Write-Host "$Service not running: pid_file_missing"
        return
    }

    $rawPid = (Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    $pidValue = 0
    if (-not [int]::TryParse($rawPid, [ref]$pidValue)) {
        Remove-Item -LiteralPath $PidFile -Force
        Write-SafeLog -Event "process_not_stopped" -Fields @{ service = $Service; reason = "invalid_pid_file" }
        Write-Host "$Service not stopped: invalid_pid_file"
        return
    }

    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $pidValue" -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        Remove-Item -LiteralPath $PidFile -Force
        Write-SafeLog -Event "process_not_running" -Fields @{ service = $Service; reason = "process_missing"; process_id = $pidValue }
        Write-Host "$Service not running: process_missing"
        return
    }

    $commandLine = [string]$process.CommandLine
    if ($commandLine -notlike "*burp_ai_redaction_gateway*" -or $commandLine -notlike "* $ExpectedCommand *") {
        Write-SafeLog -Event "process_not_stopped" -Fields @{ service = $Service; reason = "unexpected_process"; process_id = $pidValue }
        Write-Host "$Service not stopped: unexpected_process"
        return
    }

    Stop-Process -Id $pidValue -Force
    Remove-Item -LiteralPath $PidFile -Force
    Write-SafeLog -Event "process_stopped" -Fields @{ service = $Service; process_id = $pidValue }
    Write-Host "$Service stopped: process_id=$pidValue"
}

$ReceiverPidFile = Join-Path $StateDir "receiver.pid"
$DashboardPidFile = Join-Path $StateDir "dashboard.pid"

Stop-ManagedGatewayProcess -Service "dashboard" -PidFile $DashboardPidFile -ExpectedCommand "dashboard"
Stop-ManagedGatewayProcess -Service "receiver" -PidFile $ReceiverPidFile -ExpectedCommand "serve"
Write-Host "Gateway launcher stop completed."
