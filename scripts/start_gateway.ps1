param(
    [ValidateRange(1, 65535)]
    [int]$ReceiverPort = 8765,

    [ValidateRange(1, 65535)]
    [int]$DashboardPort = 8766,

    [string]$Output = "out\receiver",

    [string]$Project = "receiver_alias",

    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$StateDir = Join-Path $RepoRoot "out\.launcher"
$ReceiverPidFile = Join-Path $StateDir "receiver.pid"
$DashboardPidFile = Join-Path $StateDir "dashboard.pid"
$LauncherLog = Join-Path $StateDir "launcher.log"
$ReceiverLog = Join-Path $StateDir "receiver.log"
$ReceiverErr = Join-Path $StateDir "receiver.err.log"
$DashboardLog = Join-Path $StateDir "dashboard.log"
$DashboardErr = Join-Path $StateDir "dashboard.err.log"

function Write-SafeLog {
    param(
        [string]$Event,
        [hashtable]$Fields = @{}
    )

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

function Fail-Safe {
    param(
        [string]$ErrorType
    )

    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    Write-SafeLog -Event "startup_failed" -Fields @{ error_type = $ErrorType }
    Write-Host "Launcher startup failed: $ErrorType"
    exit 1
}

function Get-SafeOutputAlias {
    param(
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        Fail-Safe "invalid_output_alias"
    }
    if ([System.IO.Path]::IsPathRooted($Value)) {
        Fail-Safe "absolute_output_path_not_allowed"
    }

    $normalized = $Value -replace "/", "\"
    $parts = @($normalized -split "\\+" | Where-Object { $_ -ne "" })
    if ($parts.Count -lt 2 -or $parts[0] -ne "out") {
        Fail-Safe "output_must_be_under_out"
    }

    foreach ($part in $parts) {
        if ($part -eq "." -or $part -eq "..") {
            Fail-Safe "path_traversal_not_allowed"
        }
        if ($part -in @("local_only", "raw", "raw_vault")) {
            Fail-Safe "forbidden_output_directory"
        }
        if ($part -notmatch "^[A-Za-z0-9_.-]+$") {
            Fail-Safe "invalid_output_alias"
        }
    }

    return ($parts -join "\")
}

function Assert-SafeProjectAlias {
    param(
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$") {
        Fail-Safe "invalid_project_alias"
    }
}

function Test-PortAvailable {
    param(
        [int]$Port
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if ($connect.AsyncWaitHandle.WaitOne(300, $false)) {
            $client.EndConnect($connect)
            return $false
        }
        return $true
    } catch {
        return $true
    } finally {
        $client.Close()
    }
}

function Test-ExistingManagedProcess {
    param(
        [string]$PidFile
    )

    if (-not (Test-Path -LiteralPath $PidFile)) {
        return $false
    }

    $rawPid = (Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    $pidValue = 0
    if (-not [int]::TryParse($rawPid, [ref]$pidValue)) {
        Remove-Item -LiteralPath $PidFile -Force
        return $false
    }

    $process = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        Remove-Item -LiteralPath $PidFile -Force
        return $false
    }

    return $true
}

function Start-GatewayProcess {
    param(
        [string]$Name,
        [string[]]$Arguments,
        [string]$PidFile,
        [string]$StandardOutputPath,
        [string]$StandardErrorPath
    )

    $process = Start-Process `
        -FilePath "python" `
        -ArgumentList $Arguments `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $StandardOutputPath `
        -RedirectStandardError $StandardErrorPath `
        -WindowStyle Hidden `
        -PassThru

    Set-Content -Path $PidFile -Value ([string]$process.Id) -Encoding ascii
    Write-SafeLog -Event "process_started" -Fields @{ service = $Name; process_id = $process.Id }
    return $process
}

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

$OutputAlias = Get-SafeOutputAlias -Value $Output
Assert-SafeProjectAlias -Value $Project

if ($ReceiverPort -eq $DashboardPort) {
    Fail-Safe "ports_must_be_distinct"
}
if (Test-ExistingManagedProcess -PidFile $ReceiverPidFile) {
    Fail-Safe "receiver_already_running"
}
if (Test-ExistingManagedProcess -PidFile $DashboardPidFile) {
    Fail-Safe "dashboard_already_running"
}
if (-not (Test-PortAvailable -Port $ReceiverPort)) {
    Fail-Safe "receiver_port_in_use"
}
if (-not (Test-PortAvailable -Port $DashboardPort)) {
    Fail-Safe "dashboard_port_in_use"
}

Write-SafeLog -Event "startup_requested" -Fields @{
    receiver_port = $ReceiverPort
    dashboard_port = $DashboardPort
    output_alias = ($OutputAlias -replace "\\", "/")
    project_alias = $Project
}

$receiverArgs = @(
    "-m",
    "burp_ai_redaction_gateway",
    "serve",
    "--host",
    "127.0.0.1",
    "--port",
    [string]$ReceiverPort,
    "--output",
    $OutputAlias,
    "--project",
    $Project
)
$dashboardArgs = @(
    "-m",
    "burp_ai_redaction_gateway",
    "dashboard",
    "--host",
    "127.0.0.1",
    "--port",
    [string]$DashboardPort,
    "--root",
    "out"
)

$receiverProcess = $null
$dashboardProcess = $null
try {
    $receiverProcess = Start-GatewayProcess `
        -Name "receiver" `
        -Arguments $receiverArgs `
        -PidFile $ReceiverPidFile `
        -StandardOutputPath $ReceiverLog `
        -StandardErrorPath $ReceiverErr

    Start-Sleep -Milliseconds 500
    if ($receiverProcess.HasExited) {
        Fail-Safe "receiver_exited_during_startup"
    }

    $dashboardProcess = Start-GatewayProcess `
        -Name "dashboard" `
        -Arguments $dashboardArgs `
        -PidFile $DashboardPidFile `
        -StandardOutputPath $DashboardLog `
        -StandardErrorPath $DashboardErr

    Start-Sleep -Milliseconds 500
    if ($dashboardProcess.HasExited) {
        if ($null -ne $receiverProcess -and -not $receiverProcess.HasExited) {
            Stop-Process -Id $receiverProcess.Id -Force
        }
        Fail-Safe "dashboard_exited_during_startup"
    }

    if (-not $NoBrowser) {
        Start-Process -FilePath "http://127.0.0.1:$DashboardPort/" | Out-Null
        Write-SafeLog -Event "browser_open_requested" -Fields @{ dashboard_port = $DashboardPort }
    }

    Write-SafeLog -Event "startup_succeeded" -Fields @{
        receiver_port = $ReceiverPort
        dashboard_port = $DashboardPort
        output_alias = ($OutputAlias -replace "\\", "/")
        project_alias = $Project
        receiver_pid = $receiverProcess.Id
        dashboard_pid = $dashboardProcess.Id
        raw_data_included = "false"
    }

    Write-Host "Gateway launcher started."
    Write-Host "receiver_port=$ReceiverPort"
    Write-Host "dashboard_port=$DashboardPort"
    Write-Host "output_alias=$($OutputAlias -replace '\\', '/')"
    Write-Host "project_alias=$Project"
    Write-Host "receiver_pid=$($receiverProcess.Id)"
    Write-Host "dashboard_pid=$($dashboardProcess.Id)"
    Write-Host "raw_data_included=false"
    Write-Host "Stop with scripts\stop_gateway.ps1"
} catch {
    if ($null -ne $dashboardProcess -and -not $dashboardProcess.HasExited) {
        Stop-Process -Id $dashboardProcess.Id -Force
    }
    if ($null -ne $receiverProcess -and -not $receiverProcess.HasExited) {
        Stop-Process -Id $receiverProcess.Id -Force
    }
    Fail-Safe "launcher_start_failed"
}
