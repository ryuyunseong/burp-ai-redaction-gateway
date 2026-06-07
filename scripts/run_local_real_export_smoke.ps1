param(
    [Parameter(Mandatory = $true)]
    [Alias("Input")]
    [string]$InputPath,

    [string]$Project = "real_export_alias",

    [string]$Output = "out\local_real_export_smoke",

    [string]$Policy = "policy.json",

    [ValidateRange(1, 65535)]
    [int]$DashboardPort = 8766,

    [switch]$SkipReport,

    [switch]$SkipDashboardSmoke
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$StateDir = Join-Path $RepoRoot "out\.local_real_export_smoke"

function Write-SafeLine {
    param([string]$Message)
    Write-Host $Message
}

function Fail-Safe {
    param([string]$ErrorType)
    Write-SafeLine "local_real_export_smoke status=failed error_type=$ErrorType raw_data_included=false"
    exit 1
}

function Get-AbsolutePath {
    param([string]$Value)
    if ([System.IO.Path]::IsPathRooted($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }
    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Value))
}

function Test-PathUnderRoot {
    param(
        [string]$ChildPath,
        [string]$RootPath
    )
    $root = [System.IO.Path]::GetFullPath($RootPath).TrimEnd("\", "/")
    $child = [System.IO.Path]::GetFullPath($ChildPath)
    return $child.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-SafeOutputAlias {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or [System.IO.Path]::IsPathRooted($Value)) {
        Fail-Safe "invalid_output_alias"
    }
    $normalized = $Value -replace "/", "\"
    $parts = @($normalized -split "\\+" | Where-Object { $_ -ne "" })
    if ($parts.Count -ne 2 -or $parts[0] -ne "out") {
        Fail-Safe "output_alias_must_be_direct_child_of_out"
    }
    foreach ($part in $parts) {
        if ($part -eq "." -or $part -eq ".." -or $part -in @("local_only", "raw", "raw_vault")) {
            Fail-Safe "forbidden_output_alias"
        }
        if ($part -notmatch "^[A-Za-z0-9_.-]+$") {
            Fail-Safe "invalid_output_alias"
        }
    }
    return ($parts -join "\")
}

function Assert-SafeProjectAlias {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$") {
        Fail-Safe "invalid_project_alias"
    }
}

function Test-PortAvailable {
    param([int]$Port)
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

function Invoke-GatewayCommand {
    param(
        [string]$Step,
        [string[]]$Arguments
    )
    $commandOutput = & python @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Write-SafeLine "step=$Step status=failed raw_data_included=false"
        Fail-Safe "$Step`_failed"
    }
    Write-SafeLine "step=$Step status=passed raw_data_included=false"
    return ($commandOutput -join "`n")
}

function Assert-DashboardBodySafe {
    param(
        [string]$Body,
        [string]$InputFullPath
    )
    $forbiddenMarkers = @(
        ("raw" + "_request"),
        ("raw" + "_response"),
        ("Authorization" + ": Bearer"),
        ("Cookie" + ":"),
        ("DUMMY" + "_BEARER" + "_TOKEN"),
        ("DUMMY" + "_COOKIE" + "_VALUE"),
        $InputFullPath
    )
    foreach ($marker in $forbiddenMarkers) {
        if (-not [string]::IsNullOrEmpty($marker) -and $Body.Contains($marker)) {
            Fail-Safe "dashboard_forbidden_marker_detected"
        }
    }
}

function Invoke-DashboardSmoke {
    param(
        [string]$RootAlias,
        [string]$ProjectAlias,
        [int]$Port,
        [string]$InputFullPath
    )
    if (-not (Test-PortAvailable -Port $Port)) {
        Fail-Safe "dashboard_port_in_use"
    }

    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $dashboardLog = Join-Path $StateDir "dashboard.log"
    $dashboardErr = Join-Path $StateDir "dashboard.err.log"
    $dashboardArgs = @(
        "-m",
        "burp_ai_redaction_gateway",
        "dashboard",
        "--host",
        "127.0.0.1",
        "--port",
        [string]$Port,
        "--root",
        $RootAlias
    )

    $process = Start-Process `
        -FilePath "python" `
        -ArgumentList $dashboardArgs `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $dashboardLog `
        -RedirectStandardError $dashboardErr `
        -WindowStyle Hidden `
        -PassThru

    try {
        $ready = $false
        for ($index = 0; $index -lt 30; $index++) {
            if ($process.HasExited) {
                Fail-Safe "dashboard_exited_during_smoke"
            }
            try {
                Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri "http://127.0.0.1:$Port/" | Out-Null
                $ready = $true
                break
            } catch {
                Start-Sleep -Milliseconds 250
            }
        }
        if (-not $ready) {
            Fail-Safe "dashboard_not_ready"
        }

        $routes = @(
            "/",
            "/output?project=$ProjectAlias",
            "/preflight?project=$ProjectAlias",
            "/handoff?project=$ProjectAlias",
            "/triage?project=$ProjectAlias",
            "/report-readiness?project=$ProjectAlias",
            "/workflow?project=$ProjectAlias",
            "/prompt-readiness?project=$ProjectAlias",
            "/evidence-boundary?project=$ProjectAlias",
            "/operator-runbook?project=$ProjectAlias",
            "/safe-files?project=$ProjectAlias",
            "/settings",
            "/help",
            "/operations"
        )
        $readOnlyRoutes = @(
            "/preflight",
            "/handoff",
            "/triage",
            "/report-readiness",
            "/workflow",
            "/prompt-readiness",
            "/evidence-boundary",
            "/operator-runbook",
            "/safe-files",
            "/settings",
            "/help",
            "/operations"
        )

        foreach ($route in $routes) {
            $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 -Uri "http://127.0.0.1:$Port$route"
            if ($response.StatusCode -ne 200) {
                Fail-Safe "dashboard_route_failed"
            }
            $body = [string]$response.Content
            Assert-DashboardBodySafe -Body $body -InputFullPath $InputFullPath
            foreach ($readOnlyPrefix in $readOnlyRoutes) {
                if ($route.StartsWith($readOnlyPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $lower = $body.ToLowerInvariant()
                    if ($lower.Contains("<form") -or $lower.Contains("<button") -or $lower.Contains("method=`"post`"")) {
                        Fail-Safe "dashboard_read_only_route_has_action"
                    }
                }
            }
        }
        Write-SafeLine "step=dashboard_smoke status=passed route_count=$($routes.Count) raw_data_included=false"
    } finally {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
        }
    }
}

$LocalOnlyRoot = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot "local_only"))
$InputFull = Get-AbsolutePath -Value $InputPath
if (-not (Test-PathUnderRoot -ChildPath $InputFull -RootPath $LocalOnlyRoot)) {
    Fail-Safe "input_must_be_under_local_only"
}
if (-not (Test-Path -LiteralPath $InputFull -PathType Leaf)) {
    Fail-Safe "input_not_found"
}
$extension = [System.IO.Path]::GetExtension($InputFull).ToLowerInvariant()
if ($extension -notin @(".xml", ".json", ".har")) {
    Fail-Safe "unsupported_input_extension"
}

Assert-SafeProjectAlias -Value $Project
$OutputAlias = Get-SafeOutputAlias -Value $Output
$OutputParts = @($OutputAlias -split "\\+")
$DashboardProject = $OutputParts[1]
$OutputFull = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $OutputAlias))
if (-not (Test-PathUnderRoot -ChildPath $OutputFull -RootPath ([System.IO.Path]::GetFullPath((Join-Path $RepoRoot "out"))))) {
    Fail-Safe "output_must_be_under_out"
}

$PolicyArgs = @()
if (-not [string]::IsNullOrWhiteSpace($Policy)) {
    $PolicyFull = Get-AbsolutePath -Value $Policy
    if (-not (Test-Path -LiteralPath $PolicyFull -PathType Leaf)) {
        Fail-Safe "policy_not_found"
    }
    $PolicyArgs = @("--policy", $PolicyFull)
}

Write-SafeLine "local_real_export_smoke status=started input_alias=local_only_input output_alias=$($OutputAlias -replace '\\', '/') project_alias=$Project raw_data_included=false"

$generateArgs = @("-m", "burp_ai_redaction_gateway", "generate", "--input", $InputFull, "--output", $OutputFull, "--project", $Project, "--risk-profile", "conservative") + $PolicyArgs
Invoke-GatewayCommand -Step "generate" -Arguments $generateArgs | Out-Null

$verifyArgs = @("-m", "burp_ai_redaction_gateway", "verify", "--input", $OutputFull) + $PolicyArgs
$verifyOutput = Invoke-GatewayCommand -Step "verify" -Arguments $verifyArgs
$verifyText = $verifyOutput -join "`n"
if ($verifyText -match "Verification passed: ([0-9]+) files checked") {
    Write-SafeLine "verify_files_checked=$($Matches[1]) raw_data_included=false"
}

$reviewArgs = @("-m", "burp_ai_redaction_gateway", "review", "--input", $OutputFull) + $PolicyArgs
$reviewOutput = Invoke-GatewayCommand -Step "review" -Arguments $reviewArgs
$reviewText = $reviewOutput -join "`n"
if ($reviewText -match "Candidate count: ([0-9]+)") {
    Write-SafeLine "review_candidate_count=$($Matches[1]) raw_data_included=false"
}

if (-not $SkipReport) {
    $reportPath = Join-Path $OutputFull "report_draft.md"
    $reportArgs = @("-m", "burp_ai_redaction_gateway", "report", "--input", $OutputFull, "--output", $reportPath, "--profile", "conservative") + $PolicyArgs
    $reportOutput = Invoke-GatewayCommand -Step "report" -Arguments $reportArgs
    $reportText = $reportOutput -join "`n"
    if ($reportText -match "Candidate count: ([0-9]+)") {
        Write-SafeLine "report_candidate_count=$($Matches[1]) raw_data_included=false"
    }
}

if (-not $SkipDashboardSmoke) {
    Invoke-DashboardSmoke -RootAlias "out" -ProjectAlias $DashboardProject -Port $DashboardPort -InputFullPath $InputFull
}

Write-SafeLine "local_real_export_smoke status=passed safe_files=4 raw_data_included=false"
