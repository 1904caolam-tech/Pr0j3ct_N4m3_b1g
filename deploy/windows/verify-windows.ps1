#Requires -Version 5.1
<#
.SYNOPSIS
    Check a P4B installation on Windows Server 2022.

.DESCRIPTION
    Verifies the venv, the package entry point, p4b.yaml (bind + auth), the database,
    the scheduled task and the HTTP health endpoint. Exit code is non-zero if
    anything fails.

.EXAMPLE
    .\verify-windows.ps1 -InstallDir C:\p4b
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\p4b",
    [int]$Port = 8080,
    [string]$TaskName = "P4B",
    [switch]$NoService
)

$ErrorActionPreference = "Continue"
$script:passed = 0
$script:failed = 0

function Check {
    param(
        [string]$Name,
        [scriptblock]$Test,
        [string]$Hint = ""
    )
    try {
        if ([bool](& $Test)) {
            Write-Host "  PASS  $Name" -ForegroundColor Green
            $script:passed++
        } else {
            Write-Host "  FAIL  $Name  $Hint" -ForegroundColor Red
            $script:failed++
        }
    } catch {
        Write-Host "  FAIL  $Name  $($_.Exception.Message)" -ForegroundColor Red
        $script:failed++
    }
}

Write-Host "== P4B Windows verification =="

$venvPython = Join-Path $InstallDir ".venv\Scripts\python.exe"
$p4bExe = Join-Path $InstallDir ".venv\Scripts\p4b.exe"
$config = Join-Path $InstallDir "p4b.yaml"
$db = Join-Path $InstallDir "data\p4b.db"

Check "install directory" { Test-Path $InstallDir } "run install-service.ps1"
Check "virtualenv" { Test-Path $venvPython } "run install-service.ps1"
Check "p4b entry point" {
    & $p4bExe --version | Out-Null
    $LASTEXITCODE -eq 0
} "pip install did not finish"
Check "p4b.yaml" { Test-Path $config } "run install-service.ps1"

if (Test-Path $config) {
    $raw = Get-Content $config -Raw
    Check "config binds 0.0.0.0" { $raw -match "api_host:\s*0\.0\.0\.0" }
    Check "config requires auth" { $raw -match "require_auth:\s*true" }
    Check "config has data dir" { $raw -match "data_dir:" }
}

Check "database" { Test-Path $db } "run p4b init"

if (-not $NoService) {
    Check "scheduled task exists" {
        $null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop)
    } "run install-service.ps1 (or pass -NoService)"
    Check "scheduled task running" {
        (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State -eq "Running"
    } "start it: Start-ScheduledTask -TaskName $TaskName"
} else {
    Write-Host "  SKIP  scheduled task (-NoService)" -ForegroundColor Yellow
}

Check "http health" {
    (Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/v1/health" -TimeoutSec 5).status -eq "ok"
} "task running? firewall? port $Port"
Check "http reads are protected" {
    try {
        Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/v1/summary" -TimeoutSec 5 | Out-Null
        $false
    } catch {
        [int]$_.Exception.Response.StatusCode -eq 401
    }
} "expected 401 because p4b.yaml sets require_auth: true (writes and reads need a token)"

Write-Host ""
Write-Host "passed=$($script:passed) failed=$($script:failed)"
if ($script:failed -eq 0) { exit 0 } else { exit 1 }
