#Requires -Version 5.1
<#
.SYNOPSIS
    Install P4B on Windows Server 2022 (or any Windows with Python 3.10+).

.DESCRIPTION
    Creates a virtualenv, installs the package from this checkout, writes p4b.yaml
    (SQLite under the data dir, bearer auth required), initialises the schema, issues
    one API token and registers a startup scheduled task that runs `p4b serve` as
    SYSTEM. Use -DryRun to preview, -Uninstall to remove the task (data is kept).

.EXAMPLE
    .\install-service.ps1 -InstallDir C:\p4b

.EXAMPLE
    .\install-service.ps1 -InstallDir C:\p4b -DryRun
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\p4b",
    [string]$SourceDir = "",
    [string]$DataDir,
    [int]$Port = 8080,
    [string]$TaskName = "P4B",
    [switch]$Uninstall,
    [switch]$NoService,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string]$Text) Write-Host "== $Text" -ForegroundColor Cyan }
function Write-Item { param([string]$Text) Write-Host "   $Text" }

if (-not $PSBoundParameters.ContainsKey("DataDir") -or -not $DataDir) {
    $DataDir = Join-Path $InstallDir "data"
}
if (-not $SourceDir) {
    $SourceDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $DryRun -and -not $NoService -and -not $isAdmin) {
    throw "Run this from an elevated PowerShell, or pass -NoService (no task) / -DryRun."
}

if ($Uninstall) {
    Write-Step "uninstall"
    if ($DryRun) {
        Write-Item "would unregister scheduled task '$TaskName'"
        return
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Item "task '$TaskName' removed; data in $DataDir kept"
    return
}

Write-Step "layout"
Write-Item "install: $InstallDir"
Write-Item "source:  $SourceDir"
Write-Item "data:    $DataDir"

if (-not (Test-Path (Join-Path $SourceDir "pyproject.toml"))) {
    throw "no pyproject.toml in $SourceDir; pass -SourceDir <checkout>"
}
if (-not $DryRun) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python -and -not $DryRun) {
    throw "python.exe not on PATH; install Python 3.10+ (3.12 recommended) first"
}
if ($python) {
    Write-Item "python:  $((& python --version) 2>&1)"
} else {
    Write-Item "python:  not found (dry run continues)"
}

$venv = Join-Path $InstallDir ".venv"
$venvPython = Join-Path $venv "Scripts\python.exe"
$p4bExe = Join-Path $venv "Scripts\p4b.exe"
$config = Join-Path $InstallDir "p4b.yaml"

Write-Step "create venv"
if (Test-Path $venv) {
    Write-Item "already exists: $venv"
} elseif ($DryRun) {
    Write-Item "would run: python -m venv $venv"
} else {
    & python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
}

Write-Step "install p4b"
if ($DryRun) {
    Write-Item "would run: $venvPython -m pip install -e $SourceDir"
} else {
    & $venvPython -m pip install --quiet --upgrade pip
    & $venvPython -m pip install --quiet -e $SourceDir
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
}

Write-Step "write p4b.yaml"
$sqlitePath = ($DataDir -replace '\\', '/')
$yaml = @"
data_dir: $DataDir
db_url: sqlite:///$sqlitePath/p4b.db
api_host: 0.0.0.0
api_port: $Port
require_auth: true
"@
if ($DryRun) {
    Write-Item "would write $config"
    Write-Host $yaml
} else {
    # UTF8 without BOM: PyYAML chokes on a leading BOM.
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($config, $yaml, $utf8)
}

Write-Step "initialise database"
if ($DryRun) {
    Write-Item "would run: $p4bExe init"
} else {
    Push-Location $InstallDir
    try { & $p4bExe init | Out-Null } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "p4b init failed" }
}

Write-Step "issue an API token"
if ($DryRun) {
    Write-Item "would run: $p4bExe --json token create --name server --scopes read,write"
} else {
    Push-Location $InstallDir
    try {
        $token = (& $p4bExe --json token create --name server --scopes read,write) |
            ConvertFrom-Json
    } finally {
        Pop-Location
    }
    Write-Host ""
    Write-Host "  token (shown once): $($token.token)" -ForegroundColor Yellow
    Write-Host ""
}

Write-Step "register startup task"
if ($NoService) {
    Write-Item "skipped (-NoService); run it yourself: $p4bExe serve --host 0.0.0.0 --port $Port"
} elseif ($DryRun) {
    Write-Item "would register task '$TaskName' -> $p4bExe serve --host 0.0.0.0 --port $Port"
} else {
    $action = New-ScheduledTaskAction -Execute $p4bExe `
        -Argument "serve --host 0.0.0.0 --port $Port" -WorkingDirectory $InstallDir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    Write-Item "task '$TaskName' registered and started"
}

Write-Step "next"
Write-Item "firewall: New-NetFirewallRule -DisplayName 'P4B $Port' -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow"
Write-Item "verify:   .\deploy\windows\verify-windows.ps1 -InstallDir $InstallDir -Port $Port"
