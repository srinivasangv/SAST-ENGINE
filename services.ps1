<#
.SYNOPSIS
  Start, stop, and check the three services the SAST engine runs on.

.EXAMPLE
  .\services.ps1 start
  .\services.ps1 status
  .\services.ps1 stop
  .\services.ps1 restart
#>

param (
    [Parameter(Position = 0)]
    [ValidateSet("start", "stop", "restart", "status")]
    [string]$Action = "status"
)

$ErrorActionPreference = "SilentlyContinue"
$Root = $PSScriptRoot
Set-Location $Root

$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $Python = "python"
}

$LogDir = Join-Path $Root ".run"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$EnvFile = Join-Path $Root ".env.local"
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line.Split("=", 2)
            $name = $parts[0].Trim()
            $val = $parts[1].Trim().Trim("'`"")
            [Environment]::SetEnvironmentVariable($name, $val, "Process")
        }
    }
}

$DefectDojoUrl = if ($env:DEFECTDOJO_URL) { $env:DEFECTDOJO_URL } else { "http://localhost:8080" }
$DefectDojoDir = if ($env:DEFECTDOJO_DIR) { $env:DEFECTDOJO_DIR } else { "$HOME\django-DefectDojo" }
$DefectDojoPort = try { ([System.Uri]$DefectDojoUrl).Port } catch { 8080 }

$ApiUrl = "http://127.0.0.1:8000"
$UiUrl = "http://localhost:5173"

function Test-PortOpen([string]$HostName = "127.0.0.1", [int]$Port = 8000) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne(500, $false)
        if ($wait) {
            $client.EndConnect($async)
            $client.Close()
            return $true
        }
        $client.Close()
    } catch {}

    if ($HostName -eq "127.0.0.1") {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect("localhost", $Port, $null, $null)
            $wait = $async.AsyncWaitHandle.WaitOne(500, $false)
            if ($wait) {
                $client.EndConnect($async)
                $client.Close()
                return $true
            }
            $client.Close()
        } catch {}
    }
    return $false
}

function Wait-PortOpen([string]$HostName = "127.0.0.1", [int]$Port = 8000, [int]$MaxSeconds = 10) {
    for ($i = 0; $i -lt $MaxSeconds; $i++) {
        if (Test-PortOpen $HostName $Port) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Stop-Port([int]$Port, [string]$Name) {
    $conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($conns) {
        $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($p in $pids) {
            if ($p -and $p -ne 0) {
                Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
                Write-Host "  $Name stopped (PID $p on :$Port)" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "  $Name not running" -ForegroundColor DarkGray
    }
}

function Start-Api() {
    if (Test-PortOpen "127.0.0.1" 8000) {
        Write-Host "  api        up        already running on :8000" -ForegroundColor Green
        return
    }
    Start-Process -FilePath $Python -ArgumentList "server.py" -WorkingDirectory $Root
    if (Wait-PortOpen "127.0.0.1" 8000 10) {
        Write-Host "  api        started   :8000" -ForegroundColor Green
    } else {
        Write-Host "  api        FAILED to start" -ForegroundColor Red
    }
}

function Start-Ui() {
    if (Test-PortOpen "127.0.0.1" 5173) {
        Write-Host "  dashboard  up        already running on :5173" -ForegroundColor Green
        return
    }
    $nodeModules = Join-Path $Root "ui\node_modules"
    if (-not (Test-Path $nodeModules)) {
        Write-Host "  dashboard  no node_modules -- run: cd ui; npm install" -ForegroundColor Red
        return
    }
    $uiDir = Join-Path $Root "ui"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c npm run dev" -WorkingDirectory $uiDir
    if (Wait-PortOpen "127.0.0.1" 5173 15) {
        Write-Host "  dashboard  started   :5173" -ForegroundColor Green
    } else {
        Write-Host "  dashboard  FAILED to start" -ForegroundColor Red
    }
}

function Start-Dojo() {
    if (Test-PortOpen "127.0.0.1" $DefectDojoPort) {
        Write-Host "  defectdojo up        already running on $DefectDojoUrl" -ForegroundColor Green
        return
    }
    if (-not (Test-Path $DefectDojoDir)) {
        Write-Host "  defectdojo not found at $DefectDojoDir" -ForegroundColor Red
        return
    }
    
    # Check if Docker Desktop process is running
    $dockerProc = Get-Process "Docker Desktop" -ErrorAction SilentlyContinue
    if (-not $dockerProc) {
        Write-Host "  defectdojo Docker Desktop is not running. Launch Docker Desktop to start DefectDojo." -ForegroundColor Yellow
        return
    }

    Write-Host "  defectdojo starting container in $DefectDojoDir..." -ForegroundColor Cyan
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c docker compose up -d" -WorkingDirectory $DefectDojoDir
    if (Wait-PortOpen "127.0.0.1" $DefectDojoPort 40) {
        Write-Host "  defectdojo started   $DefectDojoUrl" -ForegroundColor Green
    } else {
        Write-Host "  defectdojo docker compose started in background." -ForegroundColor Yellow
    }
}

function Show-Status() {
    Write-Host "`n== Services Status ==" -ForegroundColor Cyan
    $apiUp = Test-PortOpen "127.0.0.1" 8000
    $uiUp = Test-PortOpen "127.0.0.1" 5173
    $dojoUp = Test-PortOpen "127.0.0.1" $DefectDojoPort

    Write-Host ("  API        : " + $(if ($apiUp) { "[UP]   $ApiUrl" } else { "[DOWN] $ApiUrl" })) -ForegroundColor $(if ($apiUp) { "Green" } else { "Red" })
    Write-Host ("  Dashboard  : " + $(if ($uiUp) { "[UP]   $UiUrl" } else { "[DOWN] $UiUrl" })) -ForegroundColor $(if ($uiUp) { "Green" } else { "Red" })
    Write-Host ("  DefectDojo : " + $(if ($dojoUp) { "[UP]   $DefectDojoUrl" } else { "[DOWN] $DefectDojoUrl" })) -ForegroundColor $(if ($dojoUp) { "Green" } else { "Red" })

    if ($apiUp) {
        Write-Host "`n== Engine Self-Report ==" -ForegroundColor Cyan
        try {
            $h = Invoke-RestMethod -Uri "$ApiUrl/api/health" -Method Get
            $llmStatus = if ($h.llm_configured) { "$($h.llm_provider) ($($h.llm_model))" } else { "offline (deterministic rules fallback)" }
            $joernStatus = if ($h.engines.joern) { "available ($($h.engines.joern_version))" } else { "not available ($($h.engines.joern_error))" }
            $dojoStatus = if ($h.defectdojo.reachable) { "reachable & authenticated" } else { "unreachable ($($h.defectdojo.error))" }

            Write-Host "  LLM Validator  : $llmStatus"
            Write-Host "  Joern Engine   : $joernStatus"
            Write-Host "  Semgrep Engine : $(if ($h.semgrep_available) { 'available' } else { 'not found' })"
            Write-Host "  DefectDojo API : $dojoStatus"
            Write-Host "  Scans on Disk  : $($h.scans_stored)"
        } catch {
            Write-Host "  (could not fetch health metrics from API)" -ForegroundColor Yellow
        }
    }
}

switch ($Action) {
    "start" {
        Write-Host "Starting SAST Engine Services..." -ForegroundColor Cyan
        Start-Api
        Start-Ui
        Start-Dojo
        Show-Status
    }
    "stop" {
        Write-Host "Stopping SAST Engine Services..." -ForegroundColor Cyan
        Stop-Port 8000 "API"
        Stop-Port 5173 "Dashboard"
    }
    "restart" {
        Write-Host "Restarting Services..." -ForegroundColor Cyan
        Stop-Port 8000 "API"
        Stop-Port 5173 "Dashboard"
        Start-Sleep -Seconds 1
        Start-Api
        Start-Ui
        Show-Status
    }
    "status" {
        Show-Status
    }
}
