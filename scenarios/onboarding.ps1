# Live onboarding evidence: start Guardian (heuristic-only) and send twin-alt N+20.
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Guardian = Join-Path $Repo "guardian"
$Python = Join-Path $Repo ".venv\Scripts\python.exe"
$Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$Capture = Join-Path $Guardian "logs\onboarding-uvicorn-$Stamp.log"
$CaptureErr = Join-Path $Guardian "logs\onboarding-uvicorn-$Stamp.err.log"
$Port = if ($env:GUARDIAN_PORT) { $env:GUARDIAN_PORT } else { "8000" }

New-Item -ItemType Directory -Force -Path (Join-Path $Guardian "logs") | Out-Null
$ProfileDir = Join-Path $Guardian "data\onboarding-run"
if (Test-Path $ProfileDir) { Remove-Item -Recurse -Force $ProfileDir }
Get-NetTCPConnection -LocalPort ([int]$Port) -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

$env:PYTHONPATH = "src"
$env:GUARDIAN_ONBOARDING_MIN_PROPOSERS = "1"
$env:GUARDIAN_FORWARD_TO_BRAIN = "false"
$env:GUARDIAN_TIMELINE_MODE = "local"
$env:GUARDIAN_PROFILE_DIR = "data/onboarding-run"
$env:GUARDIAN_ONBOARDING_CAPTURE = $Capture

$Uvicorn = Start-Process -FilePath $Python -ArgumentList @(
    "-m", "uvicorn", "guardian.main:app",
    "--host", "127.0.0.1",
    "--port", $Port,
    "--log-level", "info"
) -WorkingDirectory $Guardian -RedirectStandardOutput $Capture -RedirectStandardError $CaptureErr -PassThru

try {
    $Ready = $false
    foreach ($i in 1..40) {
        try {
            $Response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/ready" -UseBasicParsing -TimeoutSec 2
            if ($Response.StatusCode -eq 200) { $Ready = $true; break }
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $Ready) { throw "Guardian /ready did not become ready" }

    Push-Location $Guardian
    try {
        & $Python -m mocks.onboarding_run --base-url "http://127.0.0.1:$Port" --count 21 --interval 0.5 --capture $Capture
        exit $LASTEXITCODE
    } finally {
        Pop-Location
    }
}
finally {
    if (-not $Uvicorn.HasExited) {
        Stop-Process -Id $Uvicorn.Id -Force
    }
}
