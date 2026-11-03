# Pull the Guardian chat and embedding models from a local Ollama server.
# Reads guardian/.env, then guardian/.env.example. Does not change either file.

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $Root "guardian\.env"
$ExampleFile = Join-Path $Root "guardian\.env.example"
$TagsUrl = "http://127.0.0.1:11434/api/tags"

function Get-DotEnvValue {
    param(
        [string]$Path,
        [string]$Name
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return ""
    }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) {
            continue
        }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) {
            continue
        }
        $key = $trimmed.Substring(0, $eq).Trim()
        if ($key -ne $Name) {
            continue
        }
        $value = $trimmed.Substring($eq + 1).Trim()
        if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        return $value
    }
    return ""
}

function Get-ModelName {
    param([string]$Name)
    $fromEnv = Get-DotEnvValue -Path $EnvFile -Name $Name
    if ($fromEnv) {
        return $fromEnv
    }
    return Get-DotEnvValue -Path $ExampleFile -Name $Name
}

function Fail {
    param([string]$Message)
    [Console]::Error.WriteLine($Message)
    exit 1
}

try {
    & ollama --version
    if ($LASTEXITCODE -ne 0) {
        Fail "Ollama is not installed or not on PATH. Install Ollama, then run this script again."
    }
}
catch {
    Fail "Ollama is not installed or not on PATH. Install Ollama, then run this script again."
}

$chatModel = Get-ModelName "GUARDIAN_LLM_MODEL"
$embedModel = Get-ModelName "GUARDIAN_EMBED_MODEL"
if (-not $chatModel) {
    Fail "GUARDIAN_LLM_MODEL is empty in guardian/.env and guardian/.env.example."
}
if (-not $embedModel) {
    Fail "GUARDIAN_EMBED_MODEL is empty in guardian/.env and guardian/.env.example."
}

curl.exe -fsS --max-time 5 $TagsUrl -o NUL
if ($LASTEXITCODE -ne 0) {
    Fail "Ollama is not reachable at http://127.0.0.1:11434. Start Ollama, then run this script again."
}

$names = @($chatModel, $embedModel) | Select-Object -Unique
foreach ($name in $names) {
    & ollama pull $name
    if ($LASTEXITCODE -ne 0) {
        Fail "ollama pull $name failed."
    }
}

$raw = curl.exe -fsS --max-time 10 $TagsUrl
if ($LASTEXITCODE -ne 0 -or -not $raw) {
    Fail "Ollama is not reachable at http://127.0.0.1:11434. Start Ollama, then run this script again."
}
$parsed = $raw | ConvertFrom-Json
foreach ($model in @($parsed.models)) {
    if ($model.name) {
        Write-Output $model.name
    }
}
exit 0
