param(
    [string]$Bind = '127.0.0.1:8787',
    [string]$DbPath = '.\upm-dev.sqlite3'
)

$ErrorActionPreference = 'Stop'

$server = Join-Path $PSScriptRoot '..\target\debug\upm-server.exe'
if (-not (Test-Path $server)) {
    Write-Host 'Debug server not found; building it first...' -ForegroundColor Yellow
    cargo build -p upm-server
    if ($LASTEXITCODE -ne 0) { throw 'Server build failed' }
}

$env:UPM_BIND = $Bind
$env:UPM_DB_PATH = $DbPath

Write-Host "Starting UPM server on $Bind" -ForegroundColor Cyan
Write-Host "Database: $DbPath" -ForegroundColor Cyan
& $server
