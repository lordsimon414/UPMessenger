$ErrorActionPreference = 'Stop'

cargo build --workspace --release
if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }

$client = Join-Path $PSScriptRoot '..\target\release\upm-windows.exe'
$server = Join-Path $PSScriptRoot '..\target\release\upm-server.exe'

if (-not (Test-Path $client)) { throw "Windows client build output missing: $client" }
if (-not (Test-Path $server)) { throw "Server build output missing: $server" }

Write-Host "Client: $client" -ForegroundColor Green
Write-Host "Server: $server" -ForegroundColor Green
