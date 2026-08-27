$ErrorActionPreference = 'Stop'

cargo build -p upm-windows --release

$target = Join-Path $PSScriptRoot '..\..\target\release\upm-windows.exe'
if (-not (Test-Path $target)) {
    throw "Build output not found: $target"
}

Write-Host "UPM Windows client built: $target"
