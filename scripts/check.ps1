$ErrorActionPreference = 'Stop'

Write-Host '== UPM workspace checks ==' -ForegroundColor Cyan

cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { throw 'cargo fmt check failed' }

cargo check --workspace --all-targets
if ($LASTEXITCODE -ne 0) { throw 'cargo check failed' }

cargo test --workspace
if ($LASTEXITCODE -ne 0) { throw 'cargo test failed' }

cargo clippy --workspace --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) { throw 'cargo clippy failed' }

Write-Host 'All checks passed.' -ForegroundColor Green
