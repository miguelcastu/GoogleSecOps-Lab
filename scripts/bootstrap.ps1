$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        throw 'Install uv from https://docs.astral.sh/uv/getting-started/installation/.'
    }
    uv sync --locked --python 3.12 --extra dev
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    uv run --locked --no-sync secops-lab demo
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
