$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Run start-shellsentry.cmd once before building the Windows package."
}

& $python -m pip install --disable-pip-version-check -e "${projectRoot}[packaging]"
& $python -m PyInstaller `
    --noconfirm `
    --clean `
    --onedir `
    --console `
    --name ShellSentry `
    --paths (Join-Path $projectRoot "src") `
    --add-data "$(Join-Path $projectRoot 'src\shellsentry\web\static');shellsentry/web/static" `
    (Join-Path $projectRoot "packaging\windows_entry.py")

Write-Host "Windows package created at: $(Join-Path $projectRoot 'dist\ShellSentry')"
