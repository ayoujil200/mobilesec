param(
    [Parameter(Mandatory = $true)]
    [string]$ApkDir,

    [string]$MobSFUrl = $(if ($env:MOBSF_URL) { $env:MOBSF_URL } else { "https://mobsf.live" }),
    [string]$ApiKey = $env:MOBSF_API_KEY,
    [string]$Output = "backend/ml-model/data/mobsf_static_dataset.csv",
    [string]$ReportsDir = "backend/ml-model/data/mobsf_reports",
    [int]$Limit = 0,
    [switch]$Resume,
    [switch]$Force,
    [switch]$Train
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

if (-not $ApiKey) {
    throw "MOBSF_API_KEY is required. Pass -ApiKey or set the MOBSF_API_KEY environment variable."
}

$ArgsList = @(
    "scripts/mobsf-static-dataset.js",
    $ApkDir,
    "--mobsf-url", $MobSFUrl,
    "--api-key", $ApiKey,
    "--output", $Output,
    "--reports-dir", $ReportsDir
)

if ($Limit -gt 0) {
    $ArgsList += @("--limit", "$Limit")
}
if ($Resume) {
    $ArgsList += "--resume"
}
if ($Force) {
    $ArgsList += "--force"
}
node @ArgsList
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($Train) {
    docker cp $Output ml-model:/app/data/mobsf_static_dataset.csv
    docker exec ml-model sh -lc "cd /app && python - <<'PY'
from src.model.trainer import train_model
train_model('/app/data/mobsf_static_dataset.csv')
PY"
}
