# One-command pipeline: ingest new mail, refresh enrichment + reports, and
# deploy the dashboard to Azure Static Web Apps.
#
#   .\publish.ps1                 # full run: ingest -> lookups -> reports -> deploy
#   .\publish.ps1 -SkipIngest     # just rebuild reports + deploy (no new mail)
#   .\publish.ps1 -SkipDeploy     # local only, nothing sent to Azure
#
# Raw emails NEVER leave this machine. The only thing deployed is
# dashboard/ -- the static app plus data/data.json, which holds extracted,
# defanged indicators and aggregate stats (built by build_dashboard_data.py).
#
# One-time setup for deploys:
#   1. Create a free Azure Static Web App (portal: Static Web Apps -> Create,
#      plan "Free", deployment source "Other").
#   2. npm install -g @azure/static-web-apps-cli
#   3. Grab the deployment token (portal: your SWA -> Manage deployment token)
#      and set it once for your user:
#        [Environment]::SetEnvironmentVariable("SWA_CLI_DEPLOYMENT_TOKEN", "<token>", "User")
#   4. Lock the site to yourself: portal -> Role management -> Invite, your
#      email, role "analyst" (staticwebapp.config.json only admits that role).

param(
    [switch]$SkipIngest,
    [switch]$SkipDeploy,
    [switch]$SkipLookups
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not $SkipIngest) {
    Write-Host "`n=== 1/4 Ingesting data/input/ (lookups run automatically) ===" -ForegroundColor Cyan
    if ($SkipLookups) { python scripts/process_mail.py --skip-lookups } else { python scripts/process_mail.py }
    if ($LASTEXITCODE -ne 0) { throw "process_mail.py failed" }
} else {
    Write-Host "`n=== 1/4 Skipping ingest ===" -ForegroundColor DarkGray
}

Write-Host "`n=== 2/4 Rebuilding output/master_report.xlsx ===" -ForegroundColor Cyan
python scripts/build_master_report.py
if ($LASTEXITCODE -ne 0) { throw "build_master_report.py failed" }

Write-Host "`n=== 3/4 Rebuilding dashboard/data/data.json ===" -ForegroundColor Cyan
python scripts/build_dashboard_data.py
if ($LASTEXITCODE -ne 0) { throw "build_dashboard_data.py failed" }

if ($SkipDeploy) {
    Write-Host "`n=== 4/4 Skipping deploy (preview locally: python -m http.server -d dashboard 8080) ===" -ForegroundColor DarkGray
    exit 0
}

Write-Host "`n=== 4/4 Deploying dashboard/ to Azure Static Web Apps ===" -ForegroundColor Cyan
if (-not $env:SWA_CLI_DEPLOYMENT_TOKEN) {
    throw "SWA_CLI_DEPLOYMENT_TOKEN is not set -- see the one-time setup notes at the top of this script."
}
swa deploy dashboard --env production
if ($LASTEXITCODE -ne 0) { throw "swa deploy failed" }

Write-Host "`nDone." -ForegroundColor Green
