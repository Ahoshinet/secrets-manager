<#
.SYNOPSIS
    Opinionated production quick start for Secrets Manager.

.DESCRIPTION
    Wraps setup.ps1 with practical nginx defaults for a Cloudflare Origin
    Certificate style deployment. Pass your own domain; the app still binds only
    to loopback, and nginx terminates TLS.

.EXAMPLE
    sudo pwsh ./scripts/quick-start.ps1 -Domain secrets-manager.example.com

.EXAMPLE
    sudo pwsh ./scripts/quick-start.ps1 -Domain secrets-manager.example.com `
      -SSLCertPath /etc/ssl/certs/cf.crt `
      -SSLKeyPath /etc/ssl/private/cf.key
#>
param(
    [string]$Domain,

    [int]$Port = 8787,
    [string]$SSLCertPath = "/etc/ssl/certs/cf.crt",
    [string]$SSLKeyPath = "/etc/ssl/private/cf.key",
    [string]$InstallPrefix = "/usr/local/bin",
    [switch]$SkipBuild,
    [switch]$SkipService,
    [switch]$SkipNginx,
    [switch]$Force,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info { param([string]$m) Write-Host $m -ForegroundColor Green }
function Write-Err  { param([string]$m) Write-Host $m -ForegroundColor Red }

if ($Help) {
    Write-Host "Secrets Manager quick start"
    Write-Host ""
    Write-Host "Usage: sudo pwsh ./scripts/quick-start.ps1 -Domain <fqdn> [options]"
    Write-Host "  -Domain         public HTTPS hostname, for example secrets.example.com"
    Write-Host "  -Port           local secrets-server port (default: 8787)"
    Write-Host "  -SSLCertPath    nginx TLS certificate (default: /etc/ssl/certs/cf.crt)"
    Write-Host "  -SSLKeyPath     nginx TLS private key (default: /etc/ssl/private/cf.key)"
    Write-Host "  -InstallPrefix  binary install prefix (default: /usr/local/bin)"
    Write-Host "  -SkipBuild      skip cargo build"
    Write-Host "  -SkipService    skip systemd service installation"
    Write-Host "  -SkipNginx      skip nginx reverse proxy installation"
    Write-Host "  -Force          regenerate the master passphrase; only safe on a fresh install"
    exit 0
}

if (-not $Domain) {
    Write-Err "-Domain is required. Example: sudo pwsh ./scripts/quick-start.ps1 -Domain secrets-manager.example.com"
    exit 1
}

if ($Domain -match '^https?://' -or $Domain -match '/') {
    Write-Err "-Domain must be a hostname only, for example secrets-manager.daruks.com"
    exit 1
}
if ($Domain -eq "secrets.example.com") {
    Write-Err "secrets.example.com is a placeholder; pass your real domain."
    exit 1
}
if ($Domain -notmatch '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' -or $Domain -notmatch '\.') {
    Write-Err "-Domain does not look like a valid fully-qualified domain name: $Domain"
    exit 1
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$setup = Join-Path $repoRoot "setup.ps1"
if (-not (Test-Path $setup)) {
    Write-Err "setup.ps1 not found at $setup"
    exit 1
}

Write-Info "Quick-starting Secrets Manager for https://$Domain"
Write-Info "Using nginx TLS certificate: $SSLCertPath"
Write-Info "Using nginx TLS private key: $SSLKeyPath"

$setupArgs = @(
    "-Domain", $Domain,
    "-Port", "$Port",
    "-SSLCertPath", $SSLCertPath,
    "-SSLKeyPath", $SSLKeyPath,
    "-InstallPrefix", $InstallPrefix
)

if ($SkipBuild) { $setupArgs += "-SkipBuild" }
if ($SkipService) { $setupArgs += "-SkipService" }
if ($SkipNginx) { $setupArgs += "-SkipNginx" }
if ($Force) { $setupArgs += "-Force" }

& $setup @setupArgs
