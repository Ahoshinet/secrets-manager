<#
.SYNOPSIS
    Rebuild secrets-server on the production host.

.DESCRIPTION
    Pull the latest code, rebuild the release binaries, reinstall them to the
    install prefix (where the systemd unit's ExecStart points), and restart the
    service. Run directly on the VPS as root (sudo pwsh ./scripts/rebuild.ps1).

    Note: the systemd unit runs /usr/local/bin/secrets-server, so a fresh
    `cargo build` alone is not enough — the binary must be reinstalled to the
    prefix. This script does that.

.EXAMPLE
    sudo pwsh ./scripts/rebuild.ps1
    sudo pwsh ./scripts/rebuild.ps1 -SkipGit
    sudo pwsh ./scripts/rebuild.ps1 -SkipBuild        # restart only
#>
param(
    [string]$ServiceName   = "secrets-server",
    [string]$Branch        = "master",
    [string]$InstallPrefix = "/usr/local/bin",
    [switch]$SkipGit,
    [switch]$SkipBuild,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step    { param([string]$m) Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-Info    { param([string]$m) Write-Host "info: $m" }
function Write-Success { param([string]$m) Write-Host "ok: $m" -ForegroundColor Green }
function Write-Warn    { param([string]$m) Write-Host "warn: $m" -ForegroundColor Yellow }
function Write-Err     { param([string]$m) Write-Host "error: $m" -ForegroundColor Red }
function Assert-Exit   { param([string]$label) if ($LASTEXITCODE -ne 0) { throw "$label failed (exit=$LASTEXITCODE)" } }

if ($Help) {
    Write-Host "secrets-server rebuild script"
    Write-Host ""
    Write-Host "Usage: sudo pwsh ./scripts/rebuild.ps1 [options]"
    Write-Host "  -ServiceName    systemd service name (default: secrets-server)"
    Write-Host "  -Branch         git branch (default: master)"
    Write-Host "  -InstallPrefix  where to install binaries (default: /usr/local/bin)"
    Write-Host "  -SkipGit        skip git pull"
    Write-Host "  -SkipBuild      skip build+install (restart only)"
    Write-Host "  -Help           show this help"
    exit 0
}

function Test-SystemdEnabled { param([string]$n) & systemctl is-enabled $n *> $null; return ($LASTEXITCODE -eq 0) }
function Get-SystemdActive    { param([string]$n) try { (& systemctl is-active $n 2>$null | Out-String).Trim() } catch { "unknown" } }

# --- preflight --------------------------------------------------------
if (-not (Get-Command systemctl -ErrorAction SilentlyContinue)) {
    Write-Err "systemctl not found (this script is for the Linux production host)."
    exit 1
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Err "cargo not found. Install the Rust toolchain first."
    exit 1
}
if ((& id -u) -ne "0") {
    Write-Err "Run as root: sudo pwsh ./scripts/rebuild.ps1"
    exit 1
}

# Find repo root (contains Cargo.toml): this script lives in <repo>/scripts.
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not (Test-Path (Join-Path $repoRoot "Cargo.toml"))) {
    Write-Err "Cargo.toml not found at $repoRoot. Run from the repo's scripts/ directory."
    exit 1
}

Write-Host "Rebuilding $ServiceName (repo: $repoRoot)"
Push-Location $repoRoot
try {
    # --- stop service ---
    if (Test-SystemdEnabled -n $ServiceName) {
        Write-Step "Stopping $ServiceName"
        & systemctl stop $ServiceName; Assert-Exit "systemctl stop"
    } else {
        Write-Warn "$ServiceName is not enabled; continuing (will not auto-start at end)."
    }

    # --- git pull ---
    if (-not $SkipGit) {
        Write-Step "Updating source ($Branch)"
        $dirty = & git status --porcelain 2>$null
        if ($dirty) {
            Write-Warn "Uncommitted changes detected:"
            & git status --short
            $choice = ""
            while ($choice -notin @('1','2','3')) {
                Write-Host "  1) stash, pull, restore   2) discard local changes and pull   3) skip pull"
                $choice = Read-Host "select [1-3]"
            }
            switch ($choice) {
                '1' {
                    & git stash push -m "rebuild.ps1 $(Get-Date -Format s)"; Assert-Exit "git stash"
                    & git pull origin $Branch; Assert-Exit "git pull"
                    & git stash pop
                    if ($LASTEXITCODE -ne 0) { Write-Warn "stash pop conflicted; resolve manually, then re-run with -SkipGit." }
                }
                '2' {
                    & git reset --hard HEAD; Assert-Exit "git reset"
                    & git clean -fd;         Assert-Exit "git clean"
                    & git pull origin $Branch; Assert-Exit "git pull"
                }
                '3' { Write-Warn "Skipped git pull." }
            }
        } else {
            & git pull origin $Branch; Assert-Exit "git pull"
        }
    } else { Write-Warn "Skipping git pull (-SkipGit)" }

    # --- build + install ---
    if (-not $SkipBuild) {
        Write-Step "cargo build --release --locked --bins"
        & cargo build --release --locked --bins; Assert-Exit "cargo build"

        Write-Step "Installing binaries to $InstallPrefix"
        & install -m 0755 (Join-Path $repoRoot "target/release/secrets-server") (Join-Path $InstallPrefix "secrets-server"); Assert-Exit "install secrets-server"
        & install -m 0755 (Join-Path $repoRoot "target/release/secrets")        (Join-Path $InstallPrefix "secrets");        Assert-Exit "install secrets"
        Write-Success "Binaries reinstalled."
    } else { Write-Warn "Skipping build+install (-SkipBuild)" }

    # --- start service ---
    if (Test-SystemdEnabled -n $ServiceName) {
        Write-Step "Starting $ServiceName"
        & systemctl start $ServiceName; Assert-Exit "systemctl start"
        Start-Sleep -Seconds 2
        $state = Get-SystemdActive -n $ServiceName
        if ($state -eq "active") { Write-Success "$ServiceName is active" }
        else {
            Write-Err "$ServiceName is $state; recent logs:"
            & journalctl -u $ServiceName -n 20 --no-pager
            throw "service failed to start"
        }
    } else {
        Write-Warn "$ServiceName not enabled; not starting. Enable with: systemctl enable --now $ServiceName"
        exit 0
    }

    # --- health check (loopback; endpoint is /v1/health) ---
    Write-Step "Health check"
    $bind = (& systemctl show $ServiceName -p Environment --value 2>$null | Select-String -Pattern 'SECRETS_BIND=(\S+)' | ForEach-Object { $_.Matches[0].Groups[1].Value })
    if (-not $bind) { $bind = "127.0.0.1:8787" }
    $code = (& curl -s -o /dev/null -w "%{http_code}" "http://$bind/v1/health" 2>$null)
    if ($code -eq "200") { Write-Success "GET /v1/health -> 200 OK" } else { Write-Warn "GET /v1/health -> $code" }

    Write-Host ""
    Write-Success "Rebuild complete."
    exit 0
}
catch {
    Write-Err "rebuild failed: $($_.Exception.Message)"
    if ((Get-SystemdActive -n $ServiceName) -ne "active") {
        Write-Warn "Attempting to restart $ServiceName..."
        & systemctl start $ServiceName 2>$null
    }
    exit 1
}
finally {
    Pop-Location
}
