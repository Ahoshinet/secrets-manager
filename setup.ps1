# Secrets Manager setup script
# Cross-platform (PowerShell Core / pwsh 7+). Linux = full production install;
# Windows = local/dev install (build + passphrase + run instructions).
#
# Unlike a typical web app, this server:
#   - stores no .env and has no JWT; the ONLY secret it needs is a master
#     passphrase, from which the encryption key is derived (Argon2id).
#   - binds LOOPBACK ONLY (default 127.0.0.1:8787); TLS is terminated by nginx.
#     The app port is never opened in the firewall.
#   - reads runtime settings from SECRETS_* env vars and the passphrase from a
#     systemd credential (LoadCredential) on Linux.
#
# REQUIREMENTS: PowerShell 7+ (pwsh). On Linux run as root (sudo pwsh ./setup.ps1).
#
# EXAMPLES:
#   sudo pwsh ./setup.ps1 -Domain secrets.example.com
#   sudo pwsh ./setup.ps1 -Domain secrets.example.com -Port 8787 -SkipNginx
#   pwsh ./setup.ps1            # Windows: local dev install
#
# PARAMETERS (see below).

param(
    [switch]$Win,
    [string]$Domain = "secrets.example.com",
    [int]$Port = 8787,
    [string]$InstallPrefix = "/usr/local/bin",
    [string]$SSLCertPath,
    [string]$SSLKeyPath,
    [string]$DataDir,                 # Windows only: local data/passphrase dir
    [switch]$SkipBuild,
    [switch]$SkipService,
    [switch]$SkipNginx,
    [switch]$Force                    # overwrite an existing passphrase file
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:IsWindowsMode = $false
$script:ProjectRoot = $null
$script:Bind = "127.0.0.1:$Port"
$script:ServiceName = "secrets-server"
$script:ServiceUser = "secrets"
$script:EtcDir = "/etc/secrets-manager"
$script:PassphraseFile = "/etc/secrets-manager/master-passphrase"

function Write-Info    { param([string]$m) Write-Host $m -ForegroundColor Green }
function Write-Step    { param([string]$m) Write-Host "=== $m ===" -ForegroundColor Cyan }
function Write-Note    { param([string]$m) Write-Host $m -ForegroundColor Yellow }
function Write-Err     { param([string]$m) Write-Host $m -ForegroundColor Red }
function Assert-Exit   { param([string]$label) if ($LASTEXITCODE -ne 0) { throw "$label failed (exit=$LASTEXITCODE)" } }

# --- OS detection -----------------------------------------------------
function Detect-OS {
    Write-Step "Detecting OS"
    if ($Win -or ($IsWindows)) {
        $script:IsWindowsMode = $true
        Write-Note "Mode: Windows (local/dev)"
    } else {
        $script:IsWindowsMode = $false
        Write-Note "Mode: Linux (production)"
    }
}

# --- find repo root (contains Cargo.toml with [workspace]) ------------
function Find-ProjectRoot {
    Write-Step "Locating project root"
    $p = Get-Location
    for ($i = 0; $i -lt 10; $i++) {
        if (Test-Path (Join-Path $p "Cargo.toml")) { $script:ProjectRoot = "$p"; break }
        $parent = Split-Path $p -Parent
        if (-not $parent -or $parent -eq $p) { break }
        $p = $parent
    }
    if (-not $script:ProjectRoot) {
        Write-Err "Cargo.toml not found. Run this from inside the secrets-manager checkout."
        exit 1
    }
    Write-Info "Project root: $script:ProjectRoot"
}

function Assert-Root {
    if ($script:IsWindowsMode) { return }
    $uid = (& id -u)
    if ($uid -ne "0") {
        Write-Err "Linux production install must run as root. Re-run: sudo pwsh ./setup.ps1"
        exit 1
    }
}

function Assert-Tools {
    Write-Step "Checking toolchain"
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Err "cargo not found. Install Rust: https://rustup.rs  then re-run."
        exit 1
    }
    & cargo --version | ForEach-Object { Write-Info $_ }
}

# --- generate a high-entropy master passphrase (never printed) --------
function New-Passphrase {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToBase64String($bytes)
}

function Build-Binaries {
    if ($SkipBuild) { Write-Note "Skipping build (-SkipBuild)"; return }
    Write-Step "Building release binaries"
    Push-Location $script:ProjectRoot
    try {
        & cargo build --release --locked --bins
        Assert-Exit "cargo build --release"
    } finally { Pop-Location }
    Write-Info "Built secrets-server and secrets."
}

# ====================================================================
# Linux production install
# ====================================================================
function Install-Linux {
    $binExt = ""
    $serverBin = Join-Path $script:ProjectRoot "target/release/secrets-server"
    $clientBin = Join-Path $script:ProjectRoot "target/release/secrets"

    # 1) service user
    Write-Step "Creating service user '$script:ServiceUser'"
    & id $script:ServiceUser *> $null
    if ($LASTEXITCODE -ne 0) {
        & useradd --system --no-create-home --shell /usr/sbin/nologin $script:ServiceUser
        Assert-Exit "useradd"
        Write-Info "Created system user '$script:ServiceUser'."
    } else { Write-Note "User '$script:ServiceUser' already exists." }

    # 2) install binaries
    Write-Step "Installing binaries to $InstallPrefix"
    & install -m 0755 $serverBin (Join-Path $InstallPrefix "secrets-server"); Assert-Exit "install secrets-server"
    & install -m 0755 $clientBin (Join-Path $InstallPrefix "secrets");        Assert-Exit "install secrets"
    Write-Info "Installed secrets-server, secrets -> $InstallPrefix"

    # 3) master passphrase (root:root 0600) consumed by systemd LoadCredential
    Write-Step "Provisioning master passphrase"
    & install -d -m 0700 $script:EtcDir; Assert-Exit "mkdir $script:EtcDir"
    if ((Test-Path $script:PassphraseFile) -and -not $Force) {
        Write-Note "Passphrase file already exists at $script:PassphraseFile (keeping it; use -Force to regenerate)."
    } else {
        if ((Test-Path $script:PassphraseFile) -and $Force) {
            Write-Note "WARNING: regenerating the passphrase makes all EXISTING secrets undecryptable."
            Write-Note "Only proceed on a fresh install, or rekey first."
        }
        $pass = New-Passphrase
        # Write with no trailing newline; the server strips one trailing newline anyway.
        [System.IO.File]::WriteAllText($script:PassphraseFile, $pass)
        $pass = $null
        & chmod 600 $script:PassphraseFile; Assert-Exit "chmod passphrase"
        & chown root:root $script:PassphraseFile; Assert-Exit "chown passphrase"
        Write-Info "Wrote $script:PassphraseFile (root:root 0600)."
        Write-Note "BACK THIS FILE UP OFFLINE. If it is lost, every stored secret is unrecoverable."
    }

    if ($SkipService) { Write-Note "Skipping systemd service (-SkipService)"; return }

    # 4) systemd unit (from repo template; patch bind if non-default)
    Write-Step "Installing systemd service"
    $unitSrc = Join-Path $script:ProjectRoot "deploy/systemd/secrets-server.service"
    $unit = Get-Content $unitSrc -Raw
    if ($script:Bind -ne "127.0.0.1:8787") {
        $unit = $unit -replace "SECRETS_BIND=127\.0\.0\.1:8787", "SECRETS_BIND=$($script:Bind)"
    }
    $unitDst = "/etc/systemd/system/secrets-server.service"
    [System.IO.File]::WriteAllText($unitDst, $unit)
    Write-Info "Installed $unitDst"

    & systemctl daemon-reload; Assert-Exit "daemon-reload"
    & systemctl enable secrets-server.service; Assert-Exit "enable"
    & systemctl restart secrets-server.service; Assert-Exit "restart"
    Start-Sleep -Seconds 2
    $state = (& systemctl is-active secrets-server.service 2>$null | Out-String).Trim()
    if ($state -eq "active") { Write-Info "secrets-server is active." }
    else {
        Write-Err "secrets-server is '$state'. Recent logs:"
        & journalctl -u secrets-server.service -n 20 --no-pager
        throw "service failed to start"
    }

    # 5) health check on loopback
    Write-Step "Health check"
    $code = (& curl -s -o /dev/null -w "%{http_code}" "http://$($script:Bind)/v1/health" 2>$null)
    if ($code -eq "200") { Write-Info "GET /v1/health -> 200 OK" } else { Write-Note "GET /v1/health -> $code (check logs)" }

    if (-not $SkipNginx) { Install-Nginx }
    Configure-Firewall
}

function Install-Nginx {
    Write-Step "Configuring nginx reverse proxy"
    if (-not (Get-Command nginx -ErrorAction SilentlyContinue)) {
        Write-Note "nginx not installed; installing..."
        & apt-get update; & apt-get install -y nginx
    }
    $certPath = if ($SSLCertPath) { $SSLCertPath } else { "/etc/letsencrypt/live/$Domain/fullchain.pem" }
    $keyPath = if ($SSLKeyPath) { $SSLKeyPath } else { "/etc/letsencrypt/live/$Domain/privkey.pem" }
    if (-not (Test-Path $certPath) -or -not (Test-Path $keyPath)) {
        Write-Err "TLS certificate files were not found for nginx:"
        Write-Err "  certificate: $certPath"
        Write-Err "  private key: $keyPath"
        $enabled = "/etc/nginx/sites-enabled/$Domain"
        if (Test-Path $enabled) {
            Write-Note "An existing enabled nginx site may still reference missing certs: $enabled"
        }
        Write-Note "Use your real -Domain, provision the certificate first, or pass -SSLCertPath/-SSLKeyPath."
        Write-Note "To install the server without nginx for now, re-run with -SkipNginx."
        throw "nginx TLS certificate is missing"
    }

    $confSrc = Join-Path $script:ProjectRoot "deploy/nginx/secrets-manager.conf"
    $conf = Get-Content $confSrc -Raw
    $conf = $conf -replace "secrets\.example\.com", $Domain
    $conf = $conf -replace "ssl_certificate\s+\S+;", "ssl_certificate $certPath;"
    $conf = $conf -replace "ssl_certificate_key\s+\S+;", "ssl_certificate_key $keyPath;"
    if ($script:Bind -ne "127.0.0.1:8787") { $conf = $conf -replace "127\.0\.0\.1:8787", $script:Bind }

    $avail = "/etc/nginx/sites-available/$Domain"
    [System.IO.File]::WriteAllText($avail, $conf)
    $enabled = "/etc/nginx/sites-enabled/$Domain"
    if (-not (Test-Path $enabled)) { & ln -s $avail $enabled }
    Write-Info "Wrote $avail and enabled the site."

    & nginx -t
    if ($LASTEXITCODE -ne 0) {
        Write-Err "nginx config test failed. Fix certs/domain in $avail, then: nginx -t && systemctl reload nginx"
        return
    }
    & systemctl reload nginx; Assert-Exit "nginx reload"
    Write-Info "nginx reloaded."
}

function Configure-Firewall {
    Write-Step "Firewall"
    # Only 80/443 (nginx). The app port ($script:Bind) is loopback and must NOT be exposed.
    if (Get-Command ufw -ErrorAction SilentlyContinue) {
        & ufw allow 'Nginx Full' 2>$null
        Write-Info "Allowed 80/443 via ufw (app port stays loopback-only)."
    } else {
        Write-Note "ufw not found. Open 80 and 443 in your firewall; do NOT open the app port ($script:Bind)."
    }
}

# ====================================================================
# Windows local/dev install
# ====================================================================
function Install-Windows {
    if (-not $DataDir) { $DataDir = Join-Path $env:LOCALAPPDATA "secrets-manager" }
    Write-Step "Windows local/dev setup ($DataDir)"
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

    $ppFile = Join-Path $DataDir "master-passphrase"
    if ((Test-Path $ppFile) -and -not $Force) {
        Write-Note "Passphrase file exists at $ppFile (keeping it; use -Force to regenerate)."
    } else {
        $pass = New-Passphrase
        [System.IO.File]::WriteAllText($ppFile, $pass)
        $pass = $null
        # Restrict to the current user only. Use the fully-qualified identity
        # (DOMAIN\user or COMPUTER\user); a bare username may fail to resolve,
        # which would leave an empty DACL that denies read to everyone -- even
        # the owner -- so `serve` could not open the passphrase file.
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls $ppFile /inheritance:r /grant:r "${me}:(R,W)" > $null
        if ($LASTEXITCODE -ne 0) { throw "icacls failed to restrict $ppFile (exit=$LASTEXITCODE)" }
        Write-Info "Wrote $ppFile (restricted to $me)."
        Write-Note "BACK THIS FILE UP OFFLINE. If lost, every stored secret is unrecoverable."
    }

    $serverExe = Join-Path $script:ProjectRoot "target\release\secrets-server.exe"
    $clientExe = Join-Path $script:ProjectRoot "target\release\secrets.exe"
    $dbPath    = Join-Path $DataDir "secrets.db"
    $auditPath = Join-Path $DataDir "audit.jsonl"

    Write-Host ""
    Write-Info "Setup complete (Windows dev). To run the server:"
    Write-Host ""
    Write-Host "  `$env:SECRETS_DB_PATH        = `"$dbPath`""       -ForegroundColor White
    Write-Host "  `$env:SECRETS_AUDIT_PATH     = `"$auditPath`""    -ForegroundColor White
    Write-Host "  `$env:SECRETS_BIND           = `"$($script:Bind)`"" -ForegroundColor White
    Write-Host "  `$env:SECRETS_PASSPHRASE_FILE= `"$ppFile`""       -ForegroundColor White
    Write-Host "  & `"$serverExe`" serve"                            -ForegroundColor White
    Write-Host ""
    Write-Info "Create a token (server may be stopped for this):"
    Write-Host "  & `"$serverExe`" token create --name dev"          -ForegroundColor White
    Write-Host ""
    Write-Note "Production deployment (systemd + nginx + LoadCredential) is Linux-only; run this script on the VPS with 'sudo pwsh ./setup.ps1'."
}

# --- next steps banner (Linux) ---------------------------------------

function Show-NextSteps {
    Write-Host ""
    Write-Info "======================================================"
    Write-Info " Setup complete."
    Write-Info "======================================================"
    Write-Host ""
    Write-Note "Next steps:"
    Write-Host "  1) Issue an access token (90-day TTL by default):"        -ForegroundColor White
    Write-Host "       sudo -u $script:ServiceUser SECRETS_DB_PATH=/var/lib/secrets-manager/secrets.db \\" -ForegroundColor White
    Write-Host "         secrets-server token create --name ci --project app" -ForegroundColor White
    Write-Host "  2) Provision a project via the API (admin operation):"    -ForegroundColor White
    Write-Host "       curl -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \\" -ForegroundColor White
    Write-Host "         -d '{`"name`":`"app`"}' https://$Domain/v1/projects" -ForegroundColor White
    Write-Host "  3) On a client machine, point the CLI at the server:"     -ForegroundColor White
    Write-Host "       export SECRETS_SERVER_URL=https://$Domain"           -ForegroundColor White
    Write-Host "       export SECRETS_TOKEN=<token>"                        -ForegroundColor White
    Write-Host "       secrets set app DATABASE_URL   # value read from stdin/prompt" -ForegroundColor White
    Write-Host "       secrets run app -- your-program" -ForegroundColor White
    Write-Host ""
    Write-Note "Manage the service: systemctl status|restart secrets-server ; journalctl -u secrets-server -f"
    Write-Note "Rebuild after code changes: sudo pwsh ./scripts/rebuild.ps1"
}

# --- main -------------------------------------------------------------
function Main {
    Write-Info "======================================================"
    Write-Info " Secrets Manager setup"
    Write-Info "======================================================"
    Detect-OS
    Find-ProjectRoot
    Assert-Root
    Assert-Tools
    Build-Binaries

    if ($script:IsWindowsMode) {
        Install-Windows
    } else {
        Install-Linux
        Show-NextSteps
    }
}

Main
