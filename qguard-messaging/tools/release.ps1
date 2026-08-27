<#
.SYNOPSIS
  One-command QGuard Messaging release: set the version everywhere, build + sign
  the installer, publish it to public/downloads, and (optionally) push to deploy.

.DESCRIPTION
  Removes the three-place version footgun (a missed bump silently breaks
  auto-update). Given -Version 1.3.0 it:
    1. Sets the version in src-tauri/tauri.conf.json, src-tauri/Cargo.toml, and the
       website download label (../src/app/qguard-messaging/_shared.tsx).
    2. Runs tools/release-installer.ps1 (loads the updater signing key from
       src-tauri/updater-keys, builds with AV-lock retries, copies the exe to
       public/downloads, writes a signed latest.json).
    3. Updates the website label's sizeMb AND the published SHA-256 checksum
       to match the freshly built installer.
    4. With -Push: commits the release and pushes main, which triggers the
       production deploy (Cloudflare Pages -> qguardhelix.com).

  ASCII only (PowerShell 5.1 reads BOM-less scripts as ANSI; smart punctuation
  can be mis-parsed as quotes).

.EXAMPLE
  # Local build only (no deploy) - the installer lands in public/downloads and
  # the target dir, ready for manual download / local testing:
  pwsh tools/release.ps1 -Version 1.3.0

.EXAMPLE
  # Build AND deploy (commit + push main):
  pwsh tools/release.ps1 -Version 1.3.0 -Notes "What changed" -Push

.NOTES
  * Keep src-tauri/updater-keys (key + .password) backed up OFFLINE. Losing it
    means no installed app will accept future updates. See RELEASE.md.
  * The updater endpoint is COMPILED from tauri.conf.json (plugins.updater.
    endpoints) at build time. For production it must be a domain that actually
    serves public/downloads. See RELEASE.md "Going live" - do this once before
    your first production release.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Notes = "Security and reliability improvements.",
  [string]$BaseUrl = "https://api.qguard.dev",
  [switch]$Push
)
$ErrorActionPreference = "Stop"
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
  throw "Version must be MAJOR.MINOR.PATCH, e.g. 1.3.0 (got '$Version')."
}

$app   = Split-Path -Parent $PSScriptRoot        # qguard-messaging
$repo  = Split-Path -Parent $app                 # repo root
$tauriConf = Join-Path $app  "src-tauri\tauri.conf.json"
$cargo     = Join-Path $app  "src-tauri\Cargo.toml"
$shared    = Join-Path $repo "src\app\qguard-messaging\_shared.tsx"

# Replace via .NET regex and write UTF-8 WITHOUT a BOM (WriteAllText default),
# so JSON/TOML/TSX stay byte-clean. Throws if the pattern is missing, so a
# renamed field fails loudly instead of silently shipping a stale version.
function Set-FileRegex {
  param([string]$Path, [string]$Pattern, [string]$Replacement, [int]$Count = 0)
  if (-not (Test-Path $Path)) { throw "Missing file: $Path" }
  $text = [System.IO.File]::ReadAllText($Path)
  $rx = [regex]$Pattern
  if ($rx.Matches($text).Count -eq 0) { throw "Version pattern not found in $Path" }
  $new = if ($Count -gt 0) { $rx.Replace($text, $Replacement, $Count) } else { $rx.Replace($text, $Replacement) }
  [System.IO.File]::WriteAllText($Path, $new)
}

Write-Host "[release] Setting version to $Version across 3 files" -ForegroundColor Cyan
# tauri.conf.json: the single top-level "version": "x.y.z"
Set-FileRegex $tauriConf '("version":\s*")\d+\.\d+\.\d+(")' "`${1}$Version`${2}"
# Cargo.toml: only the FIRST 'version = "x.y.z"' (the [package] one, not deps)
Set-FileRegex $cargo '(?m)^(version = ")\d+\.\d+\.\d+(")' "`${1}$Version`${2}" 1
# Website label: version: 'x.y.z' in MESSAGING_INSTALLER
Set-FileRegex $shared "(version:\s*')\d+\.\d+\.\d+(')" "`${1}$Version`${2}"

# Build + sign + publish (reuse the existing tool; do not duplicate its logic).
Write-Host "[release] Building + signing + publishing installer..." -ForegroundColor Cyan
& (Join-Path $PSScriptRoot "release-installer.ps1") -BaseUrl $BaseUrl -Notes $Notes
if ($LASTEXITCODE) { throw "release-installer.ps1 failed (exit $LASTEXITCODE)" }

# Sync the displayed size to the real installer.
$exe = Join-Path $repo "public\downloads\QGuard-Messaging-Setup.exe"
if (Test-Path $exe) {
  $sizeMb = [math]::Round((Get-Item $exe).Length / 1MB)
  Set-FileRegex $shared "(sizeMb:\s*)\d+" "`${1}$sizeMb"
  # Publish the checksum of the EXACT file just copied into public/downloads, so
  # the site's "verify your download" panel can never drift from the binary users
  # actually receive. Derived here rather than maintained by hand: a stale hash
  # accuses an honest download of being tampered with, which is worse than
  # showing none. Set-FileRegex throws if the field is missing, so a renamed or
  # deleted sha256 field fails the release loudly instead of shipping a lie.
  $sha256 = (Get-FileHash $exe -Algorithm SHA256).Hash.ToUpperInvariant()
  Set-FileRegex $shared "(sha256:\s*')[0-9A-Fa-f]{64}(')" "`${1}$sha256`${2}"
  Write-Host "[release] Website label: v$Version, ~$sizeMb MB" -ForegroundColor Cyan
  Write-Host "[release] Published SHA256: $sha256" -ForegroundColor Cyan
}

if ($Push) {
  Write-Host "[release] Committing + pushing main (this triggers the production deploy)..." -ForegroundColor Yellow
  Push-Location $repo
  try {
    git add public/downloads qguard-messaging/src-tauri/tauri.conf.json qguard-messaging/src-tauri/Cargo.toml qguard-messaging/src-tauri/Cargo.lock src/app/qguard-messaging/_shared.tsx
    git commit -m "Release $Version"
    if ($LASTEXITCODE) { throw "git commit failed (nothing staged?)" }
    git push origin main
    if ($LASTEXITCODE) { throw "git push failed" }
    Write-Host "[release] Pushed. Confirm the deploy finished on your host dashboard, then verify the live download shows v$Version." -ForegroundColor Green
  } finally { Pop-Location }
} else {
  Write-Host ""
  Write-Host "[release] LOCAL build only - nothing was pushed or deployed." -ForegroundColor Green
  Write-Host "[release] Installer: $exe" -ForegroundColor Green
  Write-Host "[release] To go live later: re-run with -Push, or commit public/downloads + the 3 version files and push main." -ForegroundColor Green
}
