# Builds, signs, and publishes the QGuard Messaging Windows installer.
# (ASCII only: PowerShell 5.1 reads BOM-less scripts as ANSI, and smart
# punctuation bytes can be parsed as quote characters.)
#
#   powershell -ExecutionPolicy Bypass -File tools\release-installer.ps1
#   powershell ... -File tools\release-installer.ps1 -BaseUrl "https://your-domain" -Notes "What changed"
#
# Does four things:
#  1. Loads the updater signing key (src-tauri\updater-keys\ - NEVER commit it).
#  2. Runs `npx tauri build` with retries - antivirus real-time scanning
#     intermittently locks fresh build archives on this machine (os error 32).
#  3. Copies the setup exe to ..\public\downloads\QGuard-Messaging-Setup.exe.
#  4. Writes ..\public\downloads\latest.json (the signed-update manifest the
#     installed apps poll). Deploy public\downloads to $BaseUrl for updates to
#     reach users; bump `version` in src-tauri\tauri.conf.json per release.
param(
  [string]$BaseUrl = "https://api.qguard.dev",
  [string]$Notes = "Security and reliability improvements."
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$keyPath = Join-Path $root "src-tauri\updater-keys\qguard-messaging.key"
if (-not (Test-Path $keyPath)) { throw "Updater signing key missing: $keyPath (run: npx tauri signer generate)" }
# Tauri v2 reads TAURI_SIGNING_PRIVATE_KEY (the key CONTENT or a path) -- there
# is no *_PATH variant. Pass the raw key text so path-detection quirks can't
# leave the signer unable to find the private half (the "public key found but
# no private key" failure).
$env:TAURI_SIGNING_PRIVATE_KEY = (Get-Content $keyPath -Raw).Trim()
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = (Get-Content "$keyPath.password" -Raw).Trim()

# Build OUTSIDE the user-profile Music library: Windows Search / AV watch
# profile libraries and lock fresh .rlib/.lib archives mid-build, which made
# release builds fail with os error 32. AppData\Local is not indexed.
if (-not $env:CARGO_TARGET_DIR) {
  $env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA "qguard-messaging-target"
}
$targetDir = $env:CARGO_TARGET_DIR

$built = $false
for ($attempt = 1; $attempt -le 4; $attempt++) {
  Write-Host "=== tauri build attempt $attempt ==="
  npx tauri build
  if ($LASTEXITCODE -eq 0) { $built = $true; break }
  Write-Host "Build failed (often a transient AV file lock) - retrying in 10s..."
  Start-Sleep -Seconds 10
}
if (-not $built) { throw "tauri build failed after 4 attempts" }

$conf = Get-Content (Join-Path $root "src-tauri\tauri.conf.json") -Raw | ConvertFrom-Json
$version = $conf.version
$bundle = Get-ChildItem (Join-Path $targetDir "release\bundle\nsis\*_${version}_*-setup.exe") | Select-Object -First 1
if (-not $bundle) { throw "No v$version setup exe found under $targetDir\release\bundle\nsis" }
$sigPath = "$($bundle.FullName).sig"
if (-not (Test-Path $sigPath)) { throw "Updater signature missing: $sigPath (is bundle.createUpdaterArtifacts true?)" }

$downloads = Join-Path $root "..\public\downloads"
New-Item -ItemType Directory -Force $downloads | Out-Null
Copy-Item $bundle.FullName (Join-Path $downloads "QGuard-Messaging-Setup.exe") -Force

$manifest = @{
  version  = $version
  notes    = $Notes
  pub_date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  platforms = @{
    "windows-x86_64" = @{
      signature = (Get-Content $sigPath -Raw).Trim()
      url       = "$BaseUrl/downloads/QGuard-Messaging-Setup.exe"
    }
  }
}
# WriteAllText emits UTF-8 WITHOUT a BOM. PowerShell 5.1's `Out-File -Encoding
# utf8` prepends a BOM, and Tauri's updater parses this manifest with serde_json,
# which rejects a leading BOM ("expected value") -- silently breaking updates.
$manifestJson = $manifest | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText((Join-Path $downloads "latest.json"), $manifestJson)

Write-Host ""
Write-Host "Published v${version}:"
Get-FileHash (Join-Path $downloads "QGuard-Messaging-Setup.exe") -Algorithm SHA256 | Format-List Algorithm, Hash
Write-Host "Installer + latest.json in public\downloads (update url base: ${BaseUrl})"
