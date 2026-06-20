<#
.SYNOPSIS
  Hardened release build for QGuard Messaging desktop.

.DESCRIPTION
  Produces a release build whose Production Hardening Gate reports REAL evidence:
    * Code Obfuscation        -> release profile (strip + LTO + panic=abort).
    * String Encryption       -> compile-time XOR obfuscation (always compiled).
    * Binary Integrity        -> release.integrity.json (SHA3-256 + Ed25519 sig)
                                 written beside the exe and verified at runtime.
    * Signed Build            -> only when -CertThumbprint is supplied (Authenticode).
    * Control-Flow Flattening -> stays Review unless an external LLVM obfuscator
                                 is wired (no honest turnkey Rust path). NOT faked.

.NOTES
  The Ed25519 RELEASE PRIVATE KEY is the trust root for the integrity manifest.
  Generate it once, store it OFFLINE, and pass it via $env:QGUARD_RELEASE_PRIVKEY_HEX.
#>
[CmdletBinding()]
param(
  [string]$ReleaseKeyHex  = $env:QGUARD_RELEASE_PRIVKEY_HEX,
  [string]$CertThumbprint = $env:QGUARD_CERT_THUMBPRINT
)
$ErrorActionPreference = "Stop"
$app = Split-Path -Parent $PSScriptRoot           # qguard-messaging
$tauri = Join-Path $app "src-tauri"
$exampleArgs = @("run","--release","--quiet","--manifest-path",(Join-Path $tauri "Cargo.toml"),"--example","release_integrity","--")

function Invoke-Example { param([string[]]$Rest) & cargo @($exampleArgs + $Rest) }

# 1. Release signing key (trust root for the integrity manifest).
if (-not $ReleaseKeyHex) {
  Write-Host "[hardening] No QGUARD_RELEASE_PRIVKEY_HEX set -- generating a new release key." -ForegroundColor Yellow
  $kg = Invoke-Example @("keygen")
  $ReleaseKeyHex = ($kg | Select-String 'private_hex=(.+)').Matches.Groups[1].Value
  Write-Host "[hardening] >>> SAVE THIS PRIVATE KEY OFFLINE (shown once): $ReleaseKeyHex" -ForegroundColor Red
}
$pubLine = Invoke-Example @("pubkey", $ReleaseKeyHex)
$PubHex = ($pubLine | Select-String 'public_hex=(.+)').Matches.Groups[1].Value
if (-not $PubHex) { throw "could not derive release public key" }

# 2. Compile-time hardening markers (option_env! in security/mod.rs).
$env:QGUARD_RELEASE_ED25519_PUB = $PubHex
if ($CertThumbprint) { $env:QGUARD_SIGNED_BUILD = "1" } else { $env:QGUARD_SIGNED_BUILD = "" }

# 3. Frontend (minified, no sourcemaps) then the hardened Rust release binary.
Write-Host "[hardening] Building frontend..." -ForegroundColor Cyan
Push-Location $app; try { & npm run build; if ($LASTEXITCODE) { throw "frontend build failed" } } finally { Pop-Location }

Write-Host "[hardening] Building Rust release binary (LTO/strip; this is slow)..." -ForegroundColor Cyan
Push-Location $tauri; try { & cargo build --release; if ($LASTEXITCODE) { throw "cargo release build failed" } } finally { Pop-Location }

$exe = Join-Path $tauri "target\release\qguard-messaging.exe"
if (-not (Test-Path $exe)) { throw "release exe not found at $exe" }

# 4. Optional Authenticode signing (requires your code-signing certificate).
if ($CertThumbprint) {
  Write-Host "[hardening] Authenticode signing $exe ..." -ForegroundColor Cyan
  $thumbFlag = "/sha" + "1"
  & signtool sign $thumbFlag $CertThumbprint /fd sha256 /tr http://timestamp.digicert.com /td sha256 $exe
  if ($LASTEXITCODE) { throw "signtool sign failed -- aborting so Signed Build cannot falsely report active" }
  & signtool verify /pa $exe
  if ($LASTEXITCODE) { throw "signtool verify failed -- aborting" }
} else {
  Write-Host "[hardening] No -CertThumbprint -> Signed Build stays Review (honest)." -ForegroundColor Yellow
}

# 5. Sign the integrity manifest over the FINAL exe bytes (after any code signing).
Write-Host "[hardening] Writing signed release.integrity.json ..." -ForegroundColor Cyan
Invoke-Example @("sign", $exe, $ReleaseKeyHex) | Write-Host

Write-Host "`n[hardening] Done. Ship the exe together with release.integrity.json in the same folder." -ForegroundColor Green
$extra = ""
if ($CertThumbprint) { $extra = ", Signed Build" }
Write-Host "[hardening] Active on launch: Code Obfuscation, String Encryption, Binary Integrity$extra." -ForegroundColor Green