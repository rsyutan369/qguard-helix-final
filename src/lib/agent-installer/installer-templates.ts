/**
 * Qguard Helix Agent — installer artifact generators.
 *
 * Every generator returns a REAL, runnable artifact (spec §4, §7, §8): the
 * script downloads the published single-file agent runtime from this tenant's
 * own control plane, verifies its SHA-256 against the checksum embedded at
 * generation time, writes a 0600 configuration file, registers a supervised
 * service and reports each installation phase back to the backend.
 *
 * Pure functions — no Node or browser APIs — so the API server can render them
 * and the frontend can display/checksum them identically.
 *
 * Security posture (spec §23):
 *  - the enrollment token is written only to a root/Administrator-owned 0600
 *    configuration file, never echoed to stdout and never sent in a URL;
 *  - the runtime is fetched over the tenant's API URL with agent credentials in
 *    headers and rejected unless its digest matches;
 *  - no remote `curl | sh` bootstrap: download, verify, then execute.
 */

import {
  AGENT_MIN_NODE_MAJOR,
  AGENT_RUNTIME_FILENAME,
  agentPlatform,
  agentRole,
  type AgentPlatform,
  type AgentRole,
} from './agent-release'

export interface InstallerPolicy {
  intervalSeconds: number
  allowedTargets: string[]
  allowedPaths: string[]
  scanTypes: string[]
  alertThreshold: string
}

export interface InstallerContext {
  apiUrl: string
  tenantId: string
  agentId: string
  agentToken: string
  agentName: string
  role: AgentRole
  /** The scanned host's environment label (asset metadata) — QGUARD_AGENT_ENVIRONMENT. */
  environment: string
  /**
   * The control-plane trust environment the URL was validated against when
   * this package was generated — QGUARD_ENVIRONMENT. The agent re-validates
   * the same URL against the same environment at boot, so generation and
   * runtime apply identical rules. Defaults to development (the strictest
   * reading of a missing value is the doc's "safe-to-be-wrong" default).
   */
  controlPlaneEnvironment?: string
  version: string
  /** SHA-256 (hex) of the published runtime bundle this installer will accept. */
  runtimeSha256: string
  policy: InstallerPolicy
  /** Set when the operator explicitly authorised configuration remediation. */
  remediationEnabled: boolean
  /** Set when the operator explicitly authorised Live Migration execution. */
  migrationEnabled: boolean
  generatedAt: string
  generatedBy: string
}

const RUNTIME_PATH = '/api/v1/agent-installer/runtime'
const EVENT_PATH = '/api/v1/agent-installer/installation-event'
const SELF_PATH = '/api/v1/agent-installer/self'

function stripTrailingSlash(url: string) {
  return url.replace(/\/+$/, '')
}

function artifactFilename(platform: AgentPlatform, agentId: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$/.test(agentId)) throw new Error('Agent ID must be a safe deployment identifier')
  return agentPlatform(platform).filename.replace(/(\.[^.]+)$/, `-${agentId}$1`)
}

/**
 * Identity fields (URL, ids, token, version, digest) are machine-generated and
 * must be embedded verbatim. Anything outside their alphabet means the caller
 * passed something it should not have, so fail loudly rather than emit a script
 * that could be injected into.
 */
function safeValue(value: string, field: string) {
  const text = String(value ?? '')
  if (/["'`$\\\r\n]/.test(text)) {
    throw new Error(`Installer field ${field} contains characters that cannot be embedded safely`)
  }
  return text
}

/**
 * Operator-supplied scope values (allowed paths, allowed targets, names) legitimately
 * contain Windows backslashes and colons, so they cannot use the strict validator.
 * Strip every character that is meaningful to a shell, to PowerShell, or to a YAML
 * scalar; backslash survives and is escaped per-format at embed time.
 */
/** Characters that are meaningful to a shell, PowerShell or a YAML scalar. */
const SHELL_META = new Set(['"', "'", '`', '$', ';', '|', '&', '<', '>'])
function sanitizeScalar(value: unknown): string {
  const text = String(value ?? '')
  let out = ''
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0
    if (code < 32 || code === 127) { out += ' '; continue }
    if (SHELL_META.has(char)) continue
    out += char
  }
  return out.trim()
}
function sanitizeList(values: string[]): string[] {
  return (values || []).map(sanitizeScalar).filter(Boolean)
}

/** Backslashes are escape characters inside a double-quoted YAML scalar. */
function yamlScalar(value: string) {
  return value.replace(/\\/g, '\\\\')
}

interface NormalisedContext extends InstallerContext {
  apiUrl: string
  runtimeUrl: string
  eventUrl: string
  selfUrl: string
  /** Shell/PowerShell-safe CSVs (embedded in quoted heredocs and single quotes). */
  scanTypesCsv: string
  allowedTargetsCsv: string
  allowedPathsCsv: string
  /** Same CSVs with backslashes escaped for double-quoted YAML scalars. */
  scanTypesYaml: string
  allowedTargetsYaml: string
  allowedPathsYaml: string
  roleLabel: string
  controlPlaneEnvironment: 'development' | 'staging' | 'production'
  /** curl flags: HTTPS only, TLS 1.2+ (empty for a plaintext development control plane). */
  curlTls: string
}

/**
 * Windows PowerShell 5.1 on older .NET can negotiate SSL 3 / TLS 1.0. Raise
 * the floor to TLS 1.2 (keeping 1.3 where the OS offers it) before any request.
 */
const POWERSHELL_TLS_FLOOR = `# TLS 1.2+ only — Windows PowerShell 5.1 can otherwise negotiate SSL 3 / TLS 1.0.
[Net.ServicePointManager]::SecurityProtocol = ([Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12) -band -bnot ([Net.SecurityProtocolType]::Ssl3 -bor [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11)`

/**
 * Container runtime download. Node's own fetch: verified TLS, no redirects
 * (a redirect would replay the agent token to wherever it points), HTTPS
 * required outside development, bounded by a timeout. Written to a file and
 * run as a script, never as an inline one-liner. Contains no "$" so it embeds
 * in compose unescaped.
 */
const CONTAINER_FETCH_SCRIPT = `import { writeFileSync } from 'node:fs'
const [url, out] = process.argv.slice(2)
if (!url.startsWith('https://') && process.env.QGUARD_ENVIRONMENT !== 'development') {
  console.error('[qguard] refusing to download the runtime over plaintext: ' + url)
  process.exit(1)
}
const response = await fetch(url, {
  redirect: 'error',
  signal: AbortSignal.timeout(120000),
  headers: { 'x-qguard-agent-id': process.env.QGUARD_AGENT_ID, 'x-qguard-agent-token': process.env.QGUARD_AGENT_TOKEN },
})
if (!response.ok) {
  console.error('[qguard] runtime download failed: HTTP ' + response.status)
  process.exit(1)
}
writeFileSync(out, Buffer.from(await response.arrayBuffer()), { mode: 0o600 })`

function indent(text: string, spaces: number) {
  const pad = ' '.repeat(spaces)
  return text.split('\n').map((line) => (line ? pad + line : line)).join('\n')
}

function normalise(context: InstallerContext): NormalisedContext {
  const apiUrl = stripTrailingSlash(safeValue(context.apiUrl, 'apiUrl'))
  const policy = context.policy || {
    intervalSeconds: 60,
    allowedTargets: [],
    allowedPaths: [],
    scanTypes: [],
    alertThreshold: 'moderate',
  }
  const scanTypesCsv = sanitizeList(policy.scanTypes).join(',')
  const allowedTargetsCsv = sanitizeList(policy.allowedTargets).join(',')
  const allowedPathsCsv = sanitizeList(policy.allowedPaths).join(',')

  return {
    ...context,
    apiUrl,
    tenantId: safeValue(context.tenantId, 'tenantId'),
    agentId: safeValue(context.agentId, 'agentId'),
    agentToken: safeValue(context.agentToken, 'agentToken'),
    agentName: sanitizeScalar(context.agentName) || 'Qguard Helix Agent',
    environment: sanitizeScalar(context.environment) || 'production',
    version: safeValue(context.version, 'version'),
    runtimeSha256: safeValue(context.runtimeSha256, 'runtimeSha256'),
    generatedAt: sanitizeScalar(context.generatedAt),
    generatedBy: sanitizeScalar(context.generatedBy),
    runtimeUrl: `${apiUrl}${RUNTIME_PATH}`,
    eventUrl: `${apiUrl}${EVENT_PATH}`,
    selfUrl: `${apiUrl}${SELF_PATH}`,
    scanTypesCsv,
    allowedTargetsCsv,
    allowedPathsCsv,
    scanTypesYaml: yamlScalar(scanTypesCsv),
    allowedTargetsYaml: yamlScalar(allowedTargetsCsv),
    allowedPathsYaml: yamlScalar(allowedPathsCsv),
    roleLabel: agentRole(context.role).label,
    controlPlaneEnvironment: (['development', 'staging', 'production'] as const).find((value) => value === String(context.controlPlaneEnvironment || '').toLowerCase()) || 'development',
    curlTls: apiUrl.startsWith('https://') ? "--proto '=https' --tlsv1.2 " : '',
  }
}

function headerBanner(context: NormalisedContext, comment: string) {
  return [
    `${comment} Qguard Helix Lightweight Agent installer`,
    `${comment} Role         : ${context.roleLabel}`,
    `${comment} Agent        : ${context.agentName} (${context.agentId})`,
    `${comment} Environment  : ${context.environment}`,
    `${comment} Version      : ${context.version}`,
    `${comment} Control plane: ${context.apiUrl}`,
    `${comment} Generated    : ${context.generatedAt}`,
    `${comment}`,
    `${comment} This file contains a tenant enrollment credential. Treat it as a secret:`,
    `${comment} do not commit it, share it, or store it outside your secret manager.`,
    `${comment} Rotate the token from the Qguard Helix Agent Center if it is exposed.`,
  ].join('\n')
}

/* ------------------------------------------------------------------ */
/* Linux — systemd                                                     */
/* ------------------------------------------------------------------ */

function linuxInstaller(context: NormalisedContext) {
  return `#!/usr/bin/env bash
${headerBanner(context, '#')}

set -euo pipefail

API_URL="${context.apiUrl}"
TENANT_ID="${context.tenantId}"
AGENT_ID="${context.agentId}"
AGENT_TOKEN="${context.agentToken}"
AGENT_VERSION="${context.version}"
RUNTIME_SHA256="${context.runtimeSha256}"
INSTALL_DIR="/opt/qguard-agent/$AGENT_ID"
CONFIG_DIR="/etc/qguard-agent/$AGENT_ID"
CONFIG_FILE="$CONFIG_DIR/agent.env"
RUNTIME_FILE="$INSTALL_DIR/${AGENT_RUNTIME_FILENAME}"
SERVICE_NAME="qguard-agent-$AGENT_ID"
STATE_DIR="/var/lib/qguard-agent/$AGENT_ID"
COORDINATION_DIR="/var/lib/qguard-agent/coordination"

log()  { printf '\\033[36m[qguard]\\033[0m %s\\n' "$1"; }
ok()   { printf '\\033[32m  OK\\033[0m %s\\n' "$1"; }
fail() { printf '\\033[31m  FAILED\\033[0m %s\\n' "$1" >&2; }

# Phase reporting. Never prints or logs the token; failures are non-fatal so a
# transient control-plane outage cannot block a local installation.
report() {
  curl ${context.curlTls}-fsS -m 15 -X POST "${context.eventUrl}" \\
    -H "content-type: application/json" \\
    -H "x-qguard-agent-id: $AGENT_ID" \\
    -H "x-qguard-agent-token: $AGENT_TOKEN" \\
    -d "{\\"phase\\":\\"$1\\",\\"detail\\":\\"$2\\",\\"platform\\":\\"linux\\",\\"version\\":\\"$AGENT_VERSION\\"}" \\
    >/dev/null 2>&1 || true
}

on_error() {
  fail "Installation aborted on line $1"
  report "failed" "installer aborted at line $1"
  exit 1
}
trap 'on_error $LINENO' ERR

if [ "$(id -u)" -ne 0 ]; then
  fail "Run this installer as root (sudo ./$(basename "$0"))."
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)   ARCH_LABEL="x86_64" ;;
  aarch64|arm64)  ARCH_LABEL="aarch64" ;;
  *) fail "Unsupported architecture: $ARCH (x86_64 and aarch64 are supported)."; exit 1 ;;
esac
log "Host: $(uname -s) $ARCH_LABEL / $(hostname)"
report "installation_started" "$ARCH_LABEL"

# --- 1. Node.js runtime ------------------------------------------------------
ensure_node() {
  if command -v node >/dev/null 2>&1; then
    local major
    major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
    if [ "$major" -ge ${AGENT_MIN_NODE_MAJOR} ]; then
      ok "Node.js $(node -v) present"
      return 0
    fi
    log "Node.js $(node -v) is older than v${AGENT_MIN_NODE_MAJOR}; installing a supported runtime"
  else
    log "Node.js not found; installing"
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq nodejs || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q nodejs || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q nodejs || true
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache nodejs || true
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install nodejs || true
  fi

  if ! command -v node >/dev/null 2>&1; then
    fail "Node.js ${AGENT_MIN_NODE_MAJOR}+ is required and could not be installed automatically."
    fail "Install it from https://nodejs.org/en/download and re-run this installer."
    report "failed" "node runtime unavailable"
    exit 1
  fi
  ok "Node.js $(node -v) installed"
}
ensure_node

for tool in curl sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { fail "Required tool missing: $tool"; exit 1; }
done

# --- 2. Download the agent runtime ------------------------------------------
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0700 "$CONFIG_DIR"
TMP_RUNTIME="$(mktemp)"
log "Downloading agent runtime v$AGENT_VERSION"
# No -L: a redirect would replay the agent token to wherever it points.
curl ${context.curlTls}-fsS -m 120 "${context.runtimeUrl}" \\
  -H "x-qguard-agent-id: $AGENT_ID" \\
  -H "x-qguard-agent-token: $AGENT_TOKEN" \\
  -o "$TMP_RUNTIME"
ok "Runtime downloaded ($(wc -c < "$TMP_RUNTIME") bytes)"
report "runtime_downloaded" "$AGENT_VERSION"

# --- 3. Verify integrity -----------------------------------------------------
ACTUAL_SHA="$(sha256sum "$TMP_RUNTIME" | awk '{print $1}')"
if [ "$ACTUAL_SHA" != "$RUNTIME_SHA256" ]; then
  rm -f "$TMP_RUNTIME"
  fail "Checksum mismatch. Expected $RUNTIME_SHA256, got $ACTUAL_SHA."
  fail "The package was NOT installed. Re-generate the installer from the Agent Center."
  report "failed" "runtime checksum mismatch"
  exit 1
fi
ok "SHA-256 verified"
report "package_verified" "$RUNTIME_SHA256"

systemctl stop "$SERVICE_NAME" 2>/dev/null || true
install -m 0644 "$TMP_RUNTIME" "$RUNTIME_FILE"
rm -f "$TMP_RUNTIME"

# --- 4. Configuration (0600, root-owned) ------------------------------------
umask 077
cat > "$CONFIG_FILE" <<'QGUARD_CONFIG_EOF'
QGUARD_API_URL=${context.apiUrl}
QGUARD_TENANT_ID=${context.tenantId}
QGUARD_AGENT_ID=${context.agentId}
QGUARD_AGENT_TOKEN=${context.agentToken}
QGUARD_AGENT_ROLE=${context.role}
QGUARD_ENVIRONMENT=${context.controlPlaneEnvironment}
QGUARD_AGENT_ENVIRONMENT=${context.environment}
QGUARD_AGENT_VERSION=${context.version}
QGUARD_STATE_DIR=/var/lib/qguard-agent/${context.agentId}
QGUARD_COORDINATION_DIR=/var/lib/qguard-agent/coordination
QGUARD_SCAN_TYPES=${context.scanTypesCsv}
QGUARD_ALLOWED_TARGETS=${context.allowedTargetsCsv}
QGUARD_ALLOWED_PATHS=${context.allowedPathsCsv}
QGUARD_ENABLE_REMEDIATION=${context.remediationEnabled ? 'true' : 'false'}
QGUARD_ENABLE_CONFIG_PATCHES=${context.remediationEnabled ? 'true' : 'false'}
QGUARD_ENABLE_MIGRATION=${context.migrationEnabled ? 'true' : 'false'}
QGUARD_NATIVE_RUNTIME_ENABLED=true
QGUARD_CONFIG_EOF
chmod 0600 "$CONFIG_FILE"
chown root:root "$CONFIG_FILE"
ok "Configuration written to $CONFIG_FILE (0600 root)"

# Request-signing keys are generated by the agent on first start and never
# leave this host. 0700 root, and it must persist: a lost key has to be reset
# in the Agent Center before the agent is accepted again.
install -d -m 0700 -o root -g root "$STATE_DIR" "$COORDINATION_DIR"
LEGACY_KEY="/var/lib/qguard-agent/signing-keys-$AGENT_ID.json"
if [ -f "$LEGACY_KEY" ] && [ ! -e "$STATE_DIR/signing-keys-$AGENT_ID.json" ]; then
  install -m 0600 -o root -g root "$LEGACY_KEY" "$STATE_DIR/signing-keys-$AGENT_ID.json"
fi
if [ -f /etc/qguard-agent/agent.env ] && grep -Fxq "QGUARD_AGENT_ID=$AGENT_ID" /etc/qguard-agent/agent.env; then
  systemctl stop qguard-agent 2>/dev/null || true
  systemctl disable qguard-agent 2>/dev/null || true
fi
ok "Signing-key state directory $STATE_DIR (0700 root)"

# --- 5. systemd service ------------------------------------------------------
NODE_BIN="$(command -v node)"
cat > "/etc/systemd/system/$SERVICE_NAME.service" <<QGUARD_UNIT_EOF
[Unit]
Description=Qguard Helix Lightweight Agent (${context.roleLabel})
Documentation=${context.apiUrl}/downloads
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$CONFIG_FILE
ExecStart=$NODE_BIN $RUNTIME_FILE watch --config $CONFIG_FILE
Restart=always
RestartSec=15
User=root
WorkingDirectory=$INSTALL_DIR
StateDirectory=qguard-agent/$AGENT_ID
StateDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
QGUARD_UNIT_EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
ok "systemd unit installed"
report "agent_installed" "$RUNTIME_FILE"

systemctl restart "$SERVICE_NAME"
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "Service $SERVICE_NAME started"
  report "service_started" "systemd"
else
  fail "Service failed to start. Inspect: journalctl -u $SERVICE_NAME -n 50"
  report "failed" "service did not start"
  exit 1
fi

# --- 6. Verify the control plane sees this agent -----------------------------
log "Verifying backend connection"
CONNECTED="no"
for attempt in $(seq 1 20); do
  RESPONSE="$(curl ${context.curlTls}-fsS -m 10 "${context.selfUrl}" \\
    -H "x-qguard-agent-id: $AGENT_ID" \\
    -H "x-qguard-agent-token: $AGENT_TOKEN" 2>/dev/null || echo '')"
  case "$RESPONSE" in
    *'"connected":true'*) CONNECTED="yes"; break ;;
  esac
  sleep 3
done

if [ "$CONNECTED" = "yes" ]; then
  ok "Backend connection established"
  echo
  log "Installation complete. Open ${context.apiUrl}/downloads to run the first scan."
else
  fail "The agent installed and started, but no heartbeat has reached the control plane yet."
  fail "Check outbound HTTPS access to ${context.apiUrl} and: journalctl -u $SERVICE_NAME -n 50"
  echo
  log "The Agent Center will show 'Connecting' until the first heartbeat arrives."
fi
`
}

/* ------------------------------------------------------------------ */
/* Windows — scheduled task supervised service                         */
/* ------------------------------------------------------------------ */

function windowsInstaller(context: NormalisedContext) {
  return `#Requires -Version 5.1
${headerBanner(context, '#')}

[CmdletBinding()]
param(
  [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
${POWERSHELL_TLS_FLOOR}

$ApiUrl        = '${context.apiUrl}'
$TenantId      = '${context.tenantId}'
$AgentId       = '${context.agentId}'
$AgentToken    = '${context.agentToken}'
$AgentVersion  = '${context.version}'
$RuntimeSha256 = '${context.runtimeSha256}'
$AgentSlot     = $AgentId -replace '[^A-Za-z0-9_-]', '_'
$LaunchId      = [guid]::NewGuid().ToString('N')
$InstallRoot   = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'QGuardHelix\\Agents'))
$InstallDir    = [IO.Path]::GetFullPath((Join-Path $InstallRoot $AgentSlot))
if ((Split-Path -Parent $InstallDir) -ne $InstallRoot) { throw 'Invalid agent installation directory' }
$StateDir      = Join-Path $InstallDir 'state'
$CoordinationDir = Join-Path $env:ProgramData 'QGuardHelix\\coordination'
$ConfigFile    = Join-Path $InstallDir 'agent.env'
$RuntimeFile   = Join-Path $InstallDir '${AGENT_RUNTIME_FILENAME}'
$LogFile       = Join-Path $InstallDir 'agent.log'
$TaskName      = "QGuardHelixAgent-$AgentSlot"
$LegacyDir     = Join-Path $env:ProgramData 'QGuardHelix\\Agent'
$LegacyConfig  = Join-Path $LegacyDir 'agent.env'
$LegacyTask    = 'QGuardHelixAgent'
# Do not let a directory junction redirect installation or recursive removal.
foreach ($guardPath in @((Join-Path $env:ProgramData 'QGuardHelix'), $InstallRoot, $InstallDir, $LegacyDir)) {
  if ((Test-Path -LiteralPath $guardPath) -and ((Get-Item -LiteralPath $guardPath).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Refusing agent directory reparse point: $guardPath" }
}
$LegacyIsThisAgent = $false
if (Test-Path -LiteralPath $LegacyConfig) {
  $LegacyIsThisAgent = @(Get-Content -LiteralPath $LegacyConfig | Where-Object { $_ -eq "QGUARD_AGENT_ID=$AgentId" }).Count -gt 0
}

function Write-Step($Message) { Write-Host "[qguard] $Message" -ForegroundColor Cyan }
function Write-Ok($Message)   { Write-Host "  OK     $Message" -ForegroundColor Green }
function Write-Fail($Message) { Write-Host "  FAILED $Message" -ForegroundColor Red }

function Stop-AgentTask($Name) {
  if (-not (Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue)) { return }
  Stop-ScheduledTask -TaskName $Name
  $deadline = [DateTime]::UtcNow.AddSeconds(20)
  while ((Get-ScheduledTask -TaskName $Name).State -eq 'Running') {
    if ([DateTime]::UtcNow -gt $deadline) { throw "Task '$Name' did not stop; configuration was not replaced" }
    Start-Sleep -Milliseconds 250
  }
}

function Protect-AgentDirectory($Directory) {
  New-Item -ItemType Directory -Force -Path $Directory | Out-Null
  if ((Get-Item -LiteralPath $Directory).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing agent directory reparse point: $Directory" }
  $privateAcl = Get-Acl -LiteralPath $Directory
  $privateAcl.SetAccessRuleProtection($true, $false)
  $privateAcl.Access | ForEach-Object { $privateAcl.RemoveAccessRule($_) | Out-Null }
  foreach ($identity in @('NT AUTHORITY\\SYSTEM', 'BUILTIN\\Administrators')) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $privateAcl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $Directory -AclObject $privateAcl
}

# Phase reporting. Never writes the token to the console or to a URL.
function Report-Phase($Phase, $Detail) {
  try {
    $body = @{ phase = $Phase; detail = "$Detail"; platform = 'windows'; version = $AgentVersion } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Post -Uri "${context.eventUrl}" -TimeoutSec 15 -MaximumRedirection 0 -ContentType 'application/json' \`
      -Headers @{ 'x-qguard-agent-id' = $AgentId; 'x-qguard-agent-token' = $AgentToken } -Body $body | Out-Null
  } catch { }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Fail 'Run this installer from an elevated PowerShell session (Run as Administrator).'
  exit 1
}

if ($Uninstall) {
  Write-Step "Removing Qguard Helix agent $AgentId"
  Stop-AgentTask $TaskName
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  if (Test-Path -LiteralPath $InstallDir) {
    if ((Get-Item -LiteralPath $InstallDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to remove a directory reparse point' }
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
  }
  if ($LegacyIsThisAgent -and (Get-ScheduledTask -TaskName $LegacyTask -ErrorAction SilentlyContinue)) {
    Stop-AgentTask $LegacyTask
    Unregister-ScheduledTask -TaskName $LegacyTask -Confirm:$false -ErrorAction SilentlyContinue
    Write-Step 'Legacy files retained for recovery; the shared startup task was removed.'
  }
  Write-Ok 'Agent removed. Revoke the agent from the Agent Center to invalidate its token.'
  exit 0
}

Write-Step "Host: $env:COMPUTERNAME ($env:PROCESSOR_ARCHITECTURE)"
Report-Phase 'installation_started' $env:PROCESSOR_ARCHITECTURE

# --- 1. Node.js runtime ------------------------------------------------------
function Resolve-NodePath {
  $cmd = Get-Command node.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  foreach ($candidate in @("$env:ProgramFiles\\nodejs\\node.exe", "\${env:ProgramFiles(x86)}\\nodejs\\node.exe")) {
    if (Test-Path $candidate) { return $candidate }
  }
  return $null
}

$NodePath = Resolve-NodePath
if ($NodePath) {
  $nodeMajor = 0
  # Avoid embedded quotes: Windows PowerShell 5.1 strips them for native commands.
  try { $nodeMajor = [int]((& $NodePath -p 'parseInt(process.versions.node,10)') 2>$null) } catch { }
  if ($nodeMajor -lt ${AGENT_MIN_NODE_MAJOR}) { $NodePath = $null; Write-Step "Installed Node.js is older than v${AGENT_MIN_NODE_MAJOR}" }
}

if (-not $NodePath) {
  Write-Step 'Installing Node.js LTS via winget'
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    try {
      winget install --id OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements | Out-Null
    } catch { }
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
    $NodePath = Resolve-NodePath
  }
}

if (-not $NodePath) {
  Write-Fail "Node.js ${AGENT_MIN_NODE_MAJOR}+ is required and could not be installed automatically."
  Write-Fail 'Install it from https://nodejs.org/en/download and re-run this installer.'
  Report-Phase 'failed' 'node runtime unavailable'
  exit 1
}
Write-Ok "Node.js runtime: $NodePath"

# --- 2. Download the agent runtime ------------------------------------------
Protect-AgentDirectory $InstallRoot
Protect-AgentDirectory $InstallDir
Protect-AgentDirectory $CoordinationDir
$TempRuntime = Join-Path $env:TEMP ("qguard-agent-" + [guid]::NewGuid().ToString('N') + '.cjs')
Write-Step "Downloading agent runtime v$AgentVersion"
try {
  Invoke-WebRequest -Uri "${context.runtimeUrl}" -OutFile $TempRuntime -TimeoutSec 120 -MaximumRedirection 0 -UseBasicParsing \`
    -Headers @{ 'x-qguard-agent-id' = $AgentId; 'x-qguard-agent-token' = $AgentToken }
} catch {
  Write-Fail "Runtime download failed: $($_.Exception.Message)"
  Report-Phase 'failed' 'runtime download failed'
  exit 1
}
Write-Ok "Runtime downloaded ($((Get-Item $TempRuntime).Length) bytes)"
Report-Phase 'runtime_downloaded' $AgentVersion

# --- 3. Verify integrity -----------------------------------------------------
$ActualSha = (Get-FileHash -Path $TempRuntime -Algorithm SHA256).Hash.ToLower()
if ($ActualSha -ne $RuntimeSha256.ToLower()) {
  Remove-Item -Force $TempRuntime
  Write-Fail "Checksum mismatch. Expected $RuntimeSha256, got $ActualSha."
  Write-Fail 'The package was NOT installed. Re-generate the installer from the Agent Center.'
  Report-Phase 'failed' 'runtime checksum mismatch'
  exit 1
}
Write-Ok 'SHA-256 verified'
Report-Phase 'package_verified' $RuntimeSha256

# Stop only this agent before replacing files. Register-ScheduledTask -Force
# updates the definition but does not replace an already running Node process.
Stop-AgentTask $TaskName
if ($LegacyIsThisAgent -and (Get-ScheduledTask -TaskName $LegacyTask -ErrorAction SilentlyContinue)) {
  Write-Step 'Migrating the legacy shared task configured for this agent'
  Stop-AgentTask $LegacyTask
  Unregister-ScheduledTask -TaskName $LegacyTask -Confirm:$false -ErrorAction SilentlyContinue
  Write-Step 'Re-run the new installer for any other role previously installed into the shared slot.'
}
Move-Item -Force -LiteralPath $TempRuntime -Destination $RuntimeFile

# --- 4. Configuration (Administrators + SYSTEM only) ------------------------
$configLines = @(
  "QGUARD_API_URL=${context.apiUrl}",
  "QGUARD_TENANT_ID=${context.tenantId}",
  "QGUARD_AGENT_ID=${context.agentId}",
  "QGUARD_AGENT_TOKEN=${context.agentToken}",
  "QGUARD_AGENT_ROLE=${context.role}",
  "QGUARD_ENVIRONMENT=${context.controlPlaneEnvironment}",
  "QGUARD_AGENT_ENVIRONMENT=${context.environment}",
  "QGUARD_AGENT_VERSION=${context.version}",
  "QGUARD_STATE_DIR=$StateDir",
  "QGUARD_LOG_FILE=$LogFile",
  "QGUARD_COORDINATION_DIR=$CoordinationDir",
  "QGUARD_LAUNCH_ID=$LaunchId",
  "QGUARD_SCAN_TYPES=${context.scanTypesCsv}",
  "QGUARD_ALLOWED_TARGETS=${context.allowedTargetsCsv}",
  "QGUARD_ALLOWED_PATHS=${context.allowedPathsCsv}",
  "QGUARD_ENABLE_REMEDIATION=${context.remediationEnabled ? 'true' : 'false'}",
  "QGUARD_ENABLE_CONFIG_PATCHES=${context.remediationEnabled ? 'true' : 'false'}",
  "QGUARD_ENABLE_MIGRATION=${context.migrationEnabled ? 'true' : 'false'}",
  "QGUARD_NATIVE_RUNTIME_ENABLED=true"
)
Set-Content -Path $ConfigFile -Value $configLines -Encoding ASCII -Force

# Strip inheritance so only SYSTEM and Administrators can read the token.
$acl = Get-Acl $ConfigFile
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
foreach ($identity in @('NT AUTHORITY\\SYSTEM', 'BUILTIN\\Administrators')) {
  $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
  $acl.AddAccessRule($rule)
}
Set-Acl -Path $ConfigFile -AclObject $acl
Write-Ok "Configuration written to $ConfigFile (SYSTEM + Administrators only)"

# Request-signing keys: generated by the agent on first start, never leave this
# host. Same ACL as the token, set on the directory BEFORE any key is written so
# every file created inside inherits it.
Protect-AgentDirectory $StateDir
# Preserve this identity's bound signing key on a legacy upgrade. Other agents'
# keys are neither copied nor reset. Never overwrite an existing private key.
$SigningKeyName = "signing-keys-$AgentSlot.json"
$LegacyKey = Join-Path (Join-Path $LegacyDir 'state') $SigningKeyName
$SigningKey = Join-Path $StateDir $SigningKeyName
if (-not (Test-Path -LiteralPath $SigningKey) -and (Test-Path -LiteralPath $LegacyKey)) {
  Copy-Item -LiteralPath $LegacyKey -Destination $SigningKey
  Write-Ok 'Existing request-signing key preserved'
}
Write-Ok "Signing-key state directory $StateDir (SYSTEM + Administrators only)"

# --- 5. Supervised startup task (runs as SYSTEM, restarts on failure) -------
$action = New-ScheduledTaskAction -Execute $NodePath -Argument "\`"$RuntimeFile\`" watch --config \`"$ConfigFile\`"" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable \`
  -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $taskPrincipal \`
  -Settings $settings -Description 'Qguard Helix Lightweight Agent (${context.roleLabel})' -Force | Out-Null
Write-Ok "Startup task '$TaskName' registered (SYSTEM, highest privileges)"
Report-Phase 'agent_installed' $RuntimeFile

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
$taskState = (Get-ScheduledTask -TaskName $TaskName).State
if ($taskState -eq 'Running') {
  Write-Ok "Agent service started (state: $taskState)"
  Report-Phase 'service_started' "scheduled-task:$taskState"
} else {
  Write-Fail "Agent task is in state '$taskState'."
  Report-Phase 'failed' "scheduled task state $taskState"
  Write-Fail "Read startup diagnostics: Get-Content -LiteralPath '$LogFile' -Tail 40"
  exit 1
}

# --- 6. Verify the control plane sees this agent -----------------------------
Write-Step "Verifying backend connection for agent $AgentId (up to 120 seconds)"
$connected = $false
$verifyStarted = [DateTime]::UtcNow
$verifyDeadline = $verifyStarted.AddSeconds(120)
$lastStatus = 'No heartbeat received'
while ([DateTime]::UtcNow -lt $verifyDeadline) {
  $elapsed = [int]([DateTime]::UtcNow - $verifyStarted).TotalSeconds
  Write-Host "[qguard] Waiting for this agent heartbeat ($elapsed / 120 seconds)"
  try {
    $remaining = [Math]::Max(1, [Math]::Min(10, [int]($verifyDeadline - [DateTime]::UtcNow).TotalSeconds))
    $status = Invoke-RestMethod -Method Get -Uri "${context.selfUrl}" -TimeoutSec $remaining -MaximumRedirection 0 \`
      -Headers @{ 'x-qguard-agent-id' = $AgentId; 'x-qguard-agent-token' = $AgentToken }
    # Require a signed heartbeat from THIS launch, never a stale heartbeat from
    # the previous process. Comparing launch IDs also avoids host clock skew.
    if ($status.data.connected -eq $true -and $status.data.runtimeLaunchId -eq $LaunchId) { $connected = $true; break }
    $lastStatus = "Backend reached; agent state: $($status.data.connectionState)"
  } catch { $lastStatus = "Backend status request failed: $($_.Exception.Message)" }
  if ((Get-ScheduledTask -TaskName $TaskName).State -ne 'Running') { $lastStatus = 'Agent task exited before a heartbeat'; break }
  if ([DateTime]::UtcNow.AddSeconds(3) -lt $verifyDeadline) { Start-Sleep -Seconds 3 }
}

if ($connected) {
  Write-Ok 'Backend connection established'
  Write-Step "Installation complete. Open ${context.apiUrl}/downloads to run the first scan."
} else {
  Write-Fail 'The agent installed and started, but no heartbeat has reached the control plane yet.'
  Write-Fail $lastStatus
  Write-Fail "Read startup diagnostics: Get-Content -LiteralPath '$LogFile' -Tail 40"
  Write-Fail "Task diagnostics: Get-ScheduledTaskInfo -TaskName '$TaskName'"
  Report-Phase 'failed' "Heartbeat verification failed: $lastStatus. Read $LogFile"
  exit 1
}
`
}

/* ------------------------------------------------------------------ */
/* PowerShell — portable, no installation                              */
/* ------------------------------------------------------------------ */

function powershellPortable(context: NormalisedContext) {
  return `#Requires -Version 5.1
${headerBanner(context, '#')}
#
# Portable runner: downloads the agent runtime to a temporary directory, verifies
# it, and runs a single collection cycle in the foreground. Nothing is installed
# and no service is registered. Use qguard-agent-install.ps1 for a persistent
# deployment.

[CmdletBinding()]
param(
  [ValidateSet('scan','watch')]
  [string] $Mode = 'scan'
)

$ErrorActionPreference = 'Stop'
${POWERSHELL_TLS_FLOOR}

$AgentId       = '${context.agentId}'
$AgentToken    = '${context.agentToken}'
$RuntimeSha256 = '${context.runtimeSha256}'

$node = Get-Command node.exe -ErrorAction SilentlyContinue
if (-not $node) {
  Write-Host 'Node.js ${AGENT_MIN_NODE_MAJOR}+ is required on PATH. Install from https://nodejs.org/en/download' -ForegroundColor Red
  exit 1
}

$workDir = Join-Path $env:TEMP ('qguard-agent-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$runtime = Join-Path $workDir '${AGENT_RUNTIME_FILENAME}'

Write-Host '[qguard] Downloading agent runtime v${context.version}' -ForegroundColor Cyan
Invoke-WebRequest -Uri "${context.runtimeUrl}" -OutFile $runtime -TimeoutSec 120 -MaximumRedirection 0 -UseBasicParsing \`
  -Headers @{ 'x-qguard-agent-id' = $AgentId; 'x-qguard-agent-token' = $AgentToken }

$actual = (Get-FileHash -Path $runtime -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $RuntimeSha256.ToLower()) {
  Remove-Item -Recurse -Force $workDir
  Write-Host "  FAILED Checksum mismatch. Expected $RuntimeSha256, got $actual." -ForegroundColor Red
  exit 1
}
Write-Host '  OK     SHA-256 verified' -ForegroundColor Green

$env:QGUARD_API_URL                 = '${context.apiUrl}'
$env:QGUARD_TENANT_ID               = '${context.tenantId}'
$env:QGUARD_AGENT_ID                = $AgentId
$env:QGUARD_AGENT_TOKEN             = $AgentToken
$env:QGUARD_AGENT_ROLE              = '${context.role}'
$env:QGUARD_ENVIRONMENT             = '${context.controlPlaneEnvironment}'
$env:QGUARD_AGENT_ENVIRONMENT       = '${context.environment}'
# Signing keys persist in this user's profile (private by default) so later runs
# present the same key; ProgramData would leave them readable by local users.
$env:QGUARD_STATE_DIR               = Join-Path $env:LOCALAPPDATA 'QGuardHelix\\Agent\\state'
$env:QGUARD_AGENT_VERSION           = '${context.version}'
$env:QGUARD_SCAN_TYPES              = '${context.scanTypesCsv}'
$env:QGUARD_ALLOWED_TARGETS         = '${context.allowedTargetsCsv}'
$env:QGUARD_ALLOWED_PATHS           = '${context.allowedPathsCsv}'
$env:QGUARD_ENABLE_REMEDIATION      = '${context.remediationEnabled ? 'true' : 'false'}'
$env:QGUARD_ENABLE_CONFIG_PATCHES   = '${context.remediationEnabled ? 'true' : 'false'}'
$env:QGUARD_ENABLE_MIGRATION        = '${context.migrationEnabled ? 'true' : 'false'}'
$env:QGUARD_NATIVE_RUNTIME_ENABLED  = 'true'

try {
  & $node.Source $runtime $Mode
} finally {
  Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
  Remove-Item Env:\\QGUARD_AGENT_TOKEN -ErrorAction SilentlyContinue
}
`
}

/* ------------------------------------------------------------------ */
/* Docker — compose                                                    */
/* ------------------------------------------------------------------ */

function dockerCompose(context: NormalisedContext) {
  // `$$VAR` escapes Compose interpolation so the value is resolved by the
  // container shell from the environment block rather than substituted here.
  return `${headerBanner(context, '#')}
#
# Start:  docker compose -f ${artifactFilename('docker', context.agentId)} up -d
# Logs:   docker compose -f ${artifactFilename('docker', context.agentId)} logs -f
# Stop:   docker compose -f ${artifactFilename('docker', context.agentId)} down

name: qguard-agent-${context.agentId.toLowerCase()}

services:
  qguard-agent:
    image: node:22-alpine
    container_name: qguard-agent-${context.agentId.toLowerCase()}
    restart: unless-stopped
    read_only: false
    security_opt:
      - no-new-privileges:true
    environment:
      QGUARD_API_URL: "${context.apiUrl}"
      QGUARD_TENANT_ID: "${context.tenantId}"
      QGUARD_AGENT_ID: "${context.agentId}"
      QGUARD_AGENT_TOKEN: "${context.agentToken}"
      QGUARD_AGENT_ROLE: "${context.role}"
      QGUARD_ENVIRONMENT: "${context.controlPlaneEnvironment}"
      QGUARD_AGENT_ENVIRONMENT: "${context.environment}"
      QGUARD_AGENT_VERSION: "${context.version}"
      QGUARD_STATE_DIR: "/var/lib/qguard-agent"
      QGUARD_COORDINATION_DIR: "/var/lib/qguard-coordination"
      QGUARD_SCAN_TYPES: "${context.scanTypesYaml}"
      QGUARD_ALLOWED_TARGETS: "${context.allowedTargetsYaml}"
      QGUARD_ALLOWED_PATHS: "${context.allowedPathsYaml}"
      QGUARD_ENABLE_REMEDIATION: "${context.remediationEnabled ? 'true' : 'false'}"
      QGUARD_ENABLE_CONFIG_PATCHES: "${context.remediationEnabled ? 'true' : 'false'}"
      QGUARD_ENABLE_MIGRATION: "${context.migrationEnabled ? 'true' : 'false'}"
      QGUARD_NATIVE_RUNTIME_ENABLED: "true"
      QGUARD_RUNTIME_SHA256: "${context.runtimeSha256}"
    # Request-signing keys must survive container re-creation; a lost key has
    # to be reset in the Agent Center. Do not run "down -v" on this volume.
    volumes:
      - qguard-agent-state:/var/lib/qguard-agent
      - qguard-host-coordination:/var/lib/qguard-coordination
    command:
      - sh
      - -c
      - |
        set -eu
        echo "[qguard] downloading agent runtime v${context.version}"
        cat > /tmp/qguard-fetch.mjs <<'QGUARD_FETCH_EOF'
${indent(CONTAINER_FETCH_SCRIPT, 8)}
        QGUARD_FETCH_EOF
        node /tmp/qguard-fetch.mjs "${context.runtimeUrl}" /tmp/${AGENT_RUNTIME_FILENAME}
        echo "$$QGUARD_RUNTIME_SHA256  /tmp/${AGENT_RUNTIME_FILENAME}" | sha256sum -c - \\
          || { echo "[qguard] FAILED checksum mismatch - refusing to run"; exit 1; }
        echo "[qguard] SHA-256 verified"
        exec node /tmp/${AGENT_RUNTIME_FILENAME} watch
    healthcheck:
      test: ["CMD-SHELL", "pgrep -f ${AGENT_RUNTIME_FILENAME} > /dev/null || exit 1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 60s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  qguard-agent-state:
  qguard-host-coordination:
    name: qguard-helix-host-coordination
`
}

/* ------------------------------------------------------------------ */
/* Kubernetes                                                          */
/* ------------------------------------------------------------------ */

function kubernetesManifest(context: NormalisedContext) {
  const b64 = (value: string) => value // stringData keeps values readable; k8s encodes on write
  const manifest = `${headerBanner(context, '#')}
#
# Apply:  kubectl apply -f ${artifactFilename('kubernetes', context.agentId)}
# Status: kubectl -n qguard-helix get pods -l app=qguard-agent
# Logs:   kubectl -n qguard-helix logs -l app=qguard-agent -f
# Remove: kubectl delete -f ${artifactFilename('kubernetes', context.agentId)}

apiVersion: v1
kind: Namespace
metadata:
  name: qguard-helix
  labels:
    app.kubernetes.io/part-of: qguard-helix
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: qguard-agent
  namespace: qguard-helix
automountServiceAccountToken: false
---
apiVersion: v1
kind: Secret
metadata:
  name: qguard-agent-credentials
  namespace: qguard-helix
type: Opaque
stringData:
  QGUARD_AGENT_ID: "${b64(context.agentId)}"
  QGUARD_AGENT_TOKEN: "${b64(context.agentToken)}"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: qguard-agent-config
  namespace: qguard-helix
data:
  QGUARD_API_URL: "${context.apiUrl}"
  QGUARD_TENANT_ID: "${context.tenantId}"
  QGUARD_AGENT_ROLE: "${context.role}"
  QGUARD_ENVIRONMENT: "${context.controlPlaneEnvironment}"
  QGUARD_AGENT_ENVIRONMENT: "${context.environment}"
  QGUARD_AGENT_VERSION: "${context.version}"
  QGUARD_STATE_DIR: "/var/lib/qguard-agent"
  QGUARD_SCAN_TYPES: "${context.scanTypesYaml}"
  QGUARD_ALLOWED_TARGETS: "${context.allowedTargetsYaml}"
  QGUARD_ALLOWED_PATHS: "${context.allowedPathsYaml}"
  QGUARD_ENABLE_REMEDIATION: "${context.remediationEnabled ? 'true' : 'false'}"
  QGUARD_ENABLE_CONFIG_PATCHES: "${context.remediationEnabled ? 'true' : 'false'}"
  QGUARD_ENABLE_MIGRATION: "${context.migrationEnabled ? 'true' : 'false'}"
  QGUARD_NATIVE_RUNTIME_ENABLED: "true"
  QGUARD_RUNTIME_SHA256: "${context.runtimeSha256}"
---
# Request-signing keys are generated in the pod and must survive rescheduling;
# a lost key has to be reset in the Agent Center. Uses the default StorageClass.
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: qguard-agent-state
  namespace: qguard-helix
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 16Mi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qguard-agent
  namespace: qguard-helix
  labels:
    app: qguard-agent
    app.kubernetes.io/name: qguard-agent
    app.kubernetes.io/version: "${context.version}"
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: qguard-agent
  template:
    metadata:
      labels:
        app: qguard-agent
    spec:
      serviceAccountName: qguard-agent
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        # Re-chowning on every mount would add group read to the 0600 key file,
        # which the agent then refuses to use. Only fix ownership once.
        fsGroupChangePolicy: "OnRootMismatch"
      containers:
        - name: agent
          image: node:22-alpine
          imagePullPolicy: IfNotPresent
          envFrom:
            - configMapRef:
                name: qguard-agent-config
            - secretRef:
                name: qguard-agent-credentials
          command: ["sh", "-c"]
          args:
            - |
              set -eu
              echo "[qguard] downloading agent runtime v${context.version}"
              cat > /tmp/qguard-fetch.mjs <<'QGUARD_FETCH_EOF'
${indent(CONTAINER_FETCH_SCRIPT, 14)}
              QGUARD_FETCH_EOF
              node /tmp/qguard-fetch.mjs "${context.runtimeUrl}" /tmp/${AGENT_RUNTIME_FILENAME}
              echo "$QGUARD_RUNTIME_SHA256  /tmp/${AGENT_RUNTIME_FILENAME}" | sha256sum -c - \\
                || { echo "[qguard] FAILED checksum mismatch - refusing to run"; exit 1; }
              echo "[qguard] SHA-256 verified"
              exec node /tmp/${AGENT_RUNTIME_FILENAME} watch
          resources:
            requests:
              cpu: "50m"
              memory: "96Mi"
            limits:
              cpu: "500m"
              memory: "384Mi"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: state
              mountPath: /var/lib/qguard-agent
      volumes:
        - name: tmp
          emptyDir: {}
        - name: state
          persistentVolumeClaim:
            claimName: qguard-agent-state
`
  const namespace = `qguard-helix-${context.agentId.toLowerCase()}`
  return manifest.replace(/^(\s*(?:namespace|name): )qguard-helix$/gm, `$1${namespace}`)
    .replace(/kubectl -n qguard-helix /g, `kubectl -n ${namespace} `)
}

/* ------------------------------------------------------------------ */
/* Cloud-init                                                          */
/* ------------------------------------------------------------------ */

function cloudInit(context: NormalisedContext) {
  const install = linuxInstaller(context)
    .split('\n')
    .map((line) => (line ? `      ${line}` : ''))
    .join('\n')

  return `#cloud-config
${headerBanner(context, '#')}
#
# Paste into the instance User Data field at launch. The agent is installed,
# verified and started on first boot.

package_update: true
packages:
  - curl
  - coreutils

write_files:
  - path: /opt/qguard-agent/bootstrap-${context.agentId}.sh
    permissions: '0700'
    owner: root:root
    content: |
${install}

runcmd:
  - [ bash, /opt/qguard-agent/bootstrap-${context.agentId}.sh ]
  - [ rm, -f, /opt/qguard-agent/bootstrap-${context.agentId}.sh ]

final_message: "Qguard Helix agent provisioning finished after $UPTIME seconds"
`
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

export interface GeneratedInstaller {
  platform: AgentPlatform
  filename: string
  contentType: string
  language: string
  content: string
  /** Command the operator runs after saving the file. */
  runCommand: string
  privileges: string
  prerequisites: string[]
  service: string
  architectures: string[]
}

const GENERATORS: Record<AgentPlatform, (context: NormalisedContext) => string> = {
  linux: linuxInstaller,
  windows: windowsInstaller,
  powershell: powershellPortable,
  docker: dockerCompose,
  kubernetes: kubernetesManifest,
  'cloud-init': cloudInit,
}

export function generateInstaller(platformId: AgentPlatform, context: InstallerContext): GeneratedInstaller {
  const platform = agentPlatform(platformId)
  const normalised = normalise(context)
  const generator = GENERATORS[platform.id]
  const content = generator(normalised)
  const filename = artifactFilename(platform.id, normalised.agentId)
  return {
    platform: platform.id,
    filename,
    contentType: platform.contentType,
    language: platform.language,
    content,
    runCommand: platform.runCommand(filename),
    privileges: platform.privileges,
    prerequisites: platform.prerequisites,
    service: platform.service,
    architectures: platform.architectures,
  }
}

/**
 * Short, copy-pasteable command shown next to the download button. It does NOT
 * contain the enrollment token — the token lives only inside the downloaded
 * artifact (spec §6: never expose the token through a URL or frontend source).
 */
export function installQuickCommand(platformId: AgentPlatform): string {
  const platform = agentPlatform(platformId)
  return platform.runCommand(platform.filename)
}
