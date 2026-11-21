/**
 * Qguard Helix Agent — release, role and platform model.
 *
 * Isomorphic (no Node/browser-only APIs) so the API server, the Downloads Agent
 * Center, the Agent Collector Console and the agent runtime itself all agree on
 * one definition of what an agent IS, what it may do, and how it is installed.
 *
 * Spec: Qguard_Wiki/Agent_Installer §2 (agent types), §3 (lightweight core +
 * collector modules), §4 (platform support), §10 (realtime events), §22
 * (upgrades), §29 (accuracy vocabulary).
 */

/** Runtime version of the lightweight agent bundle. Bump on any agent.ts change. */
export const AGENT_VERSION = '1.6.4'
/** Every writer on a shared host must participate in the host mutation mutex. */
export const AGENT_COORDINATION_MIN_VERSION = '1.6.3'

/**
 * First runtime that signs its requests (agent-request-signing.ts) and refuses
 * redirects, weakened TLS and loosely-permissioned credential files.
 */
export const AGENT_SIGNING_MIN_VERSION = '1.6.0'

/**
 * First runtime that understands the `rollback` command.
 *
 * Checked before a rollback is dispatched, because an older agent answers an
 * unknown command with "Unsupported command type" — which would settle the
 * snapshot as a FAILED restore and leave an operator retrying a rollback that
 * can never run until the host is upgraded. Refusing up front names the real
 * fix instead.
 */
export const AGENT_ROLLBACK_MIN_VERSION = '1.5.3'

/** Semver-ish comparison, tolerant of missing/garbage version strings. */
export function agentVersionAtLeast(version: string | null | undefined, minimum: string): boolean {
  const parse = (value: string) => String(value || '').trim().split('.').map((part) => Number.parseInt(part, 10) || 0)
  const have = parse(version || '')
  const want = parse(minimum)
  if (!String(version || '').trim()) return false
  for (let i = 0; i < Math.max(have.length, want.length); i += 1) {
    const a = have[i] || 0
    const b = want[i] || 0
    if (a !== b) return a > b
  }
  return true
}

/** Minimum Node.js major the bundled runtime requires (uses node: builtins + X509Certificate). */
export const AGENT_MIN_NODE_MAJOR = 18

/** Release channel. Only `stable` is published today; the field exists so pinning works. */
export type ReleaseChannel = 'stable'
export const RELEASE_CHANNEL: ReleaseChannel = 'stable'

/** File name of the published single-file runtime bundle. */
export const AGENT_RUNTIME_FILENAME = 'qguard-agent.cjs'

/* ------------------------------------------------------------------ */
/* Agent roles (spec §2)                                              */
/* ------------------------------------------------------------------ */

export type AgentRole = 'collector' | 'scanner' | 'patcher' | 'operator'

export interface AgentRoleDefinition {
  id: AgentRole
  label: string
  tagline: string
  /** Collector modules loaded for this role (spec §3 — modular, load only what is needed). */
  modules: string[]
  /** Scan types requested from the backend policy for this role. */
  scanTypes: string[]
  /** Capability flags written to `scanner_agents.capabilities`. */
  capabilities: Record<string, boolean>
  /** Whether the role may change customer configuration at all. */
  mutatesTargets: boolean
  /** Human-readable authority statement rendered in the UI. */
  authority: string
}

/** Discovery/telemetry scan types understood by the agent runtime and backend policy. */
const DISCOVERY_SCAN_TYPES = [
  'tls',
  'certificates',
  'pki',
  'ssh',
  'packages',
  'configs',
  'libraries',
  'runtime',
]

const EXTENDED_SCAN_TYPES = [
  ...DISCOVERY_SCAN_TYPES,
  'vpn',
  'kubernetes',
  'service_mesh',
  'api_gateway',
  'load_balancer',
  'hsm',
  'database',
  'container',
]

export const AGENT_ROLES: AgentRoleDefinition[] = [
  {
    id: 'collector',
    label: 'Collector',
    tagline: 'Inventory and evidence collection. Read-only.',
    modules: [
      'crypto_inventory',
      'tls_inventory',
      'certificate_inventory',
      'pki_inventory',
      'filesystem_crypto',
      'application_crypto',
      'package_inventory',
      'runtime_crypto',
    ],
    scanTypes: EXTENDED_SCAN_TYPES,
    capabilities: {
      crypto_discovery: true,
      certificate_discovery: true,
      tls_inspection: true,
      pki_discovery: true,
      runtime_crypto: true,
      cbom: true,
      telemetry: true,
      remediation: false,
      migration: false,
    },
    mutatesTargets: false,
    authority: 'Reads cryptographic evidence from allowed paths and targets only. Never writes to the host.',
  },
  {
    id: 'scanner',
    label: 'Scanner',
    tagline: 'Quantum-vulnerability analysis of discovered cryptography. Read-only.',
    modules: [
      'crypto_inventory',
      'tls_inventory',
      'certificate_inventory',
      'pki_inventory',
      'filesystem_crypto',
      'application_crypto',
    ],
    scanTypes: DISCOVERY_SCAN_TYPES,
    capabilities: {
      crypto_discovery: true,
      certificate_discovery: true,
      tls_inspection: true,
      pki_discovery: true,
      runtime_crypto: false,
      cbom: true,
      telemetry: true,
      remediation: false,
      migration: false,
    },
    mutatesTargets: false,
    authority: 'Classifies discovered algorithms against FIPS 203/204/205. Never writes to the host.',
  },
  {
    id: 'patcher',
    label: 'Patcher',
    tagline: 'Approved cryptographic remediation on allowed configuration paths.',
    modules: [
      'crypto_inventory',
      'tls_inventory',
      'certificate_inventory',
      'filesystem_crypto',
      'config_remediation',
    ],
    scanTypes: EXTENDED_SCAN_TYPES,
    capabilities: {
      crypto_discovery: true,
      certificate_discovery: true,
      tls_inspection: true,
      pki_discovery: true,
      runtime_crypto: true,
      cbom: true,
      remediation: true,
      config_patches: true,
      migration: false,
      telemetry: true,
    },
    mutatesTargets: true,
    authority:
      'Applies approved changes only to explicitly allow-listed paths, always with a snapshot, post-change validation and automatic rollback on failure.',
  },
  {
    id: 'operator',
    label: 'Migration Operator',
    tagline: 'Executes approved Live Migration cutovers on claimed jobs.',
    modules: [
      'crypto_inventory',
      'tls_inventory',
      'certificate_inventory',
      'pki_inventory',
      'filesystem_crypto',
      'config_remediation',
      'migration_execution',
    ],
    scanTypes: EXTENDED_SCAN_TYPES,
    capabilities: {
      crypto_discovery: true,
      certificate_discovery: true,
      tls_inspection: true,
      pki_discovery: true,
      runtime_crypto: true,
      cbom: true,
      remediation: true,
      config_patches: true,
      migration: true,
      telemetry: true,
    },
    mutatesTargets: true,
    authority:
      'Claims only migration jobs that match tenant, asset, capability, policy, approval and allowed-path checks. Rollback configuration is mandatory.',
  },
]

export function agentRole(id: string | null | undefined): AgentRoleDefinition {
  return AGENT_ROLES.find((role) => role.id === id) || AGENT_ROLES[0]
}

/** Human-facing capability list for the detail drawer (spec §12). */
export const CAPABILITY_LABELS: Record<string, string> = {
  crypto_discovery: 'Crypto Discovery',
  certificate_discovery: 'Certificate Discovery',
  tls_inspection: 'TLS Inspection',
  pki_discovery: 'PKI Discovery',
  runtime_crypto: 'Runtime Crypto',
  cbom: 'CBOM',
  remediation: 'Remediation',
  config_patches: 'Config Patching',
  migration: 'Migration',
  telemetry: 'Telemetry',
}

/* ------------------------------------------------------------------ */
/* Platforms (spec §4)                                                */
/* ------------------------------------------------------------------ */

export type AgentPlatform =
  | 'linux'
  | 'windows'
  | 'docker'
  | 'kubernetes'
  | 'powershell'
  | 'cloud-init'

export interface PlatformDefinition {
  id: AgentPlatform
  label: string
  /** Generated artifact file name. */
  filename: string
  /** MIME type used for the download. */
  contentType: string
  /** Syntax hint for the code viewer. */
  language: string
  /** Architectures the produced install supports. */
  architectures: string[]
  /** Service/supervision mechanism the installer configures. */
  service: string
  /** Command the operator runs after downloading the artifact. */
  runCommand: (filename: string) => string
  /** Elevation requirement, shown before download. */
  privileges: string
  /** Prerequisites checked (and where possible installed) by the generated script. */
  prerequisites: string[]
}

export const AGENT_PLATFORMS: PlatformDefinition[] = [
  {
    id: 'linux',
    label: 'Linux',
    filename: 'qguard-agent-install.sh',
    contentType: 'application/x-sh',
    language: 'bash',
    architectures: ['x86_64', 'aarch64 (ARM64)'],
    service: 'One unit per agent: qguard-agent-<agent-id>.service',
    runCommand: (f) => `chmod +x ${f} && sudo ./${f}`,
    privileges: 'root (sudo) — required to install the systemd unit',
    prerequisites: ['bash', 'curl or wget', 'sha256sum', `Node.js ${AGENT_MIN_NODE_MAJOR}+ (auto-installed via apt/dnf/yum/apk when missing)`],
  },
  {
    id: 'windows',
    label: 'Windows',
    filename: 'qguard-agent-install.ps1',
    contentType: 'text/plain',
    language: 'powershell',
    architectures: ['x64', 'ARM64'],
    service: 'One task per agent: QGuardHelixAgent-<agent-id> (SYSTEM, at startup)',
    runCommand: (f) => `powershell -ExecutionPolicy Bypass -File .\\${f}`,
    privileges: 'Administrator — required to register the startup task',
    prerequisites: ['Windows 10/11 or Server 2016+', 'PowerShell 5.1+', `Node.js ${AGENT_MIN_NODE_MAJOR}+ (auto-installed via winget when missing)`],
  },
  {
    id: 'docker',
    label: 'Docker',
    filename: 'qguard-agent-compose.yml',
    contentType: 'text/yaml',
    language: 'yaml',
    architectures: ['linux/amd64', 'linux/arm64'],
    service: 'Agent-specific Docker Compose project (restart: unless-stopped)',
    runCommand: (f) => `docker compose -f ${f} up -d`,
    privileges: 'Docker daemon access',
    prerequisites: ['Docker Engine 20.10+', 'Docker Compose v2'],
  },
  {
    id: 'kubernetes',
    label: 'Kubernetes',
    filename: 'qguard-agent-k8s.yaml',
    contentType: 'text/yaml',
    language: 'yaml',
    architectures: ['linux/amd64', 'linux/arm64'],
    service: 'Deployment qguard-agent in namespace qguard-helix',
    runCommand: (f) => `kubectl apply -f ${f}`,
    privileges: 'Namespace create + Deployment/Secret/ServiceAccount RBAC',
    prerequisites: ['Kubernetes 1.24+', 'kubectl context pointed at the target cluster'],
  },
  {
    id: 'powershell',
    label: 'PowerShell (portable)',
    filename: 'qguard-agent-run.ps1',
    contentType: 'text/plain',
    language: 'powershell',
    architectures: ['x64', 'ARM64'],
    service: 'None — foreground run, no installation',
    runCommand: (f) => `powershell -ExecutionPolicy Bypass -File .\\${f}`,
    privileges: 'Standard user (reads only what the user can read)',
    prerequisites: ['PowerShell 5.1+', `Node.js ${AGENT_MIN_NODE_MAJOR}+ already on PATH`],
  },
  {
    id: 'cloud-init',
    label: 'Cloud-Init',
    filename: 'qguard-agent-cloud-init.yaml',
    contentType: 'text/yaml',
    language: 'yaml',
    architectures: ['x86_64', 'aarch64 (ARM64)'],
    service: 'systemd unit qguard-agent.service, provisioned at first boot',
    runCommand: () => 'Paste into the instance User Data / cloud-init field at launch',
    privileges: 'Instance provisioning (runs as root at first boot)',
    prerequisites: ['cloud-init enabled Linux image', 'Outbound HTTPS to the Qguard Helix API'],
  },
]

export function agentPlatform(id: string | null | undefined): PlatformDefinition {
  return AGENT_PLATFORMS.find((platform) => platform.id === id) || AGENT_PLATFORMS[0]
}

/* ------------------------------------------------------------------ */
/* Installation phases (spec §32)                                     */
/* ------------------------------------------------------------------ */

export const INSTALL_PHASES = [
  { id: 'package_generated', label: 'Installer generated' },
  { id: 'installer_downloaded', label: 'Installer downloaded' },
  { id: 'runtime_downloaded', label: 'Runtime downloaded' },
  { id: 'package_verified', label: 'Package verified (SHA-256)' },
  { id: 'agent_installed', label: 'Agent installed' },
  { id: 'service_started', label: 'Agent service started' },
  { id: 'enrolled', label: 'Enrollment successful' },
  { id: 'connected', label: 'Backend connection established' },
  { id: 'first_scan', label: 'First scan complete' },
] as const

export type InstallPhaseId = (typeof INSTALL_PHASES)[number]['id']

/** Heartbeat statuses the installer/agent write; consumed by the activity timeline. */
export const INSTALL_PHASE_STATUS_PREFIX = 'install:'

/* ------------------------------------------------------------------ */
/* Realtime event names (spec §10)                                    */
/* ------------------------------------------------------------------ */

export const AGENT_EVENTS = [
  'agent.created',
  'agent.installation_started',
  'agent.enrollment_started',
  'agent.enrolled',
  'agent.connected',
  'agent.disconnected',
  'agent.heartbeat',
  'agent.scan_started',
  'agent.scan_progress',
  'agent.scan_completed',
  'agent.finding_detected',
  'agent.evidence_observed',
  'agent.migration_started',
  'agent.migration_progress',
  'agent.migration_completed',
  'agent.upgrade_available',
  'agent.upgrade_started',
  'agent.upgrade_completed',
  'agent.error',
] as const

export type AgentEventName = (typeof AGENT_EVENTS)[number]

/* ------------------------------------------------------------------ */
/* Commands the control plane may queue for an agent                  */
/* ------------------------------------------------------------------ */

export type AgentCommandType =
  | 'scan'
  | 'upgrade'
  | 'disable'
  | 'enable'
  | 'rescan_validation'
  /**
   * Restore a configuration the agent itself backed up before it patched.
   *
   * Rollback is a WRITE, so it is only ever queued for a `patcher`/`operator`
   * agent, and only for the agent that holds the backup — the backup file lives
   * on the host that was changed, so "rolling back via" any other agent would
   * restore nothing. The payload carries the snapshot id, the recorded
   * target/backup paths and the pre-change digest; the agent refuses the command
   * unless the backup still hashes to that digest.
   */
  | 'rollback'

/** Command types that modify the host and therefore need a write-capable role. */
export const MUTATING_COMMAND_TYPES: readonly AgentCommandType[] = ['rollback']

export interface AgentCommand {
  id: string
  type: AgentCommandType
  /** ISO timestamp the command was queued. */
  queuedAt: string
  /** Who queued it (user id) — audit trail. */
  requestedBy: string
  /** Optional payload, e.g. { targetVersion } for upgrade. */
  payload?: Record<string, unknown>
  status: 'queued' | 'delivered' | 'running' | 'completed' | 'failed'
  deliveredAt?: string | null
  startedAt?: string | null
  completedAt?: string | null
  result?: Record<string, unknown> | null
  error?: string | null
}

/** Bounded queue sizes so `scanner_agents.metadata` cannot grow without limit. */
export const MAX_QUEUED_COMMANDS = 25
export const MAX_COMMAND_HISTORY = 50

/* ------------------------------------------------------------------ */
/* Assessment vocabulary (spec §29 — never fabricate certainty)       */
/* ------------------------------------------------------------------ */

export type AssessmentState =
  | 'Detected'
  | 'Verified'
  | 'Pending'
  | 'Unknown'
  | 'Failed'
  | 'Not Supported'
  | 'Not Scanned'

export const NOT_ASSESSED_LABEL = 'Not Yet Assessed'

/**
 * Connection state derived from heartbeat recency only. `Waiting` means the agent
 * has never checked in — it is NOT "offline" and must never read as healthy.
 */
export type ConnectionState = 'Connected' | 'Connecting' | 'Offline' | 'Error' | 'Waiting'

/** Heartbeat older than this is no longer a live connection. */
export const HEARTBEAT_ONLINE_WINDOW_MS = 10 * 60 * 1000
/** Freshly installed agents are "Connecting" for this long before they read Offline. */
export const HEARTBEAT_GRACE_WINDOW_MS = 5 * 60 * 1000
