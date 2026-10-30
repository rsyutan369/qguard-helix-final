/**
 * Qguard Helix Agent — scope, module and write-authority model.
 *
 * Isomorphic (no Node/browser-only APIs). The Agent Center wizard, the agent
 * detail drawer, the enrolment/policy API, the installer generator AND the
 * agent runtime all import this file, so "what the operator selected" and
 * "what the agent does" are decided by one definition rather than several that
 * are supposed to agree.
 *
 * Three defects this module exists to prevent from coming back:
 *
 *  1. WRITE AUTHORITY WAS DECORATIVE. The wizard's "Authorize configuration
 *     remediation" checkbox was sent to the API, which then overwrote the
 *     capabilities with the role's full set — so a Patcher created with the box
 *     unticked still received `remediation: true` and an installer with
 *     `QGUARD_ENABLE_REMEDIATION=true`. `authorizedCapabilities` and
 *     `resolveWriteAuthority` are now the only way either is computed.
 *
 *  2. SURFACE MODULES DID NOTHING. "Kubernetes", "VPN", "Databases" … were
 *     offered as scope, but the runtime only read configuration under
 *     `configs`. Selecting "Kubernetes" alone collected nothing; deselecting it
 *     changed nothing. Surface modules now narrow configuration collection to
 *     that surface (`configEvidenceInScope`), and the wizard says exactly that.
 *
 *  3. SCOPE THAT CANNOT BE FED. A module that reads network targets does
 *     nothing without targets, and one that reads files does nothing without
 *     paths. An agent enrolled like that reports a clean scan of nothing.
 *     `planAgentScope` names every such module before the agent is created.
 */

import { agentRole, type AgentRole } from './agent-release'

/* ------------------------------------------------------------------ */
/* Scan module catalogue                                              */
/* ------------------------------------------------------------------ */

/** Which part of the operator's scope feeds a module. */
export type ScopeInput = 'targets' | 'paths' | 'host'

export type ScanModuleGroup = 'transport' | 'host' | 'surface'

export interface AgentScanModule {
  id: string
  label: string
  group: ScanModuleGroup
  /** What the runtime ACTUALLY does when the module is on — rendered verbatim. */
  does: string
  /** Scope inputs that feed it; the module is live when any one is present. */
  inputs: ScopeInput[]
  /** For target-fed modules: which parsed target kinds it consumes. */
  targetKinds?: Array<'tls' | 'ssh'>
}

export const SCAN_MODULE_GROUP_LABEL: Record<ScanModuleGroup, string> = {
  transport: 'Transport & PKI',
  host: 'Host & application',
  surface: 'Platform surfaces',
}

/**
 * Every module the agent runtime implements, described by what it does.
 *
 * Surface modules are NOT separate collectors: they select which configuration
 * files (by surface) are collected. `configs` collects every surface, so a
 * surface module only changes behaviour when `configs` is off. The wizard says
 * this in so many words rather than implying a cloud connector exists.
 */
export const AGENT_SCAN_MODULES: AgentScanModule[] = [
  {
    id: 'tls',
    label: 'TLS endpoints',
    group: 'transport',
    does: 'Handshakes with each TLS target to record protocol version, cipher suite, key-exchange group and the served certificate chain.',
    inputs: ['targets'],
    targetKinds: ['tls'],
  },
  {
    id: 'certificates',
    label: 'Certificates',
    group: 'transport',
    does: 'Parses certificate and key files (.pem .crt .cer .der .key …) under allowed paths — algorithm, key size, issuer and expiry — plus the JWKS and SAML metadata that publish signing keys (shared with PKI metadata).',
    inputs: ['paths'],
  },
  {
    id: 'pki',
    label: 'PKI metadata',
    group: 'transport',
    does: 'Reads certificate material plus JWKS and SAML metadata under allowed paths, and trust-store references in configuration.',
    inputs: ['paths'],
  },
  {
    id: 'ssh',
    label: 'SSH',
    group: 'transport',
    does: 'Probes SSH targets for key-exchange and host-key algorithms, and reads authorized_keys / known_hosts / *.pub under allowed paths.',
    inputs: ['targets', 'paths'],
    targetKinds: ['ssh'],
  },
  {
    id: 'configs',
    label: 'Config files',
    group: 'host',
    does: 'Reads configuration files under allowed paths line by line for protocol versions, cipher suites, key-exchange groups and signature algorithms — every platform surface included.',
    inputs: ['paths'],
  },
  {
    id: 'packages',
    label: 'Package manifests',
    group: 'host',
    does: 'Reads dependency manifests and lock files (package.json, requirements.txt, go.mod, pom.xml …) under allowed paths.',
    inputs: ['paths'],
  },
  {
    id: 'libraries',
    label: 'Crypto libraries',
    group: 'host',
    does: 'Identifies cryptographic libraries (OpenSSL, BouncyCastle, libsodium …) in those manifests. Shares the manifest reader with Package manifests.',
    inputs: ['paths'],
  },
  {
    id: 'runtime',
    label: 'Runtime crypto',
    group: 'host',
    does: 'Observes the host the agent runs on: crypto libraries loaded by running processes, the system certificate store, and eBPF (Linux) / ETW (Windows) handshake telemetry where the host supports it.',
    inputs: ['host'],
  },
  {
    id: 'kubernetes',
    label: 'Kubernetes',
    group: 'surface',
    does: 'Collects Kubernetes configuration (Ingress, cert-manager, issuers) found under allowed paths.',
    inputs: ['paths'],
  },
  {
    id: 'container',
    label: 'Containers',
    group: 'surface',
    does: 'Collects container and registry configuration (Dockerfile, compose, image references) under allowed paths.',
    inputs: ['paths'],
  },
  {
    id: 'service_mesh',
    label: 'Service mesh',
    group: 'surface',
    does: 'Collects Istio / Linkerd / Consul mTLS policy under allowed paths.',
    inputs: ['paths'],
  },
  {
    id: 'api_gateway',
    label: 'API gateway',
    group: 'surface',
    does: 'Collects gateway and reverse-proxy TLS configuration (NGINX, Envoy, Kong, Traefik, HAProxy) under allowed paths.',
    inputs: ['paths'],
  },
  {
    id: 'load_balancer',
    label: 'Load balancer',
    group: 'surface',
    does: 'Collects load-balancer TLS policy definitions under allowed paths.',
    inputs: ['paths'],
  },
  {
    id: 'vpn',
    label: 'VPN profiles',
    group: 'surface',
    does: 'Collects OpenVPN, WireGuard, IPsec and strongSwan profiles under allowed paths.',
    inputs: ['paths'],
  },
  {
    id: 'database',
    label: 'Database crypto',
    group: 'surface',
    does: 'Collects database TLS and encryption settings (PostgreSQL, MySQL, SQL Server, MongoDB …) under allowed paths.',
    inputs: ['paths'],
  },
  {
    id: 'hsm',
    label: 'HSM integration',
    group: 'surface',
    does: 'Collects PKCS#11, KMS and key-vault integration settings under allowed paths.',
    inputs: ['paths'],
  },
]

const MODULE_BY_ID = new Map(AGENT_SCAN_MODULES.map((module) => [module.id, module]))

export function agentScanModule(id: string): AgentScanModule | undefined {
  return MODULE_BY_ID.get(id)
}

/** Modules that read the agent's own host rather than any scope entry. */
const RUNTIME_MODULE_IDS = new Set(['runtime', 'native', 'ebpf', 'etw'])

/** Surface module ids — they narrow configuration collection. */
export const SURFACE_MODULE_IDS: readonly string[] = AGENT_SCAN_MODULES.filter((module) => module.group === 'surface').map(
  (module) => module.id,
)

/**
 * Configuration evidence type -> the surface module that selects it.
 *
 * Keys are the `evidenceType` values the runtime's configuration classifier
 * emits. Evidence types with no entry (`config-reference`, `jwt-algorithm` …)
 * are generic configuration and are collected under `configs` only. Surface ids
 * the Agent Collector Console also offers (`cloud`, `cloud_kms`, `api`,
 * `web_application`) are mapped too, so a policy saved from either console
 * behaves the same way on the host.
 */
export const CONFIG_EVIDENCE_SURFACE: Readonly<Record<string, string>> = {
  'kubernetes-crypto-policy': 'kubernetes',
  'container-crypto-policy': 'container',
  'service-mesh-crypto-policy': 'service_mesh',
  'api-gateway-crypto-policy': 'api_gateway',
  'load-balancer-crypto-policy': 'load_balancer',
  'vpn-crypto-profile': 'vpn',
  'database-crypto-policy': 'database',
  'cloud-database-crypto-policy': 'database',
  'hsm-integration': 'hsm',
  'cloud-hsm-policy': 'hsm',
  'cloud-kms-policy': 'cloud_kms',
  'cloud-certificate-manager': 'cloud',
  'cloud-iam-key-policy': 'cloud',
  'cloud-storage-encryption-policy': 'cloud_storage',
  'cdn-tls-policy': 'cdn',
  'saas-crypto-policy': 'saas',
  'network-device-crypto-policy': 'network_device',
  'web-application-crypto-policy': 'web_application',
  'trust-store': 'pki',
  'pki-metadata': 'pki',
  'jwt-algorithm': 'api',
}

const CONFIG_SELECTING_IDS = new Set<string>(['configs', ...Object.values(CONFIG_EVIDENCE_SURFACE)])

/** Does this module selection read configuration files at all? */
export function readsConfigFiles(scanTypes: ReadonlySet<string>): boolean {
  for (const id of scanTypes) if (CONFIG_SELECTING_IDS.has(id)) return true
  return false
}

/**
 * Is one configuration evidence row inside the operator's module selection?
 *
 * `configs` means every surface. Without it, a row is kept only when its
 * surface module is selected — which is what makes "Kubernetes only" collect
 * Kubernetes configuration and nothing else.
 */
export function configEvidenceInScope(evidenceType: string, scanTypes: ReadonlySet<string>): boolean {
  if (scanTypes.has('configs')) return true
  const surface = CONFIG_EVIDENCE_SURFACE[evidenceType]
  return Boolean(surface && scanTypes.has(surface))
}

/* ------------------------------------------------------------------ */
/* Role ceilings                                                      */
/* ------------------------------------------------------------------ */

/**
 * May an agent in `role` run this module?
 *
 * Derived from the role's capabilities rather than a second list: the Scanner
 * role is defined as `runtime_crypto: false`, so it may not run the host
 * runtime collectors, whatever a policy editor sends. Everything else is
 * decided by the plan, not the role.
 */
export function roleAllowsScanType(role: AgentRole | string | null | undefined, scanType: string): boolean {
  const definition = agentRole(typeof role === 'string' ? role : null)
  if (RUNTIME_MODULE_IDS.has(scanType)) return definition.capabilities.runtime_crypto === true
  return true
}

const SCAN_TYPE_ID = /^[a-z][a-z0-9_]{0,39}$/

export interface ScanTypeClamp {
  allowed: string[]
  /** Requested modules the role does not permit. */
  deniedByRole: string[]
  /** Requested modules the plan does not include (only when a plan list was given). */
  deniedByPlan: string[]
  /** Values that are not a module id at all. */
  rejected: string[]
}

/**
 * Normalise and clamp a requested module list.
 *
 * `planPermitted` null means "plan not consulted here" (the caller has already
 * clamped, or cannot read billing and must not guess). Removals are returned,
 * never swallowed: an absent dimension reads as a clean one.
 */
export function clampAgentScanTypes(
  role: AgentRole | string | null | undefined,
  requested: readonly unknown[] | null | undefined,
  planPermitted: readonly string[] | null,
): ScanTypeClamp {
  const permitted = planPermitted ? new Set(planPermitted) : null
  const seen = new Set<string>()
  const result: ScanTypeClamp = { allowed: [], deniedByRole: [], deniedByPlan: [], rejected: [] }
  for (const raw of requested || []) {
    const id = String(raw ?? '').trim().toLowerCase()
    if (!id || seen.has(id)) continue
    seen.add(id)
    if (!SCAN_TYPE_ID.test(id)) {
      result.rejected.push(id.slice(0, 40))
      continue
    }
    if (!roleAllowsScanType(role, id)) {
      result.deniedByRole.push(id)
      continue
    }
    if (permitted && !permitted.has(id)) {
      result.deniedByPlan.push(id)
      continue
    }
    result.allowed.push(id)
  }
  return result
}

/* ------------------------------------------------------------------ */
/* Scope entry validation                                             */
/* ------------------------------------------------------------------ */

export interface ParsedAgentTarget {
  original: string
  type: 'tls' | 'ssh'
  host: string
  port: number
  protocol: 'tls' | 'ssh'
}

/**
 * Parse one allowed-target entry exactly as the agent runtime does.
 *
 * The runtime imports THIS function, so the wizard's preview ("TLS
 * api.example.com:443") is the parse the host will perform, not an
 * approximation of it.
 */
/** A DNS name, IPv4 address or bracketed IPv6 literal — nothing a probe cannot dial. */
const TARGET_HOST = /^(?:\[[0-9a-f:.]+\]|[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?)$/i

export function parseAgentTarget(raw: string): ParsedAgentTarget | null {
  const parsed = parseAgentTargetUnchecked(raw)
  /* Hosts are validated, not just parsed: a non-special URL scheme accepts
     almost anything as a host, so "not a target!" used to become a TLS probe
     of a name no resolver will answer — a scan step that could only fail. */
  if (!parsed || !TARGET_HOST.test(parsed.host)) return null
  if (!Number.isInteger(parsed.port) || parsed.port < 1 || parsed.port > 65535) return null
  return parsed
}

function parseAgentTargetUnchecked(raw: string): ParsedAgentTarget | null {
  const value = String(raw ?? '').trim()
  if (!value) return null

  try {
    const explicitScheme = value.includes('://')
    const url = explicitScheme ? new URL(value) : new URL(`tls://${value}`)
    const protocol = url.protocol.replace(':', '').toLowerCase()
    const host = url.hostname
    if (!host) return null

    /* A bare `host:22` is SSH. The runtime used to read it as TLS on port 22 —
       only its fallback branch knew the convention — so an SSH server listed
       without a scheme was probed with a TLS handshake and never measured. */
    if (protocol === 'ssh' || (!explicitScheme && url.port === '22')) {
      return { original: value, type: 'ssh', host, port: Number(url.port || 22), protocol: 'ssh' }
    }
    if (protocol === 'https' || protocol === 'tls' || protocol === 'http') {
      return { original: value, type: 'tls', host, port: Number(url.port || 443), protocol: 'tls' }
    }
  } catch {
    const [host, port] = value.split(':')
    if (!host) return null
    const numeric = Number(port || 443)
    if (!Number.isFinite(numeric)) return null
    return { original: value, type: numeric === 22 ? 'ssh' : 'tls', host, port: numeric, protocol: numeric === 22 ? 'ssh' : 'tls' }
  }

  return null
}

export type PathIssue = 'relative' | 'home-shorthand' | 'looks-like-target'

/**
 * Why an allowed-path entry will not do what the operator expects.
 *
 * The agent resolves paths with Node's `path.resolve`, which never expands `~`
 * and resolves a relative path against the service's working directory — on a
 * systemd unit or a SYSTEM scheduled task, not a directory anyone chose.
 */
export function agentPathIssue(raw: string): PathIssue | null {
  const value = String(raw ?? '').trim()
  if (!value) return null
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value) || /^[^\\/\s:]+:\d{1,5}$/.test(value)) return 'looks-like-target'
  if (value === '~' || value.startsWith('~/') || value.startsWith('~\\')) return 'home-shorthand'
  const absolute = value.startsWith('/') || /^[a-z]:[\\/]/i.test(value) || value.startsWith('\\\\')
  return absolute ? null : 'relative'
}

export const PATH_ISSUE_COPY: Record<PathIssue, string> = {
  relative: 'Relative path — the agent would resolve it against its service directory. Use an absolute path.',
  'home-shorthand': '~ is not expanded by the agent. Write the full path (e.g. /home/svc/app).',
  'looks-like-target': 'This looks like a network target. Move it to Allowed targets.',
}

/** Bound and de-duplicate a scope list the way the API stores it. */
export function normaliseScopeList(values: readonly unknown[] | null | undefined, maxItems = 100, maxLength = 1000): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of values || []) {
    if (typeof raw !== 'string') continue
    const value = raw.trim()
    if (!value || value.length > maxLength || seen.has(value)) continue
    seen.add(value)
    out.push(value)
    if (out.length >= maxItems) break
  }
  return out
}

/* ------------------------------------------------------------------ */
/* Write authority                                                    */
/* ------------------------------------------------------------------ */

export interface WriteAuthorityInput {
  remediationAuthorized?: unknown
  migrationAuthorized?: unknown
}

export interface WriteAuthority {
  /** May apply approved configuration remediation. */
  remediation: boolean
  /** May execute approved Live Migration cutovers. */
  migration: boolean
}

/**
 * The operator's explicit authorisation, reduced to what the role can hold.
 *
 * Strict `=== true`: an absent field is "not authorised", because a write
 * capability granted by omission is the failure this model exists to end.
 * Migration implies remediation — a cutover IS a configuration change, and an
 * agent authorised for one but not the other would claim jobs it then refuses.
 */
export function authorityFromRequest(role: AgentRole | string | null | undefined, input: WriteAuthorityInput): WriteAuthority {
  const definition = agentRole(typeof role === 'string' ? role : null)
  if (!definition.mutatesTargets) return { remediation: false, migration: false }
  const remediation = input.remediationAuthorized === true
  const migration = remediation && definition.id === 'operator' && input.migrationAuthorized === true
  return { remediation, migration }
}

/**
 * Capabilities to persist for a role, with write capabilities present ONLY
 * when the operator authorised them. The role definition is the ceiling;
 * authorisation can only lower it.
 */
export function authorizedCapabilities(role: AgentRole | string | null | undefined, authority: WriteAuthority): Record<string, boolean> {
  const definition = agentRole(typeof role === 'string' ? role : null)
  const capabilities: Record<string, boolean> = { ...definition.capabilities }
  if (!authority.remediation) {
    capabilities.remediation = false
    capabilities.config_patches = false
  }
  if (!authority.migration) capabilities.migration = false
  return capabilities
}

/**
 * Whether a persisted agent currently holds write authority.
 *
 * Reads BOTH the capability flag and the recorded authorisation, so an agent
 * enrolled before this model existed — capabilities copied from the role even
 * though the operator ticked nothing — is not treated as authorised because of
 * that old defect.
 */
export function resolveWriteAuthority(
  role: AgentRole | string | null | undefined,
  capabilities: Record<string, unknown> | null | undefined,
  metadata: Record<string, unknown> | null | undefined,
): WriteAuthority {
  const definition = agentRole(typeof role === 'string' ? role : null)
  if (!definition.mutatesTargets) return { remediation: false, migration: false }
  const caps = capabilities || {}
  const meta = metadata || {}
  const remediation = caps.remediation === true && meta.remediationAuthorized !== false
  const migration = remediation && definition.id === 'operator' && caps.migration === true && meta.migrationAuthorized !== false
  return { remediation, migration }
}

/* ------------------------------------------------------------------ */
/* Scan presets                                                       */
/* ------------------------------------------------------------------ */

export interface AgentScanPreset {
  id: string
  label: string
  summary: string
  modules: readonly string[]
}

const ALL_MODULE_IDS = AGENT_SCAN_MODULES.map((module) => module.id)

export const AGENT_SCAN_PRESETS: AgentScanPreset[] = [
  {
    id: 'role-default',
    label: 'Role default',
    summary: 'Everything this agent type is built to collect, within your plan.',
    modules: [],
  },
  {
    id: 'host-inventory',
    label: 'Host crypto inventory',
    summary: 'TLS, certificates, SSH, configuration and dependencies — a complete CBOM of the host.',
    modules: ['tls', 'certificates', 'pki', 'ssh', 'configs', 'packages', 'libraries'],
  },
  {
    id: 'transport-pki',
    label: 'Transport & PKI',
    summary: 'Endpoints and certificate material only — the fastest route to HNDL and expiry exposure.',
    modules: ['tls', 'certificates', 'pki', 'ssh'],
  },
  {
    id: 'supply-chain',
    label: 'Libraries & dependencies',
    summary: 'Which cryptographic libraries each application ships, from its manifests.',
    modules: ['packages', 'libraries'],
  },
  {
    id: 'runtime',
    label: 'Runtime telemetry',
    summary: 'What the host is actually running: loaded crypto libraries, certificate store, handshakes.',
    modules: ['runtime'],
  },
  {
    id: 'platform',
    label: 'Platform surfaces',
    summary: 'Kubernetes, containers, mesh, gateways, VPN, databases and HSM configuration only.',
    modules: SURFACE_MODULE_IDS,
  },
  {
    id: 'full',
    label: 'Full estate',
    summary: 'Every module the runtime implements, within your role and plan.',
    modules: ALL_MODULE_IDS,
  },
]

export interface ResolvedPreset {
  modules: string[]
  /** Preset modules removed by the role or plan — shown, never hidden. */
  excluded: Array<{ id: string; reason: 'role' | 'plan' }>
}

/** A preset's modules for a role, clamped to the role and (when known) the plan. */
export function resolveScanPreset(
  presetId: string,
  role: AgentRole | string | null | undefined,
  planPermitted: readonly string[] | null,
): ResolvedPreset {
  const preset = AGENT_SCAN_PRESETS.find((item) => item.id === presetId)
  const definition = agentRole(typeof role === 'string' ? role : null)
  const requested = !preset || preset.id === 'role-default'
    ? definition.scanTypes.filter((id) => MODULE_BY_ID.has(id))
    : [...preset.modules]
  const clamp = clampAgentScanTypes(definition.id, requested, planPermitted && planPermitted.length ? planPermitted : null)
  return {
    modules: clamp.allowed,
    excluded: [
      ...clamp.deniedByRole.map((id) => ({ id, reason: 'role' as const })),
      ...clamp.deniedByPlan.map((id) => ({ id, reason: 'plan' as const })),
    ],
  }
}

/** Which preset (if any) a module selection is exactly equal to. */
export function matchScanPreset(
  modules: readonly string[],
  role: AgentRole | string | null | undefined,
  planPermitted: readonly string[] | null,
): string {
  const wanted = [...new Set(modules)].sort().join(',')
  for (const preset of AGENT_SCAN_PRESETS) {
    const resolved = resolveScanPreset(preset.id, role, planPermitted).modules
    if (resolved.length && [...resolved].sort().join(',') === wanted) return preset.id
  }
  return 'custom'
}

/**
 * The agent preset that corresponds to a Local assessment scan profile.
 *
 * Used when an operator moves from the browser Local assessment to a Local
 * Agent, so the intent they already expressed ("Supply Chain", "Kubernetes
 * Deep") is carried over instead of starting again from a blank scope. The
 * mapping is by what each side actually reads: the browser profiles that
 * inspect certificates and crypto usage map to the host inventory, the
 * dependency profile to libraries, and the platform profiles to surfaces.
 */
export const LOCAL_PROFILE_TO_AGENT_PRESET: Readonly<Record<string, string>> = {
  quick: 'transport-pki',
  standard: 'host-inventory',
  cryptographic: 'host-inventory',
  quantum: 'host-inventory',
  secrets: 'host-inventory',
  'supply-chain': 'supply-chain',
  'container-deep': 'platform',
  'kubernetes-deep': 'platform',
  deep: 'full',
  custom: 'role-default',
}

export function presetForLocalProfile(profileId: string | null | undefined): string | null {
  if (!profileId) return null
  return LOCAL_PROFILE_TO_AGENT_PRESET[profileId] ?? null
}

/* ------------------------------------------------------------------ */
/* The scope contract                                                  */
/* ------------------------------------------------------------------ */

export type ModuleScopeState =
  /** Selected, and the scope feeds it. */
  | 'active'
  /** Selected, but nothing in the scope feeds it — it will collect nothing. */
  | 'idle'
  /** Not selected, but collected anyway through `configs`. */
  | 'via-configs'
  | 'off'
  | 'plan-locked'
  | 'role-excluded'

export interface ModuleScopePlan {
  id: string
  label: string
  group: ScanModuleGroup
  state: ModuleScopeState
  /** One sentence: what happens, or why nothing will. */
  detail: string
}

export interface TargetPreview {
  raw: string
  parsed: ParsedAgentTarget | null
}

export interface PathPreview {
  raw: string
  issue: PathIssue | null
}

export interface ScopePlan {
  modules: ModuleScopePlan[]
  targets: TargetPreview[]
  paths: PathPreview[]
  tlsTargets: number
  sshTargets: number
  invalidTargets: number
  pathIssues: number
  activeModules: number
  idleModules: number
  /** True when no selected module has anything to read. */
  collectsNothing: boolean
  authority: WriteAuthority
  /** Plain statements of what the agent will do, in order. */
  will: string[]
  /** Plain statements of what it will not do. */
  wont: string[]
  /** Problems the operator should fix before deploying. */
  warnings: string[]
  /** Problems that make the configuration unusable as stated. */
  blockers: string[]
}

export interface ScopePlanInput {
  role: AgentRole | string
  scanTypes: readonly string[]
  allowedTargets: readonly string[]
  allowedPaths: readonly string[]
  /** Modules the plan includes; null when not yet known. */
  planPermitted?: readonly string[] | null
  remediationAuthorized?: boolean
  migrationAuthorized?: boolean
}

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`
}

/**
 * Everything the agent will and will not do with this configuration.
 *
 * Pure, so the wizard can re-run it on every keystroke and the drawer can run
 * it over a persisted policy — the same contract before and after deployment.
 */
export function planAgentScope(input: ScopePlanInput): ScopePlan {
  const definition = agentRole(input.role)
  const selected = new Set(input.scanTypes.map((id) => String(id).toLowerCase()))
  const permitted = input.planPermitted && input.planPermitted.length ? new Set(input.planPermitted) : null

  const targets: TargetPreview[] = normaliseScopeList(input.allowedTargets).map((raw) => ({ raw, parsed: parseAgentTarget(raw) }))
  const paths: PathPreview[] = normaliseScopeList(input.allowedPaths).map((raw) => ({ raw, issue: agentPathIssue(raw) }))
  const tlsTargets = targets.filter((item) => item.parsed?.type === 'tls').length
  const sshTargets = targets.filter((item) => item.parsed?.type === 'ssh').length
  const invalidTargets = targets.filter((item) => !item.parsed).length
  const usablePaths = paths.filter((item) => item.issue !== 'looks-like-target').length
  const pathIssues = paths.filter((item) => item.issue).length

  const modules: ModuleScopePlan[] = AGENT_SCAN_MODULES.map((module) => {
    const base = { id: module.id, label: module.label, group: module.group }
    if (!roleAllowsScanType(definition.id, module.id)) {
      return { ...base, state: 'role-excluded' as const, detail: `Not part of the ${definition.label} role.` }
    }
    if (permitted && !permitted.has(module.id)) {
      return { ...base, state: 'plan-locked' as const, detail: 'Not included in your plan.' }
    }
    if (!selected.has(module.id)) {
      if (module.group === 'surface' && selected.has('configs') && usablePaths > 0) {
        return { ...base, state: 'via-configs' as const, detail: 'Collected anyway — Config files reads every surface.' }
      }
      return { ...base, state: 'off' as const, detail: 'Off.' }
    }
    const fedByTargets = module.inputs.includes('targets') && (module.targetKinds || []).some((kind) => (kind === 'tls' ? tlsTargets : sshTargets) > 0)
    const fedByPaths = module.inputs.includes('paths') && usablePaths > 0
    const fedByHost = module.inputs.includes('host')
    if (fedByTargets || fedByPaths || fedByHost) {
      return { ...base, state: 'active' as const, detail: module.does }
    }
    const needs = module.inputs.includes('targets') && module.inputs.includes('paths')
      ? `an ${module.targetKinds?.[0]?.toUpperCase() ?? ''} target or an allowed path`
      : module.inputs.includes('targets')
        ? `a ${module.targetKinds?.map((kind) => kind.toUpperCase()).join('/')} target`
        : 'an allowed path'
    return { ...base, state: 'idle' as const, detail: `Selected, but will collect nothing until you add ${needs}.` }
  })

  const active = modules.filter((module) => module.state === 'active')
  const idle = modules.filter((module) => module.state === 'idle')
  const activeIds = new Set(active.map((module) => module.id))

  const authority = authorityFromRequest(definition.id, {
    remediationAuthorized: input.remediationAuthorized === true,
    migrationAuthorized: input.migrationAuthorized === true,
  })

  const will: string[] = []
  if (activeIds.has('tls') && tlsTargets) will.push(`Probe ${plural(tlsTargets, 'TLS endpoint')} for protocol, cipher suite, key exchange and certificate chain.`)
  if (activeIds.has('ssh') && sshTargets) will.push(`Probe ${plural(sshTargets, 'SSH endpoint')} for key-exchange and host-key algorithms.`)
  const pathReaders = active
    .filter((module) => module.id !== 'ssh' && MODULE_BY_ID.get(module.id)?.inputs.includes('paths'))
    .map((module) => module.label.toLowerCase())
  if (activeIds.has('ssh') && usablePaths) pathReaders.push('SSH keys')
  if (pathReaders.length && usablePaths) will.push(`Read ${pathReaders.join(', ')} under ${plural(usablePaths, 'allowed path')} (up to 200 files per path, 4 levels deep).`)
  if (activeIds.has('runtime')) will.push('Observe runtime cryptography on the host it is installed on.')
  if (authority.remediation) will.push('Apply approved PQC remediation inside allowed paths — snapshot first, validate after, roll back automatically on failure.')
  if (authority.migration) will.push('Claim approved Live Migration jobs that match its asset, capability, policy and allowed paths.')

  const wont: string[] = []
  if (!authority.remediation) wont.push('Never writes to the host — read-only.')
  if (definition.mutatesTargets && authority.remediation && !authority.migration) wont.push('Never executes Live Migration cutovers.')
  wont.push('Never contacts a target outside Allowed targets or reads outside Allowed paths.')
  if (!activeIds.has('runtime')) wont.push('Does not observe running processes or the system certificate store.')
  wont.push('Uploads evidence only — never file contents, private keys or secret values.')

  const warnings: string[] = []
  for (const module of idle) warnings.push(`${module.label}: ${module.detail}`)
  if (invalidTargets) warnings.push(`${plural(invalidTargets, 'target')} cannot be parsed and will be skipped.`)
  const tlsSkipped = !selected.has('tls') && tlsTargets > 0
  const sshSkipped = !selected.has('ssh') && sshTargets > 0
  if (tlsSkipped) warnings.push(`${plural(tlsTargets, 'TLS target')} listed but TLS endpoints is off — they will not be probed.`)
  if (sshSkipped) warnings.push(`${plural(sshTargets, 'SSH target')} listed but SSH is off — they will not be probed.`)
  for (const item of paths) if (item.issue) warnings.push(`${item.raw}: ${PATH_ISSUE_COPY[item.issue]}`)

  const blockers: string[] = []
  if (selected.size === 0) blockers.push('Select at least one scan module.')
  else if (active.length === 0) blockers.push('Nothing in this scope can be collected. Add an allowed target or path, or enable Runtime crypto.')
  if (authority.remediation && usablePaths === 0) {
    blockers.push(`${definition.label} write authority is scoped to allowed paths — add at least one path it may change.`)
  }

  return {
    modules,
    targets,
    paths,
    tlsTargets,
    sshTargets,
    invalidTargets,
    pathIssues,
    activeModules: active.length,
    idleModules: idle.length,
    collectsNothing: active.length === 0,
    authority,
    will,
    wont,
    warnings,
    blockers,
  }
}
