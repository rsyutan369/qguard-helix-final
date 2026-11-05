/**
 * Agent asset binding — WHERE an agent's findings land.
 *
 * Without an explicit binding, an installed agent uses one stable device
 * profile. Its certificates, files and packages are components and observations
 * inside that profile. An operator who deploys an agent to cover
 * "Payments API" or "/etc/nginx" wants the results filed under that name, not
 * scattered across forty auto-named rows.
 *
 * A binding names one tenant-owned asset — an existing one, or one created for
 * the purpose (an application, a folder, a file, a profile …) — and an
 * attribution mode:
 *
 *   bound    every finding is recorded against the bound asset; what was
 *            actually observed is kept on the finding as `discoveredTarget`
 *   grouped  discovered assets keep their own rows and are tagged with the
 *            bound asset as their parent, so they roll up under it
 *
 * This module is the single definition of the binding contract. The enrolment
 * and rebinding routes parse requests with it, the evidence pipeline reads the
 * stored binding with it, and the console renders from it — so the three can
 * never disagree about what a binding is.
 */

export const BINDING_KINDS = [
  { id: 'application', label: 'Application', hint: 'A product, app or workload', needsPath: false, pathLabel: '', pathPlaceholder: '' },
  { id: 'server', label: 'Host / Server', hint: 'A physical, virtual or cloud host', needsPath: false, pathLabel: '', pathPlaceholder: '' },
  { id: 'service', label: 'Service / API', hint: 'An endpoint, API or microservice', needsPath: false, pathLabel: '', pathPlaceholder: '' },
  { id: 'folder', label: 'Folder', hint: 'A directory tree the agent scans', needsPath: true, pathLabel: 'Folder path', pathPlaceholder: '/etc/nginx  or  C:\\inetpub\\certs' },
  { id: 'file', label: 'File', hint: 'A single config, keystore or certificate', needsPath: true, pathLabel: 'File path', pathPlaceholder: '/etc/ssl/private/server.key' },
  { id: 'repository', label: 'Repository', hint: 'A source repository or checkout', needsPath: true, pathLabel: 'Repository URL or path', pathPlaceholder: 'https://github.com/acme/payments' },
  { id: 'profile', label: 'Profile', hint: 'A named scope, e.g. "PCI estate"', needsPath: false, pathLabel: '', pathPlaceholder: '' },
  { id: 'environment', label: 'Environment', hint: 'Production, staging, a region …', needsPath: false, pathLabel: '', pathPlaceholder: '' },
  { id: 'business-unit', label: 'Business Unit', hint: 'A team, department or subsidiary', needsPath: false, pathLabel: '', pathPlaceholder: '' },
] as const

export type BindingKindId = (typeof BINDING_KINDS)[number]['id']

export const BINDING_ATTRIBUTIONS = [
  {
    id: 'bound',
    label: 'File every finding under this target',
    detail: 'All findings, CBOM entries, exposures and alerts are recorded against the bound asset. The host, file or package actually observed is kept on each finding.',
  },
  {
    id: 'grouped',
    label: 'Keep discovered assets, grouped under this target',
    detail: 'Each discovered host, file or package keeps its own asset row and is tagged with this target as its parent, so it rolls up without losing per-asset detail.',
  },
] as const

export type BindingAttribution = (typeof BINDING_ATTRIBUTIONS)[number]['id']

/** What a client may ask for. Every field is re-validated server-side. */
export type AgentBindingRequest =
  | { mode: 'none' }
  | { mode: 'existing'; assetId: string; attribution?: BindingAttribution }
  | {
      mode: 'new'
      name: string
      kind: BindingKindId
      path?: string
      owner?: string
      description?: string
      attribution?: BindingAttribution
    }

export type NormalizedBindingRequest =
  | { mode: 'none' }
  | { mode: 'existing'; assetId: string; attribution: BindingAttribution }
  | {
      mode: 'new'
      name: string
      kind: BindingKindId
      path: string | null
      owner: string | null
      description: string | null
      attribution: BindingAttribution
    }

export type BindingParseResult =
  | { ok: true; value: NormalizedBindingRequest }
  | { ok: false; code: string; message: string }

/** The binding as persisted on `scanner_agents.metadata.binding`. */
export type AgentBinding = {
  assetId: string
  assetName: string
  kind: string | null
  path: string | null
  attribution: BindingAttribution
  boundAt: string | null
  boundBy: string | null
  /** True when the target asset was created by the binding itself. */
  createdForBinding: boolean
}

export const BINDING_NAME_MAX = 120
const PATH_MAX = 1000
const OWNER_MAX = 255
const DESCRIPTION_MAX = 500
const ASSET_ID_PATTERN = /^[A-Za-z0-9_-]{1,80}$/
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/

export function bindingKind(id: string | null | undefined) {
  return BINDING_KINDS.find((kind) => kind.id === id) || null
}

export function isBindingAttribution(value: unknown): value is BindingAttribution {
  return BINDING_ATTRIBUTIONS.some((item) => item.id === value)
}

function text(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed ? trimmed.slice(0, max) : null
}

/** Whether a proposed binding name is acceptable, with the reason if not. */
export function bindingNameIssue(value: string): string | null {
  const name = value.trim()
  if (!name) return 'Give the target a name.'
  if (name.length > BINDING_NAME_MAX) return `Keep the name under ${BINDING_NAME_MAX} characters.`
  if (CONTROL_CHARS.test(name)) return 'The name contains control characters.'
  return null
}

/** Whether a path is acceptable for a kind that needs one, with the reason if not. */
export function bindingPathIssue(kind: BindingKindId, value: string | null | undefined): string | null {
  const meta = bindingKind(kind)
  const path = (value || '').trim()
  if (!meta?.needsPath) return null
  if (!path) return `${meta.pathLabel} is required for a ${meta.label.toLowerCase()} binding.`
  if (path.length > PATH_MAX) return `Keep the path under ${PATH_MAX} characters.`
  if (CONTROL_CHARS.test(path)) return 'The path contains control characters.'
  return null
}

/**
 * Parse a binding request from the request body.
 *
 * `legacyAssetId` is the `metadata.assetId` the Agent Center wizard has always
 * sent; it is honoured as an `existing` binding so that wizard keeps working.
 * An absent binding is `none` — the ingestion layer resolves the agent's
 * default device profile once it first reports evidence.
 */
export function parseBindingRequest(raw: unknown, legacyAssetId?: unknown): BindingParseResult {
  const body = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : null
  const attribution: BindingAttribution = isBindingAttribution(body?.attribution) ? body!.attribution as BindingAttribution : 'bound'

  if (!body) {
    const legacy = text(legacyAssetId, 80)
    if (!legacy) return { ok: true, value: { mode: 'none' } }
    if (!ASSET_ID_PATTERN.test(legacy)) return { ok: false, code: 'BINDING_INVALID', message: 'The selected asset id is malformed.' }
    return { ok: true, value: { mode: 'existing', assetId: legacy, attribution } }
  }

  if (body.attribution !== undefined && !isBindingAttribution(body.attribution)) {
    return { ok: false, code: 'BINDING_INVALID', message: 'Attribution must be "bound" or "grouped".' }
  }

  switch (body.mode) {
    case undefined:
    case null:
    case 'none':
      return { ok: true, value: { mode: 'none' } }
    case 'existing': {
      const assetId = text(body.assetId, 80)
      if (!assetId || !ASSET_ID_PATTERN.test(assetId)) {
        return { ok: false, code: 'BINDING_INVALID', message: 'Choose an asset to bind this agent to.' }
      }
      return { ok: true, value: { mode: 'existing', assetId, attribution } }
    }
    case 'new': {
      const name = typeof body.name === 'string' ? body.name : ''
      const nameIssue = bindingNameIssue(name)
      if (nameIssue) return { ok: false, code: 'BINDING_INVALID', message: nameIssue }
      const kind = bindingKind(typeof body.kind === 'string' ? body.kind : null)
      if (!kind) return { ok: false, code: 'BINDING_INVALID', message: 'Choose what kind of target this is.' }
      const pathIssue = bindingPathIssue(kind.id, typeof body.path === 'string' ? body.path : null)
      if (pathIssue) return { ok: false, code: 'BINDING_INVALID', message: pathIssue }
      return {
        ok: true,
        value: {
          mode: 'new',
          name: name.trim(),
          kind: kind.id,
          path: kind.needsPath ? text(body.path, PATH_MAX) : null,
          owner: text(body.owner, OWNER_MAX),
          description: text(body.description, DESCRIPTION_MAX),
          attribution,
        },
      }
    }
    default:
      return { ok: false, code: 'BINDING_INVALID', message: 'Binding mode must be "none", "existing" or "new".' }
  }
}

/**
 * Read the binding an agent row carries.
 *
 * Agents enrolled before bindings existed carry only `metadata.assetId` /
 * `assetName`; those read as a `bound` binding with no kind, which is what the
 * Agent Center's asset picker always meant.
 */
export function agentBindingFromMetadata(metadata: unknown): AgentBinding | null {
  const meta = metadata && typeof metadata === 'object' ? (metadata as Record<string, unknown>) : {}
  const stored = meta.binding && typeof meta.binding === 'object' ? (meta.binding as Record<string, unknown>) : null
  const assetId = text(stored?.assetId, 80) || text(meta.assetId, 80)
  if (!assetId) return null
  return {
    assetId,
    assetName: text(stored?.assetName, 255) || text(meta.assetName, 255) || 'Bound asset',
    kind: text(stored?.kind, 40) || text(meta.assetType, 100),
    path: text(stored?.path, PATH_MAX),
    attribution: isBindingAttribution(stored?.attribution) ? stored!.attribution as BindingAttribution : 'bound',
    boundAt: text(stored?.boundAt, 40),
    boundBy: text(stored?.boundBy, 80),
    createdForBinding: stored?.createdForBinding === true,
  }
}

/** The finding-level record of which binding a finding was filed under. */
export function bindingStamp(binding: AgentBinding, agentId: string | null | undefined, discoveredTarget: string) {
  return {
    assetId: binding.assetId,
    assetName: binding.assetName,
    kind: binding.kind,
    attribution: binding.attribution,
    agentId: agentId || null,
    discoveredTarget,
  }
}
