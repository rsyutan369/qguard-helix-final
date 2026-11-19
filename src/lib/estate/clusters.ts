/**
 * Fix-centric remediation clusters.
 *
 * "412 vulnerable assets" is not a plan. "Re-issue the 380 certificates signed
 * by Corp-Issuing-02 with ML-DSA" is. Every actionable observation is routed to
 * exactly ONE fix (the action that resolves it), so the sum of the fixes is the
 * whole backlog with nothing counted twice.
 *
 * Progress is evidence-based: an asset is `validated` only when a migration job
 * completed AND a scan recorded after that completion no longer shows the
 * vulnerable component. A completed job alone is `awaiting validation`.
 */
import { migrationTargetFor, type CanonicalAlgorithm } from '@/lib/scanner/exposure/algorithms'
import type { CryptoRole, FindingSeverity } from '@/lib/scanner/exposure/types'
import {
  ENVIRONMENT_LABEL, assetWeight, worstSeverity,
  type CertificateIdentity, type EnvironmentKey, type EstateAsset, type Observation, type Row,
} from './model'
import { str } from '@/lib/migration/asset-intelligence'
import { PQC_TRANSITION_SOURCES } from '@/lib/crypto/pqc-transition-sources'

/* ------------------------------------------------------------------ */
/* Migration jobs → per-asset progress                                 */
/* ------------------------------------------------------------------ */

export type JobPhase = 'planned' | 'running' | 'completed' | 'failed'

export function jobPhase(status: string): JobPhase | null {
  const value = status.toLowerCase()
  if (/complete|succeed|success|done|finished/.test(value)) return 'completed'
  if (/fail|error|roll|cancel/.test(value)) return 'failed'
  if (/run|progress|execut|dispatch|validat/.test(value)) return 'running'
  if (/queue|pend|await|pause|block|schedul|plan|approv|draft/.test(value)) return 'planned'
  return null
}

export interface AssetJob { id: string; phase: JobPhase; status: string; updatedAt: number; targetAlgorithm: string }

/** Latest migration job per asset. */
export function latestJobs(rows: Row[]): Map<string, AssetJob> {
  const latest = new Map<string, AssetJob>()
  for (const row of rows) {
    const assetId = str(row.asset_id)
    const phase = jobPhase(str(row.status))
    if (!assetId || !phase) continue
    const updatedAt = Date.parse(str(row.updated_at) || str(row.created_at)) || 0
    const current = latest.get(assetId)
    if (!current || updatedAt > current.updatedAt) {
      latest.set(assetId, { id: str(row.id), phase, status: str(row.status), updatedAt, targetAlgorithm: str(row.target_algorithm) })
    }
  }
  return latest
}

export type MemberStatus = 'open' | 'planned' | 'running' | 'failed' | 'awaiting-validation' | 'validated' | 'regressed'

export const MEMBER_STATUS_LABEL: Record<MemberStatus, string> = {
  open: 'Not started',
  planned: 'Planned / queued',
  running: 'In progress',
  failed: 'Failed / rolled back',
  'awaiting-validation': 'Completed — awaiting rescan',
  validated: 'Validated by rescan',
  regressed: 'Rescan still vulnerable',
}

/* ------------------------------------------------------------------ */
/* Fix kinds                                                           */
/* ------------------------------------------------------------------ */

export type FixKind =
  | 'ca-reissue' | 'certificate-keys' | 'library-upgrade' | 'key-exchange'
  | 'signing-keys' | 'data-encryption' | 'classical-weakness' | 'classify-usage'

export const FIX_KIND_LABEL: Record<FixKind, string> = {
  'ca-reissue': 'Certificate re-issuance',
  'certificate-keys': 'Certificate keys',
  'library-upgrade': 'Library upgrade',
  'key-exchange': 'Key exchange',
  'signing-keys': 'Signing & authentication keys',
  'data-encryption': 'Data encryption',
  'classical-weakness': 'Classical weakness',
  'classify-usage': 'Usage needs classification',
}

/** Planning estimate in engineer-days: fixed cost + per-asset cost. Published as an estimate, never as a measurement. */
const EFFORT: Record<FixKind, { base: number; perAsset: number }> = {
  'ca-reissue': { base: 3, perAsset: 0.25 },
  'certificate-keys': { base: 1, perAsset: 0.3 },
  'library-upgrade': { base: 2, perAsset: 0.5 },
  'key-exchange': { base: 1, perAsset: 0.15 },
  'signing-keys': { base: 2, perAsset: 0.5 },
  'data-encryption': { base: 3, perAsset: 1 },
  'classical-weakness': { base: 1, perAsset: 0.2 },
  'classify-usage': { base: 0.5, perAsset: 0.1 },
}

const SIGNATURE_PRIMITIVE = /ECDSA|EdDSA|Ed25519|Ed448|\bDSA\b|RSA-?PSS|\bPSS\b/i
const KEY_AGREEMENT_PRIMITIVE = /ECDHE?|\bDHE?\b|FFDHE|X25519|X448|Diffie|MQV/i
const SIGNING_ROLES: CryptoRole[] = ['signature', 'code-signing', 'token-signing', 'authentication', 'key-management']
const ENCRYPTION_ROLES: CryptoRole[] = ['encryption', 'storage-encryption', 'database-encryption']

/* ------------------------------------------------------------------ */
/* General transition timing (NIST IR 8547, final)                     */
/* ------------------------------------------------------------------ */

export interface Deadline { year: number | null; label: string; basis: string }

type TimingObservation = { algorithm?: string; classical: boolean }
const IR_8547_PUBLIC_KEY_SCHEMES = new Set(['RSA', 'ECDSA', 'Ed25519', 'ECDH', 'X25519', 'Diffie-Hellman'])

export function deadlineFor(observations: TimingObservation[]): Deadline {
  if (observations.some((o) => o.classical)) {
    return { year: 0, label: 'Now — broken today', basis: 'Classically weak: exploitable without a quantum computer.' }
  }
  if (observations.some((o) => o.algorithm && IR_8547_PUBLIC_KEY_SCHEMES.has(o.algorithm))) {
    return { year: 2030, label: 'Deprecated after 2030', basis: `${PQC_TRANSITION_SOURCES.nist.summary} Earlier federal requirements may apply.` }
  }
  return { year: null, label: 'Review timing', basis: 'No covered scheme was identified in this fix. Confirm the algorithm and applicable requirements.' }
}

/* ------------------------------------------------------------------ */
/* Cluster model                                                       */
/* ------------------------------------------------------------------ */

export interface FixCluster {
  id: string
  kind: FixKind
  kindLabel: string
  title: string
  /** What to do, in one sentence. */
  action: string
  /** Approved replacement, or null with the reason one cannot be named yet. */
  target: string | null
  targetNote: string | null
  rootCause: { type: 'issuer' | 'library' | 'algorithm'; label: string }
  severity: FindingSeverity
  assets: number
  observations: number
  uniqueComponents: number
  certificates: { unique: number; reusedAcrossAssets: number } | null
  algorithms: string[]
  internetFacingAssets: number
  criticalAssets: number
  environments: Array<{ key: EnvironmentKey; label: string; assets: number }>
  owners: Array<{ owner: string; assets: number }>
  unownedAssets: number
  /** Share of all assets with an actionable finding that this fix touches. */
  shareOfAffectedAssets: number
  impact: number
  effort: { days: number; basis: string }
  priority: number
  priorityRank: number
  priorityFactors: string[]
  deadline: Deadline
  progress: Record<MemberStatus, number>
  firstSeenAt: number
}

/** Internal: everything needed for detail, graph and campaign views. */
export interface ClusterState {
  cluster: FixCluster
  /** asset id → member facts. */
  members: Map<string, { severity: FindingSeverity; observations: number; firstSeenAt: number; status: MemberStatus; weight: number }>
  certificateKeys: Set<string>
}

interface Accumulator {
  id: string
  kind: FixKind
  rootType: 'issuer' | 'library' | 'algorithm'
  rootLabel: string
  roleHint: CryptoRole
  algorithms: Map<string, number>
  componentKeys: Set<string>
  certificateKeys: Set<string>
  reusedCertificates: number
  observations: number
  deadlineInputs: TimingObservation[]
  members: Map<string, { severity: FindingSeverity; observations: number; firstSeenAt: number; latestAt: number }>
}

const slug = (value: string) => value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'unknown'

function route(observation: Observation, assetHasCertificates: boolean): { kind: FixKind; key: string; rootType: Accumulator['rootType']; label: string } | 'covered' | null {
  if (observation.actionability === 'none' || observation.actionability === 'unclassified') return null
  const name = observation.canonical?.canonical ?? observation.algorithm
  const sized = observation.keySize ? `${name}-${observation.keySize}` : name
  if (observation.actionability === 'classical') return { kind: 'classical-weakness', key: name, rootType: 'algorithm', label: sized }
  if (observation.packageName) return { kind: 'library-upgrade', key: observation.packageName, rootType: 'library', label: observation.packageName }
  if (observation.role === 'key-exchange' || observation.role === 'tls') {
    // Route by what the primitive DOES, not by the protocol it was seen in: ECDSA
    // in a TLS suite authenticates the server; it never exchanges keys, so its
    // replacement is a signature scheme (ML-DSA), not ML-KEM.
    if (SIGNATURE_PRIMITIVE.test(name)) return { kind: 'signing-keys', key: sized, rootType: 'algorithm', label: sized }
    if (KEY_AGREEMENT_PRIMITIVE.test(name) || observation.role === 'key-exchange') return { kind: 'key-exchange', key: name, rootType: 'algorithm', label: name }
    // e.g. RSA seen in TLS: static key transport or authentication — the scan cannot tell.
    return { kind: 'classify-usage', key: name, rootType: 'algorithm', label: name }
  }
  if (observation.role === 'certificate') {
    // The certificate record carries the issuer and is grouped by CA; the
    // inventory copy of the same key would count the asset twice.
    if (assetHasCertificates) return 'covered'
    return { kind: 'certificate-keys', key: sized, rootType: 'algorithm', label: sized }
  }
  if (SIGNING_ROLES.includes(observation.role)) return { kind: 'signing-keys', key: sized, rootType: 'algorithm', label: sized }
  if (ENCRYPTION_ROLES.includes(observation.role)) return { kind: 'data-encryption', key: name, rootType: 'algorithm', label: name }
  return { kind: 'classify-usage', key: name, rootType: 'algorithm', label: name }
}

function describe(acc: Accumulator): Pick<FixCluster, 'title' | 'action' | 'target' | 'targetNote'> {
  const algos = [...acc.algorithms.keys()]
  const primary = algos[0] ?? acc.rootLabel
  // Every fix here is for a Shor-broken primitive; the target depends on the ROLE.
  const stub: CanonicalAlgorithm = { canonical: primary, family: 'unknown', shorBroken: true, groverAffected: false, classicallyWeak: false, aliases: [] }
  const target = (role: CryptoRole) => migrationTargetFor(stub, role) ?? null
  switch (acc.kind) {
    case 'ca-reissue':
      return {
        title: `Re-issue certificates signed by ${acc.rootLabel}`,
        action: `Re-issue every ${primary} certificate from this issuer with a post-quantum (or hybrid) signature, then redeploy it everywhere it is used.`,
        target: target('certificate'), targetNote: null,
      }
    case 'certificate-keys':
      return {
        title: `Replace ${acc.rootLabel} certificate keys`,
        action: 'The issuing CA was not captured; replace these certificate keys with post-quantum signatures as certificates are renewed.',
        target: target('certificate'), targetNote: null,
      }
    case 'library-upgrade':
      return {
        title: `Upgrade ${acc.rootLabel}`,
        action: `Move to a release of ${acc.rootLabel} that supports ML-KEM (FIPS 203) and ML-DSA (FIPS 204), then rebuild and redeploy the dependents.`,
        target: null,
        targetNote: 'Pick the first vendor release with FIPS 203/204 support; the platform does not assume a version number.',
      }
    case 'key-exchange':
      return {
        title: `Enable hybrid ML-KEM key exchange (replacing ${primary})`,
        action: 'Turn on a hybrid X25519MLKEM768 group on the TLS terminators and clients that negotiate this key exchange.',
        target: target('key-exchange'), targetNote: null,
      }
    case 'signing-keys':
      return {
        title: `Rotate ${acc.rootLabel} signing / authentication keys`,
        action: `Rotate these ${primary} keys to a post-quantum signature scheme and update every verifier that trusts them.`,
        target: target('signature'), targetNote: null,
      }
    case 'data-encryption':
      return {
        title: `Re-wrap data encrypted with ${primary}`,
        action: 'Wrap data keys with ML-KEM and keep bulk encryption on AES-256-GCM.',
        target: target('encryption'), targetNote: null,
      }
    case 'classical-weakness':
      return {
        title: `Retire ${acc.rootLabel}`,
        action: `${acc.rootLabel} is broken today, independent of quantum computing. Remove it before the PQC migration.`,
        target: null, targetNote: 'Replace with the modern equivalent for its role (e.g. SHA-256/SHA3-256 for hashing, AES-256-GCM for encryption).',
      }
    case 'classify-usage':
    default:
      return {
        title: `Classify how ${primary} is used`,
        action: `${primary} is quantum-vulnerable, but the scan could not tell whether it signs, encrypts or exchanges keys. Record its role so the correct replacement can be planned.`,
        target: null, targetNote: 'No replacement is recommended until the role is known (ML-KEM and ML-DSA are not interchangeable).',
      }
  }
}

export interface ClusterBuild {
  states: ClusterState[]
  /** Assets with at least one actionable finding. */
  affectedAssetIds: Set<string>
  coveredByCertificate: number
}

export function buildClusters(
  observations: Observation[],
  certificates: CertificateIdentity[],
  assets: Map<string, EstateAsset>,
  jobs: Map<string, AssetJob>,
): ClusterBuild {
  const accumulators = new Map<string, Accumulator>()
  const affected = new Set<string>()
  const assetsWithCertificates = new Set<string>()
  for (const certificate of certificates) for (const id of certificate.assetIds) assetsWithCertificates.add(id)

  const touch = (kind: FixKind, key: string, rootType: Accumulator['rootType'], label: string, roleHint: CryptoRole) => {
    const id = `${kind}:${slug(key)}`
    let acc = accumulators.get(id)
    if (!acc) {
      acc = {
        id, kind, rootType, rootLabel: label, roleHint, algorithms: new Map(), componentKeys: new Set(), certificateKeys: new Set(),
        reusedCertificates: 0, observations: 0, deadlineInputs: [], members: new Map(),
      }
      accumulators.set(id, acc)
    }
    return acc
  }
  const addMember = (acc: Accumulator, assetId: string, severity: FindingSeverity, at: number) => {
    const member = acc.members.get(assetId)
    if (member) {
      member.observations += 1
      if (severity && worstSeverity([member.severity, severity]) !== member.severity) member.severity = severity
      if (at > 0) member.firstSeenAt = member.firstSeenAt > 0 ? Math.min(member.firstSeenAt, at) : at
      member.latestAt = Math.max(member.latestAt, at)
    } else {
      acc.members.set(assetId, { severity, observations: 1, firstSeenAt: at, latestAt: at })
    }
  }

  let coveredByCertificate = 0
  for (const observation of observations) {
    if (!observation.assetId) continue
    const routed = route(observation, assetsWithCertificates.has(observation.assetId))
    if (routed === null) continue
    affected.add(observation.assetId)
    if (routed === 'covered') { coveredByCertificate += 1; continue }
    const acc = touch(routed.kind, routed.key, routed.rootType, routed.label, observation.role)
    acc.observations += 1
    acc.componentKeys.add(observation.componentKey)
    const algo = observation.canonical?.canonical ?? observation.algorithm
    acc.algorithms.set(algo, (acc.algorithms.get(algo) ?? 0) + 1)
    acc.deadlineInputs.push({ algorithm: observation.canonical?.canonical, classical: observation.actionability === 'classical' })
    addMember(acc, observation.assetId, observation.severity, observation.observedAt)
  }

  for (const certificate of certificates) {
    if (certificate.actionability !== 'quantum' && certificate.actionability !== 'classical') continue
    const acc = touch('ca-reissue', certificate.issuerName || 'unknown-issuer', 'issuer', certificate.issuerName || 'Unknown issuer', 'certificate')
    acc.certificateKeys.add(certificate.key)
    if (certificate.assetIds.size > 1) acc.reusedCertificates += 1
    acc.componentKeys.add(certificate.key)
    const algo = certificate.canonical?.canonical ?? certificate.algorithm
    acc.algorithms.set(algo, (acc.algorithms.get(algo) ?? 0) + 1)
    acc.deadlineInputs.push({ algorithm: certificate.canonical?.canonical, classical: certificate.actionability === 'classical' })
    for (const assetId of certificate.assetIds) {
      affected.add(assetId)
      acc.observations += 1
      addMember(acc, assetId, certificate.severity, certificate.observedAt)
    }
  }

  // Latest scan evidence per asset, for validation after a completed job.
  const latestScanAt = new Map<string, number>()
  for (const observation of observations) {
    latestScanAt.set(observation.assetId, Math.max(latestScanAt.get(observation.assetId) ?? 0, observation.observedAt))
  }
  for (const certificate of certificates) {
    for (const assetId of certificate.assetIds) latestScanAt.set(assetId, Math.max(latestScanAt.get(assetId) ?? 0, certificate.observedAt))
  }

  const statusOf = (assetId: string, member: { latestAt: number }): MemberStatus => {
    const job = jobs.get(assetId)
    if (!job) return 'open'
    if (job.phase !== 'completed') return job.phase
    const rescanned = (latestScanAt.get(assetId) ?? 0) > job.updatedAt
    if (!rescanned) return 'awaiting-validation'
    // A rescan after completion that still recorded this fix's vulnerable component.
    return member.latestAt > job.updatedAt ? 'regressed' : 'validated'
  }

  const states: ClusterState[] = []
  const urgencies: number[] = []
  for (const acc of accumulators.values()) {
    const members: ClusterState['members'] = new Map()
    let impact = 0
    const environments = new Map<EnvironmentKey, number>()
    const owners = new Map<string, number>()
    let unowned = 0
    let internetFacing = 0
    let critical = 0
    const progress: Record<MemberStatus, number> = { open: 0, planned: 0, running: 0, failed: 0, 'awaiting-validation': 0, validated: 0, regressed: 0 }
    let firstSeenAt = Number.POSITIVE_INFINITY

    for (const [assetId, member] of acc.members) {
      const asset = assets.get(assetId)
      const weight = assetWeight(member.severity, asset)
      const status = statusOf(assetId, member)
      progress[status] += 1
      if (status !== 'validated') impact += weight
      members.set(assetId, { severity: member.severity, observations: member.observations, firstSeenAt: member.firstSeenAt, status, weight })
      if (member.firstSeenAt > 0) firstSeenAt = Math.min(firstSeenAt, member.firstSeenAt)
      const env = asset?.environment ?? 'unknown'
      environments.set(env, (environments.get(env) ?? 0) + 1)
      if (asset?.owner) owners.set(asset.owner, (owners.get(asset.owner) ?? 0) + 1)
      else unowned += 1
      if (asset?.internetFacing) internetFacing += 1
      if (asset?.criticality === 'critical' || asset?.criticality === 'high') critical += 1
    }

    const deadline = deadlineFor(acc.deadlineInputs)
    const effortSpec = EFFORT[acc.kind]
    const remaining = acc.members.size - progress.validated
    const effortDays = Math.round((effortSpec.base + effortSpec.perAsset * Math.max(remaining, 0)) * 10) / 10
    const urgency = deadline.year === 0 ? 1.5 : deadline.year === 2030 ? 1.2 : 1
    const severity = worstSeverity([...acc.members.values()].map((m) => m.severity))
    const text = describe(acc)
    const algorithms = [...acc.algorithms.entries()].sort((a, b) => b[1] - a[1]).map(([name]) => name)

    states.push({
      certificateKeys: acc.certificateKeys,
      members,
      cluster: {
        id: acc.id,
        kind: acc.kind,
        kindLabel: FIX_KIND_LABEL[acc.kind],
        ...text,
        rootCause: { type: acc.rootType, label: acc.rootLabel },
        severity,
        assets: acc.members.size,
        observations: acc.observations,
        uniqueComponents: acc.componentKeys.size,
        certificates: acc.kind === 'ca-reissue' ? { unique: acc.certificateKeys.size, reusedAcrossAssets: acc.reusedCertificates } : null,
        algorithms: algorithms.slice(0, 6),
        internetFacingAssets: internetFacing,
        criticalAssets: critical,
        environments: [...environments.entries()].sort((a, b) => b[1] - a[1]).map(([key, count]) => ({ key, label: ENVIRONMENT_LABEL[key], assets: count })),
        owners: [...owners.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([owner, count]) => ({ owner, assets: count })),
        unownedAssets: unowned,
        shareOfAffectedAssets: 0,
        impact: Math.round(impact * 100) / 100,
        effort: { days: effortDays, basis: `Planning estimate: ${effortSpec.base} d setup + ${effortSpec.perAsset} d per remaining asset (${FIX_KIND_LABEL[acc.kind].toLowerCase()}). Not a measurement.` },
        priority: 0,
        priorityRank: 0,
        priorityFactors: [],
        deadline,
        progress,
        firstSeenAt: Number.isFinite(firstSeenAt) ? firstSeenAt : 0,
      },
    })
    urgencies.push(urgency)
  }

  // Priority = risk still open per day of effort, weighted by deadline urgency; 0–100 relative to the top fix.
  const raw = states.map((state, index) => (state.cluster.impact * urgencies[index]) / Math.max(state.cluster.effort.days, 0.5))
  const max = Math.max(0, ...raw)
  states.forEach((state, index) => {
    const c = state.cluster
    c.priority = max > 0 ? Math.round((raw[index] / max) * 100) : 0
    c.shareOfAffectedAssets = affected.size ? Math.round((c.assets / affected.size) * 1000) / 10 : 0
    const factors: string[] = []
    factors.push(`${c.assets - c.progress.validated} of ${c.assets} affected asset(s) still open`)
    if (c.internetFacingAssets) factors.push(`${c.internetFacingAssets} internet-facing`)
    if (c.criticalAssets) factors.push(`${c.criticalAssets} high/critical business asset(s)`)
    if (c.deadline.year !== null) factors.push(c.deadline.label.toLowerCase())
    factors.push(`≈${c.effort.days} engineer-days (estimate)`)
    c.priorityFactors = factors
  })
  states.sort((a, b) => b.cluster.priority - a.cluster.priority || b.cluster.assets - a.cluster.assets)
  states.forEach((state, index) => { state.cluster.priorityRank = index + 1 })

  return { states, affectedAssetIds: affected, coveredByCertificate }
}

export function environmentLabel(key: EnvironmentKey) { return ENVIRONMENT_LABEL[key] }
