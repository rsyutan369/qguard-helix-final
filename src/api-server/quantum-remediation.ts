import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { createSingleFlightCache } from '@/lib/single-flight-cache'
import { isInternetFacing } from '@/lib/migration/asset-intelligence'
import { buildScannerIntelligence } from './scanner'
import { evaluateEligibility, gatherEvidence, loadPolicy, type EvidenceBundle } from './quantum-certification'
import { payloadFingerprint, streamLiveSnapshot } from './live-snapshot-stream'
import { isDeterministicReadGap, SnapshotReadError } from './quantum-readiness'
import type { CertificationPolicy, EligibilityResult } from '@/types/quantum-certification'
import type {
  AdvisorAnswer,
  BlastRadius,
  CertificationRequirementGap,
  CriterionProgress,
  ReadinessLadderStep,
  RemediationAction,
  RemediationDomain,
  RemediationImpact,
  RemediationPlan,
  RemediationPriority,
  RemediationProgress,
} from '@/types/quantum-remediation'

/**
 * Intelligent Quantum Remediation Engine™ — Q-REMEDY algorithm.
 *
 * Turns "Not Quantum Ready" into "Here's exactly how to become Quantum Ready":
 * every discovered asset's measured vulnerabilities are converted into
 * NIST-aligned remediation actions (FIPS 203 ML-KEM / FIPS 204 ML-DSA /
 * FIPS 205 SLH-DSA / CNSA 2.0 / CISA-NCSC migration guidance), prioritized by
 * a multi-factor scoring model, and fed through a deterministic marginal-gain
 * simulation that projects the live Certification Readiness Score™ after each
 * recommendation — the exact same 10 required criteria the Quantum Trust
 * Certification Engine™ enforces (100% == certification eligible).
 *
 * Evidence honesty: the engine only reasons over findings, components,
 * certificates, relationships and migration records the platform has actually
 * observed. Action status is derived from live evidence (a finding present in
 * the latest scan = open; a running migration job on the asset = in progress),
 * never asserted, so the score updates automatically as vulnerabilities are
 * resolved and assets are rescanned. Projections are labelled as simulations
 * and the full methodology ships with every payload.
 */

const router = Router()

export const REMEDIATION_ENGINE_VERSION = '1.0.0'
const MAX_ACTIONS = 400 // payload cap — estate-wide counts stay exact
const LADDER_DETAIL_STEPS = 8

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  // Header-only auth (Authorization: Bearer). The SSE stream is consumed via
  // fetch()+ReadableStream so no token ever appears in a URL.
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}
router.use(requireAuth)

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
function str(value: unknown): string {
  return typeof value === 'string' ? value : value == null ? '' : String(value)
}
function num(value: unknown): number {
  const n = Number(value)
  return Number.isFinite(n) ? n : 0
}
function clamp(value: number, min = 0, max = 100): number {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, value))
}
function clamp01(value: number): number {
  return Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0))
}
function round1(value: number): number {
  return Math.round(value * 10) / 10
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any): Promise<Record<string, unknown>[]> {
  // A deterministic gap reads as "no rows"; a transient failure fails the
  // build (see SnapshotReadError) rather than planning without a table.
  let result: { data: unknown; error: { message?: string } | null }
  try {
    result = await build(client.from(table))
  } catch (error) {
    throw new SnapshotReadError(table, error)
  }
  if (result.error) {
    if (!isDeterministicReadGap(result.error)) throw new SnapshotReadError(table, result.error)
    console.warn(`quantum-remediation ${table} query skipped:`, result.error.message || result.error)
    return []
  }
  return (result.data as Record<string, unknown>[]) || []
}

/* ------------------------------------------------------------------ */
/* Remediation playbooks — NIST / CNSA 2.0 / CISA-NCSC aligned          */
/* ------------------------------------------------------------------ */
interface Playbook {
  label: string
  risk: string
  recommendation: string
  steps: string[]
  targetState: string
  standards: string[]
  unitEffortWeeks: number
  downtime: string
  rollback: string
  breakingChange: string | null
  automatable: boolean
  hndlRelevant: boolean
  dataSensitive: boolean
  integration: { label: string; route: string }
}

export const REMEDIATION_PLAYBOOKS: Record<RemediationDomain, Playbook> = {
  tls: {
    label: 'TLS / Transport Security',
    risk: 'Harvest Now, Decrypt Later — recorded TLS sessions using classical key exchange are decryptable once a cryptographically relevant quantum computer exists.',
    recommendation: 'Upgrade to TLS 1.3 and enable hybrid post-quantum key establishment (X25519 + ML-KEM-768).',
    steps: [
      'Inventory every TLS endpoint and terminating proxy for this asset (listeners, load balancers, CDN edges).',
      'Enable TLS 1.3 and disable TLS 1.0/1.1 plus legacy cipher suites.',
      'Deploy the hybrid key-exchange group X25519MLKEM768 (IETF hybrid design; ML-KEM per FIPS 203).',
      'Validate interoperability with connecting clients in the Migration Sandbox before production rollout.',
      'Roll out with a rolling restart, then rescan to verify the hybrid group is negotiated.',
    ],
    targetState: 'TLS 1.3 with hybrid X25519 + ML-KEM-768 key establishment (FIPS 203)',
    standards: ['FIPS 203', 'TLS 1.3 (RFC 8446)', 'CNSA 2.0', 'CISA PQC Roadmap'],
    unitEffortWeeks: 0.6,
    downtime: '≈5 minutes (rolling restart per endpoint)',
    rollback: 'Re-enable the previous key-exchange configuration; hybrid groups fail open to classical negotiation during rollout.',
    breakingChange: 'Clients that cannot negotiate TLS 1.3 or the hybrid group will fall back or fail — verify dependent consumers first.',
    automatable: true,
    hndlRelevant: true,
    dataSensitive: false,
    integration: { label: 'Open Migration Planner', route: '/dashboard/migration-planner' },
  },
  ssh: {
    label: 'SSH Configuration',
    risk: 'Classical SSH key exchange (ECDH/DH) exposes recorded administrative sessions to future quantum decryption.',
    recommendation: 'Upgrade OpenSSH and enable the post-quantum hybrid key exchange (mlkem768x25519-sha256 / sntrup761x25519).',
    steps: [
      'Upgrade the SSH daemon to a release with PQC hybrid KEX support (OpenSSH 9.x+).',
      'Prefer mlkem768x25519-sha256 (or sntrup761x25519-sha256) in KexAlgorithms and remove legacy DH groups.',
      'Retire weak host-key and MAC algorithms (ssh-rsa/SHA-1) and rotate host keys.',
      'Validate automation, CI runners and jump hosts still connect, then reload sshd.',
      'Rescan to confirm only PQC-hybrid key exchange is offered.',
    ],
    targetState: 'SSH with hybrid ML-KEM-768 + X25519 key exchange and modern host keys',
    standards: ['FIPS 203', 'CNSA 2.0', 'NCSC PQC Guidance'],
    unitEffortWeeks: 0.4,
    downtime: 'None (configuration reload)',
    rollback: 'Restore the previous sshd_config; existing sessions are unaffected by KEX changes.',
    breakingChange: 'Old SSH clients without hybrid KEX support must be upgraded or they will fail to connect.',
    automatable: true,
    hndlRelevant: true,
    dataSensitive: false,
    integration: { label: 'Open Migration Planner', route: '/dashboard/migration-planner' },
  },
  vpn: {
    label: 'VPN / Tunnel Configuration',
    risk: 'Classical IKE/VPN tunnels carry long-lived sensitive traffic that is being recorded today for future quantum decryption (HNDL).',
    recommendation: 'Move to quantum-resistant VPN: RFC 8784 post-quantum pre-shared keys now, vendor ML-KEM hybrid IKEv2 as it ships.',
    steps: [
      'Inventory VPN concentrators, site-to-site tunnels and remote-access profiles on this asset.',
      'Apply RFC 8784 post-quantum pre-shared keys (PPK) to IKEv2 tunnels as the interim mitigation.',
      'Track and deploy the vendor firmware that implements hybrid ML-KEM key establishment for IKEv2.',
      'Rotate tunnel credentials and enforce AES-256-GCM for bulk encryption.',
      'Validate failover pairs, then rescan to confirm the quantum-resistant configuration.',
    ],
    targetState: 'IKEv2 with PQ pre-shared keys (RFC 8784) and hybrid ML-KEM on vendor support',
    standards: ['RFC 8784', 'FIPS 203', 'CNSA 2.0'],
    unitEffortWeeks: 1.2,
    downtime: '≈10 minutes per tunnel (renegotiation window)',
    rollback: 'Remove the PPK/hybrid proposal from the IKE policy; tunnels renegotiate classically.',
    breakingChange: 'Both tunnel ends must support the PQ configuration — coordinate with the peer organization first.',
    automatable: false,
    hndlRelevant: true,
    dataSensitive: true,
    integration: { label: 'Open Migration Planner', route: '/dashboard/migration-planner' },
  },
  pki: {
    label: 'PKI & Certificates',
    risk: 'RSA/ECDSA certificates anchor trust in quantum-vulnerable signatures, and expired certificates break the estate’s verifiable trust chain.',
    recommendation: 'Renew expired certificates, shorten validity, and plan CA migration to ML-DSA (with hybrid/composite certificates in transition).',
    steps: [
      'Renew or retire every expired certificate tied to this asset.',
      'Reissue long-lived certificates with ≤398-day validity and automated (ACME/managed) rotation.',
      'Prepare the CA hierarchy for ML-DSA (FIPS 204) signing — stand up a test hybrid/composite chain.',
      'Track client/library readiness for PQC certificate chains in the Compatibility Lab.',
      'Rescan PKI visibility to verify no expired or weak-signature certificates remain.',
    ],
    targetState: 'Automated short-lived certificates on an ML-DSA-ready (FIPS 204) chain',
    standards: ['FIPS 204', 'FIPS 205', 'CNSA 2.0', 'CA/Browser Forum'],
    unitEffortWeeks: 0.8,
    downtime: 'None (staged certificate rotation)',
    rollback: 'Previous certificates remain valid until natural expiry; re-pin the prior chain if clients fail.',
    breakingChange: 'Certificate pinning and old trust stores must be updated before rotating issuing chains.',
    automatable: true,
    hndlRelevant: false,
    dataSensitive: false,
    integration: { label: 'Open PKI Visibility', route: '/dashboard/pki-visibility' },
  },
  'key-management': {
    label: 'Key Management',
    risk: 'Long-lived classical keys (RSA/ECC) protect data whose confidentiality must outlive the quantum threat horizon.',
    recommendation: 'Rotate long-lived keys into QKMS governance with AES-256 envelopes and ML-KEM key establishment.',
    steps: [
      'Inventory the keys this asset uses and their protection lifetimes.',
      'Migrate key generation and storage into QKMS (or the HSM/KMS of record) with rotation policies.',
      'Re-wrap data-encryption keys under AES-256-GCM envelopes established via ML-KEM.',
      'Retire static RSA/ECC wrapping keys after re-encryption completes.',
      'Verify rotation telemetry and rescan the key inventory.',
    ],
    targetState: 'QKMS-governed keys: AES-256-GCM envelopes, ML-KEM (FIPS 203) establishment, enforced rotation',
    standards: ['FIPS 203', 'AES-256-GCM (FIPS 197)', 'NIST SP 800-57'],
    unitEffortWeeks: 1.0,
    downtime: 'None (online re-wrap)',
    rollback: 'Previous key versions are retained in the KMS until re-wrap verification passes.',
    breakingChange: null,
    automatable: true,
    hndlRelevant: true,
    dataSensitive: true,
    integration: { label: 'Open QKMS', route: '/dashboard/qkms/overview' },
  },
  application: {
    label: 'Application & Libraries',
    risk: 'Application code and dependencies invoke quantum-vulnerable primitives directly, blocking crypto-agile migration.',
    recommendation: 'Upgrade cryptographic libraries to PQC-capable releases and route calls through a crypto-agility abstraction.',
    steps: [
      'Locate the libraries and call sites using vulnerable algorithms (CBOM component evidence).',
      'Upgrade to PQC-capable library releases (e.g. OpenSSL 3.5+/liboqs provider, BouncyCastle PQC, language-native ML-KEM/ML-DSA).',
      'Introduce a policy-driven crypto-agility layer so algorithms are swappable without code changes.',
      'Switch signatures to ML-DSA (FIPS 204) and key establishment to ML-KEM (FIPS 203) or hybrids.',
      'Run the regression suite in the Migration Sandbox, then deploy and rescan.',
    ],
    targetState: 'PQC-capable libraries behind a policy-driven crypto-agility abstraction',
    standards: ['FIPS 203', 'FIPS 204', 'NIST SP 1800-38'],
    unitEffortWeeks: 1.6,
    downtime: 'Deployment window per release process',
    rollback: 'Standard application rollback (previous release remains deployable).',
    breakingChange: 'Downstream services validating signatures must upgrade verification before the switch.',
    automatable: false,
    hndlRelevant: false,
    dataSensitive: false,
    integration: { label: 'Open CBOM Explorer', route: '/dashboard/cbom' },
  },
  cloud: {
    label: 'Cloud Services',
    risk: 'Managed cloud services negotiating classical crypto keep the estate quantum-vulnerable regardless of workload changes.',
    recommendation: 'Enable the provider’s PQC options (hybrid TLS endpoints, symmetric KMS wrapping) and constrain classical-only services.',
    steps: [
      'Review the cloud connector inventory for services still negotiating classical-only crypto.',
      'Enable provider hybrid PQC TLS where offered (major providers expose X25519+ML-KEM endpoints).',
      'Move KMS master keys to symmetric AES-256 wrapping and enable automatic rotation.',
      'Constrain or replace services with no PQC roadmap; record vendor exceptions.',
      'Re-run the cloud discovery scan to verify the new posture.',
    ],
    targetState: 'Cloud services on hybrid PQC TLS with AES-256 KMS wrapping and rotation',
    standards: ['FIPS 203', 'CNSA 2.0', 'CISA PQC Roadmap'],
    unitEffortWeeks: 1.0,
    downtime: 'None (provider-side configuration)',
    rollback: 'Disable the hybrid endpoint option; classical endpoints remain available during transition.',
    breakingChange: null,
    automatable: true,
    hndlRelevant: true,
    dataSensitive: false,
    integration: { label: 'Open Migration Planner', route: '/dashboard/migration-planner' },
  },
  'data-at-rest': {
    label: 'Data at Rest',
    risk: 'Long-lived sensitive data encrypted under classical envelopes is the primary Harvest-Now-Decrypt-Later target.',
    recommendation: 'Re-encrypt long-lived data under AES-256-GCM with PQC (ML-KEM) key establishment for the envelope keys.',
    steps: [
      'Classify the data on this asset by confidentiality lifetime (which secrets must survive 10+ years?).',
      'Re-encrypt long-lived data under AES-256-GCM data keys.',
      'Wrap data keys via ML-KEM-established envelopes (hybrid during transition).',
      'Destroy superseded classical envelope keys after verification.',
      'Verify HNDL exposure drops on the next Harvest-Now assessment.',
    ],
    targetState: 'AES-256-GCM data envelopes with ML-KEM (FIPS 203) key establishment',
    standards: ['FIPS 203', 'AES-256-GCM (FIPS 197)', 'CISA HNDL Guidance'],
    unitEffortWeeks: 1.4,
    downtime: 'None (online re-encryption)',
    rollback: 'Previous ciphertext versions retained until re-encryption integrity checks pass.',
    breakingChange: null,
    automatable: true,
    hndlRelevant: true,
    dataSensitive: true,
    integration: { label: 'Open Harvest Now Center', route: '/dashboard/harvest-now' },
  },
  identity: {
    label: 'Identity & Tokens',
    risk: 'Identity tokens signed with quantum-vulnerable algorithms (RSA/ECDSA JWTs) allow future forgery of authentication.',
    recommendation: 'Migrate token signing to ML-DSA (hybrid Ed25519 + ML-DSA during transition) and shorten token lifetimes.',
    steps: [
      'Inventory the token issuers and signing keys this asset depends on.',
      'Shorten token and signing-key lifetimes to bound the forgery window.',
      'Introduce hybrid Ed25519 + ML-DSA-65 signing; verify all consumers validate the new algorithm.',
      'Cut over issuance to the hybrid chain and revoke legacy signing keys.',
      'Validate with runtime identity telemetry, then rescan.',
    ],
    targetState: 'Hybrid Ed25519 + ML-DSA-65 (FIPS 204) token signing with short lifetimes',
    standards: ['FIPS 204', 'CNSA 2.0'],
    unitEffortWeeks: 1.2,
    downtime: 'None (staged key rollover)',
    rollback: 'Re-activate the previous signing key (kept in escrow until cutover verification).',
    breakingChange: 'Every token consumer must support the new signature algorithm before cutover.',
    automatable: false,
    hndlRelevant: false,
    dataSensitive: false,
    integration: { label: 'Open PQAuth Command Center', route: '/dashboard/pqauth' },
  },
  vendor: {
    label: 'Vendor / Third Party',
    risk: 'A third-party dependency without a PQC roadmap keeps this trust chain quantum-vulnerable no matter what is migrated internally.',
    recommendation: 'Engage the vendor for their PQC readiness roadmap and apply compensating controls until they deliver.',
    steps: [
      'Identify the vendor components and interfaces in this trust chain.',
      'Request the vendor’s PQC migration roadmap (reference NIST FIPS 203/204/205 timelines and CNSA 2.0 deadlines).',
      'Apply compensating controls: wrap vendor traffic in hybrid-PQC tunnels, minimize long-lived data shared.',
      'Track readiness in the Vendor PQC Readiness Center and set a contract review checkpoint.',
      'Re-assess the trust chain when the vendor ships PQC support.',
    ],
    targetState: 'Vendor on a committed PQC roadmap with compensating hybrid controls in place',
    standards: ['CNSA 2.0', 'CISA Supply-Chain Guidance'],
    unitEffortWeeks: 2.0,
    downtime: 'None',
    rollback: 'Not applicable (vendor engagement).',
    breakingChange: 'Upgrading the shared interface may require coordinated vendor-side changes — agree a joint window.',
    automatable: false,
    hndlRelevant: true,
    dataSensitive: false,
    integration: { label: 'Open Vendor PQC Readiness', route: '/dashboard/vendor-pqc-readiness' },
  },
  inventory: {
    label: 'Evidence & Coverage',
    risk: 'Certification requires high-confidence evidence — uncovered estate areas keep assessment confidence below the certification threshold.',
    recommendation: 'Connect the missing evidence source so the assessment covers the full estate.',
    steps: [
      'Connect the evidence source listed in this action.',
      'Run a discovery scan to populate the new evidence.',
      'Verify the source appears in the assessment telemetry.',
    ],
    targetState: 'Full-estate evidence coverage at certification-grade confidence',
    standards: ['CBOM Best Practice', 'NIST SP 1800-38'],
    unitEffortWeeks: 0.5,
    downtime: 'None',
    rollback: 'Not applicable (evidence onboarding).',
    breakingChange: null,
    automatable: true,
    hndlRelevant: false,
    dataSensitive: false,
    integration: { label: 'Open Scanner', route: '/dashboard/scanner' },
  },
}

/* ------------------------------------------------------------------ */
/* Domain classification                                               */
/* ------------------------------------------------------------------ */
export function classifyDomain(input: { category: string; algorithm: string; protocol: string; name: string; assetType: string }): RemediationDomain {
  const text = `${input.category} ${input.protocol} ${input.name}`.toLowerCase()
  const algo = input.algorithm.toUpperCase()
  const assetType = input.assetType.toLowerCase()
  if (/vpn|ipsec|ike|wireguard|tunnel/.test(text) || /vpn|tunnel/.test(assetType)) return 'vpn'
  if (/ssh|sftp|scp/.test(text) || /ssh/.test(assetType)) return 'ssh'
  // Identity tokens before PKI: "token issuer" is an identity finding, while
  // bare "issuer"/"authority" without token context stays with certificates.
  if (/jwt|token|oauth|oidc|saml|identity|sso\b/.test(text) || /identity/.test(assetType)) return 'identity'
  if (/cert|x\.?509|pki|ca\b|issuer|chain/.test(text)) return 'pki'
  if (/tls|ssl|cipher|https|handshake|key.?exchange|kex/.test(text)) return 'tls'
  if (/key(store)?\b|kms|hsm|secret|wrap/.test(text)) return 'key-management'
  if (/vault|storage|database|db\b|backup|archive|s3|bucket|disk|volume/.test(text) || /database|storage|data/.test(assetType)) return 'data-at-rest'
  if (/vendor|third.?party|saas|external|partner|supplier/.test(text) || /vendor|third|saas|partner/.test(assetType)) return 'vendor'
  if (/cloud|aws|azure|gcp|lambda|function/.test(text) || /cloud/.test(assetType)) return 'cloud'
  if (/lib|package|sdk|code|api|application|service|framework|dependency/.test(text)) return 'application'
  // Algorithm-only fallback: signatures → PKI/identity, key exchange → TLS.
  if (/^(ECDSA|DSA|ED25519)/.test(algo)) return 'pki'
  if (/^(ECDH|DH|X25519)/.test(algo)) return 'tls'
  if (/^(RSA)/.test(algo)) return 'tls'
  if (/^(SHA-?1|MD5|3?DES|RC4)/.test(algo)) return 'application'
  return 'application'
}

/* ------------------------------------------------------------------ */
/* Certification Readiness Score™ — continuous progress on the same    */
/* 10 required criteria evaluateEligibility() enforces                 */
/* ------------------------------------------------------------------ */
export interface CriteriaMeasures {
  readiness: number
  quantumRisk: number
  hndl: number
  residualRisk: number
  confidence: number
  pqcAdoption: number
  critical: number
  high: number
  medium: number
  low: number
  vulnerableComponents: number
  pqcReadyComponents: number
  totalComponents: number
  disallowedCount: number
  expiredCertificates: number
  validationPass: boolean
  runtimeMeasured: boolean
  /**
   * Runtime telemetry is not merely present but CURRENT (newest observation
   * within 6 hours). `runtimeMeasured` is true for a single event of any age,
   * which is not enough to claim continuous monitoring.
   */
  runtimeFresh: boolean
}

interface CriterionSpec {
  id: string
  criterion: string
  evidence: string
}

const REQUIRED_CRITERIA: CriterionSpec[] = [
  { id: 'readiness', criterion: 'Overall Quantum Readiness', evidence: 'Quantum Readiness Assessment Engine™ snapshot' },
  { id: 'critical-vulns', criterion: 'Critical Quantum Vulnerabilities', evidence: 'PQC scan findings (severity distribution)' },
  { id: 'hndl', criterion: 'Harvest-Now-Decrypt-Later Exposure', evidence: 'HNDL Assessment (harvest-now intelligence)' },
  { id: 'residual-risk', criterion: 'Residual Risk', evidence: 'Enterprise report risk forecast (post-programme)' },
  { id: 'confidence', criterion: 'Assessment Confidence', evidence: 'Evidence-confidence model (per-source coverage)' },
  { id: 'pqc-adoption', criterion: 'PQC Adoption', evidence: 'CBOM component posture (quantum-safe / hybrid share)' },
  { id: 'disallowed-algorithms', criterion: 'Disallowed Legacy Algorithms', evidence: 'Cryptographic inventory + scan findings algorithm scan' },
  { id: 'vulnerable-components', criterion: 'Quantum-Vulnerable Components', evidence: 'CBOM (cryptographic bill of materials)' },
  { id: 'expired-certificates', criterion: 'Expired Certificates', evidence: 'Certificate inventory (not_after)' },
  { id: 'validation', criterion: 'Report Self-Validation', evidence: 'Enterprise report validation engine' },
]

/** Continuous 0–1 progress of one criterion toward its certification threshold. */
function criterionProgress(id: string, m: CriteriaMeasures, baseline: CriteriaMeasures, policy: CertificationPolicy): { progress: number; met: boolean; required: string; actual: string } {
  switch (id) {
    case 'readiness': {
      const met = m.readiness >= policy.minReadiness
      return { met, progress: met ? 1 : clamp01(m.readiness / Math.max(1, policy.minReadiness)), required: `≥ ${policy.minReadiness}/100`, actual: `${Math.round(m.readiness)}/100` }
    }
    case 'critical-vulns': {
      const met = m.critical <= policy.maxCriticalFindings
      const over = Math.max(0, m.critical - policy.maxCriticalFindings)
      const baseOver = Math.max(1, baseline.critical - policy.maxCriticalFindings)
      return { met, progress: met ? 1 : clamp01(1 - over / baseOver), required: `≤ ${policy.maxCriticalFindings}`, actual: `${Math.round(m.critical)} critical finding(s)` }
    }
    case 'hndl': {
      const met = m.hndl <= policy.maxHndlRisk
      return { met, progress: met ? 1 : clamp01((100 - m.hndl) / Math.max(1, 100 - policy.maxHndlRisk)), required: `≤ ${policy.maxHndlRisk}/100`, actual: `${Math.round(m.hndl)}/100` }
    }
    case 'residual-risk': {
      const met = m.residualRisk <= policy.maxResidualRisk
      return { met, progress: met ? 1 : clamp01((100 - m.residualRisk) / Math.max(1, 100 - policy.maxResidualRisk)), required: `≤ ${policy.maxResidualRisk}/100`, actual: `${Math.round(m.residualRisk)}/100` }
    }
    case 'confidence': {
      const met = m.confidence >= policy.minConfidence
      return { met, progress: met ? 1 : clamp01(m.confidence / Math.max(1, policy.minConfidence)), required: `≥ ${policy.minConfidence}%`, actual: `${Math.round(m.confidence)}%` }
    }
    case 'pqc-adoption': {
      const met = m.pqcAdoption >= policy.minPqcAdoption
      return { met, progress: met ? 1 : clamp01(m.pqcAdoption / Math.max(1, policy.minPqcAdoption)), required: `≥ ${policy.minPqcAdoption}%`, actual: `${Math.round(m.pqcAdoption)}%` }
    }
    case 'disallowed-algorithms': {
      const met = m.disallowedCount === 0
      return { met, progress: met ? 1 : clamp01(1 - m.disallowedCount / Math.max(1, baseline.disallowedCount)), required: 'None', actual: `${Math.round(m.disallowedCount)} hit(s)` }
    }
    case 'vulnerable-components': {
      const met = m.vulnerableComponents <= policy.maxVulnerableComponents
      const over = Math.max(0, m.vulnerableComponents - policy.maxVulnerableComponents)
      const baseOver = Math.max(1, baseline.vulnerableComponents - policy.maxVulnerableComponents)
      return { met, progress: met ? 1 : clamp01(1 - over / baseOver), required: `≤ ${policy.maxVulnerableComponents}`, actual: `${Math.round(m.vulnerableComponents)} component(s)` }
    }
    case 'expired-certificates': {
      const met = m.expiredCertificates <= policy.maxExpiredCertificates
      const over = Math.max(0, m.expiredCertificates - policy.maxExpiredCertificates)
      const baseOver = Math.max(1, baseline.expiredCertificates - policy.maxExpiredCertificates)
      return { met, progress: met ? 1 : clamp01(1 - over / baseOver), required: `≤ ${policy.maxExpiredCertificates}`, actual: `${Math.round(m.expiredCertificates)} expired`, }
    }
    case 'validation': {
      return { met: m.validationPass, progress: m.validationPass ? 1 : 0, required: 'PASS', actual: m.validationPass ? 'PASS' : 'FAIL' }
    }
    default:
      return { met: true, progress: 1, required: '', actual: '' }
  }
}

export function computeCertificationReadiness(m: CriteriaMeasures, baseline: CriteriaMeasures, policy: CertificationPolicy): { pct: number; criteria: CriterionProgress[] } {
  const weight = 100 / REQUIRED_CRITERIA.length
  const criteria: CriterionProgress[] = REQUIRED_CRITERIA.map((spec) => {
    const p = criterionProgress(spec.id, m, baseline, policy)
    return {
      id: spec.id,
      criterion: spec.criterion,
      required: p.required,
      actual: p.actual,
      met: p.met,
      progressPct: Math.round(p.progress * 100),
      weightPct: Math.round(weight * 10) / 10,
      evidence: spec.evidence,
    }
  })
  // 1-decimal precision so small per-action marginal gains stay visible in the
  // projection ladder instead of vanishing to integer rounding.
  const pct = criteria.reduce((sum, c) => sum + (c.progressPct / 100) * weight, 0)
  return { pct: round1(pct), criteria }
}

/* ------------------------------------------------------------------ */
/* Simulation — apply an action's measured impact and recompute the    */
/* score model (mirrors the QR snapshot blend; documented projection)  */
/* ------------------------------------------------------------------ */
export function applyImpact(m: CriteriaMeasures, baseline: CriteriaMeasures, impact: RemediationImpact): CriteriaMeasures {
  const next: CriteriaMeasures = { ...m }
  next.critical = Math.max(0, m.critical - impact.criticalResolved)
  next.high = Math.max(0, m.high - impact.highResolved)
  next.medium = Math.max(0, m.medium - impact.mediumResolved)
  next.low = Math.max(0, m.low - impact.lowResolved)
  next.vulnerableComponents = Math.max(0, m.vulnerableComponents - impact.vulnerableComponentsResolved)
  next.pqcReadyComponents = Math.min(next.totalComponents || m.pqcReadyComponents + impact.pqcComponentsAdded, m.pqcReadyComponents + impact.pqcComponentsAdded)
  next.disallowedCount = Math.max(0, m.disallowedCount - impact.disallowedAlgorithmsRetired.length)
  next.expiredCertificates = Math.max(0, m.expiredCertificates - impact.expiredCertificatesRenewed)
  if (impact.validationRepair) next.validationPass = true
  next.confidence = clamp(m.confidence + impact.confidenceGainPct)

  // Re-blend the QR score model with the new component posture. Residual parts
  // of each score that this model cannot attribute (internet exposure share,
  // runtime/governance factors, vault posture) are held at their current
  // measured contribution — the projection only moves what the action moves,
  // and each step composes on the previous simulated state.
  const total = Math.max(1, next.totalComponents)
  const currentVulnShare = (m.vulnerableComponents / Math.max(1, m.totalComponents)) * 100
  const vulnShare = (next.vulnerableComponents / total) * 100
  const findings = next.critical + next.high + next.medium + next.low
  const severityPressure = findings > 0 ? clamp(((next.critical * 4 + next.high * 2.5 + next.medium * 1 + next.low * 0.4) / findings) * 22) : 0
  const currentFindings = m.critical + m.high + m.medium + m.low
  const currentSeverityPressure = currentFindings > 0 ? clamp(((m.critical * 4 + m.high * 2.5 + m.medium * 1 + m.low * 0.4) / currentFindings) * 22) : 0

  const internetPart = Math.max(0, m.quantumRisk - currentSeverityPressure * 0.45 - currentVulnShare * 0.4)
  next.quantumRisk = clamp(Math.round(severityPressure * 0.45 + vulnShare * 0.4 + internetPart))

  const hndlOther = m.hndl - currentVulnShare * 0.4
  next.hndl = clamp(Math.round(Math.max(0, vulnShare * 0.4 + hndlOther - impact.hndlReductionPts)))
  const baselineVulnShare = (baseline.vulnerableComponents / Math.max(1, baseline.totalComponents)) * 100

  next.pqcAdoption = clamp(m.pqcAdoption + (impact.pqcComponentsAdded / total) * 100)

  // Readiness blend delta (pqcAdoption 45%, inverse quantum risk 25%; runtime/
  // governance held at baseline). Connecting runtime telemetry re-includes the
  // runtime factor exactly as the QR model does (weight renormalisation).
  const weightSum = m.runtimeMeasured ? 1 : 0.85
  let readiness = m.readiness + (0.45 * (next.pqcAdoption - m.pqcAdoption) + 0.25 * (m.quantumRisk - next.quantumRisk)) / weightSum
  if (impact.runtimeTelemetryConnected && !m.runtimeMeasured) {
    readiness = readiness * 0.85 + 15
    next.runtimeMeasured = true
    // Deliberately NOT setting runtimeFresh: connecting telemetry makes it
    // measured, but freshness is only established by an actual recent event.
  }
  next.readiness = clamp(Math.round(readiness))

  next.residualRisk = baselineVulnShare > 0 ? clamp(Math.round(Math.min(m.residualRisk, baseline.residualRisk * (vulnShare / baselineVulnShare)))) : m.residualRisk
  return next
}

/* ------------------------------------------------------------------ */
/* Evidence input (assembled by the route, consumable offline by tools) */
/* ------------------------------------------------------------------ */
export interface RemediationEvidence {
  hasData: boolean
  generatedAt: string
  policy: CertificationPolicy
  eligibility: EligibilityResult
  measures: CriteriaMeasures
  scores: { quantumReadiness: number; quantumRisk: number; hndlRisk: number; pqcAdoption: number; migrationComplexity: number }
  trustScore: number
  levelLabel: string
  parallelWorkstreams: number
  readinessTrend: Array<{ label: string; readiness: number; risk: number }>
  disallowedAlgorithms: string[]
  missingEvidenceSources: Array<{ id: string; label: string; route: string }>
  validationPass: boolean
  cryptoAgilityActive: boolean
  assets: Array<{
    id: string
    name: string
    type: string
    environment: string
    owner: string
    criticality: string
    internetFacing: boolean
    riskScore: number
    pqcCapable: boolean
    vendorParty: boolean
    vulnerabilities: Array<{
      id: string
      name: string
      itemType: string
      algorithm: string
      protocol: string
      severity: string
      instances: number
      description: string
    }>
  }>
  relationships: Array<{ source: string; target: string; type: string }>
  expiredCertsByAsset: Map<string, number>
  unlinkedExpiredCerts: number
  migrationJobs: Array<{ id: string; status: string; assetId: string; jobType: string; updatedAt: string }>
  assetNameById: Map<string, string>
}

/* ------------------------------------------------------------------ */
/* Action synthesis                                                    */
/* ------------------------------------------------------------------ */
const CRITICALITY_SCORE: Record<string, number> = { critical: 100, high: 75, medium: 50, low: 25 }

function severityRank(severity: string): number {
  const s = severity.toLowerCase()
  if (s.includes('critical')) return 100
  if (s.includes('high')) return 75
  if (s.includes('medium') || s.includes('moderate')) return 50
  if (s.includes('low')) return 25
  return 25
}

function effortLabel(weeks: number): 'low' | 'medium' | 'high' {
  if (weeks <= 1) return 'low'
  if (weeks <= 3) return 'medium'
  return 'high'
}

function matchesDisallowed(algorithm: string, disallowed: string[]): string | null {
  const upper = ` ${algorithm.toUpperCase()} `
  for (const bad of disallowed) {
    const token = bad.toUpperCase()
    const re = new RegExp(`(^|[^A-Z0-9])${token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^A-Z0-9]|$)`)
    if (re.test(upper)) return bad
  }
  return null
}

interface DraftAction {
  action: Omit<RemediationAction, 'rank' | 'certificationGainPct' | 'projectedReadinessPct' | 'priorityScore' | 'priority' | 'priorityBreakdown' | 'quickWin'>
  severityScore: number
  internetScore: number
  criticalityScore: number
  dataScore: number
  hndlScore: number
  blastScore: number
  complianceScore: number
}

function synthesizeActions(ev: RemediationEvidence): DraftAction[] {
  const drafts: DraftAction[] = []
  const dependentsByAsset = new Map<string, string[]>()
  const dependenciesByAsset = new Map<string, string[]>()
  for (const rel of ev.relationships) {
    const sourceName = ev.assetNameById.get(rel.source) || rel.source
    const targetName = ev.assetNameById.get(rel.target) || rel.target
    if (!dependenciesByAsset.has(rel.source)) dependenciesByAsset.set(rel.source, [])
    if (!dependentsByAsset.has(rel.target)) dependentsByAsset.set(rel.target, [])
    const deps = dependenciesByAsset.get(rel.source)!
    if (targetName && deps.length < 12 && !deps.includes(targetName)) deps.push(targetName)
    const dents = dependentsByAsset.get(rel.target)!
    if (sourceName && dents.length < 12 && !dents.includes(sourceName)) dents.push(sourceName)
  }

  const runningJobAssets = new Set(ev.migrationJobs.filter((j) => /running|in_progress|active|executing/i.test(j.status)).map((j) => j.assetId))

  for (const asset of ev.assets) {
    if (!asset.vulnerabilities.length && !(ev.expiredCertsByAsset.get(asset.id) || 0)) continue

    // Group this asset's measured vulnerabilities by remediation domain.
    const groups = new Map<RemediationDomain, RemediationEvidence['assets'][number]['vulnerabilities']>()
    for (const vuln of asset.vulnerabilities) {
      let domain = classifyDomain({ category: vuln.itemType, algorithm: vuln.algorithm, protocol: vuln.protocol, name: vuln.name, assetType: asset.type })
      if (asset.vendorParty) domain = 'vendor'
      if (!groups.has(domain)) groups.set(domain, [])
      groups.get(domain)!.push(vuln)
    }
    const expiredHere = ev.expiredCertsByAsset.get(asset.id) || 0
    if (expiredHere > 0 && !groups.has('pki')) groups.set('pki', [])

    for (const [domain, vulns] of groups) {
      const playbook = REMEDIATION_PLAYBOOKS[domain]
      const instances = vulns.reduce((sum, v) => sum + Math.max(1, v.instances), 0) + (domain === 'pki' ? expiredHere : 0)
      const algorithms = Array.from(new Set(vulns.map((v) => v.algorithm).filter(Boolean)))
      const disallowedRetired = Array.from(new Set(algorithms.map((a) => matchesDisallowed(a, ev.disallowedAlgorithms)).filter((x): x is string => Boolean(x))))
      const worstSeverity = vulns.reduce((max, v) => Math.max(max, severityRank(v.severity)), domain === 'pki' && expiredHere > 0 ? 75 : 25)

      const impact: RemediationImpact = {
        criticalResolved: vulns.filter((v) => severityRank(v.severity) === 100).reduce((s, v) => s + Math.max(1, v.instances), 0),
        highResolved: vulns.filter((v) => severityRank(v.severity) === 75).reduce((s, v) => s + Math.max(1, v.instances), 0),
        mediumResolved: vulns.filter((v) => severityRank(v.severity) === 50).reduce((s, v) => s + Math.max(1, v.instances), 0),
        lowResolved: vulns.filter((v) => severityRank(v.severity) === 25).reduce((s, v) => s + Math.max(1, v.instances), 0),
        vulnerableComponentsResolved: vulns.length,
        pqcComponentsAdded: vulns.length,
        disallowedAlgorithmsRetired: disallowedRetired,
        expiredCertificatesRenewed: domain === 'pki' ? expiredHere : 0,
        evidenceSourcesConnected: [],
        confidenceGainPct: 0,
        hndlReductionPts: playbook.hndlRelevant ? Math.min(4, vulns.length) : 0,
        validationRepair: false,
        runtimeTelemetryConnected: false,
      }

      const effortWeeks = Math.max(0.5, round1(playbook.unitEffortWeeks * (1 + Math.log(1 + instances) / 3) * (1 + ev.scores.migrationComplexity / 200)))
      const primaryAlgo = algorithms[0] || (domain === 'pki' ? 'Expired certificate' : 'Legacy algorithm')
      const problem = domain === 'pki' && !vulns.length
        ? `${expiredHere} expired certificate(s) anchored to this asset`
        : `${playbook.label} uses ${algorithms.slice(0, 3).join(', ') || 'quantum-vulnerable cryptography'}${instances > vulns.length ? ` (${instances} instances)` : ''}`

      const whyNotReady: string[] = []
      for (const v of vulns.slice(0, 5)) {
        whyNotReady.push(`${v.algorithm || v.name || 'Vulnerable component'} (${v.severity.toLowerCase() || 'flagged'}${v.instances > 1 ? `, ${v.instances}×` : ''}) — ${v.itemType || 'crypto inventory'}`)
      }
      if (expiredHere > 0 && domain === 'pki') whyNotReady.push(`${expiredHere} expired certificate(s) in the inventory (not_after in the past)`)
      if (asset.internetFacing) whyNotReady.push('Internet-facing: recorded traffic is exposed to Harvest-Now-Decrypt-Later collection')

      const blastRadius: BlastRadius = {
        dependents: dependentsByAsset.get(asset.id) || [],
        dependencies: dependenciesByAsset.get(asset.id) || [],
        vendorParties: asset.vendorParty ? [asset.name] : (dependentsByAsset.get(asset.id) || []).concat(dependenciesByAsset.get(asset.id) || []).filter((n) => /vendor|third|saas|partner|external/i.test(n)).slice(0, 6),
        degree: (dependentsByAsset.get(asset.id)?.length || 0) + (dependenciesByAsset.get(asset.id)?.length || 0),
      }

      const criteriaAddressed: string[] = []
      if (impact.criticalResolved > 0) criteriaAddressed.push('critical-vulns')
      if (impact.vulnerableComponentsResolved > 0) criteriaAddressed.push('vulnerable-components', 'pqc-adoption', 'readiness', 'residual-risk')
      if (playbook.hndlRelevant) criteriaAddressed.push('hndl')
      if (disallowedRetired.length) criteriaAddressed.push('disallowed-algorithms')
      if (impact.expiredCertificatesRenewed > 0) criteriaAddressed.push('expired-certificates')

      drafts.push({
        action: {
          id: `${asset.id}:${domain}`,
          asset: asset.name,
          assetType: asset.type,
          environment: asset.environment,
          owner: asset.owner,
          internetFacing: asset.internetFacing,
          criticality: asset.criticality || 'unknown',
          domain,
          domainLabel: playbook.label,
          problem,
          risk: playbook.risk,
          whyNotReady,
          findings: vulns.slice(0, 12).map((v) => ({
            id: v.id,
            algorithm: v.algorithm || v.name || '—',
            category: v.itemType || 'crypto inventory',
            severity: v.severity || 'flagged',
            description: v.description,
            instances: Math.max(1, v.instances),
          })),
          recommendation: playbook.recommendation,
          steps: playbook.steps,
          currentState: `${primaryAlgo}${algorithms.length > 1 ? ` +${algorithms.length - 1} more` : ''}`,
          targetState: playbook.targetState,
          standards: playbook.standards,
          effort: effortLabel(effortWeeks),
          effortWeeks,
          estimatedDowntime: playbook.downtime,
          rollback: playbook.rollback,
          breakingChangeWarning: blastRadius.dependents.length && playbook.breakingChange
            ? `${playbook.breakingChange} Dependent assets: ${blastRadius.dependents.slice(0, 4).join(', ')}${blastRadius.dependents.length > 4 ? '…' : ''}.`
            : playbook.breakingChange,
          blastRadius,
          requiresReplacement: !asset.pqcCapable,
          automatable: playbook.automatable,
          status: runningJobAssets.has(asset.id) ? 'in_progress' : 'open',
          statusEvidence: runningJobAssets.has(asset.id)
            ? 'A migration job for this asset is currently running (migration_jobs).'
            : 'Finding present in the latest scan evidence — resolves automatically on a clean rescan.',
          impact,
          criteriaAddressed: Array.from(new Set(criteriaAddressed)),
          integration: playbook.integration,
        },
        severityScore: worstSeverity,
        internetScore: asset.internetFacing ? 100 : 20,
        criticalityScore: CRITICALITY_SCORE[str(asset.criticality).toLowerCase()] ?? 50,
        dataScore: playbook.dataSensitive || /database|storage|data|vault|backup/i.test(asset.type) ? 100 : 30,
        hndlScore: playbook.hndlRelevant ? 100 : 25,
        blastScore: clamp(blastRadius.degree * 12),
        complianceScore: disallowedRetired.length ? 100 : 40,
      })
    }
  }

  // Estate-level actions --------------------------------------------------
  if (ev.unlinkedExpiredCerts > 0) {
    const playbook = REMEDIATION_PLAYBOOKS.pki
    drafts.push(estateDraft('estate:pki-expired', 'Certificate estate', 'pki', playbook,
      `${ev.unlinkedExpiredCerts} expired certificate(s) without asset linkage`,
      [`${ev.unlinkedExpiredCerts} certificate(s) past not_after in the inventory`],
      { expiredCertificatesRenewed: ev.unlinkedExpiredCerts }, ['expired-certificates'],
      Math.max(0.5, round1(playbook.unitEffortWeeks * (1 + Math.log(1 + ev.unlinkedExpiredCerts) / 3))), 75))
  }

  // Evidence-coverage actions (confidence / runtime / validation gaps).
  if (ev.missingEvidenceSources.length && ev.measures.confidence < ev.policy.minConfidence) {
    const gainEach = round1((ev.policy.minConfidence - ev.measures.confidence) / ev.missingEvidenceSources.length)
    for (const source of ev.missingEvidenceSources) {
      const playbook = { ...REMEDIATION_PLAYBOOKS.inventory, integration: { label: `Open ${source.label}`, route: source.route } }
      drafts.push(estateDraft(`estate:evidence-${source.id}`, source.label, 'inventory', playbook,
        `Evidence source not connected: ${source.label}`,
        [`Assessment confidence ${Math.round(ev.measures.confidence)}% is below the certification threshold ${ev.policy.minConfidence}% — ${source.label} evidence is missing`],
        {
          evidenceSourcesConnected: [source.id],
          confidenceGainPct: gainEach,
          runtimeTelemetryConnected: source.id === 'runtime-telemetry',
        },
        ['confidence', ...(source.id === 'runtime-telemetry' ? ['readiness'] : [])],
        playbook.unitEffortWeeks, 50))
    }
  }
  if (!ev.validationPass && ev.hasData) {
    const playbook = { ...REMEDIATION_PLAYBOOKS.inventory, integration: { label: 'Open Report Center', route: '/dashboard/quantum-readiness/reports' } }
    drafts.push(estateDraft('estate:validation', 'Assessment validation', 'inventory', playbook,
      'Report self-validation is failing',
      ['The enterprise report validation engine reports inconsistent or incomplete evidence — regenerate after evidence gaps close'],
      { validationRepair: true }, ['validation'], 0.5, 50))
  }

  return drafts
}

function estateDraft(
  id: string,
  assetLabel: string,
  domain: RemediationDomain,
  playbook: Playbook,
  problem: string,
  whyNotReady: string[],
  impactPartial: Partial<RemediationImpact>,
  criteria: string[],
  effortWeeks: number,
  severityScore: number,
): DraftAction {
  const impact: RemediationImpact = {
    criticalResolved: 0,
    highResolved: 0,
    mediumResolved: 0,
    lowResolved: 0,
    vulnerableComponentsResolved: 0,
    pqcComponentsAdded: 0,
    disallowedAlgorithmsRetired: [],
    expiredCertificatesRenewed: 0,
    evidenceSourcesConnected: [],
    confidenceGainPct: 0,
    hndlReductionPts: 0,
    validationRepair: false,
    runtimeTelemetryConnected: false,
    ...impactPartial,
  }
  return {
    action: {
      id,
      asset: assetLabel,
      assetType: 'estate',
      environment: 'estate-wide',
      owner: 'Security Engineering',
      internetFacing: false,
      criticality: 'high',
      domain,
      domainLabel: playbook.label,
      problem,
      risk: playbook.risk,
      whyNotReady,
      findings: [],
      recommendation: playbook.recommendation,
      steps: playbook.steps,
      currentState: problem,
      targetState: playbook.targetState,
      standards: playbook.standards,
      effort: effortLabel(effortWeeks),
      effortWeeks: round1(effortWeeks),
      estimatedDowntime: playbook.downtime,
      rollback: playbook.rollback,
      breakingChangeWarning: playbook.breakingChange,
      blastRadius: { dependents: [], dependencies: [], vendorParties: [], degree: 0 },
      requiresReplacement: false,
      automatable: playbook.automatable,
      status: 'open',
      statusEvidence: 'Derived from live estate evidence — resolves automatically once the gap closes.',
      impact,
      criteriaAddressed: criteria,
      integration: playbook.integration,
    },
    severityScore,
    internetScore: 20,
    criticalityScore: 75,
    dataScore: 30,
    hndlScore: domain === 'pki' ? 25 : 25,
    blastScore: 0,
    complianceScore: domain === 'pki' ? 100 : 40,
  }
}

/* ------------------------------------------------------------------ */
/* Q-REMEDY core — marginal-gain greedy ordering + projection ladder   */
/* ------------------------------------------------------------------ */
const PRIORITY_WEIGHTS = [
  { key: 'severityScore', factor: 'Finding severity', weightPct: 20 },
  { key: 'certScore', factor: 'Certification impact', weightPct: 16 },
  { key: 'criticalityScore', factor: 'Business criticality', weightPct: 14 },
  { key: 'internetScore', factor: 'Internet exposure', weightPct: 12 },
  { key: 'hndlScore', factor: 'HNDL relevance', weightPct: 12 },
  { key: 'dataScore', factor: 'Data sensitivity', weightPct: 10 },
  { key: 'blastScore', factor: 'Blast radius', weightPct: 8 },
  { key: 'complianceScore', factor: 'Compliance impact', weightPct: 8 },
] as const

function priorityBand(score: number): RemediationPriority {
  if (score >= 70) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

export function buildRemediationPlan(ev: RemediationEvidence): RemediationPlan {
  const baseline = ev.measures
  const { pct: currentPct, criteria } = computeCertificationReadiness(baseline, baseline, ev.policy)

  if (!ev.hasData) {
    return emptyPlan(ev, criteria)
  }

  const drafts = synthesizeActions(ev)

  // Marginal-gain greedy: repeatedly pick the remaining action with the best
  // certification-readiness gain per unit of effort (diminishing returns are
  // handled naturally because gains are recomputed against the evolving
  // simulated measures each round).
  let state = baseline
  let statePct = currentPct
  const ordered: Array<{ draft: DraftAction; gain: number; cumulativePct: number }> = []
  const remaining = [...drafts]
  // Cap the greedy set for very large estates; the tail is aggregated.
  remaining.sort((a, b) => b.severityScore + b.internetScore - (a.severityScore + a.internetScore))
  const greedySet = remaining.slice(0, MAX_ACTIONS)
  const tailSet = remaining.slice(MAX_ACTIONS)

  while (greedySet.length) {
    let bestIndex = 0
    let bestScore = -Infinity
    let bestNext: CriteriaMeasures | null = null
    let bestPct = statePct
    for (let i = 0; i < greedySet.length; i += 1) {
      const candidate = greedySet[i]
      const next = applyImpact(state, baseline, candidate.action.impact)
      const nextPct = computeCertificationReadiness(next, baseline, ev.policy).pct
      const gain = nextPct - statePct
      const score = (gain + 0.05) / Math.pow(Math.max(0.5, candidate.action.effortWeeks), 0.6)
      if (score > bestScore) {
        bestScore = score
        bestIndex = i
        bestNext = next
        bestPct = nextPct
      }
    }
    const [selected] = greedySet.splice(bestIndex, 1)
    state = bestNext!
    const gain = bestPct - statePct
    statePct = bestPct
    ordered.push({ draft: selected, gain: Math.max(0, gain), cumulativePct: statePct })
  }
  // Apply the aggregated tail (kept out of the per-action list for payload size).
  for (const tail of tailSet) {
    state = applyImpact(state, baseline, tail.action.impact)
  }
  const finalPct = computeCertificationReadiness(state, baseline, ev.policy).pct

  // Priority scoring (certification impact factor uses the greedy marginal gain).
  const maxGain = Math.max(0.1, ...ordered.map((o) => o.gain))
  const actions: RemediationAction[] = ordered.map((o, index) => {
    const certScore = clamp((o.gain / maxGain) * 100)
    const factors: Record<string, number> = {
      severityScore: o.draft.severityScore,
      certScore,
      criticalityScore: o.draft.criticalityScore,
      internetScore: o.draft.internetScore,
      hndlScore: o.draft.hndlScore,
      dataScore: o.draft.dataScore,
      blastScore: o.draft.blastScore,
      complianceScore: o.draft.complianceScore,
    }
    const priorityScore = Math.round(PRIORITY_WEIGHTS.reduce((sum, w) => sum + factors[w.key] * (w.weightPct / 100), 0))
    return {
      ...o.draft.action,
      rank: index + 1,
      priorityScore,
      priority: priorityBand(priorityScore),
      priorityBreakdown: PRIORITY_WEIGHTS.map((w) => ({ factor: w.factor, score: Math.round(factors[w.key]), weightPct: w.weightPct })),
      certificationGainPct: round1(o.gain),
      projectedReadinessPct: o.cumulativePct,
      quickWin: false,
    }
  })

  // Quick wins: meaningful certification gain at low effort.
  const gainPerWeek = actions.map((a) => a.certificationGainPct / Math.max(0.5, a.effortWeeks))
  const leverageThreshold = [...gainPerWeek].sort((a, b) => b - a)[Math.min(4, gainPerWeek.length - 1)] ?? 0
  for (const action of actions) {
    action.quickWin = action.effortWeeks <= 1.5 && action.certificationGainPct > 0 && action.certificationGainPct / Math.max(0.5, action.effortWeeks) >= Math.max(0.1, leverageThreshold)
  }

  // Projection ladder.
  const ladder: ReadinessLadderStep[] = [
    {
      stage: 'Current Readiness',
      actionId: null,
      actionTitle: 'Measured from live evidence',
      readinessPct: currentPct,
      gainPct: 0,
      effortWeeks: 0,
      detail: `${criteria.filter((c) => c.met).length}/${REQUIRED_CRITERIA.length} certification criteria currently met.`,
    },
  ]
  for (const action of actions.slice(0, LADDER_DETAIL_STEPS)) {
    ladder.push({
      stage: `After Recommendation #${action.rank}`,
      actionId: action.id,
      actionTitle: `${action.asset} — ${action.recommendation}`,
      readinessPct: action.projectedReadinessPct,
      gainPct: action.certificationGainPct,
      effortWeeks: action.effortWeeks,
      detail: `${action.domainLabel}: ${action.problem}`,
    })
  }
  if (actions.length > LADDER_DETAIL_STEPS || tailSet.length) {
    const hidden = actions.length - LADDER_DETAIL_STEPS + tailSet.length
    ladder.push({
      stage: `After remaining ${hidden} action(s)`,
      actionId: null,
      actionTitle: 'Complete the remaining remediation queue',
      readinessPct: finalPct,
      gainPct: round1(Math.max(0, finalPct - (ladder[ladder.length - 1]?.readinessPct ?? currentPct))),
      effortWeeks: round1(actions.slice(LADDER_DETAIL_STEPS).reduce((s, a) => s + a.effortWeeks, 0) + tailSet.reduce((s, t) => s + t.action.effortWeeks, 0)),
      detail: 'Aggregated projection across the remaining queue.',
    })
  }
  const projectionComplete = finalPct >= 100
  ladder.push({
    stage: projectionComplete ? 'Certification Eligible' : 'Projected Maximum',
    actionId: null,
    actionTitle: projectionComplete
      ? 'All 10 required criteria projected to pass — issue the Quantum Trust Certificate™'
      : `Simulation reaches ${finalPct}% — remaining criteria need new evidence (rescan) to close`,
    readinessPct: finalPct,
    gainPct: 0,
    effortWeeks: 0,
    detail: projectionComplete
      ? 'Rescan after execution: eligibility is granted from measured evidence, never from the projection.'
      : 'Projections are simulations; the live score updates as vulnerabilities are resolved and assets are rescanned.',
  })

  // Requirements gap analysis (all criteria; unmet ones enriched).
  const requirements = buildRequirements(ev, criteria, actions, baseline)

  // Effort → estimated certification date.
  const openActions = actions.filter((a) => a.status !== 'resolved')
  const totalEffortWeeks = round1(openActions.reduce((s, a) => s + a.effortWeeks, 0) + tailSet.reduce((s, t) => s + t.action.effortWeeks, 0))
  const workstreams = Math.max(1, ev.parallelWorkstreams)
  const calendarWeeks = Math.ceil(totalEffortWeeks / workstreams)
  const eligible = ev.eligibility.eligible
  // Day precision: a millisecond timestamp here made every rebuild look like a
  // content change to the live stream, and a planning estimate has no
  // sub-day meaning anyway.
  const dayOf = (ms: number) => `${new Date(ms).toISOString().slice(0, 10)}T00:00:00.000Z`
  const estimatedCertificationDate = eligible
    ? dayOf(Date.now())
    : actions.length
      ? dayOf(Date.now() + calendarWeeks * 7 * 86400000)
      : null

  const queues: Record<RemediationPriority, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const action of actions) queues[action.priority] += 1

  const progress = buildProgress(ev, actions)
  const advisor = buildAdvisorAnswers(ev, actions, requirements, currentPct, finalPct, calendarWeeks, eligible)

  const riskBands = [
    { label: 'Critical (80–100)', count: ev.assets.filter((a) => a.riskScore >= 80).length },
    { label: 'High (60–79)', count: ev.assets.filter((a) => a.riskScore >= 60 && a.riskScore < 80).length },
    { label: 'Elevated (40–59)', count: ev.assets.filter((a) => a.riskScore >= 40 && a.riskScore < 60).length },
    { label: 'Moderate (20–39)', count: ev.assets.filter((a) => a.riskScore >= 20 && a.riskScore < 40).length },
    { label: 'Low (0–19)', count: ev.assets.filter((a) => a.riskScore < 20).length },
  ]

  return {
    generatedAt: ev.generatedAt,
    hasData: true,
    certificationReadinessPct: currentPct,
    certificationEligible: eligible,
    trustScore: ev.trustScore,
    levelLabel: ev.levelLabel,
    requiredMet: ev.eligibility.requiredMet,
    requiredTotal: ev.eligibility.requiredTotal,
    quantumReadiness: ev.scores.quantumReadiness,
    quantumRisk: ev.scores.quantumRisk,
    hndlRisk: ev.scores.hndlRisk,
    pqcAdoption: ev.scores.pqcAdoption,
    estimatedCertificationDate,
    estimatedCompletionWeeks: calendarWeeks,
    parallelWorkstreams: workstreams,
    criteria,
    requirements,
    actions,
    ladder,
    queues,
    quickWins: actions.filter((a) => a.quickWin).map((a) => a.id),
    criticalBlockers: actions.filter((a) => a.priority === 'critical').slice(0, 6).map((a) => a.id),
    vendorActions: actions.filter((a) => a.domain === 'vendor' || a.blastRadius.vendorParties.length > 0).map((a) => a.id),
    replacementsRequired: actions.filter((a) => a.requiresReplacement).map((a) => a.id),
    advisor,
    progress,
    assetsByRisk: riskBands,
    remainingVulnerabilities: {
      critical: baseline.critical,
      high: baseline.high,
      medium: baseline.medium,
      low: baseline.low,
      total: baseline.critical + baseline.high + baseline.medium + baseline.low,
    },
    readinessTrend: ev.readinessTrend,
    methodology: buildMethodology(),
  }
}

/* ------------------------------------------------------------------ */
/* Requirements gap analysis                                           */
/* ------------------------------------------------------------------ */
const REQUIREMENT_CONTEXT: Record<string, { business: string; technical: string; route: { label: string; route: string } }> = {
  readiness: {
    business: 'Customers, auditors and regulators read overall readiness as the headline posture — below-threshold readiness blocks certification and weakens security assurances in deals.',
    technical: 'The blended readiness score stays low while classical components dominate the CBOM and quantum risk remains elevated.',
    route: { label: 'Open Migration Planner', route: '/dashboard/migration-planner' },
  },
  'critical-vulns': {
    business: 'Open critical findings are the fastest path to a security incident and an automatic certification blocker.',
    technical: 'Critical-severity scan findings (quantum-vulnerable primitives on live paths) must be remediated and verified by rescan.',
    route: { label: 'Open Risk Analysis', route: '/dashboard/quantum-readiness/risk-analysis' },
  },
  hndl: {
    business: 'Data recorded today can be decrypted retroactively — long-lived sensitive data is already at risk even before quantum computers arrive.',
    technical: 'Classical key exchange on transport paths plus classical data-at-rest envelopes drive the HNDL exposure score above the certification ceiling.',
    route: { label: 'Open Harvest Now Center', route: '/dashboard/harvest-now' },
  },
  'residual-risk': {
    business: 'Certification asserts that the remaining risk after the migration programme is low; an elevated forecast undermines the attestation.',
    technical: 'The post-programme risk forecast stays elevated while unmigrated vulnerable components remain in the estate.',
    route: { label: 'Open Migration Planner', route: '/dashboard/migration-planner' },
  },
  confidence: {
    business: 'A certificate issued on partial evidence would overstate assurance — confidence below threshold blocks issuance by design.',
    technical: 'Evidence sources (runtime telemetry, key inventory, PKI, cloud connectors) are missing, capping assessment confidence.',
    route: { label: 'Open Scanner', route: '/dashboard/scanner' },
  },
  'pqc-adoption': {
    business: 'PQC adoption is the core certified claim — a low quantum-safe share means the estate is still classically protected.',
    technical: 'The share of quantum-safe/hybrid components in the CBOM is below the certification threshold.',
    route: { label: 'Open CBOM Explorer', route: '/dashboard/cbom' },
  },
  'disallowed-algorithms': {
    business: 'Published certification criteria disallow legacy algorithms outright; any hit is an automatic fail visible to verifiers.',
    technical: 'RSA/ECC/SHA-1/3DES/TLS 1.0-1.1 observations remain in the inventory or scan findings.',
    route: { label: 'Open Crypto Agility Engine', route: '/dashboard/crypto-agility' },
  },
  'vulnerable-components': {
    business: 'Every vulnerable component is attack surface and a certification blocker — component-level closure is required.',
    technical: 'CBOM components flagged is_vulnerable must be migrated to ML-KEM/ML-DSA/hybrid equivalents and verified by rescan.',
    route: { label: 'Open CBOM Explorer', route: '/dashboard/cbom' },
  },
  'expired-certificates': {
    business: 'Expired certificates break customer trust chains today, independent of the quantum timeline.',
    technical: 'Inventory certificates past not_after must be renewed or retired, with managed rotation to prevent recurrence.',
    route: { label: 'Open PKI Visibility', route: '/dashboard/pki-visibility' },
  },
  validation: {
    business: 'Certification requires a self-consistent evidence report; a failing validation would propagate inconsistent numbers to auditors.',
    technical: 'Cross-section consistency checks in the report engine are failing — usually incomplete or contradictory evidence.',
    route: { label: 'Open Report Center', route: '/dashboard/quantum-readiness/reports' },
  },
}

function buildRequirements(ev: RemediationEvidence, criteria: CriterionProgress[], actions: RemediationAction[], baseline: CriteriaMeasures): CertificationRequirementGap[] {
  return criteria.map((criterion) => {
    const related = actions.filter((a) => a.criteriaAddressed.includes(criterion.id))
    const relatedAssets = Array.from(new Set(related.map((a) => a.asset))).slice(0, 12)
    const context = REQUIREMENT_CONTEXT[criterion.id]
    const check = ev.eligibility.checks.find((c) => c.id === criterion.id)

    // Simulated score increase from completing every related action.
    let scoreIncrease = 0
    if (!criterion.met && related.length) {
      let state = baseline
      for (const action of related) state = applyImpact(state, baseline, action.impact)
      scoreIncrease = Math.max(0, computeCertificationReadiness(state, baseline, ev.policy).pct - computeCertificationReadiness(baseline, baseline, ev.policy).pct)
    }
    const weeks = round1(related.reduce((s, a) => s + a.effortWeeks, 0) / Math.max(1, ev.parallelWorkstreams))

    return {
      id: criterion.id,
      requirement: criterion.criterion,
      status: criterion.met ? 'met' : 'unmet',
      severity: 'required',
      description: check ? `Required ${check.required}; measured ${check.actual}.` : `Required ${criterion.required}; measured ${criterion.actual}.`,
      businessImpact: context?.business || '',
      technicalImpact: context?.technical || '',
      recommendedSolution: check?.remediation || REMEDIATION_PLAYBOOKS.application.recommendation,
      relatedAssets,
      relatedActionIds: related.slice(0, 20).map((a) => a.id),
      estimatedCompletionWeeks: criterion.met ? 0 : weeks,
      estimatedScoreIncreasePct: round1(scoreIncrease),
      integration: context?.route || { label: 'Open Quantum Readiness', route: '/dashboard/quantum-readiness' },
    }
  })
}

/* ------------------------------------------------------------------ */
/* Progress + AI Quantum Advisor™                                      */
/* ------------------------------------------------------------------ */
function buildProgress(ev: RemediationEvidence, actions: RemediationAction[]): RemediationProgress {
  const completedJobs = ev.migrationJobs.filter((j) => /complete|succeed|done|validated/i.test(j.status))
  const runningJobs = ev.migrationJobs.filter((j) => /running|in_progress|active|executing/i.test(j.status))
  const open = actions.filter((a) => a.status === 'open').length
  const inProgress = actions.filter((a) => a.status === 'in_progress').length
  const resolvedEquivalent = completedJobs.length
  const denominator = actions.length + resolvedEquivalent
  return {
    totalActions: actions.length,
    openActions: open,
    inProgressActions: inProgress,
    resolvedActions: resolvedEquivalent,
    completionPct: denominator > 0 ? Math.round((resolvedEquivalent / denominator) * 100) : 0,
    migrationJobsCompleted: completedJobs.length,
    migrationJobsRunning: runningJobs.length,
    recentlyFixed: completedJobs.slice(0, 8).map((j) => ({
      title: `${str(j.jobType) || 'Migration job'} — ${ev.assetNameById.get(j.assetId) || 'estate asset'}`,
      detail: `Migration job ${j.id.slice(0, 8)} completed (${j.status}).`,
      completedAt: j.updatedAt || null,
      source: 'migration_jobs',
    })),
    upcomingTasks: actions
      .filter((a) => a.status === 'open')
      .slice(0, 8)
      .map((a) => ({ actionId: a.id, title: `${a.asset}: ${a.recommendation}`, priority: a.priority, effortWeeks: a.effortWeeks })),
  }
}

function buildAdvisorAnswers(
  ev: RemediationEvidence,
  actions: RemediationAction[],
  requirements: CertificationRequirementGap[],
  currentPct: number,
  finalPct: number,
  calendarWeeks: number,
  eligible: boolean,
): AdvisorAnswer[] {
  const unmet = requirements.filter((r) => r.status === 'unmet')
  const first = actions[0]
  const topGain = [...actions].sort((a, b) => b.certificationGainPct - a.certificationGainPct)[0]
  const automatable = actions.filter((a) => a.automatable)
  const vendors = actions.filter((a) => a.domain === 'vendor' || a.blastRadius.vendorParties.length > 0)
  const highestRiskAsset = [...ev.assets].sort((a, b) => b.riskScore - a.riskScore)[0]
  const certDate = calendarWeeks > 0 ? new Date(Date.now() + calendarWeeks * 7 * 86400000).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' }) : null

  const answers: AdvisorAnswer[] = [
    {
      question: 'Why am I not Quantum Ready?',
      answer: eligible
        ? 'You are — all required certification criteria pass from measured evidence. Issue the Quantum Trust Certificate™ from the Certification page.'
        : `${unmet.length} of ${requirements.length} required certification criteria are unmet: ${unmet.slice(0, 4).map((r) => r.requirement).join('; ')}${unmet.length > 4 ? '…' : ''}. Every gap has a remediation path in this plan.`,
      evidence: unmet.slice(0, 4).map((r) => r.description),
      route: '/dashboard/quantum-certification',
    },
    {
      question: 'Which assets prevent certification?',
      answer: actions.length
        ? `${new Set(actions.filter((a) => a.assetType !== 'estate').map((a) => a.asset)).size} asset(s) carry blocking findings. Highest impact: ${actions.slice(0, 3).map((a) => a.asset).join(', ')}.`
        : 'No asset-level blockers detected in the current evidence.',
      evidence: actions.slice(0, 3).map((a) => `${a.asset}: ${a.problem}`),
      route: null,
    },
    {
      question: 'What should I fix first?',
      answer: first
        ? `Recommendation #1: ${first.asset} — ${first.recommendation} (${first.effort} effort, +${first.certificationGainPct}% certification readiness).`
        : 'Nothing outstanding — run a rescan to confirm.',
      evidence: first ? [first.problem, `Priority ${first.priority.toUpperCase()} (${first.priorityScore}/100)`] : [],
      route: first?.integration.route || null,
    },
    {
      question: 'What is my highest risk?',
      answer: highestRiskAsset
        ? `${highestRiskAsset.name} (risk score ${highestRiskAsset.riskScore}/100${highestRiskAsset.internetFacing ? ', internet-facing' : ''}). Estate quantum risk is ${ev.scores.quantumRisk}/100 with HNDL exposure ${ev.scores.hndlRisk}/100.`
        : `Estate quantum risk is ${ev.scores.quantumRisk}/100.`,
      evidence: highestRiskAsset ? [`${highestRiskAsset.vulnerabilities.length} vulnerable component(s) on ${highestRiskAsset.name}`] : [],
      route: '/dashboard/quantum-readiness/risk-analysis',
    },
    {
      question: 'Which vulnerabilities have the greatest certification impact?',
      answer: topGain
        ? `${topGain.asset} — ${topGain.problem}: fixing it adds +${topGain.certificationGainPct}% certification readiness (${topGain.criteriaAddressed.length} criteria affected).`
        : 'No open vulnerabilities affect the certification criteria.',
      evidence: topGain ? topGain.whyNotReady.slice(0, 3) : [],
      route: topGain?.integration.route || null,
    },
    {
      question: 'Which migrations can be automated?',
      answer: automatable.length
        ? `${automatable.length} of ${actions.length} actions follow automatable playbooks (TLS hybrid rollout, SSH KEX, certificate rotation, KMS re-wrap, cloud configuration). Validate each in the Migration Sandbox first.`
        : 'The remaining actions require manual engineering or vendor coordination.',
      evidence: automatable.slice(0, 4).map((a) => `${a.asset}: ${a.domainLabel}`),
      route: '/dashboard/migration-sandbox',
    },
    {
      question: 'Which vendors should be contacted?',
      answer: vendors.length
        ? `${vendors.length} action(s) involve third parties: ${Array.from(new Set(vendors.flatMap((v) => (v.blastRadius.vendorParties.length ? v.blastRadius.vendorParties : [v.asset])))).slice(0, 5).join(', ')}. Request PQC roadmaps referencing FIPS 203/204/205 and CNSA 2.0 timelines.`
        : 'No third-party dependencies block certification in the current evidence.',
      evidence: vendors.slice(0, 3).map((v) => `${v.asset}: ${v.problem}`),
      route: '/dashboard/vendor-pqc-readiness',
    },
    {
      question: 'How long until certification?',
      answer: eligible
        ? 'You are eligible now — issuance takes effect immediately after signing.'
        : certDate
          ? `≈${calendarWeeks} week(s) across ${ev.parallelWorkstreams} parallel workstream(s) — estimated certification date ${certDate}, assuming the queue executes as planned and rescans verify closure.`
          : 'Run a discovery scan to generate a remediation timeline.',
      evidence: [`Total remediation effort: ${round1(actions.reduce((s, a) => s + a.effortWeeks, 0))} engineer-weeks`],
      route: '/dashboard/migration-planner',
    },
    {
      question: 'What will my readiness score become after implementing the recommendations?',
      answer: `Certification readiness is projected to rise from ${currentPct}% to ${finalPct}% after completing the full queue${finalPct >= 100 ? ' — reaching certification eligibility' : ''}. The live score updates automatically as vulnerabilities are resolved and assets are rescanned.`,
      evidence: [`Q-REMEDY marginal-gain simulation over ${actions.length} action(s)`],
      route: '/dashboard/quantum-certification',
    },
  ]
  return answers
}

function buildMethodology() {
  return {
    name: 'Q-REMEDY (Quantum Remediation & Eligibility Marginal-gain Yield)',
    version: REMEDIATION_ENGINE_VERSION,
    summary:
      'Every discovered asset’s measured vulnerabilities are grouped by remediation domain and mapped to NIST-aligned playbooks (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, CNSA 2.0, RFC 8784, CISA/NCSC migration guidance). Actions are ordered by a marginal-gain greedy algorithm that re-simulates the Certification Readiness Score after each candidate and picks the best gain per unit of effort.',
    scoreFormula:
      'Certification Readiness % = Σ (criterion progress × 10%) across the 10 required Quantum Trust Certification criteria. Threshold criteria progress linearly toward their limits; zero-tolerance criteria (critical findings, vulnerable components, disallowed algorithms, expired certificates) progress relative to the measured baseline; report validation is binary. 100% ⇔ certification eligible.',
    priorityFactors: PRIORITY_WEIGHTS.map((w) => ({
      factor: w.factor,
      weightPct: w.weightPct,
      basis:
        w.key === 'certScore'
          ? 'Marginal certification-readiness gain from the Q-REMEDY simulation'
          : w.key === 'severityScore'
            ? 'Worst finding severity on the asset (scan evidence)'
            : w.key === 'criticalityScore'
              ? 'Asset business criticality (asset inventory)'
              : w.key === 'internetScore'
                ? 'Internet exposure (asset environment/type evidence)'
                : w.key === 'hndlScore'
                  ? 'Harvest-Now-Decrypt-Later relevance of the remediation domain'
                  : w.key === 'dataScore'
                    ? 'Data sensitivity of the asset/domain'
                    : w.key === 'blastScore'
                      ? 'Dependency degree in the trust-relationship graph'
                      : 'Disallowed-algorithm (compliance) hits in the findings',
    })),
    simulation:
      'Projected scores re-blend the Quantum Readiness model with each action’s measured deltas (findings resolved, components migrated, certificates renewed, evidence connected). Residual score contributions the action does not move are held at their measured baseline. Projections are simulations: the live score only moves when a rescan verifies the change.',
    honesty:
      'No fabricated findings: every action originates from scanner findings, CBOM components, certificate inventory or dependency-graph evidence. Action status derives from live evidence and real migration jobs — it resolves automatically on a clean rescan and is never asserted.',
  }
}

function emptyPlan(ev: RemediationEvidence, criteria: CriterionProgress[]): RemediationPlan {
  return {
    generatedAt: ev.generatedAt,
    hasData: false,
    certificationReadinessPct: 0,
    certificationEligible: false,
    trustScore: 0,
    levelLabel: 'Not Eligible',
    requiredMet: 0,
    requiredTotal: REQUIRED_CRITERIA.length,
    quantumReadiness: 0,
    quantumRisk: 0,
    hndlRisk: 0,
    pqcAdoption: 0,
    estimatedCertificationDate: null,
    estimatedCompletionWeeks: 0,
    parallelWorkstreams: 1,
    criteria,
    requirements: [],
    actions: [],
    ladder: [],
    queues: { critical: 0, high: 0, medium: 0, low: 0 },
    quickWins: [],
    criticalBlockers: [],
    vendorActions: [],
    replacementsRequired: [],
    advisor: [
      {
        question: 'Why am I not Quantum Ready?',
        answer: 'No assessment evidence exists for this tenant yet. Run a PQC discovery scan to populate the Quantum Readiness Assessment Engine™ — the remediation roadmap is generated from measured evidence, never asserted.',
        evidence: [],
        route: '/dashboard/scanner',
      },
    ],
    progress: {
      totalActions: 0,
      openActions: 0,
      inProgressActions: 0,
      resolvedActions: 0,
      completionPct: 0,
      migrationJobsCompleted: 0,
      migrationJobsRunning: 0,
      recentlyFixed: [],
      upcomingTasks: [],
    },
    assetsByRisk: [],
    remainingVulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
    readinessTrend: [],
    methodology: buildMethodology(),
  }
}

/* ------------------------------------------------------------------ */
/* Evidence assembly (live route)                                      */
/* ------------------------------------------------------------------ */
export async function assembleEvidence(token: string, userId: string): Promise<RemediationEvidence> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const missing = { schema: false }
  const policy = await loadPolicy(client, userId, missing)
  const evidence: EvidenceBundle = await gatherEvidence(client, token, userId)
  const eligibility = evaluateEligibility(evidence, policy)
  const snapshot = evidence.snapshot

  // Per-asset vulnerability detail (same source as the Scanner / CBOM pages).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let intel: any = null
  try {
    intel = await buildScannerIntelligence(token, userId)
  } catch {
    intel = null
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const intelAssets: any[] = intel?.assets?.assets || []

  const [rawAssets, relationships, expiredCertRows, migrationJobs] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, criticality, service_owner, metadata').eq('user_id', userId).limit(2000)),
    safeRows(client, 'asset_relationships', (q) => q.select('source_asset_id, target_asset_id, relationship_type').eq('user_id', userId).limit(3000)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, not_after').eq('user_id', userId).lt('not_after', new Date().toISOString()).limit(1000)),
    safeRows(client, 'migration_jobs', (q) => q.select('id, status, asset_id, job_type, updated_at, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(300)),
  ])

  const rawById = new Map(rawAssets.map((a) => [str(a.id), a]))
  const assetNameById = new Map(rawAssets.map((a) => [str(a.id), str(a.name)]))
  for (const a of intelAssets) if (!assetNameById.has(str(a.id))) assetNameById.set(str(a.id), str(a.name))

  const expiredCertsByAsset = new Map<string, number>()
  let unlinkedExpiredCerts = 0
  for (const cert of expiredCertRows) {
    const assetId = str(cert.asset_id)
    if (assetId && (rawById.has(assetId) || intelAssets.some((a) => str(a.id) === assetId))) {
      expiredCertsByAsset.set(assetId, (expiredCertsByAsset.get(assetId) || 0) + 1)
    } else {
      unlinkedExpiredCerts += 1
    }
  }

  // THE canonical internet-exposure heuristic (asset-intelligence.ts). This
  // route used to carry a private copy that had already drifted — it ignored
  // `metadata.exposure`, so an asset tagged `exposure: internet` was internal here.
  const internetFacingFor = (raw: Record<string, unknown> | undefined, type: string, name: string): boolean =>
    isInternetFacing({ ...(raw || {}), type, name })

  const assets: RemediationEvidence['assets'] = intelAssets.map((asset) => {
    const raw = rawById.get(str(asset.id))
    const meta = (raw?.metadata && typeof raw.metadata === 'object' ? raw.metadata : {}) as Record<string, unknown>
    const type = str(asset.type) || str(raw?.type) || 'asset'
    const name = str(asset.name) || 'Unnamed asset'
    return {
      id: str(asset.id),
      name,
      type,
      environment: str(raw?.environment) || 'unknown',
      owner: str(raw?.service_owner) || 'Unassigned',
      criticality: str(raw?.criticality) || 'unknown',
      internetFacing: internetFacingFor(raw, type, name),
      riskScore: num(asset.riskScore),
      pqcCapable: meta.pqc_supported !== false && !/legacy|mainframe|scada|embedded|iot(-|$)/i.test(type),
      vendorParty: /vendor|third|saas|partner|external.?service/i.test(`${type} ${name}`) || meta.vendor === true,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vulnerabilities: (Array.isArray(asset.vulnerabilities) ? asset.vulnerabilities : []).slice(0, 40).map((v: any) => ({
        id: str(v.id),
        name: str(v.name),
        itemType: str(v.item_type),
        algorithm: str(v.algorithm),
        protocol: str(v.protocol),
        severity: str(v.exposure_level) || str(v.metadata?.threatLevel) || str(v.metadata?.severity) || 'medium',
        instances: Math.max(1, num(v.instances)),
        description: str(v.metadata?.description) || str(v.metadata?.recommendation) || '',
      })),
    }
  })

  const relSource = (r: Record<string, unknown>) => str(r.source_asset_id || r.parent_asset_id || r.from_asset_id)
  const relTarget = (r: Record<string, unknown>) => str(r.target_asset_id || r.child_asset_id || r.to_asset_id)

  const confidence = num(evidence.report.confidenceSummary?.assessmentConfidencePct)
  const residualRisk = num(evidence.report.riskForecast?.residualRisk)
  const validationPass = evidence.report.reportValidation?.overall === 'PASS'
  const inv = snapshot.inventory

  const missingEvidenceSources: RemediationEvidence['missingEvidenceSources'] = []
  if (num(snapshot.telemetry?.runtimeEvents) === 0) missingEvidenceSources.push({ id: 'runtime-telemetry', label: 'Runtime Cryptographic Intelligence', route: '/dashboard/runtime-crypto-intel' })
  if (num(inv?.keysDiscovered) === 0) missingEvidenceSources.push({ id: 'key-inventory', label: 'Key Inventory (QKMS)', route: '/dashboard/qkms/overview' })
  if (num(inv?.certificatesAnalyzed) === 0) missingEvidenceSources.push({ id: 'pki', label: 'PKI / Certificate Inventory', route: '/dashboard/pki-visibility' })
  if (num(inv?.cloudAccounts) === 0) missingEvidenceSources.push({ id: 'cloud-connectors', label: 'Cloud Connectors', route: '/dashboard/settings' })
  if (num(inv?.cryptoComponents) === 0) missingEvidenceSources.push({ id: 'cbom', label: 'Cryptographic Inventory (CBOM)', route: '/dashboard/scanner' })

  const measures: CriteriaMeasures = {
    readiness: num(snapshot.scores.quantumReadiness),
    quantumRisk: num(snapshot.scores.quantumRisk),
    hndl: num(snapshot.scores.hndlRisk),
    residualRisk,
    confidence,
    pqcAdoption: num(snapshot.scores.pqcAdoption),
    critical: num(snapshot.riskDistribution?.critical),
    high: num(snapshot.riskDistribution?.high),
    medium: num(snapshot.riskDistribution?.medium),
    low: num(snapshot.riskDistribution?.low),
    vulnerableComponents: num(inv?.vulnerableComponents),
    pqcReadyComponents: num(inv?.pqcReadyComponents),
    totalComponents: Math.max(num(inv?.cryptoComponents), num(inv?.vulnerableComponents) + num(inv?.pqcReadyComponents)),
    disallowedCount: evidence.disallowedHits.length,
    expiredCertificates: evidence.expiredCertificates,
    validationPass,
    runtimeMeasured: num(snapshot.telemetry?.runtimeEvents) > 0,
    runtimeFresh: (() => {
      const at = snapshot.telemetry?.latestRuntimeEventAt
      const ms = at ? Date.parse(String(at)) : 0
      return Number.isFinite(ms) && ms > 0 && Date.now() - ms < 6 * 60 * 60 * 1000
    })(),
  }

  return {
    hasData: Boolean(snapshot.hasData),
    generatedAt: new Date().toISOString(),
    policy,
    eligibility,
    measures,
    scores: {
      quantumReadiness: num(snapshot.scores.quantumReadiness),
      quantumRisk: num(snapshot.scores.quantumRisk),
      hndlRisk: num(snapshot.scores.hndlRisk),
      pqcAdoption: num(snapshot.scores.pqcAdoption),
      migrationComplexity: num(snapshot.scores.migrationComplexity),
    },
    trustScore: eligibility.trustScore,
    levelLabel: eligibility.levelLabel,
    parallelWorkstreams: Math.max(1, num(snapshot.estimates?.parallelWorkstreams) || 1),
    readinessTrend: snapshot.riskTrend || [],
    disallowedAlgorithms: policy.disallowedAlgorithms,
    missingEvidenceSources,
    validationPass,
    cryptoAgilityActive: Boolean(evidence.report.cryptoPolicy?.activeProfile),
    assets,
    relationships: relationships
      .map((r) => ({ source: relSource(r), target: relTarget(r), type: str(r.relationship_type) || 'depends-on' }))
      .filter((r) => r.source && r.target),
    expiredCertsByAsset,
    unlinkedExpiredCerts,
    migrationJobs: migrationJobs.map((j) => ({
      id: str(j.id),
      status: str(j.status),
      assetId: str(j.asset_id),
      jobType: str(j.job_type),
      updatedAt: str(j.updated_at) || str(j.created_at),
    })),
    assetNameById,
  }
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */
/* One plan per tenant per 15s window for the JSON route, the stream and every
   open tab. Assembling evidence re-reads the certification bundle, scanner
   intelligence and four tables, then runs the marginal-gain simulation — it
   used to do all of that once per connected client every 30s. */
const planCache = createSingleFlightCache<RemediationPlan>(15_000)
function buildCachedPlan(token: string, userId: string): Promise<RemediationPlan> {
  return planCache.get(userId, async () => buildRemediationPlan(await assembleEvidence(token, userId)))
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const plan = await buildCachedPlan(token!, user!.id)
    res.json({ data: { ...plan, fingerprint: payloadFingerprint(plan) } })
  } catch (error) {
    console.error('quantum-remediation plan failed:', error)
    res.status(500).json({ error: { code: 'REMEDIATION_ERROR', message: 'Unable to build remediation plan' } })
  }
})

router.get('/stream', (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  streamLiveSnapshot(req, res, {
    event: 'remediation-update',
    build: () => buildCachedPlan(token!, user!.id),
    intervalMs: 15_000,
  })
})

export default router
