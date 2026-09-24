// Sophia — platform knowledge base: module registry, intent catalog +
// detection, planner map, standards catalog, RBAC capability matrix, prompt
// sanitizer and suggested questions.
//
// PURE module — no Supabase/Express imports — so the engine, the gateway and
// tools/copilot-check.ts all exercise the exact same logic.

import type {
  CopilotAgentId,
  CopilotIntent,
  CopilotObjectiveKind,
  CopilotRole,
  CopilotSuggestion,
  RoleCapabilities,
} from '@/types/copilot'
// The canonical, token-anchored algorithm classifier the governance engine and
// every dashboard already use. Reused rather than re-implemented so "RSA" means
// the same thing to Sophia that it means to CBOM, Governance and the QR Engine.
import { algorithmFamily, ALGORITHM_FAMILY_LABEL, type AlgorithmFamily } from '@/lib/governance/subjects'

/* ------------------------------------------------------------------ */
/* Module registry — every QGuard Helix surface Sophia can deep-link   */
/* ------------------------------------------------------------------ */

export interface CopilotModule {
  id: string
  label: string
  path: string
  description: string
}

export const MODULE_REGISTRY: CopilotModule[] = [
  { id: 'overview', label: 'Dashboard Overview', path: '/dashboard', description: 'Platform overview and KPIs' },
  { id: 'scanner', label: 'PQC Scanner', path: '/dashboard/scanner', description: 'Cryptographic discovery scans and findings' },
  { id: 'assets', label: 'Assets & CBOM', path: '/dashboard/assets', description: 'Asset inventory and cryptographic bill of materials' },
  { id: 'cbom', label: 'CBOM Explorer', path: '/dashboard/cbom', description: 'Cryptographic component explorer' },
  { id: 'shadow_crypto', label: 'Shadow Crypto', path: '/dashboard/shadow-crypto', description: 'Undocumented cryptography discovery' },
  { id: 'quantum_readiness', label: 'Quantum Readiness Assessment Engine™', path: '/dashboard/quantum-readiness', description: 'Quantum readiness assessment engine' },
  { id: 'executive', label: 'AI Executive Advisor™', path: '/dashboard/quantum-readiness/ai-executive-advisor', description: 'Executive readiness and business risk view' },
  { id: 'exposure_graph', label: 'Quantum Exposure Graph™', path: '/dashboard/quantum-readiness/exposure-graph', description: 'Dependency graph, blast radius, trust chains' },
  { id: 'risk_analysis', label: 'Quantum Risk Analysis', path: '/dashboard/quantum-readiness/risk-analysis', description: 'Quantum risk scoring and drivers' },
  { id: 'remediation', label: 'Quantum Remediation Engine™', path: '/dashboard/quantum-readiness/remediation', description: 'Remediation playbooks and certification readiness ladder' },
  { id: 'harvest_now', label: 'Harvest Now (HNDL)', path: '/dashboard/harvest-now', description: 'Harvest-now-decrypt-later threat operations' },
  { id: 'certification', label: 'Quantum Trust Certification™', path: '/dashboard/quantum-certification', description: 'Evidence-gated PQC certification' },
  { id: 'reports', label: 'Report Center', path: '/dashboard/quantum-readiness/reports', description: 'Enterprise report generation and exports' },
  { id: 'migration_intelligence', label: 'Migration Intelligence™', path: '/dashboard/migration-intelligence', description: 'Shared Responsibility ownership model — who owns each finding, who can fix it, and its migration dependencies' },
  { id: 'migration_planner', label: 'Migration Planner', path: '/dashboard/migration-planner', description: 'PQC migration planning workflow' },
  { id: 'migration_sandbox', label: 'Migration Sandbox', path: '/dashboard/migration-sandbox', description: 'Safe migration simulation' },
  { id: 'live_migration', label: 'Live Migration Ops', path: '/dashboard/live-migration', description: 'Live migration execution, orchestration, snapshots and rollback' },
  { id: 'migration_timeline', label: 'Migration Timeline', path: '/dashboard/migration-timeline', description: 'Migration timeline and phases' },
  { id: 'telemetry', label: 'Runtime Telemetry', path: '/dashboard/runtime-crypto-intel', description: 'Runtime cryptographic intelligence' },
  { id: 'collectors', label: 'Agent Collectors', path: '/dashboard/scanner?tab=agents', description: 'Agent collector console (heartbeats, health, patchers)' },
  { id: 'pki', label: 'PKI Visibility', path: '/dashboard/pki-visibility', description: 'Certificates, CAs and trust stores' },
  { id: 'tls', label: 'TLS Telemetry', path: '/dashboard/tls-telemetry', description: 'TLS protocol posture and telemetry' },
  { id: 'compliance', label: 'Compliance Center', path: '/dashboard/compliance', description: 'Compliance posture and evidence' },
  { id: 'audit', label: 'Audit Vault', path: '/dashboard/audit-vault', description: 'Audit trails and evidence vault' },
  { id: 'settings', label: 'Profile & Settings', path: '/dashboard/settings', description: 'Account, subscription and integrations' },
  { id: 'sophia', label: 'Sophia AI Copilot™', path: '/dashboard/sophia', description: 'AI Security Copilot console' },
]

export function modulePath(id: string): string {
  return MODULE_REGISTRY.find((m) => m.id === id)?.path || '/dashboard'
}

export function moduleLabel(id: string): string {
  return MODULE_REGISTRY.find((m) => m.id === id)?.label || id
}

/* ------------------------------------------------------------------ */
/* Standards catalog — recommendations always cite these               */
/* ------------------------------------------------------------------ */

export const STANDARDS = {
  FIPS_203: 'FIPS 203 (ML-KEM)',
  FIPS_204: 'FIPS 204 (ML-DSA)',
  FIPS_205: 'FIPS 205 (SLH-DSA)',
  CNSA_2: 'NSA CNSA 2.0',
  NIST_CSF: 'NIST CSF 2.0',
  SP_800_53: 'NIST SP 800-53 Rev. 5',
  SP_800_57: 'NIST SP 800-57',
  SP_800_131A: 'NIST SP 800-131A Rev. 2',
  SP_800_208: 'NIST SP 800-208',
  SP_1800_38: 'NIST SP 1800-38 (Migration to PQC)',
  ISO_27001: 'ISO/IEC 27001',
  ISO_19790: 'ISO/IEC 19790',
  PCI_DSS: 'PCI DSS v4.0',
  CIS_V8: 'CIS Controls v8',
  OWASP_ASVS: 'OWASP ASVS',
  ETSI_QSC: 'ETSI Quantum-Safe Cryptography',
  IETF_HYBRID: 'IETF Hybrid TLS (X25519MLKEM768)',
} as const

/* ------------------------------------------------------------------ */
/* RBAC — role capability matrix (AI_CoPilot_Multi-Tenant_Isolation)   */
/* ------------------------------------------------------------------ */

export const ROLE_CAPABILITIES: Record<CopilotRole, RoleCapabilities> = {
  owner: { read: true, operate: true, audit: true, executive: true },
  infrastructure_admin: { read: true, operate: true, audit: true, executive: true },
  security_analyst: { read: true, operate: false, audit: false, executive: false },
  executive: { read: true, operate: false, audit: false, executive: true },
  auditor: { read: true, operate: false, audit: true, executive: true },
}

export const ROLE_LABELS: Record<CopilotRole, string> = {
  owner: 'Platform Owner',
  infrastructure_admin: 'Infrastructure Administrator',
  security_analyst: 'Security Analyst',
  executive: 'Executive',
  auditor: 'Auditor',
}

/**
 * Least privilege: an account with no role (profiles.role NULL — every
 * self-registered user) or an unrecognised one is a read-only Security Analyst.
 * Operate / audit / executive tools require an explicit role assigned by the
 * owner in Admin > Users.
 */
export const DEFAULT_COPILOT_ROLE: CopilotRole = 'security_analyst'

/**
 * Normalize a profiles.role value to a copilot role. The owner email is always
 * `owner`; explicit roles are honored when set on the profile (org/seat models
 * can extend this without changing the enforcement path); anything else falls
 * back to DEFAULT_COPILOT_ROLE.
 */
export function normalizeRole(value: unknown, isOwner: boolean): CopilotRole {
  if (isOwner) return 'owner'
  const v = String(value ?? '').trim().toLowerCase().replace(/[\s-]+/g, '_')
  if (v.includes('audit')) return 'auditor'
  if (v.includes('exec') || v.includes('ciso') || v.includes('cio')) return 'executive'
  if (v.includes('analyst') || v.includes('soc')) return 'security_analyst'
  if (v.includes('admin') || v.includes('infra') || v.includes('platform')) return 'infrastructure_admin'
  return DEFAULT_COPILOT_ROLE
}

/* ------------------------------------------------------------------ */
/* Intent catalog + detection                                          */
/* ------------------------------------------------------------------ */

interface IntentDef {
  intent: CopilotIntent
  /** Keyword/regex signals (case-insensitive), each with a weight. */
  signals: Array<{ pattern: RegExp; weight: number }>
  modules: string[]
  agents: CopilotAgentId[]
}

const INTENT_DEFS: IntentDef[] = [
  {
    intent: 'asset_status',
    signals: [
      { pattern: /\basset(s)?\b/i, weight: 3 },
      { pattern: /\binventor(y|ies)\b/i, weight: 3 },
      { pattern: /\bserver(s)?\b|\bendpoint(s)?\b|\bworkload(s)?\b|\bdatabase(s)?\b|\bvpn\b|\bgateway(s)?\b/i, weight: 2 },
      { pattern: /internet[- ]facing|public[- ]facing|exposed/i, weight: 2 },
      { pattern: /\bvulnerable\b/i, weight: 1 },
    ],
    modules: ['assets', 'scanner', 'exposure_graph'],
    agents: ['asset_intelligence'],
  },
  {
    intent: 'migration_status',
    signals: [
      { pattern: /\bmigrat(e|ion|ing|ions)\b/i, weight: 3 },
      { pattern: /\bcutover\b|\bwave(s)?\b|\bphase(s)?\b/i, weight: 2 },
      { pattern: /\bfailed migration(s)?\b|\bactive migration(s)?\b/i, weight: 4 },
      { pattern: /what should (i|we) migrate/i, weight: 4 },
    ],
    modules: ['live_migration', 'migration_planner', 'migration_timeline'],
    agents: ['migration_advisor'],
  },
  {
    intent: 'remediation',
    signals: [
      { pattern: /\bremediat(e|ion|ions)\b/i, weight: 4 },
      { pattern: /\bfix(es)?\b|\bpatch(es|ing)?\b/i, weight: 2 },
      { pattern: /\bpending action(s)?\b|\bplaybook(s)?\b/i, weight: 2 },
    ],
    modules: ['remediation'],
    agents: ['migration_advisor', 'risk_analyst'],
  },
  {
    intent: 'risk_analysis',
    signals: [
      { pattern: /\brisk(s|y)?\b/i, weight: 3 },
      { pattern: /blast radius/i, weight: 4 },
      { pattern: /\bexposure\b/i, weight: 2 },
      { pattern: /\bcritical\b|\bhigh[- ]risk\b/i, weight: 1 },
    ],
    modules: ['risk_analysis', 'exposure_graph', 'harvest_now'],
    agents: ['risk_analyst'],
  },
  {
    intent: 'certification',
    signals: [
      { pattern: /\bcertif(y|ication|ied)\b/i, weight: 4 },
      { pattern: /quantum trust/i, weight: 3 },
      { pattern: /\b(bronze|silver|gold|platinum|diamond)\b/i, weight: 2 },
      { pattern: /why.*(haven'?t|not).*(certif)/i, weight: 5 },
    ],
    modules: ['certification', 'remediation', 'quantum_readiness'],
    agents: ['compliance_advisor', 'risk_analyst'],
  },
  {
    intent: 'reports',
    signals: [
      { pattern: /\breport(s)?\b/i, weight: 4 },
      { pattern: /\bexport\b|\bpdf\b|\bexecutive summary\b/i, weight: 2 },
    ],
    modules: ['reports'],
    agents: ['executive_advisor'],
  },
  {
    intent: 'compliance',
    signals: [
      { pattern: /\bcomplian(ce|t)\b/i, weight: 4 },
      { pattern: /\bnist\b|\bfips\b|\bcnsa\b|\biso\b|\bpci\b|\bhipaa\b|\bsoc ?2\b|\bcsf\b/i, weight: 3 },
      { pattern: /\bstandard(s)?\b|\bregulat(ion|ory)\b|\bframework(s)?\b/i, weight: 2 },
    ],
    modules: ['compliance', 'certification'],
    agents: ['compliance_advisor'],
  },
  {
    intent: 'pki',
    signals: [
      { pattern: /\bpki\b/i, weight: 4 },
      { pattern: /\bcertificate(s)?\b|\bcert(s)?\b/i, weight: 3 },
      { pattern: /\bca\b|\bcertificate authorit(y|ies)\b|\btrust store(s)?\b|\bissuer(s)?\b/i, weight: 3 },
      { pattern: /\bexpir(ed|ing|y)\b/i, weight: 2 },
    ],
    modules: ['pki', 'certification'],
    agents: ['pki_expert'],
  },
  {
    intent: 'tls',
    signals: [
      { pattern: /\btls\b|\bssl\b/i, weight: 4 },
      { pattern: /\bhandshake(s)?\b|\bcipher( suite)?(s)?\b|\bprotocol(s)?\b/i, weight: 2 },
      { pattern: /hybrid tls|x25519/i, weight: 3 },
    ],
    modules: ['tls', 'pki'],
    agents: ['pki_expert'],
  },
  {
    intent: 'ssh',
    signals: [
      { pattern: /\bssh\b/i, weight: 5 },
      { pattern: /\bhost key(s)?\b/i, weight: 3 },
    ],
    modules: ['assets', 'scanner'],
    agents: ['pki_expert', 'asset_intelligence'],
  },
  {
    intent: 'cbom',
    signals: [
      { pattern: /\bcbom\b/i, weight: 5 },
      { pattern: /\balgorithm(s)?\b/i, weight: 2 },
      { pattern: /\blibrar(y|ies)\b|\bcomponent(s)?\b/i, weight: 2 },
      { pattern: /\brsa\b|\becdsa\b|\becdh\b|\baes\b|\bsha[- ]?\d/i, weight: 2 },
    ],
    modules: ['cbom', 'assets', 'scanner'],
    agents: ['asset_intelligence'],
  },
  {
    intent: 'scanner',
    signals: [
      { pattern: /\bscan(s|ner|ned|ning)?\b/i, weight: 4 },
      { pattern: /\bfinding(s)?\b|\bdiscover(y|ed)\b/i, weight: 2 },
    ],
    modules: ['scanner'],
    agents: ['asset_intelligence'],
  },
  {
    intent: 'exposure_graph',
    signals: [
      { pattern: /exposure graph|dependency graph|dependenc(y|ies)/i, weight: 4 },
      { pattern: /trust chain(s)?|trust relationship(s)?/i, weight: 3 },
      { pattern: /blast radius/i, weight: 3 },
      { pattern: /\bupstream\b|\bdownstream\b|\bconnected\b/i, weight: 1 },
    ],
    modules: ['exposure_graph'],
    agents: ['risk_analyst', 'asset_intelligence'],
  },
  {
    intent: 'telemetry',
    signals: [
      { pattern: /\btelemetry\b/i, weight: 4 },
      { pattern: /\bcollector(s)?\b|\bagent(s)?\b|\bheartbeat(s)?\b/i, weight: 3 },
      { pattern: /\bpatcher(s)?\b|\bconnector(s)?\b|\borchestrat(or|ion)\b/i, weight: 3 },
      { pattern: /\bhealth(y)?\b|\bonline\b|\boffline\b|\blive\b/i, weight: 1 },
    ],
    modules: ['telemetry', 'collectors'],
    agents: ['telemetry_agent'],
  },
  {
    intent: 'threat_intelligence',
    signals: [
      { pattern: /\bthreat(s)?\b/i, weight: 3 },
      { pattern: /\bcve(s)?\b|\bvulnerabilit(y|ies)\b/i, weight: 2 },
      { pattern: /\bquantum computer(s)?\b|\bcrqc\b|\bshor\b|\bgrover\b|\badversar(y|ies)\b/i, weight: 3 },
      { pattern: /\bpqc news\b|\bnist update(s)?\b/i, weight: 3 },
    ],
    modules: ['harvest_now', 'risk_analysis'],
    agents: ['threat_intelligence', 'risk_analyst'],
  },
  {
    intent: 'executive_dashboard',
    signals: [
      { pattern: /\bexecutive\b|\bboard\b|\bciso\b|\bbusiness\b/i, weight: 3 },
      { pattern: /\bkpi(s)?\b|\broi\b|\bcost(s)?\b|\bbudget\b|\beffort\b/i, weight: 3 },
      { pattern: /\bposture\b|\boverall\b|\bsummar(y|ize)\b/i, weight: 1 },
    ],
    modules: ['executive', 'reports', 'quantum_readiness'],
    agents: ['executive_advisor'],
  },
  {
    intent: 'harvest_now',
    signals: [
      { pattern: /harvest[- ]now|hndl|decrypt[- ]later/i, weight: 5 },
      { pattern: /\bcaptured (data|traffic)\b|\brecorded traffic\b/i, weight: 3 },
      { pattern: /forward secrecy/i, weight: 3 },
    ],
    modules: ['harvest_now'],
    agents: ['risk_analyst', 'threat_intelligence'],
  },
  {
    intent: 'quantum_readiness',
    signals: [
      { pattern: /quantum read(y|iness)/i, weight: 5 },
      { pattern: /\bpqc[- ]read(y|iness)\b|\bpost[- ]quantum\b/i, weight: 3 },
      { pattern: /\breadiness score\b|\bam i (quantum )?ready\b/i, weight: 4 },
      { pattern: /\bml[- ]?kem\b|\bml[- ]?dsa\b|\bslh[- ]?dsa\b|\bkyber\b|\bdilithium\b/i, weight: 2 },
    ],
    modules: ['quantum_readiness', 'remediation', 'certification'],
    agents: ['risk_analyst', 'executive_advisor', 'compliance_advisor'],
  },
  {
    intent: 'snapshots_rollback',
    signals: [
      { pattern: /\bsnapshot(s)?\b/i, weight: 4 },
      { pattern: /\brollback(s)?\b|\broll back\b|\brestore\b|\brevert\b/i, weight: 4 },
    ],
    modules: ['live_migration'],
    agents: ['migration_advisor'],
  },
  {
    intent: 'platform_help',
    signals: [
      { pattern: /\bhow (do|can) i\b|\bwhere (do|can) i\b|\bwhat (is|are)\b|\bexplain\b|\bhelp\b/i, weight: 1 },
      { pattern: /\bsophia\b|\bcopilot\b|\bwhat can you\b/i, weight: 4 },
    ],
    modules: ['overview'],
    agents: ['coordinator'],
  },
]

export interface IntentDetection {
  intents: CopilotIntent[]
  scores: Partial<Record<CopilotIntent, number>>
  /** True when the question leans on prior context ("which of these…"). */
  followUp: boolean
}

const FOLLOW_UP_PATTERNS = [
  /\b(which|what|how many) (of (these|those|them)|ones)\b/i,
  /\bthose\b|\bthese\b|\bthem\b|\bit\b/i,
  /^(and|also|what about|how about|ok(ay)?[,.]? )/i,
  /\bnext\b/i,
]

export function detectIntents(question: string, priorIntents: CopilotIntent[] = []): IntentDetection {
  const text = String(question || '').slice(0, 2000)
  const scores: Partial<Record<CopilotIntent, number>> = {}

  for (const def of INTENT_DEFS) {
    let score = 0
    for (const signal of def.signals) {
      if (signal.pattern.test(text)) score += signal.weight
    }
    if (score > 0) scores[def.intent] = score
  }

  const ranked = (Object.entries(scores) as Array<[CopilotIntent, number]>)
    .sort((a, b) => b[1] - a[1])

  const top = ranked.filter(([, s]) => s >= 3).slice(0, 3).map(([i]) => i)
  // Weak signals only → keep the best single guess; nothing at all → help.
  if (!top.length && ranked.length) top.push(ranked[0][0])

  const wordCount = text.trim().split(/\s+/).filter(Boolean).length
  const followUp = FOLLOW_UP_PATTERNS.some((p) => p.test(text)) && wordCount <= 14 && priorIntents.length > 0

  // A short follow-up without strong signals inherits the prior focus.
  if (followUp && (!ranked.length || ranked[0][1] < 4)) {
    for (const intent of priorIntents) {
      if (!top.includes(intent)) top.unshift(intent)
    }
  }

  if (!top.length) top.push('platform_help')

  return { intents: top.slice(0, 3), scores, followUp }
}

/** Planner — which modules and agents a set of intents requires. */
export function planForIntents(intents: CopilotIntent[]): { modules: string[]; agents: CopilotAgentId[] } {
  const modules = new Set<string>()
  const agents = new Set<CopilotAgentId>()
  for (const intent of intents) {
    const def = INTENT_DEFS.find((d) => d.intent === intent)
    if (!def) continue
    def.modules.forEach((m) => modules.add(m))
    def.agents.forEach((a) => agents.add(a))
  }
  if (!agents.size) agents.add('coordinator')
  return { modules: [...modules], agents: [...agents] }
}

/* ------------------------------------------------------------------ */
/* Deep context awareness — objective inference                        */
/* ------------------------------------------------------------------ */

export interface ObjectiveInference {
  kind: CopilotObjectiveKind
  /** Plain-language statement of what the user actually wants. */
  objective: string
  /** Whether this warrants a full cross-module deep investigation. */
  investigate: boolean
}

/**
 * Infer what the user is *actually* trying to accomplish — not the literal
 * question. "How do I migrate?" wants guidance, not a status number; "what
 * should I migrate first?" wants prioritization reasoning; "am I quantum
 * ready?" wants an executive assessment; "why can't I certify?" wants a gap
 * analysis; "why is this high risk?" wants the risk reasoning explained.
 *
 * Consultative objectives (guidance / prioritization / executive /
 * gap_analysis / explain) trigger a full-platform investigation.
 */
export function inferObjective(question: string, intents: CopilotIntent[]): ObjectiveInference {
  const q = String(question || '').toLowerCase()

  const isCertContext = intents.includes('certification') || /certif/.test(q)
  const isMigrationContext = intents.includes('migration_status') || /migrat|cutover|transition/.test(q)

  // Ranking — "most vulnerable / riskiest / top risk assets": the user wants a
  // ranked, evidence-backed view of what is most at risk, never a literal
  // text search over the question words.
  const isRanking = /\b(most|top|highest|worst|biggest|greatest|largest)\b.{0,40}\b(vulnerable|risk|risky|critical|exposed|at risk|danger)/.test(q)
    || /\b(riskiest|weakest|most vulnerable|most exposed|most critical)\b/.test(q)

  // Prioritization — "what/where should I ... first / start with / next"
  if (/\b(what|which|where)\b.{0,40}\b(first|start|begin|prioriti|next)\b/.test(q)
    || /\bprioriti[sz]/.test(q)
    || /\bwhat should i (do|migrate|fix|remediate)\b/.test(q)
    || /\bwhere (do|should) i (start|begin)\b/.test(q)
    || isRanking) {
    return {
      kind: 'prioritization',
      objective: isRanking
        ? 'You want your most vulnerable assets identified and ranked — which ones are most at risk, why they rank that way, and what to do about them.'
        : 'You want to know what to tackle first — a risk-and-dependency-based prioritization, with the reasoning behind the order.',
      investigate: true,
    }
  }

  // Gap analysis — "why can't I certify / why not certified / what's blocking"
  if ((/\bwhy\b.{0,30}\b(can'?t|cannot|haven'?t|not|no)\b/.test(q) && isCertContext)
    || /\bwhat('?s| is) blocking\b/.test(q)
    || /\b(certif\w*)\b.{0,20}\b(fail|block|gap|eligib|denied|reject)\b/.test(q)
    || /\bwhy (is|are).{0,30}\b(fail|block)/.test(q)) {
    return { kind: 'gap_analysis', objective: 'You want a gap analysis — the specific blockers standing between your current posture and the goal, with the fastest path to close them.', investigate: true }
  }

  // Explain — "why is X high risk / explain / how does / what does ... mean"
  if (/\bwhy (is|are|does|do)\b/.test(q)
    || /\bexplain\b/.test(q)
    || /\bwhat (does|is|are)\b.{0,40}\b(mean|risk|risky|expos|vulnerab)\b/.test(q)
    || /\bhelp me understand\b/.test(q)) {
    return { kind: 'explain', objective: 'You want the reasoning explained — why this is the case, what drives it, and what it means for security, business and compliance.', investigate: true }
  }

  // Guidance — "how do/can/should I ..." (migrate, fix, remediate, secure, reduce)
  if (/\bhow (do|can|should|would|might) (i|we|you)\b/.test(q)
    || /\bhow to\b/.test(q)
    || /\bguide me\b|\bwalk me through\b|\bhelp me (migrate|fix|remediate|secure|plan)\b/.test(q)
    || (/\bhow\b/.test(q) && isMigrationContext)) {
    const objective = isMigrationContext
      ? 'You want migration guidance — a dependency-safe, prioritized strategy for how to move to post-quantum cryptography, not just a status number.'
      : 'You want actionable guidance — the recommended approach, in order, with the reasoning and what to watch out for.'
    return { kind: 'guidance', objective, investigate: true }
  }

  // Executive readiness — "am I quantum ready / overall posture / summarize"
  if (/\bam i\b.{0,20}\bready\b/.test(q)
    || /\b(quantum )?readiness\b/.test(q)
    || /\boverall (posture|readiness|state|status)\b/.test(q)
    || /\bexecutive (summary|overview|briefing)\b/.test(q)
    || /\bsummar[iy]/.test(q)
    || intents.includes('executive_dashboard')) {
    return { kind: 'executive', objective: 'You want an executive readiness assessment — where you stand, the key drivers, the business risk, and what to do next, in plain language.', investigate: true }
  }

  // Otherwise a focused status/lookup question (direct mode).
  return { kind: 'status', objective: 'You want a focused status readout for a specific area.', investigate: false }
}

/* ------------------------------------------------------------------ */
/* Cryptographic entity understanding                                   */
/*                                                                      */
/* An algorithm is an ENTITY, not an asset name. "Which systems use     */
/* RSA?" previously became `name ILIKE '%rsa%'` over the assets table,  */
/* which matches an asset literally named "rsa" and nothing else, so    */
/* the answer was always "0 assets match". Algorithms are therefore     */
/* lifted OUT of the name filter and resolved against the cryptographic */
/* inventory, where they actually live.                                 */
/* ------------------------------------------------------------------ */

/**
 * Question vocabulary → canonical algorithm family. Patterns are token-anchored
 * for the same reason `algorithmFamily()` is: a loose substring let "OpenSSL"
 * register as SSL and matched "DSA" inside "ECDSA"/"ML-DSA". Order matters —
 * the most specific family must be tested first.
 */
const ALGORITHM_QUESTION_PATTERNS: Array<{ family: AlgorithmFamily; pattern: RegExp }> = [
  { family: 'ml-kem', pattern: /\bml[-\s]?kem\b|\bkyber\b/i },
  { family: 'ml-dsa', pattern: /\bml[-\s]?dsa\b|\bdilithium\b/i },
  { family: 'slh-dsa', pattern: /\bslh[-\s]?dsa\b|\bsphincs\b/i },
  { family: 'hybrid', pattern: /\bhybrid\b|\bx25519[-+\s]?ml[-\s]?kem\b/i },
  { family: 'md5', pattern: /\bmd5\b/i },
  { family: 'sha1', pattern: /\bsha[-\s]?1\b/i },
  { family: 'sha3', pattern: /\bsha[-\s]?3\b|\bshake(128|256)?\b/i },
  { family: 'sha2', pattern: /\bsha[-\s]?(224|256|384|512)\b|\bsha[-\s]?2\b/i },
  { family: 'rc4', pattern: /\brc4\b|\barcfour\b/i },
  { family: '3des', pattern: /\b3des\b|\btriple[-\s]?des\b/i },
  { family: 'des', pattern: /\bdes\b/i },
  { family: 'aes', pattern: /\baes\b/i },
  { family: 'chacha', pattern: /\bchacha20?\b|\bpoly1305\b/i },
  { family: 'ecdsa', pattern: /\becdsa\b|\bed25519\b|\bed448\b|\beddsa\b/i },
  { family: 'ecdh', pattern: /\becdhe?\b|\bx25519\b|\bx448\b|\bp-?(256|384|521)\b|\bsecp\d+r1\b/i },
  { family: 'rsa', pattern: /\brsa\b/i },
  { family: 'dh', pattern: /\bdhe?\b|\bdiffie([-\s]?hellman)?\b/i },
  { family: 'dsa', pattern: /\bdsa\b/i },
]

/**
 * "ECC" and "elliptic curve" are umbrella terms covering both the signature
 * (ECDSA/EdDSA) and key-agreement (ECDH/X25519) families, so a question about
 * ECC must resolve to BOTH rather than arbitrarily picking one.
 */
const ALGORITHM_UMBRELLAS: Array<{ families: AlgorithmFamily[]; pattern: RegExp }> = [
  { families: ['ecdsa', 'ecdh'], pattern: /\becc\b|\belliptic([-\s]?curve)?\b/i },
  { families: ['ml-kem', 'ml-dsa', 'slh-dsa'], pattern: /\bpqc\b|\bpost[-\s]?quantum\b(?!\s+(readiness|ready))/i },
]

/**
 * Canonical algorithm families named by a question, most specific first.
 *
 * Matched text is CONSUMED as it is recognised, because the family names are
 * substrings of one another across a separator: `dsa` matches inside
 * "ML-DSA" (the hyphen is a word boundary), so testing every pattern against
 * the original text reported a question about ML-DSA as ALSO naming classical
 * DSA — and a post-quantum signature would have been counted as a
 * quantum-vulnerable one. Consuming "ML-DSA" before the `dsa` pattern runs is
 * the same most-specific-wins ordering `algorithmFamily()` gets from its
 * if/return chain.
 */
export function detectAlgorithmFamilies(question: string): AlgorithmFamily[] {
  let text = String(question || '')
  const found: AlgorithmFamily[] = []
  const add = (family: AlgorithmFamily) => { if (!found.includes(family)) found.push(family) }
  for (const { family, pattern } of ALGORITHM_QUESTION_PATTERNS) {
    const global = new RegExp(pattern.source, 'gi')
    if (global.test(text)) {
      add(family)
      // Blank the match so a broader pattern later in the list cannot re-match it.
      text = text.replace(new RegExp(pattern.source, 'gi'), ' ')
    }
  }
  for (const { families, pattern } of ALGORITHM_UMBRELLAS) {
    if (new RegExp(pattern.source, 'i').test(text)) families.forEach(add)
  }
  return found.slice(0, 6)
}

export function algorithmFamilyLabel(family: AlgorithmFamily): string {
  return ALGORITHM_FAMILY_LABEL[family] || family
}

/** Re-exported so the tools classify inventory rows with the SAME function. */
export { algorithmFamily }
export type { AlgorithmFamily }

/**
 * Does this text INVOLVE the given algorithm family at all?
 *
 * This is deliberately a different question from `algorithmFamily()`, which
 * answers "what is this string's ONE canonical family?" — the right question
 * for governance, and the wrong one for "which systems use RSA?".
 *
 * Two gaps make the single-family classifier unusable for matching:
 *
 *  1. It is anchored on `\bRSA\b`, so it does not see RSA in the forms a real
 *     certificate scan actually produces — `sha256WithRSAEncryption` (the
 *     standard X.509 signature name), `rsaEncryption`, `RSASSA-PSS`. Those
 *     classify as `unknown`, so an estate full of RSA certificates reported
 *     ZERO RSA components.
 *  2. For a composite string it must pick one family, and it picks by test
 *     order: `TLS_RSA_WITH_AES_128_CBC_SHA` is `aes` and
 *     `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` is `sha2`. Both genuinely
 *     involve RSA, and a user asking "where am I using RSA" wants them.
 *
 * Matching is still token-aware — `ssl` must not match "OpenSSL" and `dsa`
 * must not match "ECDSA" — but it accepts the concatenated OID-style spellings
 * that carry a family name as an internal token.
 */
const FAMILY_MATCHERS: Record<string, RegExp> = {
  // RSA in every spelling a scanner emits, including concatenated OID names.
  rsa: /\bRSA\b|RSAENCRYPTION|RSASSA|WITHRSA|\bRSAES\b|\bRSAPSS\b/,
  // ECDSA / EdDSA signatures.
  ecdsa: /\bECDSA\b|ECDSAWITH|\bED25519\b|\bED448\b|\bEDDSA\b/,
  // Elliptic-curve key agreement.
  ecdh: /\bECDHE?\b|\bX25519\b|\bX448\b|\bSECP\d+R1\b|\bPRIME256V1\b|\bP-?(256|384|521)\b|ECPUBLICKEY/,
  // Finite-field Diffie-Hellman only — must not swallow ECDH.
  dh: /(?<!EC)\bDHE?\b|\bDIFFIE\b/,
  // Classical DSA only — must not swallow ECDSA or ML-DSA.
  dsa: /(?<!EC)(?<!ML-)(?<!ML)(?<!SLH-)(?<!SLH)\bDSA\b/,
  'ml-kem': /\bML[-\s]?KEM\b|MLKEM|\bKYBER\b/,
  'ml-dsa': /\bML[-\s]?DSA\b|MLDSA|\bDILITHIUM\b/,
  'slh-dsa': /\bSLH[-\s]?DSA\b|SLHDSA|\bSPHINCS\b/,
  // A hybrid names BOTH a classical and a PQ component, e.g. X25519MLKEM768.
  hybrid: /\bHYBRID\b|X25519MLKEM|SECP\d+R1MLKEM|ED25519[-+]?ML[-\s]?DSA|X25519[-+]ML[-\s]?KEM/,
  aes: /\bAES\b/,
  chacha: /\bCHACHA20?\b|\bPOLY1305\b/,
  '3des': /\b3DES\b|TRIPLE[-\s]?DES|DES[-\s]?EDE3/,
  // Plain DES only — 3DES is a different algorithm with different guidance.
  des: /(?<!3)(?<!TRIPLE[-\s])(?<!EDE)\bDES\b/,
  rc4: /\bRC4\b|\bARCFOUR\b/,
  sha1: /\bSHA[-\s]?1\b|SHA1WITH|WITHSHA1\b/,
  sha2: /\bSHA[-\s]?(224|256|384|512)\b|SHA(224|256|384|512)WITH|WITHSHA(224|256|384|512)\b|\bSHA[-\s]?2\b/,
  sha3: /\bSHA[-\s]?3\b|\bSHA3-(224|256|384|512)\b|\bSHAKE(128|256)\b/,
  md5: /\bMD5\b|MD5WITH|WITHMD5\b/,
}

export function involvesAlgorithmFamily(text: unknown, family: AlgorithmFamily): boolean {
  if (family === 'unknown') return false
  const matcher = FAMILY_MATCHERS[family]
  if (!matcher) return false
  // Separators become spaces so `TLS_RSA_WITH_AES` tokenises, but the raw
  // concatenated form is ALSO tested so `sha256WithRSAEncryption` is seen.
  const raw = String(text || '').toUpperCase()
  const spaced = ` ${raw.replace(/[_+.]/g, ' ')} `
  return matcher.test(spaced) || matcher.test(raw)
}


/**
 * Which KIND of record the question is about. The platform counts assets,
 * cryptographic components, certificates, keys and findings separately and they
 * are NOT interchangeable — 4 assets carrying 178 components is not 178 assets.
 * Sophia must answer in the unit the user asked about.
 */
export type QueryEntity = 'asset' | 'component' | 'certificate' | 'key' | 'finding' | 'unspecified'

export function detectEntityKind(question: string): QueryEntity {
  const q = String(question || '')
  if (/\bcertificate(s)?\b|\bcert(s)?\b|\bx\.?509\b/i.test(q)) return 'certificate'
  if (/\bfinding(s)?\b|\bvulnerabilit(y|ies)\b|\bissue(s)?\b|\balert(s)?\b/i.test(q)) return 'finding'
  if (/\bkey(s)?\b|\bkeypair(s)?\b|\bkey material\b/i.test(q)) return 'key'
  if (/\bcomponent(s)?\b|\bcbom\b|\blibrar(y|ies)\b|\bdependenc(y|ies)\b/i.test(q)) return 'component'
  if (/\basset(s)?\b|\bsystem(s)?\b|\bserver(s)?\b|\bhost(s)?\b|\bapplication(s)?\b|\bendpoint(s)?\b|\bservice(s)?\b|\bworkload(s)?\b|\bmachine(s)?\b|\bdatabase(s)?\b|\bcluster(s)?\b|\bgateway(s)?\b|\bapi(s)?\b|\bwebsite(s)?\b|\bdomain(s)?\b/i.test(q)) return 'asset'
  return 'unspecified'
}

/**
 * Terms that are never a useful asset-name/type/environment filter.
 *
 * Two classes live here:
 *   1. question and sentence scaffolding ("show", "which", "still", "use");
 *   2. platform-generic vocabulary that matches everything and therefore
 *      filters nothing ("asset", "system", "crypto", "posture").
 *
 * "Show my most vulnerable assets" must never become
 * `name ILIKE '%show my most vulnerable assets%'` — that literal search
 * returned 0 rows and produced the "0 asset(s) match" answer that contradicted
 * the live risk evidence sitting right next to it.
 */
const FILTER_STOPWORDS = new Set([
  // question/verb scaffolding
  'show', 'list', 'display', 'find', 'search', 'give', 'tell', 'get', 'see', 'want', 'need', 'needs', 'know',
  'what', 'which', 'where', 'when', 'why', 'how', 'who', 'whose', 'whom',
  'are', 'is', 'was', 'were', 'be', 'been', 'being', 'am',
  'do', 'does', 'did', 'have', 'has', 'had', 'can', 'could', 'should', 'would', 'will', 'may', 'might', 'must',
  'please', 'kindly', 'me', 'my', 'our', 'your', 'their', 'his', 'her', 'its',
  'i', 'we', 'you', 'they', 'it', 'this', 'that', 'these', 'those', 'them',
  'the', 'a', 'an', 'and', 'or', 'not', 'no', 'of', 'in', 'on', 'at', 'for', 'to', 'from', 'with', 'about', 'into', 'over', 'under', 'by', 'as', 'than', 'then', 'still', 'yet', 'also', 'just', 'only',
  'all', 'any', 'some', 'many', 'much', 'more', 'most', 'least', 'less', 'few', 'each', 'every', 'other', 'both', 'either', 'neither',
  'now', 'currently', 'today', 'here', 'there', 'out', 'up', 'down', 'left', 'remaining', 'remain', 'remains',
  // generic predicates — describe a relation, never identify a record
  'use', 'uses', 'used', 'using', 'run', 'runs', 'running', 'ran',
  'own', 'owns', 'owned', 'owner', 'owners', 'ownership', 'responsible',
  'support', 'supports', 'supported', 'supporting', 'enable', 'enabled', 'configure', 'configured',
  'affect', 'affects', 'affected', 'impact', 'impacts', 'impacted', 'contain', 'contains', 'containing',
  'deploy', 'deployed', 'install', 'installed', 'depend', 'depends', 'require', 'requires', 'required',
  'migrate', 'migrated', 'migrating', 'migration', 'fix', 'fixed', 'remediate', 'remediated',
  // ranking / severity vocabulary (drives objective + args, never a text filter)
  'top', 'highest', 'lowest', 'worst', 'best', 'biggest', 'greatest', 'largest', 'riskiest', 'weakest', 'oldest', 'newest',
  'vulnerable', 'vulnerability', 'vulnerabilities', 'risk', 'risks', 'risky', 'critical', 'severe', 'high', 'medium', 'low', 'weak', 'strong', 'insecure', 'secure',
  'exposed', 'exposure', 'external', 'internal', 'internet-facing', 'public-facing', 'facing', 'public', 'private',
  // platform-generic vocabulary (matches everything, filters nothing)
  'asset', 'assets', 'system', 'systems', 'inventory', 'quantum', 'crypto', 'cryptographic', 'cryptography', 'pqc',
  'component', 'components', 'finding', 'findings', 'algorithm', 'algorithms', 'certificate', 'certificates', 'cert', 'certs',
  'key', 'keys', 'library', 'libraries', 'dependency', 'dependencies', 'cbom', 'scan', 'scans', 'endpoint', 'endpoints',
  'status', 'state', 'posture', 'overview', 'summary', 'report', 'data', 'info', 'information', 'details', 'detail', 'result', 'results',
])

/**
 * A token that looks like a concrete identifier rather than a common word —
 * a hostname (`api.prod.example.com`), a hyphenated service name (`web-01`),
 * or anything carrying digits. These are ranked ABOVE bare words because they
 * are what actually narrows an inventory.
 */
function selectivityScore(token: string): number {
  let score = 0
  if (token.includes('.')) score += 4       // hostname / FQDN
  if (token.includes('-') || token.includes('_')) score += 3 // service-name convention
  if (/\d/.test(token)) score += 2         // instance numbering
  if (token.length >= 8) score += 1         // long words are rarely generic
  return score
}

export interface QueryFilter {
  /** Asset name/type/environment tokens ONLY — never an algorithm. */
  query: string
  /** Canonical algorithm families the question named. */
  algorithms: AlgorithmFamily[]
  /** Human labels for the detected families, for the answer text. */
  algorithmLabels: string[]
  internetFacing: boolean
  criticality: string
  /** The question asked who is responsible ("who owns them?"). */
  wantsOwner: boolean
  /** The record kind the user asked about. */
  entity: QueryEntity
}

/**
 * Parse a natural-language question into the structured filter the tools take.
 *
 * Ordering is deliberate: algorithm terms are consumed FIRST and removed from
 * the free-text pool, so "Which internet-facing systems still use RSA and who
 * owns them?" yields `{ algorithms: ['rsa'], internetFacing: true,
 * wantsOwner: true, query: '' }` — not the nonsense name filter
 * "system still use" that dropped RSA entirely and matched nothing.
 */
export function extractQueryFilter(question: string): QueryFilter {
  const raw = String(question || '')
  const algorithms = detectAlgorithmFamilies(raw)

  // Remove every algorithm term from the text before name-token extraction, so
  // an algorithm can never leak into an asset-name ILIKE.
  let residual = raw.toLowerCase()
  for (const { pattern } of ALGORITHM_QUESTION_PATTERNS) residual = residual.replace(new RegExp(pattern.source, 'gi'), ' ')
  for (const { pattern } of ALGORITHM_UMBRELLAS) residual = residual.replace(new RegExp(pattern.source, 'gi'), ' ')

  const tokens = residual
    .replace(/[^a-z0-9._\- ]+/g, ' ')
    .split(/\s+/)
    .map((t) => t.replace(/^[._-]+|[._-]+$/g, ''))
    .filter((t) => t.length >= 2 && !FILTER_STOPWORDS.has(t))
    // A trailing plural never hurts an ILIKE substring match — strip it so
    // "servers" still matches type "server".
    .map((t) => (t.length > 3 && t.endsWith('s') && !t.endsWith('ss') ? t.slice(0, -1) : t))
    .filter((t) => !FILTER_STOPWORDS.has(t))

  // Rank by selectivity, NOT by position. Taking the first three tokens in
  // sentence order is what dropped "rsa" (the only discriminating term) from
  // "...systems still use RSA..." while keeping "system still use".
  const ranked = [...new Set(tokens)].sort((a, b) => selectivityScore(b) - selectivityScore(a))

  return {
    query: ranked.slice(0, 3).join(' '),
    algorithms,
    algorithmLabels: algorithms.map(algorithmFamilyLabel),
    internetFacing: /internet[- ]facing|public[- ]facing|externally exposed|public internet|edge[- ]facing/i.test(raw),
    criticality: /\bcritical\b/i.test(raw) ? 'critical' : '',
    wantsOwner: /\bwho owns\b|\bowner(s)?\b|\bownership\b|\bwho (is |are )?responsible\b|\bwhose\b|\bwho manages\b|\bteam\b/i.test(raw),
    entity: detectEntityKind(raw),
  }
}

/**
 * Back-compatible string form — the asset name/type/environment filter only.
 * Prefer `extractQueryFilter` for anything that needs the algorithm entities.
 */
export function extractAssetFilter(question: string): string {
  return extractQueryFilter(question).query
}

/**
 * Question expansion — the related sub-topics a thorough consultant would also
 * examine when answering this question. Surfaced in Sophia's reasoning trace so
 * the investigation is transparent. Pure/heuristic.
 */
export function expandQuestion(question: string, intents: CopilotIntent[]): string[] {
  const topics = new Set<string>()
  const add = (...t: string[]) => t.forEach((x) => topics.add(x))
  const q = String(question || '').toLowerCase()

  if (intents.includes('migration_status') || /migrat/.test(q)) {
    add('current migration progress & stage', 'quantum-vulnerable assets & CBOM', 'internet-facing exposure', 'certificate & PKI trust chains', 'dependency blast radius', 'pre-migration snapshots & rollback', 'failed jobs & blockers')
  }
  if (intents.includes('prioritization' as CopilotIntent) || /first|priorit|most vulnerable|riskiest|top risk|highest risk|most at risk/.test(q)) {
    add('per-asset risk scores', 'blast radius & single points of failure', 'Harvest-Now exposure', 'internet-facing paths')
  }
  if (intents.includes('certification') || /certif/.test(q)) {
    add('certification eligibility criteria', 'unmet requirements', 'remediation readiness ladder', 'evidence coverage')
  }
  if (intents.includes('risk_analysis') || /risk/.test(q)) {
    add('risk drivers & distribution', 'exposure graph & trust chains', 'HNDL exposure', 'weak-crypto hubs')
  }
  if (intents.includes('quantum_readiness') || /ready|readiness/.test(q)) {
    add('readiness score & drivers', 'PQC adoption', 'vulnerable components', 'migration progress', 'certification gaps')
  }
  if (intents.includes('compliance') || /complian|nist|fips|cnsa|iso/.test(q)) {
    add('framework alignment', 'CNSA 2.0 transition', 'NIST PQC algorithm adoption')
  }
  if (intents.includes('pki') || /cert|pki|tls/.test(q)) {
    add('certificate expiry & weak algorithms', 'issuing authorities', 'trust-chain integrity')
  }
  // Always correlate operational health so proactive findings surface.
  add('collector & agent health', 'connector status')
  return [...topics].slice(0, 10)
}

/* ------------------------------------------------------------------ */
/* Prompt-injection protection                                         */
/* ------------------------------------------------------------------ */

export interface SanitizeResult {
  text: string
  blocked: boolean
  reasons: string[]
}

const INJECTION_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /ignore (all|any|previous|prior|the above|earlier) (instructions?|rules?|prompts?)/i, reason: 'instruction-override attempt' },
  { pattern: /disregard (your|the|all) (instructions?|rules?|guardrails?|polic(y|ies))/i, reason: 'instruction-override attempt' },
  { pattern: /\b(system|developer) prompt\b/i, reason: 'system-prompt probing' },
  { pattern: /reveal (your|the) (instructions?|prompt|configuration|secrets?)/i, reason: 'system-prompt probing' },
  // Cross-tenant probing: another/other/different/every/each/all/someone-else's
  // + up to two intervening words + a tenant-ish noun. "my organization's data"
  // is intentionally NOT matched (no cross-tenant qualifier).
  { pattern: /\b(other|another|different|every|each|all|someone else'?s?|somebody else'?s?|a different)\s+(\w+\s+){0,2}(tenant|customer|organization|org|client|company|account|user)s?\b/i, reason: 'cross-tenant access attempt' },
  { pattern: /\b(cross|inter)[- ]?tenant\b/i, reason: 'cross-tenant access attempt' },
  { pattern: /\b(service[- _]?role|api[- _]?key|secret[- _]?key|access[- _]?token|password)s?\b.{0,40}\b(show|reveal|print|dump|expose|give)\b/i, reason: 'secret-exposure attempt' },
  { pattern: /\b(show|reveal|print|dump|expose|give|leak)\b.{0,40}\b(service[- _]?role|api[- _]?key|secret[- _]?key|credential|password)s?\b/i, reason: 'secret-exposure attempt' },
  { pattern: /\b(select|insert|update|delete|drop|alter|truncate)\b.{0,50}\b(from|into|table)\b/i, reason: 'raw SQL attempt' },
  { pattern: /\byou are now\b|\bpretend (to be|you are)\b|\bact as (?!a security)/i, reason: 'role-hijack attempt' },
]

export function sanitizePrompt(raw: string): SanitizeResult {
  const reasons: string[] = []
  let text = String(raw || '')
    // Strip control characters and zero-width/invisible unicode used to smuggle instructions.
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u2028\u2029\u202A-\u202E\uFEFF]/g, '')
    .trim()

  if (text.length > 2000) {
    text = text.slice(0, 2000)
    reasons.push('truncated to 2000 characters')
  }

  let blocked = false
  for (const { pattern, reason } of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      blocked = true
      if (!reasons.includes(reason)) reasons.push(reason)
    }
  }

  return { text, blocked, reasons }
}

/* ------------------------------------------------------------------ */
/* Suggested questions                                                 */
/* ------------------------------------------------------------------ */

const GLOBAL_SUGGESTIONS: CopilotSuggestion[] = [
  { text: 'Am I quantum ready?', intent: 'quantum_readiness' },
  { text: 'Show my most vulnerable assets.', intent: 'asset_status' },
  { text: 'What is pending remediation?', intent: 'remediation' },
  { text: 'What should I migrate first?', intent: 'migration_status' },
  { text: 'Why has certification not been achieved?', intent: 'certification' },
  { text: 'What is my Harvest Now exposure?', intent: 'harvest_now' },
  { text: 'Summarize my compliance posture.', intent: 'compliance' },
  { text: 'Which certificates are expiring or weak?', intent: 'pki' },
  { text: 'Show the blast radius of my riskiest asset.', intent: 'risk_analysis' },
  { text: 'Are my collectors and agents healthy?', intent: 'telemetry' },
  { text: 'Generate an executive summary.', intent: 'executive_dashboard' },
]

const PAGE_SUGGESTIONS: Array<{ prefix: string; suggestions: CopilotSuggestion[] }> = [
  {
    prefix: '/dashboard/scanner',
    suggestions: [
      { text: 'Summarize my latest scan findings.', intent: 'scanner' },
      { text: 'Which findings are critical and why?', intent: 'scanner' },
      { text: 'Which discovered algorithms are quantum-vulnerable?', intent: 'cbom' },
    ],
  },
  {
    prefix: '/dashboard/assets',
    suggestions: [
      { text: 'Which assets are internet-facing?', intent: 'asset_status' },
      { text: 'Which assets carry the most cryptographic risk?', intent: 'asset_status' },
      { text: 'Show asset dependencies and relationships.', intent: 'exposure_graph' },
    ],
  },
  {
    prefix: '/dashboard/quantum-readiness',
    suggestions: [
      { text: 'Explain my quantum readiness score.', intent: 'quantum_readiness' },
      { text: 'What is blocking a higher readiness level?', intent: 'quantum_readiness' },
      { text: 'Show my top risk assets.', intent: 'risk_analysis' },
    ],
  },
  {
    prefix: '/dashboard/quantum-certification',
    suggestions: [
      { text: 'Am I eligible for Quantum Trust Certification?', intent: 'certification' },
      { text: 'What is blocking certification?', intent: 'certification' },
      { text: 'How do I reach the next certification level?', intent: 'certification' },
    ],
  },
  {
    prefix: '/dashboard/live-migration',
    suggestions: [
      { text: 'Show active and failed migrations.', intent: 'migration_status' },
      { text: 'Do I have snapshots to roll back to?', intent: 'snapshots_rollback' },
      { text: 'What should I migrate next?', intent: 'migration_status' },
    ],
  },
  {
    prefix: '/dashboard/harvest-now',
    suggestions: [
      { text: 'How much of my data is future-decryptable?', intent: 'harvest_now' },
      { text: 'Which endpoints lack forward secrecy?', intent: 'harvest_now' },
      { text: 'What reduces my HNDL exposure fastest?', intent: 'harvest_now' },
    ],
  },
  {
    prefix: '/dashboard/pki-visibility',
    suggestions: [
      { text: 'Which certificates are quantum-vulnerable?', intent: 'pki' },
      { text: 'Show expiring certificates.', intent: 'pki' },
      { text: 'Which issuers anchor my trust chains?', intent: 'pki' },
    ],
  },
  {
    prefix: '/dashboard/migration-planner',
    suggestions: [
      { text: 'Walk me through my migration plan.', intent: 'migration_status' },
      { text: 'What are the migration blockers?', intent: 'migration_status' },
      { text: 'Estimate the migration effort.', intent: 'executive_dashboard' },
    ],
  },
]

export function suggestionsForPage(page: string | undefined): CopilotSuggestion[] {
  const path = String(page || '')
  const match = PAGE_SUGGESTIONS
    .filter((entry) => path.startsWith(entry.prefix))
    .sort((a, b) => b.prefix.length - a.prefix.length)[0]
  const pageSuggestions = match?.suggestions || []
  const merged = [...pageSuggestions]
  for (const suggestion of GLOBAL_SUGGESTIONS) {
    if (merged.length >= 8) break
    if (!merged.some((s) => s.text === suggestion.text)) merged.push(suggestion)
  }
  return merged
}
