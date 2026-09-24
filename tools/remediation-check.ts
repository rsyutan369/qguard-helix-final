/**
 * Offline verification for the Intelligent Quantum Remediation Engine™ (Q-REMEDY).
 *
 * Drives the pure engine functions with synthetic-but-realistic evidence and asserts:
 *  - domain classification maps findings to the right NIST-aligned playbooks
 *  - the Certification Readiness Score is bounded, continuous and monotonic,
 *    and reaches exactly 100% when every required criterion is met
 *  - applyImpact floors at zero, raises PQC adoption and never raises risk
 *  - the projection ladder is monotonically non-decreasing and starts at the
 *    live score; ranks are sequential; queues partition the action set
 *  - evidence honesty: an empty estate produces no fabricated actions
 *  - PQC terminology: ML-KEM is never presented as a signature algorithm
 *
 * No server or Supabase required:  npx tsx tools/remediation-check.ts
 */
import {
  applyImpact,
  buildRemediationPlan,
  classifyDomain,
  computeCertificationReadiness,
  REMEDIATION_PLAYBOOKS,
  type CriteriaMeasures,
  type RemediationEvidence,
} from '../src/api-server/quantum-remediation'
import { DEFAULT_POLICY } from '../src/api-server/quantum-certification'
import type { EligibilityResult } from '../src/types/quantum-certification'
import type { RemediationImpact } from '../src/types/quantum-remediation'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const NO_IMPACT: RemediationImpact = {
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
}

/* ------------------------------------------------------------------ */
/* Synthetic measures                                                  */
/* ------------------------------------------------------------------ */
const VULNERABLE: CriteriaMeasures = {
  readiness: 44,
  quantumRisk: 66,
  hndl: 62,
  residualRisk: 55,
  confidence: 72,
  pqcAdoption: 28,
  critical: 5,
  high: 10,
  medium: 8,
  low: 4,
  vulnerableComponents: 20,
  pqcReadyComponents: 8,
  totalComponents: 40,
  disallowedCount: 6,
  expiredCertificates: 2,
  validationPass: true,
  runtimeMeasured: false,
  runtimeFresh: false,
}

const CERTIFIED: CriteriaMeasures = {
  readiness: 94,
  quantumRisk: 12,
  hndl: 14,
  residualRisk: 18,
  confidence: 97,
  pqcAdoption: 92,
  critical: 0,
  high: 0,
  medium: 1,
  low: 2,
  vulnerableComponents: 0,
  pqcReadyComponents: 158,
  totalComponents: 160,
  disallowedCount: 0,
  expiredCertificates: 0,
  validationPass: true,
  runtimeMeasured: true,
  runtimeFresh: true,
}

function eligibilityStub(eligible: boolean): EligibilityResult {
  const ids = ['readiness', 'critical-vulns', 'hndl', 'residual-risk', 'confidence', 'pqc-adoption', 'disallowed-algorithms', 'vulnerable-components', 'expired-certificates', 'validation']
  return {
    eligible,
    // Evidence exists in this fixture, so a baseline attestation is issuable
    // whether or not the certification criteria pass.
    issuable: true,
    evaluatedAt: new Date().toISOString(),
    hasData: true,
    requiredTotal: 10,
    requiredMet: eligible ? 10 : 3,
    trustScore: eligible ? 940 : 430,
    level: eligible ? 'gold' : null,
    levelLabel: eligible ? 'Enterprise Quantum Secure' : 'Not Eligible',
    checks: ids.map((id) => ({
      id,
      criterion: id,
      required: 'threshold',
      actual: 'measured',
      met: eligible,
      severity: 'required' as const,
      evidence: 'synthetic',
      remediation: `Resolve ${id} via the platform workflow.`,
    })),
    recommendations: [],
    policy: DEFAULT_POLICY,
  }
}

function makeEvidence(kind: 'vulnerable' | 'certified' | 'empty'): RemediationEvidence {
  const measures = kind === 'certified' ? CERTIFIED : kind === 'empty' ? { ...VULNERABLE, critical: 0, high: 0, medium: 0, low: 0, vulnerableComponents: 0, totalComponents: 0 } : VULNERABLE
  return {
    hasData: kind !== 'empty',
    generatedAt: new Date().toISOString(),
    policy: DEFAULT_POLICY,
    eligibility: eligibilityStub(kind === 'certified'),
    measures,
    scores: { quantumReadiness: measures.readiness, quantumRisk: measures.quantumRisk, hndlRisk: measures.hndl, pqcAdoption: measures.pqcAdoption, migrationComplexity: 42 },
    trustScore: kind === 'certified' ? 940 : 430,
    levelLabel: kind === 'certified' ? 'Enterprise Quantum Secure' : 'Not Eligible',
    parallelWorkstreams: 2,
    readinessTrend: [],
    disallowedAlgorithms: DEFAULT_POLICY.disallowedAlgorithms,
    missingEvidenceSources: kind === 'vulnerable'
      ? [
          { id: 'runtime-telemetry', label: 'Runtime Cryptographic Intelligence', route: '/dashboard/runtime-crypto' },
          { id: 'cloud-connectors', label: 'Cloud Connectors', route: '/dashboard/settings' },
        ]
      : [],
    validationPass: true,
    cryptoAgilityActive: kind === 'certified',
    assets: kind === 'vulnerable'
      ? [
          {
            id: 'a-web',
            name: 'web-server-01',
            type: 'web server',
            environment: 'production-dmz',
            owner: 'Platform Team',
            criticality: 'critical',
            internetFacing: true,
            riskScore: 88,
            pqcCapable: true,
            vendorParty: false,
            vulnerabilities: [
              { id: 'v1', name: 'TLS RSA cipher', itemType: 'TLS Cipher Suite', algorithm: 'RSA-2048', protocol: 'TLS 1.2', severity: 'critical', instances: 4, description: 'RSA key exchange observed' },
              { id: 'v2', name: 'ECDH key exchange', itemType: 'Key Exchange', algorithm: 'ECDH-P256', protocol: 'TLS 1.2', severity: 'high', instances: 2, description: 'Classical ECDH' },
            ],
          },
          {
            id: 'a-db',
            name: 'db-server-01',
            type: 'database',
            environment: 'production',
            owner: 'Data Team',
            criticality: 'high',
            internetFacing: false,
            riskScore: 71,
            pqcCapable: true,
            vendorParty: false,
            vulnerabilities: [
              { id: 'v3', name: 'Storage encryption key', itemType: 'Encryption Key', algorithm: 'RSA-4096', protocol: '', severity: 'high', instances: 1, description: 'Long-lived RSA wrapping key' },
            ],
          },
          {
            id: 'a-vendor',
            name: 'Acme SaaS Gateway',
            type: 'saas',
            environment: 'external',
            owner: 'Procurement',
            criticality: 'medium',
            internetFacing: true,
            riskScore: 55,
            pqcCapable: false,
            vendorParty: true,
            vulnerabilities: [
              { id: 'v4', name: 'Legacy TLS', itemType: 'TLS Protocol', algorithm: 'TLS 1.1', protocol: 'TLS 1.1', severity: 'medium', instances: 1, description: 'Deprecated protocol version' },
            ],
          },
        ]
      : [],
    relationships: kind === 'vulnerable' ? [{ source: 'a-web', target: 'a-db', type: 'depends-on' }] : [],
    expiredCertsByAsset: new Map(kind === 'vulnerable' ? [['a-web', 1]] : []),
    unlinkedExpiredCerts: kind === 'vulnerable' ? 1 : 0,
    migrationJobs: kind === 'vulnerable'
      ? [
          { id: 'job-1', status: 'completed', assetId: 'a-db', jobType: 'tls-migration', updatedAt: new Date().toISOString() },
          { id: 'job-2', status: 'running', assetId: 'a-db', jobType: 'key-rotation', updatedAt: new Date().toISOString() },
        ]
      : [],
    assetNameById: new Map(kind === 'vulnerable' ? [['a-web', 'web-server-01'], ['a-db', 'db-server-01'], ['a-vendor', 'Acme SaaS Gateway']] : []),
  }
}

/* ------------------------------------------------------------------ */
console.log('\n[1] Domain classification → playbook mapping')
assert(classifyDomain({ category: 'TLS Cipher Suite', algorithm: 'RSA-2048', protocol: 'TLS 1.2', name: 'tls', assetType: 'web server' }) === 'tls', 'TLS cipher → tls')
assert(classifyDomain({ category: 'SSH Key Exchange', algorithm: 'ECDH', protocol: 'ssh', name: 'sshd', assetType: 'server' }) === 'ssh', 'SSH KEX → ssh')
assert(classifyDomain({ category: 'Certificate', algorithm: 'RSA-2048', protocol: '', name: 'x509 cert', assetType: 'server' }) === 'pki', 'X.509 → pki')
assert(classifyDomain({ category: 'IKE proposal', algorithm: 'DH-14', protocol: 'ipsec', name: 'vpn tunnel', assetType: 'gateway' }) === 'vpn', 'IPsec → vpn')
assert(classifyDomain({ category: 'Encryption Key', algorithm: 'RSA-4096', protocol: '', name: 'kms key', assetType: 'database' }) === 'key-management', 'KMS key → key-management')
assert(classifyDomain({ category: 'JWT signing', algorithm: 'ECDSA-P256', protocol: '', name: 'token issuer', assetType: 'service' }) === 'identity', 'JWT → identity')
assert(classifyDomain({ category: 'Storage', algorithm: 'RSA', protocol: '', name: 'backup archive', assetType: 'storage' }) === 'data-at-rest', 'backup → data-at-rest')
const domains = Object.keys(REMEDIATION_PLAYBOOKS)
assert(domains.length === 11 && domains.every((d) => REMEDIATION_PLAYBOOKS[d as keyof typeof REMEDIATION_PLAYBOOKS].steps.length >= 3 && REMEDIATION_PLAYBOOKS[d as keyof typeof REMEDIATION_PLAYBOOKS].standards.length > 0), 'all 11 playbooks have ≥3 steps + standards')

console.log('\n[2] PQC terminology guard (FIPS roles)')
assert(REMEDIATION_PLAYBOOKS.tls.targetState.includes('ML-KEM'), 'TLS target uses ML-KEM (key establishment)')
assert(REMEDIATION_PLAYBOOKS.identity.targetState.includes('ML-DSA') && !REMEDIATION_PLAYBOOKS.identity.targetState.includes('ML-KEM'), 'identity signing uses ML-DSA, never ML-KEM')
assert(REMEDIATION_PLAYBOOKS.pki.targetState.includes('ML-DSA'), 'PKI signing chain targets ML-DSA')

console.log('\n[3] Certification Readiness Score — bounded, continuous, monotone')
const vulnScore = computeCertificationReadiness(VULNERABLE, VULNERABLE, DEFAULT_POLICY)
const certScore = computeCertificationReadiness(CERTIFIED, CERTIFIED, DEFAULT_POLICY)
assert(certScore.pct === 100, 'fully compliant estate scores exactly 100%', `${certScore.pct}%`)
assert(vulnScore.pct > 0 && vulnScore.pct < 100, 'vulnerable estate scores strictly between 0 and 100', `${vulnScore.pct}%`)
assert(certScore.criteria.every((c) => c.met && c.progressPct === 100), 'all criteria met at 100% progress when compliant')
const improved = computeCertificationReadiness({ ...VULNERABLE, readiness: 80 }, VULNERABLE, DEFAULT_POLICY)
assert(improved.pct > vulnScore.pct, 'raising a measure raises the score (monotone)', `${vulnScore.pct}% → ${improved.pct}%`)

console.log('\n[4] applyImpact — floors, adoption, risk monotonicity')
const impact: RemediationImpact = { ...NO_IMPACT, criticalResolved: 3, highResolved: 2, vulnerableComponentsResolved: 6, pqcComponentsAdded: 6, disallowedAlgorithmsRetired: ['RSA'], expiredCertificatesRenewed: 1 }
const after = applyImpact(VULNERABLE, VULNERABLE, impact)
assert(after.critical === 2 && after.vulnerableComponents === 14 && after.expiredCertificates === 1, 'counts reduced correctly')
assert(after.pqcAdoption > VULNERABLE.pqcAdoption, 'PQC adoption increases', `${VULNERABLE.pqcAdoption} → ${after.pqcAdoption}`)
assert(after.quantumRisk <= VULNERABLE.quantumRisk, 'quantum risk never increases', `${VULNERABLE.quantumRisk} → ${after.quantumRisk}`)
assert(after.hndl <= VULNERABLE.hndl, 'HNDL never increases', `${VULNERABLE.hndl} → ${after.hndl}`)
assert(after.readiness >= VULNERABLE.readiness, 'readiness never decreases', `${VULNERABLE.readiness} → ${after.readiness}`)
const overkill = applyImpact(VULNERABLE, VULNERABLE, { ...NO_IMPACT, criticalResolved: 999, vulnerableComponentsResolved: 999, expiredCertificatesRenewed: 999 })
assert(overkill.critical === 0 && overkill.vulnerableComponents === 0 && overkill.expiredCertificates === 0, 'over-resolution floors at zero')
const runtimeOn = applyImpact(VULNERABLE, VULNERABLE, { ...NO_IMPACT, runtimeTelemetryConnected: true, confidenceGainPct: 12 })
assert(runtimeOn.runtimeMeasured && runtimeOn.confidence === 84, 'evidence action connects runtime + raises confidence')

console.log('\n[5] Full plan — ladder, ranks, queues, honesty')
const plan = buildRemediationPlan(makeEvidence('vulnerable'))
assert(plan.hasData, 'plan has data')
assert(plan.actions.length > 0, 'actions synthesized', `${plan.actions.length} actions`)
assert(plan.certificationReadinessPct === vulnScore.pct, 'plan score equals computed live score', `${plan.certificationReadinessPct}%`)
assert(plan.ladder.length >= 2 && plan.ladder[0].readinessPct === plan.certificationReadinessPct, 'ladder starts at the live score')
const monotone = plan.ladder.every((step, i) => i === 0 || step.readinessPct >= plan.ladder[i - 1].readinessPct)
assert(monotone, 'ladder is monotonically non-decreasing', plan.ladder.map((s) => `${s.readinessPct}%`).join(' → '))
assert(plan.actions.every((a, i) => a.rank === i + 1), 'ranks are sequential 1..n')
assert(plan.actions.every((a) => a.certificationGainPct >= 0), 'no negative marginal gains')
const queueSum = plan.queues.critical + plan.queues.high + plan.queues.medium + plan.queues.low
assert(queueSum === plan.actions.length, 'priority queues partition the action set', `${queueSum} == ${plan.actions.length}`)
assert(plan.quickWins.every((id) => plan.actions.some((a) => a.id === id)), 'quick wins reference real actions')
const webAction = plan.actions.find((a) => a.asset === 'web-server-01' && a.domain === 'tls')
assert(Boolean(webAction), 'internet-facing TLS action exists')
assert(webAction ? webAction.priority === 'critical' || webAction.priority === 'high' : false, 'critical internet-facing TLS lands in top queues', webAction?.priority)
assert(webAction ? webAction.blastRadius.dependencies.includes('db-server-01') : false, 'blast radius resolves dependency names')
assert(webAction ? webAction.standards.includes('FIPS 203') : false, 'TLS action cites FIPS 203')
const dbAction = plan.actions.find((a) => a.asset === 'db-server-01')
assert(dbAction ? dbAction.status === 'in_progress' : false, 'running migration job marks the asset in progress')
const vendorAction = plan.actions.find((a) => a.asset === 'Acme SaaS Gateway')
assert(vendorAction ? vendorAction.domain === 'vendor' : false, 'third-party asset routes to the vendor playbook')
assert(vendorAction ? plan.replacementsRequired.includes(vendorAction.id) : false, 'non-PQC-capable system flagged for replacement')
assert(plan.actions.some((a) => a.id.startsWith('estate:evidence-runtime-telemetry')), 'missing runtime telemetry becomes an evidence action')
assert(plan.advisor.length === 9, 'AI Quantum Advisor answers all 9 questions', `${plan.advisor.length}`)
assert(plan.requirements.length === 10 && plan.requirements.filter((r) => r.status === 'unmet').every((r) => r.businessImpact && r.technicalImpact && r.recommendedSolution), 'requirement gaps carry business/technical impact + solution')
assert(Boolean(plan.estimatedCertificationDate), 'estimated certification date derived from effort')
assert(plan.progress.recentlyFixed.length === 1 && plan.progress.recentlyFixed[0].source === 'migration_jobs', 'recently-fixed derives from real migration jobs only')
const lastLadder = plan.ladder[plan.ladder.length - 1]
assert(lastLadder.readinessPct > plan.certificationReadinessPct, 'projection strictly improves the score', `${plan.certificationReadinessPct}% → ${lastLadder.readinessPct}%`)

console.log('\n[6] Evidence honesty — empty estate fabricates nothing')
const empty = buildRemediationPlan(makeEvidence('empty'))
assert(!empty.hasData && empty.actions.length === 0 && empty.certificationReadinessPct === 0, 'empty estate → no actions, 0% score')
assert(empty.advisor.length === 1 && empty.advisor[0].route === '/dashboard/scanner', 'empty estate advisor routes to the scanner')

console.log('\n[7] Certified estate — 100% and eligible')
const certifiedPlan = buildRemediationPlan(makeEvidence('certified'))
assert(certifiedPlan.certificationReadinessPct === 100, 'certified estate scores 100%', `${certifiedPlan.certificationReadinessPct}%`)
assert(certifiedPlan.certificationEligible, 'certified estate reports eligible')
assert(certifiedPlan.actions.length === 0, 'no remediation actions when nothing is vulnerable')

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED ✓' : `${failures} CHECK(S) FAILED ✗`}\n`)
process.exit(failures === 0 ? 0 : 1)
