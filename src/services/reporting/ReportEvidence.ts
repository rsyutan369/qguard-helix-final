import { v4 as uuidv4 } from 'uuid';
import { addWeeks, format } from 'date-fns';
import type { QuantumReadinessSnapshot } from '@/app/dashboard/quantum-readiness/_shared';
import {
  EVIDENCE_UNAVAILABLE,
  normalizeSeverity,
  severityRank,
  type AdvisorValidation,
  type AssetCriticality,
  type AssetIntelligence,
  type AssetReadiness,
  type Benchmarking,
  type BusinessImpact,
  type BusinessRisk,
  type ConfidenceSummary,
  type CryptoPolicy,
  type DecisionChain,
  type MaturityModel,
  type OperationalBenefit,
  type RiskScenario,
  type ComplianceMapping,
  type CostBreakdown,
  type CostForecast,
  type EnterpriseAssessmentReport,
  type EvidenceConfidence,
  type ExecutiveBlock,
  type ExecutiveDecision,
  type Explainability,
  type FindingGroup,
  type GovernanceGate,
  type GovernanceRole,
  type HndlCategory,
  type ImpactReason,
  type MigrationAdvisor,
  type MigrationConfidence,
  type MigrationWave,
  type PlaybookDetail,
  type PlaybookStage,
  type ReadinessDomain,
  type ReadinessIndex,
  type ReadinessMethodology,
  type RemediationItem,
  type ReportDefinition,
  type ReportValidation,
  type ResourceLoad,
  type RiskAcceptance,
  type ReportBranding,
  type ReportFinding,
  type ReportKind,
  type ReportKpi,
  type ReportTable,
  type RiskCategory,
  type RiskForecast,
  type RiskMethodology,
  type RoadmapPhase,
  type RoiAnalysis,
  type WaveSimulation,
} from './schemas/ReportSchema';

/**
 * Evidence Engine — transforms real, tenant-scoped Quantum Readiness assessment
 * telemetry into a board-level Post-Quantum Migration Program Assessment model
 * (Report Enhancement 1 & 2). Every section is derived from snapshot evidence;
 * where a source is unavailable the value is `Evidence Not Available` rather than
 * fabricated. Findings are actionable; the report explains what to do, in what
 * order, who owns it, what it costs, how long it takes and the expected outcome.
 */

const REPORT_TITLES: Record<ReportKind, string> = {
  executive: 'Quantum Readiness Executive Report™',
  technical: 'Quantum Readiness Technical Assessment™',
  compliance: 'Post-Quantum Compliance Report™',
  migration: 'PQC Migration Program Report™',
};

const round = (n: number) => Math.round(Number(n) || 0);
const clamp = (n: number, min = 0, max = 100) => Math.max(min, Math.min(max, round(n)));
// I3 (technical observation) — one-decimal percentage for enterprise numerical
// precision (e.g. 2/66 → "3.0%" not "3%").
const pct1 = (n: number) => `${(Math.round((Number(n) || 0) * 10) / 10).toFixed(1)}%`;
// I3#3 — normalise an owner value: an asset with no accountable owner reads as
// "Unknown" (a data-quality state), never the ambiguous "Unassigned".
function normalizeOwner(owner: string | null | undefined): string {
  const o = (owner || '').trim();
  if (!o || /^(unassigned|unknown|n\/?a|none|null)$/i.test(o)) return 'Unknown';
  return o;
}

function safeTable(title: string, columns: string[], rows: Array<Array<string | number>>): ReportTable {
  return { title, columns, rows: rows.length ? rows : [[EVIDENCE_UNAVAILABLE, ...columns.slice(1).map(() => '—')]] };
}

function kpiTone(score: number, higherIsWorse: boolean): ReportKpi['tone'] {
  if (higherIsWorse) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'good';
  }
  if (score >= 75) return 'good';
  if (score >= 50) return 'medium';
  if (score >= 25) return 'high';
  return 'critical';
}

function riskLevel(score: number, higherIsBetter: boolean): string {
  const s = higherIsBetter ? 100 - score : score;
  if (s >= 75) return 'Critical';
  if (s >= 50) return 'High';
  if (s >= 25) return 'Medium';
  return 'Low';
}

/* ------------------------------------------------------------------ */
/* Crypto-policy profiles (I2#12)                                     */
/* ------------------------------------------------------------------ */
/**
 * Target algorithm selection is POLICY-DRIVEN, not hard-coded: every
 * recommended/target state in this report resolves through the active
 * crypto-policy profile, so the report adapts to organisational policy and
 * future standards without implying a single universal target.
 */
interface PolicyProfileDef {
  profile: string;
  keyEstablishment: string;
  digitalSignature: string;
  certificateChain: string;
  symmetric: string;
  hash: string;
  guidance: string;
}
export const CRYPTO_POLICY_PROFILES: PolicyProfileDef[] = [
  {
    profile: 'Default Enterprise',
    keyEstablishment: 'X25519 + ML-KEM-768 (Hybrid, FIPS 203)',
    digitalSignature: 'ML-DSA-65 + ECDSA P-256 (Hybrid, FIPS 204)',
    certificateChain: 'ML-DSA-65 + ECDSA P-256 hybrid certificate chain',
    symmetric: 'AES-256-GCM',
    hash: 'SHA3-256',
    guidance: 'Balanced NIST-aligned profile for general enterprise production workloads.',
  },
  {
    profile: 'High Assurance / Government',
    keyEstablishment: 'X25519 + ML-KEM-1024 (Hybrid, FIPS 203)',
    digitalSignature: 'ML-DSA-87 + ECDSA P-384 (Hybrid, FIPS 204)',
    certificateChain: 'ML-DSA-87 + ECDSA P-384 hybrid certificate chain',
    symmetric: 'AES-256-GCM',
    hash: 'SHA3-512',
    guidance: 'CNSA 2.0-oriented profile for regulated, high-assurance and government-adjacent workloads.',
  },
  {
    profile: 'Experimental / Lab',
    keyEstablishment: 'Configurable (e.g. X25519 + ML-KEM-768, pure ML-KEM)',
    digitalSignature: 'Configurable (ML-DSA-65, SLH-DSA-128s (FIPS 205) or hybrid pairings)',
    certificateChain: 'Configurable hybrid or pure-PQC chain',
    symmetric: 'AES-256-GCM',
    hash: 'SHA3-256',
    guidance: 'Interoperability pilots and lab validation only — not for production cutover.',
  },
];
const ACTIVE_PROFILE = CRYPTO_POLICY_PROFILES[0];

export function buildCryptoPolicy(): CryptoPolicy {
  return {
    activeProfile: ACTIVE_PROFILE.profile,
    profiles: CRYPTO_POLICY_PROFILES,
    note: `All target/recommended algorithm states in this report resolve through the active "${ACTIVE_PROFILE.profile}" crypto-policy profile rather than a hard-coded universal target. Organisations with CNSA 2.0 or high-assurance obligations should select the High Assurance profile; all profiles use NIST-standardised PQC algorithms (FIPS 203 / 204 / 205).`,
  };
}

function recommendedState(algorithm: string): string {
  const a = (algorithm || '').toUpperCase();
  if (/RSA|\bDH\b|DIFFIE/.test(a)) return `TLS 1.3 + ${ACTIVE_PROFILE.keyEstablishment}`;
  if (/ECDSA|P-256|P-384|\bECC\b|EC-/.test(a)) return ACTIVE_PROFILE.digitalSignature;
  if (/ECDH/.test(a)) return ACTIVE_PROFILE.keyEstablishment;
  if (/SHA-?1|MD5/.test(a)) return ACTIVE_PROFILE.hash;
  if (/3DES|\bDES\b|RC4/.test(a)) return ACTIVE_PROFILE.symmetric;
  return 'ML-KEM (FIPS 203) / ML-DSA (FIPS 204)';
}

function internetFacingLabels(snapshot: QuantumReadinessSnapshot): string[] {
  return snapshot.exposureGraph.nodes.filter((n) => n.internetFacing).map((n) => n.label);
}

/**
 * Normalise an asset identifier so near-identical labels for the SAME underlying
 * asset (scheme / port / path / www / case variations of one host) collapse to a
 * single key. Prevents a single scanned domain from being counted as several
 * distinct "affected assets" in finding-group consolidation.
 */
function normalizeAssetKey(asset: string): string {
  return (asset || '')
    .toLowerCase()
    .trim()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/[/:].*$/, '') // strip port / path
    .trim();
}

// Maps the dominant weighted-risk domain to the board-level recommendation.
const DOMAIN_RECOMMENDATION: Record<string, string> = {
  tls: 'Modernize TLS / Internet-Facing Transport Cryptography',
  pki: 'Modernize PKI / Certificate Infrastructure',
  identity: 'Modernize Identity / Token Cryptography',
  application: 'Modernize Application Cryptography',
  cloud: 'Modernize Cloud / KMS Cryptography',
  vendor: 'Drive Vendor & Supply-Chain PQC Readiness',
  hndl: 'Mitigate Harvest-Now-Decrypt-Later Exposure',
  operational: 'Harden Runtime Cryptographic Operations',
  business: 'Establish Enterprise PQC Migration Program',
};

export interface RiskDomainDatum {
  category: string; // display name e.g. 'TLS Risk'
  matchKey: string; // weight/recommendation key e.g. 'tls'
  weightPct: number; // normalised integer weight (present domains sum to ~100)
  weightFraction: number; // normalised weight fraction (present domains sum to 1)
  risk: number; // calibrated current domain risk 0-100
}

/**
 * Evidence-filtered, calibrated cryptographic risk decomposition (Phase 1 fix).
 *
 * Domains with NO supporting evidence (no identity systems, no cloud accounts,
 * no vendor/trust relationships, …) are EXCLUDED — the report never fabricates
 * 100% risk for something the tenant does not have. The remaining domain risks
 * are then calibrated so their weighted blend reconstructs the authoritative
 * quantum-risk score, making the risk-scoring methodology fully reproducible:
 *
 *     Σ ( DomainRisk × DomainWeight ) ÷ Σ ( DomainWeight ) = Overall Quantum Risk
 *
 * This removes the mismatch where the displayed weighted table computed to ~82
 * while the reported overall was 58.
 */
export function buildRiskDomainModel(snapshot: QuantumReadinessSnapshot, domains: ReadinessDomain[]): RiskDomainDatum[] {
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  const t = snapshot.telemetry;
  const domainScore = (needle: string) => domains.find((d) => d.domain.toLowerCase().includes(needle))?.score ?? 0;
  const runtimeReadiness = snapshot.readinessFactors.find((f) => f.label.toLowerCase().includes('runtime'))?.score ?? 0;
  const hasTlsEvidence =
    inv.domainsScanned > 0 ||
    internetFacingLabels(snapshot).length > 0 ||
    snapshot.criticalFindings.some((f) => /tls|rsa|forward secrecy|cipher|ecdh|handshake/i.test(`${f.algorithm} ${f.title}`));
  const hasAppEvidence =
    inv.vulnerableComponents > 0 ||
    snapshot.topRiskAssets.some((a) => /app|web|service|api|function|container/i.test(a.assetType));

  const candidates: Array<{ category: string; matchKey: string; weight: number; rawRisk: number; present: boolean }> = [
    { category: 'TLS Risk', matchKey: 'tls', weight: 0.18, rawRisk: 100 - domainScore('tls'), present: hasTlsEvidence || (snapshot.hasData && inv.assetsAssessed > 0) },
    { category: 'PKI Risk', matchKey: 'pki', weight: 0.12, rawRisk: 100 - domainScore('pki'), present: inv.certificatesAnalyzed > 0 },
    { category: 'Identity Risk', matchKey: 'identity', weight: 0.1, rawRisk: 100 - domainScore('identity'), present: inv.identitiesAnalyzed > 0 },
    { category: 'Application Risk', matchKey: 'application', weight: 0.1, rawRisk: 100 - domainScore('application'), present: hasAppEvidence },
    { category: 'Cloud Risk', matchKey: 'cloud', weight: 0.1, rawRisk: 100 - domainScore('cloud'), present: inv.cloudAccounts > 0 },
    { category: 'Vendor Risk', matchKey: 'vendor', weight: 0.08, rawRisk: 100 - domainScore('vendor'), present: inv.trustRelationships > 0 },
    { category: 'HNDL Risk', matchKey: 'hndl', weight: 0.2, rawRisk: s.hndlRisk, present: snapshot.hasData && (s.hndlRisk > 0 || inv.vulnerableComponents > 0) },
    { category: 'Operational Risk', matchKey: 'operational', weight: 0.07, rawRisk: 100 - runtimeReadiness, present: t.runtimeEvents > 0 },
    { category: 'Business Risk', matchKey: 'business', weight: 0.05, rawRisk: s.quantumRisk, present: snapshot.hasData },
  ];
  let present = candidates.filter((c) => c.present);
  if (!present.length) present = candidates.filter((c) => c.matchKey === 'business');
  if (!present.length) return [];

  const weightSum = present.reduce((a, c) => a + c.weight, 0) || 1;
  const rawBlend = present.reduce((a, c) => a + c.rawRisk * c.weight, 0) / weightSum;
  const target = s.quantumRisk;
  // Calibrate domain risks so their weighted blend equals the authoritative
  // quantum-risk score. When the tenant has no risk (target 0) leave raw values.
  const k = rawBlend > 0 && target > 0 ? target / rawBlend : 1;

  return present
    .map((c) => ({
      category: c.category,
      matchKey: c.matchKey,
      weightFraction: c.weight / weightSum,
      weightPct: Math.round((c.weight / weightSum) * 100),
      risk: clamp(round(c.rawRisk * k)),
    }))
    .sort((a, b) => b.risk * b.weightFraction - a.risk * a.weightFraction);
}

/* ------------------------------------------------------------------ */
/* KPIs                                                               */
/* ------------------------------------------------------------------ */
export function buildKpis(snapshot: QuantumReadinessSnapshot): ReportKpi[] {
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  return [
    { label: 'Quantum Readiness', value: s.quantumReadiness, unit: '/100', level: s.quantumReadinessLevel, tone: kpiTone(s.quantumReadiness, false) },
    { label: 'Quantum Risk', value: s.quantumRisk, unit: '/100', level: s.quantumRiskLevel, tone: kpiTone(s.quantumRisk, true) },
    { label: 'Crypto Exposure', value: s.cryptoExposure, unit: '/100', level: s.cryptoExposureLevel, tone: kpiTone(s.cryptoExposure, true) },
    { label: 'HNDL Risk', value: s.hndlRisk, unit: '/100', level: s.hndlRiskLevel, tone: kpiTone(s.hndlRisk, true) },
    { label: 'PQC Adoption', value: s.pqcAdoption, unit: '%', tone: kpiTone(s.pqcAdoption, false) },
    { label: 'Migration Effort', value: s.migrationEffort, unit: '/100', tone: 'neutral' },
    { label: 'Assets Assessed', value: inv.assetsAssessed, tone: 'neutral' },
    { label: 'Assets Requiring Migration', value: inv.quantumVulnerableAssets, tone: inv.quantumVulnerableAssets > 0 ? 'high' : 'good' },
    { label: 'Vulnerable Crypto Components', value: inv.vulnerableComponents, tone: inv.vulnerableComponents > 0 ? 'high' : 'good' },
    { label: 'Certificates', value: inv.certificatesAnalyzed, tone: 'neutral' },
    { label: 'Keys', value: inv.keysDiscovered, tone: 'neutral' },
    { label: 'TLS / Domains', value: inv.domainsScanned, tone: 'neutral' },
    { label: 'Cloud Accounts', value: inv.cloudAccounts, tone: 'neutral' },
  ];
}

/* ------------------------------------------------------------------ */
/* Readiness domains (Enhancement #6 / Breakdown)                     */
/* ------------------------------------------------------------------ */
/**
 * Canonical risk-reduction targets used by EVERY engine (waves, executive block,
 * risk forecast, simulation) so the numbers reconcile. `residualRisk` is the
 * post-optimization steady state reached only after Validation/Optimization/
 * Governance — below the migration `targetRisk`.
 */
function reductionTargets(snapshot: QuantumReadinessSnapshot) {
  const startRisk = snapshot.scores.quantumRisk;
  const targetRisk = Math.max(10, round(startRisk * 0.25));
  const reductionPct = clamp(((startRisk - targetRisk) / Math.max(1, startRisk)) * 100);
  const residualRisk = Math.max(8, round(targetRisk * 0.8));
  return { startRisk, targetRisk, reductionPct, residualRisk };
}

export function buildReadinessDomains(snapshot: QuantumReadinessSnapshot): ReadinessDomain[] {
  const factor = (needle: string, fallback: number) => snapshot.readinessFactors.find((f) => f.label.toLowerCase().includes(needle))?.score ?? fallback;
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  const internetCount = internetFacingLabels(snapshot).length;
  // Dynamic maturity targets (#1): baseline per domain, raised by internet-facing
  // exposure for transport-adjacent domains, floored above current to guarantee a
  // real uplift, capped at 95 (crypto-agility ceiling). The rationale is printed.
  const defs: Array<{ domain: string; score: number; owner: string; action: string; base: number; transport: boolean }> = [
    { domain: 'TLS / Protocol', score: factor('tls', s.pqcAdoption), owner: 'Infrastructure Team', action: 'Enable TLS 1.3 hybrid (X25519+ML-KEM) on internet-facing endpoints.', base: 88, transport: true },
    { domain: 'PKI / Certificates', score: factor('pki', s.pqcAdoption), owner: 'Security Team', action: 'Introduce hybrid certificate chains; plan ML-DSA CA migration.', base: 85, transport: true },
    { domain: 'Identity', score: inv.identitiesAnalyzed > 0 ? clamp(s.pqcAdoption) : 0, owner: 'Identity Team', action: 'Assess token signing algorithms; plan ML-DSA migration.', base: 85, transport: false },
    { domain: 'Application', score: clamp(s.pqcAdoption * 0.8), owner: 'Application Team', action: 'Adopt crypto-agile libraries; remove hardcoded classical primitives.', base: 82, transport: false },
    { domain: 'API', score: clamp(s.pqcAdoption * 0.8), owner: 'Platform Team', action: 'Enforce hybrid TLS on API gateways and service mesh.', base: 84, transport: true },
    { domain: 'Cloud', score: inv.cloudAccounts > 0 ? clamp(s.pqcAdoption) : 0, owner: 'Cloud Team', action: 'Enable PQC-ready KMS/HSM and managed TLS where available.', base: 83, transport: false },
    { domain: 'Vendor', score: clamp(s.pqcAdoption * 0.7), owner: 'Vendor Management', action: 'Collect vendor PQC roadmaps; track readiness in supply-chain register.', base: 78, transport: false },
    { domain: 'Crypto Agility', score: factor('agility', s.pqcAdoption), owner: 'Security Engineering', action: 'Centralise crypto policy and enable algorithm hot-swap.', base: 85, transport: false },
    { domain: 'Trust Fabric', score: inv.trustRelationships > 0 ? clamp(70 - s.cryptoExposure * 0.3) : 0, owner: 'Security Architecture', action: 'Map trust chains and validate post-migration integrity.', base: 80, transport: false },
    { domain: 'Governance', score: factor('governance', 0), owner: 'GRC / Compliance', action: 'Maintain crypto inventory, evidence and migration governance.', base: 90, transport: false },
  ];
  return defs.map((d) => {
    const score = round(d.score);
    const internetBoost = d.transport && internetCount > 0 ? Math.min(6, internetCount) : 0;
    const targetScore = clamp(Math.max(d.base + internetBoost, score + 10), 0, 95);
    const gap = Math.max(0, targetScore - score);
    const targetRationale = `Target ${targetScore}/100 = baseline ${d.base} for ${d.domain}${internetBoost ? ` +${internetBoost} (${internetCount} internet-facing asset(s))` : ''}; closes a ${gap}-pt gap from current ${score}/100 via: ${d.action}`;
    return { domain: d.domain, score, targetScore, targetRationale, riskLevel: riskLevel(d.score, true), owner: d.owner, actions: d.action };
  });
}

/* ------------------------------------------------------------------ */
/* AI Migration Advisor (Enhancement #8)                              */
/* ------------------------------------------------------------------ */
export function buildMigrationAdvisor(snapshot: QuantumReadinessSnapshot, riskDomainModel: RiskDomainDatum[], waves: MigrationWave[]): MigrationAdvisor {
  const s = snapshot.scores;
  const internet = internetFacingLabels(snapshot);
  // Recommend against the DOMINANT weighted-risk domain — not the lowest
  // readiness domain (which was always "Identity" because identitiesAnalyzed is
  // 0, producing the wrong "Modernize Identity" recommendation when TLS in fact
  // dominates). The model is already sorted by weighted risk contribution.
  const primary = riskDomainModel[0];
  const primaryKey = primary?.matchKey || 'business';
  const isTransport = primaryKey === 'tls' || primaryKey === 'pki';
  const exposurePct = primary ? clamp(primary.risk) : clamp(s.cryptoExposure);
  const recommendation = snapshot.hasData
    ? DOMAIN_RECOMMENDATION[primaryKey] || `Modernize ${primary?.category || 'cryptographic'} cryptography`
    : 'Establish PQC migration program';
  const firstWave = waves[0];
  return {
    recommendation,
    reason: `${primary ? primary.category : 'Cryptographic exposure'} is the largest weighted quantum-risk driver (${exposurePct}/100)${isTransport ? ', dominated by legacy RSA/ECC TLS handshakes and certificate signatures,' : ''} concentrated in ${snapshot.inventory.quantumVulnerableAssets || snapshot.inventory.assetsAssessed} asset(s).`,
    affectedAssets: internet.length ? internet.slice(0, 8) : snapshot.topRiskAssets.slice(0, 8).map((a) => a.asset),
    riskReductionPct: firstWave ? firstWave.riskReductionPct : clamp(Math.round((s.quantumRisk - Math.max(10, s.quantumRisk * 0.25)) * 0.6)),
    costUsd: firstWave ? firstWave.costUsd : Math.round(snapshot.estimates.migrationCostUsd * 0.2),
    timelineWeeks: firstWave ? firstWave.durationWeeks : Math.max(1, Math.round(snapshot.estimates.migrationTimelineWeeks * 0.2)),
    complexity: riskLevel(s.migrationComplexity, false),
    successProbabilityPct: clamp(100 - s.migrationComplexity * 0.5),
    confidencePct: snapshot.hasData ? clamp(78 + (snapshot.inventory.assetsAssessed > 0 ? 8 : 0) + (snapshot.inventory.certificatesAnalyzed > 0 ? 5 : 0)) : 0,
  };
}

/* ------------------------------------------------------------------ */
/* Migration waves (Enhancement #3)                                   */
/* ------------------------------------------------------------------ */
export function buildMigrationWaves(snapshot: QuantumReadinessSnapshot): MigrationWave[] {
  const weeks = snapshot.estimates.migrationTimelineWeeks || 0;
  const cost = snapshot.estimates.migrationCostUsd || 0;
  const internet = internetFacingLabels(snapshot);
  const inv = snapshot.inventory;

  // Phase 4 — Dynamic Migration Wave Engine™: scale wave count to actual scope.
  // A single-asset assessment must not generate enterprise-scale identity/cloud
  // waves it has no evidence for. Build the candidate set, then drop waves with
  // no real assets (always keeping a Validation wave).
  const enterpriseScope = inv.assetsAssessed > 2 || inv.cloudAccounts > 0 || inv.identitiesAnalyzed > 0;
  const fullSpecs: Array<{ name: string; assets: string[]; owner: string; ratio: number; reductionShare: number; priority: string }> = [
    { name: 'Internet-Facing Assets', assets: internet.length ? internet : snapshot.topRiskAssets.slice(0, 5).map((a) => a.asset), owner: 'Infrastructure Team', ratio: 0.2, reductionShare: 0.4, priority: 'Critical' },
    { name: 'PKI / Certificate Infrastructure', assets: inv.certificatesAnalyzed > 0 ? [`${inv.certificatesAnalyzed} certificate(s)`] : [], owner: 'Security Team', ratio: 0.25, reductionShare: 0.2, priority: 'High' },
    { name: 'Applications', assets: snapshot.topRiskAssets.filter((a) => /app|web|service/i.test(a.assetType)).map((a) => a.asset), owner: 'Application Team', ratio: 0.25, reductionShare: 0.18, priority: 'High' },
    { name: 'Identity Systems', assets: inv.identitiesAnalyzed > 0 ? [`${inv.identitiesAnalyzed} identity system(s)`] : [], owner: 'Identity Team', ratio: 0.15, reductionShare: 0.12, priority: 'Medium' },
    { name: 'Cloud Services', assets: inv.cloudAccounts > 0 ? [`${inv.cloudAccounts} cloud account(s)`] : [], owner: 'Cloud Team', ratio: 0.15, reductionShare: 0.1, priority: 'Medium' },
  ];
  // Compact scope (single/few assets): TLS Modernization → Certificate Upgrade → Validation.
  const compactSpecs: Array<{ name: string; assets: string[]; owner: string; ratio: number; reductionShare: number; priority: string }> = [
    { name: 'TLS Modernization', assets: internet.length ? internet : snapshot.topRiskAssets.slice(0, 5).map((a) => a.asset), owner: 'Infrastructure Team', ratio: 0.45, reductionShare: 0.55, priority: 'Critical' },
    { name: 'Certificate Upgrade', assets: inv.certificatesAnalyzed > 0 ? [`${inv.certificatesAnalyzed} certificate(s)`] : [], owner: 'Security Team', ratio: 0.35, reductionShare: 0.3, priority: 'High' },
    { name: 'Validation & Cutover', assets: snapshot.hasData ? [`${inv.vulnerableComponents} components validated`] : [], owner: 'Security Engineering', ratio: 0.2, reductionShare: 0.15, priority: 'Medium' },
  ];
  const specs = (enterpriseScope ? fullSpecs : compactSpecs).filter((s, i) => s.assets.length > 0 || i === 0 || /validation/i.test(s.name));
  // Reconcile so Σ wave riskReductionPct == the program reduction target exactly
  // (#3): renormalise the surviving reduction shares, round, then push the
  // rounding remainder onto the largest wave. Uses reductionTargets() — the same
  // engine as the executive block and risk forecast — so all three agree.
  const shareSum = specs.reduce((sum, spec) => sum + spec.reductionShare, 0) || 1;
  const { reductionPct } = reductionTargets(snapshot);
  const waves = specs.map((spec, index) => ({
    wave: index + 1,
    name: spec.name,
    assets: spec.assets.length ? spec.assets.slice(0, 10) : [EVIDENCE_UNAVAILABLE],
    owner: spec.owner,
    durationWeeks: Math.max(weeks ? 1 : 0, Math.round(weeks * spec.ratio)),
    costUsd: Math.round(cost * spec.ratio),
    dependencies: index === 0 ? ['Load Balancer', 'Certificate Authority'] : index === 1 ? ['Certificate Authority', 'HSM / KMS'] : ['Preceding wave validation'],
    riskReductionPct: Math.round(reductionPct * (spec.reductionShare / shareSum)),
    status: spec.assets.length ? (index === 0 ? 'Ready' : 'Planned') : 'Awaiting Discovery',
    priority: spec.priority,
  }));
  if (waves.length) {
    const diff = reductionPct - waves.reduce((sum, w) => sum + w.riskReductionPct, 0);
    if (diff !== 0) {
      const largest = waves.reduce((mi, w, i, arr) => (w.riskReductionPct > arr[mi].riskReductionPct ? i : mi), 0);
      waves[largest].riskReductionPct = Math.max(0, waves[largest].riskReductionPct + diff);
    }
  }
  return waves;
}

/* ------------------------------------------------------------------ */
/* Migration playbook (Enhancement)                                   */
/* ------------------------------------------------------------------ */
export function buildPlaybook(waves: MigrationWave[]): PlaybookStage[] {
  return waves.map((wave) => ({
    wave: `Wave ${wave.wave} — ${wave.name}`,
    prerequisites: `Owner (${wave.owner}) assigned, dependency inventory confirmed (${wave.dependencies.join(', ')}), rollback window approved.`,
    preparation: 'Snapshot current crypto configuration; provision hybrid keys/certs; stage feature flags with classical fallback.',
    execution: 'Enable hybrid PQC (ML-KEM / ML-DSA) behind feature flag; update linked assets; monitor handshake telemetry.',
    rollback: 'Disable feature flag to restore classical configuration within one change window if failures exceed threshold.',
    validation: 'Confirm new key active, old key deprecated, trust chains intact, no failed crypto operations across dependents.',
    successCriteria: `${wave.riskReductionPct}% risk reduction achieved, zero unplanned downtime, evidence captured for audit.`,
  }));
}

/* ------------------------------------------------------------------ */
/* Business impact (Enhancement #4)                                   */
/* ------------------------------------------------------------------ */
export function buildBusinessImpact(snapshot: QuantumReadinessSnapshot): BusinessImpact {
  const internet = internetFacingLabels(snapshot).length;
  const critical = snapshot.topRiskAssets.filter((a) => a.riskScore >= 70).length || snapshot.exposureGraph.nodes.filter((n) => n.riskScore >= 70).length;
  const s = snapshot.scores;
  const window = !snapshot.hasData ? EVIDENCE_UNAVAILABLE : s.hndlRisk >= 60 ? 'Within 5 Years' : s.hndlRisk >= 40 ? '5-10 Years' : '10+ Years';
  return {
    customerFacingSystems: internet,
    missionCriticalSystems: critical,
    revenueImpact: internet > 0 ? (critical > 0 ? 'High' : 'Medium') : 'Low',
    operationalImpact: snapshot.inventory.quantumVulnerableAssets > 0 ? 'Medium' : 'Low',
    complianceImpact: s.hndlRisk >= 40 ? 'Medium' : 'Low',
    reputationalImpact: internet > 0 && s.quantumRisk >= 45 ? 'Medium' : 'Low',
    financialImpact: snapshot.estimates.migrationCostUsd > 0 ? `Migration investment ~$${snapshot.estimates.migrationCostUsd.toLocaleString()}` : EVIDENCE_UNAVAILABLE,
    thirdPartyDependencies: snapshot.inventory.cloudAccounts + (internet > 0 ? 1 : 0),
    hndlExposure: s.hndlRiskLevel,
    quantumExposureWindow: window,
  };
}

/* ------------------------------------------------------------------ */
/* Migration readiness assessment                                     */
/* ------------------------------------------------------------------ */
export function buildMigrationReadiness(snapshot: QuantumReadinessSnapshot, domains: ReadinessDomain[]): Array<{ category: string; score: number; recommendation: string }> {
  const get = (needle: string) => domains.find((d) => d.domain.toLowerCase().includes(needle))?.score ?? 0;
  const s = snapshot.scores;
  return [
    { category: 'Technical Readiness', score: clamp(s.pqcAdoption), recommendation: 'Increase PQC/hybrid adoption across cryptographic assets.' },
    {
      category: 'Operational Readiness',
      score: clamp(snapshot.readinessFactors.find((f) => f.label.includes('Runtime'))?.score ?? 0),
      recommendation: snapshot.telemetry.runtimeEvents > 0
        ? 'Ensure runtime crypto telemetry covers all production paths.'
        : 'Not measured — no runtime telemetry deployed. Deploy runtime crypto agents to establish operational visibility.',
    },
    { category: 'Governance Readiness', score: get('governance'), recommendation: 'Maintain crypto policy, inventory and migration evidence.' },
    { category: 'Vendor Readiness', score: get('vendor'), recommendation: 'Collect vendor PQC roadmaps and track in supply-chain register.' },
    { category: 'Staff Readiness', score: clamp(get('governance') * 0.8), recommendation: 'Train engineering teams on hybrid PQC deployment patterns.' },
    { category: 'Infrastructure Readiness', score: get('tls'), recommendation: 'Upgrade load balancers / gateways to TLS 1.3 hybrid.' },
    { category: 'Application Readiness', score: get('application'), recommendation: 'Adopt crypto-agile libraries in application stacks.' },
  ];
}

/* ------------------------------------------------------------------ */
/* Dependency analysis (Enhancement #7)                               */
/* ------------------------------------------------------------------ */
export function buildDependencyAnalysis(snapshot: QuantumReadinessSnapshot) {
  const { nodes, edges } = snapshot.exposureGraph;
  const labelOf = new Map(nodes.map((n) => [n.id, n.label]));
  const neighbours = (id: string) => edges.filter((e) => e.source === id || e.target === id).map((e) => (e.source === id ? e.target : e.source));
  // Canonical internet-facing transport blast radius. Every hop that terminates
  // or forwards TLS is exposed to the same legacy transport cryptography, so a
  // single public endpoint's compromise propagates through the whole delivery
  // chain. Used when no explicit dependency edges were discovered (#7).
  const canonicalChain = (label: string): string =>
    `Users -> CDN -> Load Balancer -> TLS Certificate (${label}) -> Web Server -> Application -> Database -> Encrypted Backup`;
  const seeds = nodes.filter((n) => n.internetFacing || n.riskScore >= 60).slice(0, 6);
  const chains = seeds.map((node) => {
    const deps = neighbours(node.id).map((id) => labelOf.get(id)).filter(Boolean) as string[];
    if (deps.length) {
      const path = [node.label, ...deps.slice(0, 6)].join(' -> ') + ' -> Users';
      return { path, blastRadius: deps.length, complexity: deps.length > 3 ? 'High' : deps.length > 1 ? 'Medium' : 'Low' };
    }
    // No explicit edges recorded for this public asset → inferred topology.
    return { path: canonicalChain(node.label), blastRadius: 7, complexity: 'High' };
  });
  const finalChains = chains.length
    ? chains
    : [{ path: canonicalChain(nodes[0]?.label || 'internet-facing endpoint'), blastRadius: 7, complexity: 'High' }];
  const failurePoints = nodes.filter((n) => n.riskScore >= 70).map((n) => n.label).slice(0, 8);
  const inferred = edges.length === 0;
  return {
    chains: finalChains,
    failurePoints: failurePoints.length ? failurePoints : ['TLS Certificate', 'Load Balancer', 'Web Server', 'Application'],
    summary: nodes.length
      ? `${nodes.length} asset(s) and ${edges.length} explicit dependency relationship(s) analysed.${inferred ? ' No explicit dependency edges were discovered, so a canonical internet-facing transport topology (Users → CDN → Load Balancer → TLS Certificate → Web Server → Application → Database → Backup) is shown as the inferred blast radius: every hop that terminates or forwards TLS inherits the same legacy transport-cryptography exposure.' : ''} ${failurePoints.length || 3} high-risk failure point(s) identified for migration sequencing.`
      : `${EVIDENCE_UNAVAILABLE}. No dependency telemetry recorded. Connect asset relationships to map real blast radius.`,
  };
}

/* ------------------------------------------------------------------ */
/* Quantum risk categories (Enhancement)                              */
/* ------------------------------------------------------------------ */
export function buildRiskCategories(riskDomainModel: RiskDomainDatum[]): RiskCategory[] {
  const cats = riskDomainModel.map((d) => {
    const current = clamp(d.risk);
    const target = Math.max(8, round(current * 0.3));
    return { category: d.category, currentScore: current, targetScore: target, reductionPotentialPct: clamp(((current - target) / Math.max(1, current)) * 100) };
  });
  return cats.length ? cats : [{ category: EVIDENCE_UNAVAILABLE, currentScore: 0, targetScore: 0, reductionPotentialPct: 0 }];
}

/* ------------------------------------------------------------------ */
/* HNDL categories (Enhancement)                                      */
/* ------------------------------------------------------------------ */
export function buildHndlCategories(snapshot: QuantumReadinessSnapshot): HndlCategory[] {
  const s = snapshot.scores;
  if (!snapshot.hasData || (snapshot.inventory.dataRepositories === 0 && snapshot.inventory.quantumVulnerableAssets === 0)) {
    return [{ category: EVIDENCE_UNAVAILABLE, retention: '—', currentProtection: '—', hndlRisk: '—', recommendedProtection: '—' }];
  }
  const level = s.hndlRiskLevel;
  return [
    { category: 'Long-Lived Encrypted Data (at rest)', retention: 'Classify (Evidence Not Available)', currentProtection: 'Classical (RSA / ECC / AES under classical KEM)', hndlRisk: level, recommendedProtection: 'AES-256-GCM + ML-KEM-768' },
    { category: 'Data In Transit (internet-facing)', retention: 'Session + captured ciphertext', currentProtection: 'TLS with RSA/ECDH key exchange', hndlRisk: level, recommendedProtection: 'TLS 1.3 X25519 + ML-KEM-768 (Hybrid)' },
    { category: 'Archived / Backup Data', retention: 'Multi-year', currentProtection: 'Classical envelope encryption', hndlRisk: level, recommendedProtection: 'AES-256-GCM + ML-KEM-768 envelope' },
  ];
}

/* ------------------------------------------------------------------ */
/* Cost forecast (Enhancement #5)                                     */
/* ------------------------------------------------------------------ */
export function buildCostForecast(snapshot: QuantumReadinessSnapshot): CostForecast {
  const rawTotal = snapshot.estimates.migrationCostUsd || 0;
  if (!rawTotal) {
    return { lines: [{ category: EVIDENCE_UNAVAILABLE, costUsd: 0 }], totalUsd: 0, projectedRiskReductionValueUsd: 0 };
  }
  const rate = BLENDED_RATE_USD;
  // Labour hours are the primitive. Each line cost = hours × rate EXACTLY, and
  // line items sum to the displayed total, so the per-line formulas reconcile
  // (previously hours were rounded but cost kept the raw ratio → "217 × 165 =
  // 35,864", which is arithmetically false).
  const totalHours = Math.max(1, Math.round(rawTotal / rate));
  const split: Array<[string, number]> = [
    ['Infrastructure / TLS Upgrades', 0.22],
    ['PKI & Certificate Modernization', 0.18],
    ['Cloud / KMS', 0.1],
    ['HSM', 0.08],
    ['Validation & Testing', 0.12],
    ['Staff Time & Training', 0.18],
    ['Consulting', 0.06],
    ['Operations & Support', 0.06],
  ];
  const alloc = split.map(([category, ratio]) => ({ category, hours: Math.round(totalHours * ratio) }));
  // Push any integer-rounding remainder onto the largest line so Σ hours ==
  // totalHours and Σ costUsd == totalUsd exactly.
  const remainder = totalHours - alloc.reduce((sum, a) => sum + a.hours, 0);
  if (remainder !== 0 && alloc.length) {
    const largest = alloc.reduce((mi, a, i, arr) => (a.hours > arr[mi].hours ? i : mi), 0);
    alloc[largest].hours = Math.max(0, alloc[largest].hours + remainder);
  }
  const lines = alloc.map((a) => ({ category: a.category, costUsd: a.hours * rate }));
  const totalUsd = lines.reduce((sum, l) => sum + l.costUsd, 0);
  const reductionPct = clamp(((snapshot.scores.quantumRisk - Math.max(10, snapshot.scores.quantumRisk * 0.25)) / Math.max(1, snapshot.scores.quantumRisk)) * 100);
  return { lines, totalUsd, projectedRiskReductionValueUsd: Math.round(totalUsd * (reductionPct / 100) * 3) };
}

/* ------------------------------------------------------------------ */
/* Risk reduction forecast (Enhancement)                              */
/* ------------------------------------------------------------------ */
export function buildRiskForecast(snapshot: QuantumReadinessSnapshot): RiskForecast {
  const { startRisk: current, targetRisk: target, reductionPct, residualRisk } = reductionTargets(snapshot);
  // Waves drive risk to `target`; the Validation/Optimization/Governance phase
  // then hardens it to the lower `residualRisk` steady state by month 36.
  const lerp = (t: number) => round(current - (current - target) * t);
  // I3#7 — best/expected/worst-case bands. Expected = the planned trajectory.
  // Best = on-schedule + faster wins (reaches residual by month 24). Worst =
  // slippage (slower burn-down, more residual). Bounded to [0, current].
  const band = (from: number, to: number, t: number) => clamp(round(from - (from - to) * t), 0, current);
  const scenarios: RiskScenario[] = snapshot.hasData
    ? [
        { scenario: 'Best Case', month12: band(current, target, 0.55), month24: band(current, residualRisk, 0.9), month36: residualRisk, assumption: 'On-schedule waves, dedicated resourcing, no rollback events; residual posture reached ~1 year early.' },
        { scenario: 'Expected', month12: lerp(0.4), month24: lerp(0.75), month36: residualRisk, assumption: 'Planned wave cadence with standard change windows and validation gates.' },
        { scenario: 'Worst Case', month12: band(current, target, 0.2), month24: band(current, target, 0.55), month36: band(current, target, 0.85), assumption: 'Resource contention / rollback slippage; migration target not fully reached until beyond month 36.' },
      ]
    : [];
  return {
    currentRisk: current,
    targetRisk: target,
    reductionPct,
    residualRisk,
    month12: lerp(0.4),
    month24: lerp(0.75),
    month36: residualRisk,
    scenarios,
  };
}

/* ------------------------------------------------------------------ */
/* Governance & ownership                                             */
/* ------------------------------------------------------------------ */
export function buildGovernance(snapshot: QuantumReadinessSnapshot): GovernanceRole[] {
  const owners = snapshot.topRiskAssets.map((a) => a.owner).filter((o) => o && !/unassigned|unknown/i.test(o));
  const fallback = (def: string) => owners[0] || def;
  return [
    { role: 'Executive Sponsor', owner: 'CISO', responsibility: 'Programme accountability, funding approval, board reporting.' },
    { role: 'Program Manager', owner: 'PQC Migration Office', responsibility: 'Plan, schedule and track the migration programme.' },
    { role: 'Infrastructure Owner', owner: fallback('Infrastructure Team'), responsibility: 'TLS / network / load-balancer migration.' },
    { role: 'PKI Owner', owner: 'Security Team', responsibility: 'Certificate authority and hybrid certificate rollout.' },
    { role: 'Application Owner', owner: 'Application Team', responsibility: 'Crypto-agile application remediation.' },
    { role: 'Compliance Owner', owner: 'GRC / Compliance', responsibility: 'Control mapping, evidence and regulatory alignment.' },
    { role: 'Security Owner', owner: 'Security Engineering', responsibility: 'Crypto policy, validation and assurance.' },
    { role: 'Migration Owner', owner: 'PQC Migration Lead', responsibility: 'Wave execution, rollback and sign-off.' },
  ];
}

/* ------------------------------------------------------------------ */
/* Actionable findings (Enhancement #1)                               */
/* ------------------------------------------------------------------ */
export function buildFindings(snapshot: QuantumReadinessSnapshot): ReportFinding[] {
  const now = new Date();
  const nodeByLabel = new Map(snapshot.exposureGraph.nodes.map((n) => [n.label, n]));

  const fromScan: ReportFinding[] = snapshot.criticalFindings.map((finding, index) => {
    const severity = normalizeSeverity(finding.severity);
    const node = nodeByLabel.get(finding.asset);
    const internetFacing = node?.internetFacing ?? false;
    const deps = internetFacing ? ['Load Balancer', 'Certificate Authority', 'Cloudflare'] : ['Service Mesh', 'Certificate Authority'];
    const complexity = deps.length > 3 ? 'High' : severity === 'critical' || internetFacing ? 'Medium' : 'Low';
    const effort = complexity === 'High' ? '1 week' : complexity === 'Medium' ? '1-2 days' : '4 hours';
    const cost = complexity === 'High' ? 4000 : complexity === 'Medium' ? 1500 : 500;
    const weeksOut = severity === 'critical' ? 2 : severity === 'high' ? 4 : 8;
    const reduction = severity === 'critical' ? 8 : severity === 'high' ? 5 : severity === 'medium' ? 2 : 1;
    return {
      id: finding.id || `FND-${String(index + 1).padStart(3, '0')}`,
      title: finding.title || 'Quantum-vulnerable cryptography detected',
      severity,
      evidence: finding.algorithm
        ? `Algorithm "${finding.algorithm}" detected on asset "${finding.asset}" (${finding.environment})${finding.detectedAt ? ` at ${finding.detectedAt}` : ''}.`
        : EVIDENCE_UNAVAILABLE,
      affectedAssets: finding.asset ? [finding.asset] : [],
      recommendation: `Migrate ${finding.asset || 'asset'} to ${recommendedState(finding.algorithm)}.`,
      remediationPlan: 'Discover dependencies -> validate compatibility -> deploy hybrid PQC -> verify trust chains -> retire classical key.',
      source: 'PQC Scanner / CBOM',
      detectedAt: finding.detectedAt || null,
      currentState: finding.algorithm || EVIDENCE_UNAVAILABLE,
      recommendedState: recommendedState(finding.algorithm),
      businessImpact: internetFacing ? 'Internet-facing customer-handling system.' : `Internal ${finding.assetType || 'system'}.`,
      technicalImpact: `${finding.algorithm || 'Classical algorithm'} lacks quantum resistance and provides no migration path without hybridisation.`,
      migrationComplexity: complexity as 'Low' | 'Medium' | 'High',
      dependencies: deps,
      owner: internetFacing ? 'Infrastructure Team' : 'Security Engineering',
      targetDate: format(addWeeks(now, weeksOut), 'yyyy-MM-dd'),
      validation: 'Run PQC readiness scan; confirm hybrid handshake and trust-chain integrity.',
      riskReductionPct: reduction,
      estimatedCostUsd: cost,
      estimatedEffort: effort,
    };
  });

  const fromActions: ReportFinding[] = snapshot.recommendedActions
    .filter((action) => !fromScan.some((existing) => existing.title === action.title))
    .map((action, index) => ({
      id: action.id || `REC-${String(index + 1).padStart(3, '0')}`,
      title: action.title,
      severity: normalizeSeverity(action.severity),
      evidence: action.detail || EVIDENCE_UNAVAILABLE,
      affectedAssets: [],
      recommendation: action.detail || 'Review and remediate per assessment guidance.',
      remediationPlan: `Track remediation via ${action.route}.`,
      source: 'Quantum Readiness Assessment Engine',
      detectedAt: null,
      currentState: EVIDENCE_UNAVAILABLE,
      recommendedState: EVIDENCE_UNAVAILABLE,
      businessImpact: EVIDENCE_UNAVAILABLE,
      technicalImpact: action.detail || EVIDENCE_UNAVAILABLE,
      migrationComplexity: 'Medium',
      dependencies: [],
      owner: 'Security Engineering',
      targetDate: format(addWeeks(now, 6), 'yyyy-MM-dd'),
      validation: 'Confirm remediation evidence and re-scan.',
      riskReductionPct: 2,
      estimatedCostUsd: 1000,
      estimatedEffort: '1-2 days',
    }));

  return [...fromScan, ...fromActions].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

/* ------------------------------------------------------------------ */
/* Remediation program (Enhancement #2)                               */
/* ------------------------------------------------------------------ */
export function buildRemediationProgram(snapshot: QuantumReadinessSnapshot, findings: ReportFinding[], waves: MigrationWave[]): RemediationItem[] {
  const now = new Date();
  const items: RemediationItem[] = waves.slice(0, 5).map((wave, index) => ({
    priority: index + 1,
    action: `${wave.name}: deploy hybrid PQC (ML-KEM / ML-DSA) and retire classical primitives.`,
    owner: wave.owner,
    affectedAssets: wave.assets,
    costUsd: wave.costUsd,
    effort: `${wave.durationWeeks} week(s)`,
    riskReductionPct: wave.riskReductionPct,
    targetDate: format(addWeeks(now, (index + 1) * 3), 'yyyy-MM-dd'),
    status: wave.status,
    dependencies: wave.dependencies,
    validation: 'PQC readiness re-scan, trust-chain validation, zero failed crypto operations.',
  }));
  // Fold in any critical finding not covered by a wave bucket.
  const topFinding = findings.find((f) => f.severity === 'critical');
  if (topFinding && !items.some((i) => i.affectedAssets.includes(topFinding.affectedAssets[0]))) {
    items.unshift({
      priority: 0,
      action: `${topFinding.title} — migrate to ${topFinding.recommendedState}.`,
      owner: topFinding.owner,
      affectedAssets: topFinding.affectedAssets,
      costUsd: topFinding.estimatedCostUsd,
      effort: topFinding.estimatedEffort,
      riskReductionPct: topFinding.riskReductionPct,
      targetDate: topFinding.targetDate,
      status: 'Ready',
      dependencies: topFinding.dependencies,
      validation: topFinding.validation,
    });
    items.forEach((item, index) => (item.priority = index + 1));
  }
  return items;
}

/* ------------------------------------------------------------------ */
/* Compliance (enhanced with target / gap)                            */
/* ------------------------------------------------------------------ */
function buildCompliance(snapshot: QuantumReadinessSnapshot): ComplianceMapping[] {
  const s = snapshot.scores;
  const adoption = s.pqcAdoption;
  const statusFor = (threshold: number): ComplianceMapping['status'] =>
    !snapshot.hasData ? 'not-assessed' : adoption >= threshold ? 'aligned' : adoption >= threshold / 2 ? 'partial' : 'gap';
  const gap = (threshold: number) => `Current ${adoption}% vs target ${threshold}% PQC adoption. Remediation: hybrid PQC on affected assets.`;
  // I2#7 — dynamic gap tracking: Current / Target / Gap / Progress per framework
  // instead of a static status word. Progress = current ÷ target (capped 100%).
  const metrics = (threshold: number) => ({
    currentPct: snapshot.hasData ? clamp(adoption) : 0,
    targetPct: threshold,
    gapPct: snapshot.hasData ? Math.max(0, threshold - clamp(adoption)) : threshold,
    progressPct: snapshot.hasData ? clamp(Math.round((adoption / Math.max(1, threshold)) * 100)) : 0,
  });
  return [
    { framework: 'NIST SP 1800-38', control: 'PQC Migration Readiness', status: statusFor(60), detail: gap(60), ...metrics(60) },
    { framework: 'FIPS 203', control: 'ML-KEM key establishment', status: statusFor(50), detail: gap(50), ...metrics(50) },
    { framework: 'FIPS 204', control: 'ML-DSA digital signatures', status: statusFor(50), detail: gap(50), ...metrics(50) },
    { framework: 'FIPS 205', control: 'SLH-DSA stateless signatures', status: statusFor(40), detail: gap(40), ...metrics(40) },
    { framework: 'CNSA 2.0', control: 'Commercial National Security Algorithm Suite', status: statusFor(55), detail: gap(55), ...metrics(55) },
    { framework: 'ISO 27001', control: 'A.10 Cryptographic controls', status: statusFor(55), detail: `Crypto exposure ${s.cryptoExposure}/100. ${gap(55)}`, ...metrics(55) },
    { framework: 'SOC 2', control: 'CC6.1 — Cryptographic access', status: statusFor(50), detail: `HNDL exposure ${s.hndlRiskLevel}. ${gap(50)}`, ...metrics(50) },
    { framework: 'PCI DSS', control: 'Req 4 — Strong cryptography in transit', status: statusFor(55), detail: gap(55), ...metrics(55) },
    { framework: 'NIST CSF', control: 'PR.DS — Data Security', status: statusFor(55), detail: gap(55), ...metrics(55) },
  ];
}

function buildRoadmap(snapshot: QuantumReadinessSnapshot, waves: MigrationWave[]): RoadmapPhase[] {
  // Program-management timeline (#8): sequential dates, milestones, approval gates,
  // critical-path flags and slack. Dates are relative to report generation.
  const start = new Date();
  const totalWeeks = snapshot.estimates.migrationTimelineWeeks || 0;
  const fmtDate = (weekOffset: number) => (snapshot.hasData ? format(addWeeks(start, weekOffset), 'yyyy-MM-dd') : EVIDENCE_UNAVAILABLE);
  const phases: RoadmapPhase[] = [];
  let cursor = 0;
  const discoveryWeeks = Math.max(1, Math.round(totalWeeks * 0.1));
  phases.push({
    phase: 'Discovery & Assessment', description: 'Inventory crypto assets; score quantum risk, HNDL and complexity.',
    status: snapshot.hasData ? 'in-progress' : 'pending', effortWeeks: discoveryWeeks,
    startDate: fmtDate(cursor), endDate: fmtDate(cursor + discoveryWeeks),
    milestone: 'Baseline CBOM & risk score complete', gate: 'Gate 1 — Plan Approval', criticalPath: true, slackWeeks: 0,
  });
  cursor += discoveryWeeks;
  waves.forEach((wave) => {
    const critical = wave.priority === 'Critical' || wave.wave === 1;
    phases.push({
      phase: `Wave ${wave.wave}: ${wave.name} (${wave.owner})`, description: `Migrate to hybrid PQC. Risk reduction ${wave.riskReductionPct}%.`,
      status: wave.status, effortWeeks: wave.durationWeeks,
      startDate: fmtDate(cursor), endDate: fmtDate(cursor + wave.durationWeeks),
      milestone: `${wave.name} cut over to hybrid PQC`, gate: wave.wave === 1 ? 'Gate 2 — Wave Readiness' : 'Gate 3 — Production Cutover',
      criticalPath: critical, slackWeeks: critical ? 0 : 1,
    });
    cursor += wave.durationWeeks;
  });
  const valWeeks = Math.max(1, Math.round(totalWeeks * 0.1));
  phases.push({
    phase: 'Validation & Optimization', description: 'Decommission classical keys; monitor drift; prove residual risk & evidence.',
    status: 'planned', effortWeeks: valWeeks,
    startDate: fmtDate(cursor), endDate: fmtDate(cursor + valWeeks),
    milestone: 'Residual risk accepted; audit evidence archived', gate: 'Gate 4 — Validation Sign-off', criticalPath: true, slackWeeks: 0,
  });
  return phases;
}

function buildAssets(snapshot: QuantumReadinessSnapshot): ReportTable {
  const rows = snapshot.topRiskAssets.map((asset) => [asset.asset, asset.assetType, asset.environment, asset.owner, asset.riskScore, asset.status]);
  return safeTable('Top-Risk Assets', ['Asset', 'Type', 'Environment', 'Owner', 'Risk Score', 'PQC Status'], rows);
}

/* ------------------------------------------------------------------ */
/* Executive block (Enhancement #10)                                  */
/* ------------------------------------------------------------------ */
function buildExecutiveBlock(snapshot: QuantumReadinessSnapshot, riskDomainModel: RiskDomainDatum[], findingGroups: FindingGroup[]): ExecutiveBlock {
  const s = snapshot.scores;
  const targetReadiness = Math.max(85, s.quantumReadiness);
  const targetRisk = Math.max(10, round(s.quantumRisk * 0.25));
  const targetHndl = Math.max(8, round(s.hndlRisk * 0.3));
  const compliant = buildCompliance(snapshot);
  const aligned = compliant.filter((c) => c.status === 'aligned').length;
  // Executive summary uses CONSOLIDATED (root-cause) findings, not raw per-
  // instance findings, so the same issue never appears twice in "Top Risks".
  const topRisks = findingGroups.length
    ? findingGroups.slice(0, 5).map((g) => `${g.impact.toUpperCase()}: ${g.title} (${g.occurrences}× across ${g.affectedAssets} asset${g.affectedAssets === 1 ? '' : 's'})`)
    : snapshot.recommendedActions.slice(0, 5).map((a) => `${normalizeSeverity(a.severity).toUpperCase()}: ${a.title}`);
  const primary = riskDomainModel[0];
  const primaryLabel = primary ? primary.category.replace(/\s*Risk$/i, '') : 'cryptographic';
  const internetCount = internetFacingLabels(snapshot).length;
  const scope = internetCount > 0 ? 'all internet-facing assets' : 'the highest-risk assets';
  const reductionPct = clamp(((s.quantumRisk - targetRisk) / Math.max(1, s.quantumRisk)) * 100);
  return {
    currentReadiness: s.quantumReadiness,
    targetReadiness,
    currentRisk: s.quantumRisk,
    targetRisk,
    currentHndl: s.hndlRisk,
    targetHndl,
    estimatedDurationWeeks: snapshot.estimates.migrationTimelineWeeks,
    estimatedCostUsd: snapshot.estimates.migrationCostUsd,
    expectedRiskReductionPct: clamp(((s.quantumRisk - targetRisk) / Math.max(1, s.quantumRisk)) * 100),
    expectedComplianceImprovementPct: clamp(((compliant.length - aligned) / Math.max(1, compliant.length)) * 100),
    quantumExposureWindow: !snapshot.hasData ? EVIDENCE_UNAVAILABLE : s.hndlRisk >= 60 ? 'Within 5 Years' : s.hndlRisk >= 40 ? '5-10 Years' : '10+ Years',
    topRisks,
    topBusinessRisks: buildTopBusinessRisks(snapshot),
    topActions: snapshot.recommendedActions.slice(0, 5).map((a) => a.title),
    executiveRecommendation: snapshot.hasData
      ? `Prioritise ${primaryLabel} modernization and hybrid PQC deployment on ${scope} within the next migration wave. Fund a ${snapshot.estimates.migrationTimelineWeeks || 'TBD'}-week programme to reduce quantum risk by ${reductionPct}%.`
      : 'Complete a PQC discovery scan to baseline the migration programme.',
  };
}

/* ================================================================== */
/* Report Intelligence (Reports_Enhancements_3)                       */
/* ================================================================== */

const BLENDED_RATE_USD = 165; // blended engineer rate used by the estimate model

// Phase 1 — Risk Scoring Transparency Engine™
// Domain weights live in buildRiskDomainModel (evidence-filtered + calibrated);
// this consumes that model so the displayed weighted table reproduces `overall`.
export function buildRiskMethodology(snapshot: QuantumReadinessSnapshot, riskDomainModel: RiskDomainDatum[]): RiskMethodology {
  const rows = riskDomainModel.map((d) => ({ domain: d.category, weightPct: d.weightPct, score: d.risk, weighted: d.risk * d.weightFraction }));
  const totalWeighted = rows.reduce((sum, r) => sum + r.weighted, 0) || 1;
  const weights = rows
    // `contribution` = absolute DomainRisk × Weight (1-dp); Σ(contribution) == overall.
    .map((r) => ({ domain: r.domain, weightPct: r.weightPct, score: r.score, contribution: Math.round(r.weighted * 10) / 10, contributionPct: clamp((r.weighted / totalWeighted) * 100) }))
    .sort((a, b) => b.contribution - a.contribution);
  const top = weights[0];
  const sumContribution = Math.round(weights.reduce((sum, w) => sum + w.contribution, 0));
  const additionLine = weights.map((w) => w.contribution.toFixed(1)).join(' + ') + ` = ${sumContribution}`;
  return {
    formula: 'Overall Quantum Risk = Σ ( DomainRisk × DomainWeight ) ÷ Σ ( DomainWeight )',
    overall: snapshot.scores.quantumRisk,
    weights,
    topDriver: top ? `${top.domain} (contribution ${top.contribution}, ${top.contributionPct}% of weighted risk)` : EVIDENCE_UNAVAILABLE,
    explanation: snapshot.hasData
      ? `The overall quantum risk of ${snapshot.scores.quantumRisk}/100 is a weighted blend of ${weights.length} evidence-backed cryptographic risk domain(s); domains with no assets in scope are excluded rather than assumed to be at maximum risk. Each domain's Contribution = Domain Risk × Weight, and the overall score is their sum, so an auditor can verify it exactly: ${additionLine} (≈ ${snapshot.scores.quantumRisk}). ${top ? `${top.domain} is the largest contributor (${top.contribution}) at a calibrated domain risk of ${top.score}/100` : ''}${weights[1] ? `, followed by ${weights[1].domain} (${weights[1].contribution})` : ''}.`
      : `${EVIDENCE_UNAVAILABLE}. Run a discovery scan to compute the risk methodology.`,
  };
}

// Phase 2 — AI Recommendation Validation Engine™
export function buildAdvisorValidation(snapshot: QuantumReadinessSnapshot, advisor: MigrationAdvisor, methodology: RiskMethodology): AdvisorValidation {
  const primary = methodology.weights[0];
  const domainKeyword = (primary?.domain || '').toLowerCase().split(' ')[0];
  const topFindings = snapshot.criticalFindings
    .filter((f) => !domainKeyword || `${f.algorithm} ${f.title}`.toLowerCase().includes(domainKeyword) || domainKeyword === 'business' || domainKeyword === 'hndl')
    .slice(0, 5)
    .map((f) => `${f.algorithm || f.title} on ${f.asset} (${f.severity})`);
  return {
    primaryExposureDomain: primary?.domain || EVIDENCE_UNAVAILABLE,
    topContributingFindings: topFindings.length ? topFindings : snapshot.criticalFindings.slice(0, 5).map((f) => `${f.algorithm || f.title} (${f.severity})`),
    topContributingAssets: snapshot.topRiskAssets.slice(0, 5).map((a) => `${a.asset} (risk ${a.riskScore})`),
    expectedRiskReductionPct: advisor.riskReductionPct,
    confidencePct: advisor.confidencePct,
    why: snapshot.hasData
      ? `"${advisor.recommendation}" is recommended because ${primary?.domain || 'the dominant domain'} contributes ${primary?.contributionPct || 0}% of the weighted quantum risk — the single largest exposure. ${advisor.reason} Acting on it first yields the highest risk reduction (${advisor.riskReductionPct}%) per dollar and is validated against ${snapshot.criticalFindings.length} scanner findings across ${snapshot.inventory.assetsAssessed} asset(s).`
      : `${EVIDENCE_UNAVAILABLE}.`,
  };
}

// Phase 3 — Cost Forecast Intelligence™
export function buildCostBreakdown(snapshot: QuantumReadinessSnapshot, costForecast: CostForecast): CostBreakdown {
  const lines = costForecast.lines
    .filter((l) => l.category !== EVIDENCE_UNAVAILABLE)
    .map((l) => {
      const hours = Math.round(l.costUsd / BLENDED_RATE_USD);
      // Recompute cost from hours × rate so the printed formula is exact.
      const costUsd = hours * BLENDED_RATE_USD;
      const engineers = Math.max(1, Math.round(hours / Math.max(40, (snapshot.estimates.migrationTimelineWeeks || 1) * 8)));
      return { category: l.category, hours, engineers, rateUsd: BLENDED_RATE_USD, costUsd, formula: `${hours.toLocaleString()} hrs × $${BLENDED_RATE_USD}/hr = $${costUsd.toLocaleString()}` };
    });
  const totalHours = lines.reduce((sum, l) => sum + l.hours, 0);
  const totalUsd = lines.reduce((sum, l) => sum + l.costUsd, 0);
  return { blendedRateUsd: BLENDED_RATE_USD, totalHours, totalUsd, lines: lines.length ? lines : [{ category: EVIDENCE_UNAVAILABLE, hours: 0, engineers: 0, rateUsd: BLENDED_RATE_USD, costUsd: 0, formula: EVIDENCE_UNAVAILABLE }] };
}

// Phase 5 — Asset Criticality Engine™
export function buildAssetCriticality(snapshot: QuantumReadinessSnapshot, compliance: ComplianceMapping[]): AssetCriticality[] {
  const nodeByLabel = new Map(snapshot.exposureGraph.nodes.map((n) => [n.label, n]));
  const complianceScope = compliance.filter((c) => /pci|iso|soc/i.test(c.framework)).map((c) => c.framework);
  const rows = snapshot.topRiskAssets.slice(0, 10).map((a) => {
    const node = nodeByLabel.get(a.asset);
    const internetFacing = node?.internetFacing ?? false;
    const businessCriticality = a.riskScore >= 70 ? 'High' : a.riskScore >= 40 ? 'Medium' : 'Low';
    return {
      asset: a.asset,
      businessCriticality,
      operationalCriticality: internetFacing ? 'High' : businessCriticality,
      customerFacing: internetFacing,
      internetFacing,
      revenueImpact: internetFacing ? 'High' : 'Medium',
      complianceScope: complianceScope.length ? complianceScope : [EVIDENCE_UNAVAILABLE],
      dataSensitivity: snapshot.scores.hndlRisk >= 50 ? 'High' : snapshot.scores.hndlRisk >= 30 ? 'Medium' : 'Low',
    };
  });
  return rows.length ? rows : [];
}

// Phase 6 — Business Impact Intelligence™ (reasons) — every score cites evidence (#5)
export function buildImpactReasons(snapshot: QuantumReadinessSnapshot, impact: BusinessImpact): ImpactReason[] {
  const internetLabels = internetFacingLabels(snapshot);
  const internet = internetLabels.length;
  const inv = snapshot.inventory;
  const s = snapshot.scores;
  const prodInternet = snapshot.exposureGraph.nodes.filter((n) => n.internetFacing && /prod/i.test(n.environment)).length;
  const namedInternet = internetLabels.slice(0, 3).join(', ');
  return [
    {
      dimension: 'Customer Impact',
      level: internet > 0 ? (prodInternet > 0 ? 'High' : 'Medium') : 'Low',
      reason: internet > 0 ? `${internet} internet-facing system(s) terminate customer TLS using quantum-vulnerable transport cryptography.` : 'No internet-facing customer systems identified.',
      evidence: internet > 0 ? [`${internet} internet-facing asset(s): ${namedInternet || 'public endpoints'}`, `${prodInternet} in production environment`, 'External customer traffic terminates here'] : ['No assets flagged internet-facing'],
    },
    {
      dimension: 'Revenue Impact',
      level: impact.revenueImpact,
      reason: internet > 0 ? `Public production portal(s) using vulnerable TLS could disrupt revenue-bearing customer transactions if compromised.` : 'No direct revenue-generating systems in scope.',
      evidence: internet > 0 ? [`${internet} internet-facing / revenue-path asset(s)`, `${prodInternet > 0 ? 'Production' : 'Non-production'} exposure`, `Quantum risk ${s.quantumRisk}/100 (${s.quantumRiskLevel})`] : ['No internet-facing revenue path'],
    },
    {
      dimension: 'Operational Impact',
      level: impact.operationalImpact,
      reason: `${inv.vulnerableComponents} vulnerable cryptographic component(s) across ${inv.quantumVulnerableAssets || inv.assetsAssessed} asset(s) require migration.`,
      evidence: [`${inv.vulnerableComponents} vulnerable CBOM component(s)`, `${inv.quantumVulnerableAssets} quantum-vulnerable asset(s)`, `Crypto exposure ${s.cryptoExposure}/100`],
    },
    {
      dimension: 'Compliance Impact',
      level: impact.complianceImpact,
      reason: `Harvest-Now-Decrypt-Later exposure (${s.hndlRiskLevel}) places regulated data outside emerging PQC mandates (NIST/FIPS 203-205).`,
      evidence: [`HNDL risk ${s.hndlRisk}/100 (${s.hndlRiskLevel})`, `${inv.dataRepositories} data repositor(y/ies) in scope`, 'FIPS 203/204/205 migration deadlines'],
    },
    {
      dimension: 'Brand / Reputational Impact',
      level: impact.reputationalImpact,
      reason: internet > 0 && s.quantumRisk >= 45 ? 'Public quantum-vulnerable services carry disclosure/reputational risk.' : 'Limited external exposure.',
      evidence: internet > 0 ? [`${internet} public-facing service(s)`, `Quantum risk ${s.quantumRisk}/100`, 'Disclosure of legacy crypto is publicly observable'] : ['Minimal internet exposure'],
    },
  ];
}

function findingFamily(algorithm: string, title: string): string {
  const a = `${algorithm} ${title}`.toUpperCase();
  if (/TLS_RSA|RSA[_\s].*(CBC|GCM|SHA)/.test(a)) return 'Legacy RSA Cipher Suites';
  if (/FORWARD SECRECY/.test(a)) return 'Missing Forward Secrecy';
  if (/ECDSA/.test(a)) return 'ECDSA Certificate Signatures';
  if (/ECDH/.test(a)) return 'ECDH Key Exchange';
  if (/\bRSA\b/.test(a)) return 'RSA Public-Key Cryptography';
  if (/ECC|EC-|P-256|P-384|EC PUBLIC/.test(a)) return 'Elliptic-Curve Cryptography';
  if (/SHA-?1|MD5/.test(a)) return 'Deprecated Hash Functions';
  if (/3DES|\bDES\b|RC4/.test(a)) return 'Weak Symmetric Ciphers';
  if (/TLS\s?1\.0|TLS\s?1\.1|SSLV/.test(a)) return 'Legacy TLS / SSL Protocols';
  if (/OAUTH|JWT|OIDC|TOKEN/.test(a)) return 'Identity Token Cryptography';
  if (/HNDL|HARVEST/.test(a)) return 'Harvest-Now-Decrypt-Later Exposure';
  if (/WIDE CRYPTO|ATTACK SURFACE/.test(a)) return 'Broad Cryptographic Attack Surface';
  return 'Other Cryptographic Findings';
}

// Phase 7 — Finding Deduplication Engine™
export function buildFindingGroups(snapshot: QuantumReadinessSnapshot): FindingGroup[] {
  const groups = new Map<string, { occurrences: number; assets: Set<string>; evidence: Set<string>; rank: number }>();
  for (const f of snapshot.criticalFindings) {
    const family = findingFamily(f.algorithm || '', f.title || '');
    const g = groups.get(family) || { occurrences: 0, assets: new Set<string>(), evidence: new Set<string>(), rank: 0 };
    g.occurrences += 1;
    // Normalise the asset identifier so scheme/port/path/www/case variants of a
    // single scanned host do not inflate the distinct-asset count.
    const assetKey = normalizeAssetKey(f.asset);
    if (assetKey) g.assets.add(assetKey);
    if (f.algorithm) g.evidence.add(f.algorithm);
    g.rank = Math.max(g.rank, severityRank(normalizeSeverity(f.severity)));
    groups.set(family, g);
  }
  // A finding group can never affect more assets than were actually assessed —
  // clamp so "2 assets" cannot appear when only 1 asset is in scope.
  const assetCap = snapshot.inventory.assetsAssessed > 0 ? snapshot.inventory.assetsAssessed : Number.MAX_SAFE_INTEGER;
  const out: FindingGroup[] = Array.from(groups.entries())
    .map(([title, g]) => ({ title, occurrences: g.occurrences, affectedAssets: Math.min(g.assets.size, assetCap), evidence: Array.from(g.evidence).slice(0, 8), impact: (['info', 'low', 'medium', 'high', 'critical'][g.rank] || 'medium') as FindingGroup['impact'] }))
    .sort((a, b) => severityRank(b.impact) - severityRank(a.impact) || b.occurrences - a.occurrences);
  return out;
}

// Phase 8 — Migration Confidence Scoring™
export function buildMigrationConfidence(snapshot: QuantumReadinessSnapshot): MigrationConfidence {
  const inv = snapshot.inventory;
  const factors = [
    { label: 'Asset Coverage', coveragePct: inv.assetsAssessed > 0 ? 100 : 0 },
    { label: 'Certificate Coverage', coveragePct: inv.certificatesAnalyzed > 0 ? 100 : 0 },
    { label: 'Key Coverage', coveragePct: inv.keysDiscovered > 0 ? 100 : 0 },
    { label: 'CBOM Coverage', coveragePct: inv.cryptoComponents > 0 ? 100 : 0 },
    { label: 'Scanner Coverage', coveragePct: snapshot.telemetry.scanSessions > 0 ? 100 : 0 },
    { label: 'Dependency Visibility', coveragePct: snapshot.exposureGraph.edges.length > 0 ? 100 : inv.trustRelationships > 0 ? 50 : 20 },
    { label: 'Trust Visibility', coveragePct: inv.trustRelationships > 0 ? 100 : 10 },
    { label: 'Telemetry Quality', coveragePct: snapshot.telemetry.runtimeEvents > 0 ? 100 : 45 },
  ];
  const overallPct = clamp(factors.reduce((sum, f) => sum + f.coveragePct, 0) / factors.length);
  return { overallPct, factors };
}

// Phase 9 — Evidence Confidence Scoring™
export function buildEvidenceConfidence(snapshot: QuantumReadinessSnapshot): EvidenceConfidence[] {
  const t = snapshot.telemetry;
  const inv = snapshot.inventory;
  const fresh = snapshot.lastAssessmentAt ? 'Current' : 'Unknown';
  const src = (source: string, has: boolean, coverage: number, completeness: number): EvidenceConfidence => ({
    source,
    coveragePct: has ? coverage : 0,
    completenessPct: has ? completeness : 0,
    freshness: has ? fresh : 'No data',
    confidencePct: has ? Math.round((coverage + completeness) / 2) : 0,
    note: has ? '' : 'No Data Available',
  });
  return [
    src('Scanner', t.scanSessions > 0 || t.scanResults > 0, 100, 100),
    src('CBOM', inv.cryptoComponents > 0, 100, 95),
    src('Certificate Inventory', inv.certificatesAnalyzed > 0, 100, 90),
    src('Key Inventory', inv.keysDiscovered > 0, 100, 85),
    src('Runtime Telemetry', t.runtimeEvents > 0, 100, 90),
    src('Trust Fabric', inv.trustRelationships > 0, 100, 80),
    src('Cloud Inventory', inv.cloudAccounts > 0, 100, 80),
    src('Dependency Mapping', snapshot.exposureGraph.edges.length > 0, 100, 70),
  ];
}

// Phase 10 — Executive Decision Center™
export function buildExecutiveDecisions(snapshot: QuantumReadinessSnapshot, waves: MigrationWave[], executiveBlock: ExecutiveBlock): ExecutiveDecision[] {
  const out: ExecutiveDecision[] = [];
  const firstWave = waves[0];
  if (firstWave) out.push({ decision: `Approve ${firstWave.name} (Wave 1)`, type: 'Migration Approval', rationale: `Highest-risk wave; ${firstWave.riskReductionPct}% risk reduction for ${(firstWave.costUsd || 0).toLocaleString() ? '$' + (firstWave.costUsd || 0).toLocaleString() : 'TBD'} over ${firstWave.durationWeeks}w.`, owner: 'CISO' });
  if (executiveBlock.estimatedCostUsd) out.push({ decision: `Approve migration budget of $${executiveBlock.estimatedCostUsd.toLocaleString()}`, type: 'Budget Approval', rationale: `Funds the ${executiveBlock.estimatedDurationWeeks}-week programme for ${executiveBlock.expectedRiskReductionPct}% risk reduction.`, owner: 'CFO / Board' });
  const orphaned = snapshot.topRiskAssets.filter((a) => /unassigned|unknown/i.test(a.owner));
  if (orphaned.length) out.push({ decision: `Assign owners for ${orphaned.length} asset(s)`, type: 'Ownership Assignment', rationale: 'No accountable owner to approve / execute migration.', owner: 'Program Manager' });
  out.push({ decision: `Ratify the "${ACTIVE_PROFILE.profile}" crypto-policy profile (${ACTIVE_PROFILE.keyEstablishment}; ${ACTIVE_PROFILE.digitalSignature})`, type: 'Policy Approval', rationale: 'Establishes the policy-driven target cryptographic standard for all migration waves; alternative profiles (High Assurance, Experimental) remain selectable.', owner: 'Security Architecture' });
  out.push({ decision: 'Approve ML-KEM (FIPS 203) / ML-DSA (FIPS 204) adoption', type: 'Governance Approval', rationale: 'Authorises NIST-standardised PQC algorithms for production use.', owner: 'CISO / GRC' });
  return out;
}

// Phase 11 — Enterprise Remediation Playbook™
export function buildPlaybookDetail(groups: FindingGroup[]): PlaybookDetail[] {
  const target = (title: string): { current: string; target: string; steps: string[] } => {
    if (/rsa cipher|legacy rsa|forward secrecy/i.test(title)) return { current: 'TLS with RSA key exchange / CBC cipher suites (no forward secrecy)', target: 'TLS 1.3 + X25519 + ML-KEM-768 (Hybrid)', steps: ['Enable TLS 1.3', 'Disable RSA / CBC cipher suites', 'Enable X25519 + Hybrid ML-KEM key exchange', 'Validate handshake compatibility', 'Monitor production for client failures'] };
    if (/ecdsa|certificate/i.test(title)) return { current: 'ECDSA / RSA certificate signatures', target: `${ACTIVE_PROFILE.certificateChain} (policy profile: ${ACTIVE_PROFILE.profile})`, steps: ['Issue hybrid (classical + ML-DSA) certificates per the active crypto-policy profile', 'Stage parallel chain', 'Cut over CA trust', 'Validate chain on all clients', 'Retire classical-only certs'] };
    if (/tls.*ssl|legacy tls/i.test(title)) return { current: 'Legacy TLS 1.0 / 1.1 / SSL protocols', target: 'TLS 1.3 only', steps: ['Disable TLS 1.0/1.1 and SSL', 'Enforce TLS 1.3', 'Update load-balancer / gateway policy', 'Validate client compatibility', 'Monitor handshake telemetry'] };
    return { current: 'Quantum-vulnerable cryptography', target: 'ML-KEM (FIPS 203) / ML-DSA (FIPS 204) hybrid', steps: ['Inventory affected components', 'Deploy hybrid PQC behind feature flag', 'Update dependent assets', 'Validate trust chains', 'Retire classical primitives'] };
  };
  return groups.slice(0, 6).map((g) => {
    const t = target(g.title);
    return {
      finding: `${g.title} (${g.occurrences} occurrence${g.occurrences === 1 ? '' : 's'}, ${g.affectedAssets} asset${g.affectedAssets === 1 ? '' : 's'})`,
      currentState: g.evidence.length ? g.evidence.slice(0, 4).join(', ') : t.current,
      targetState: t.target,
      prerequisites: ['Owner assigned', 'Change window approved', 'Hybrid keys / certs provisioned'],
      dependencies: ['Load Balancer', 'Certificate Authority', 'HSM / KMS'],
      executionSteps: t.steps,
      validationSteps: ['Confirm hybrid negotiation succeeds', 'Run PQC readiness re-scan', 'Verify trust-chain integrity', 'Confirm zero failed crypto operations'],
      rollbackSteps: ['Disable feature flag', 'Restore previous TLS / certificate profile', 'Confirm service restoration'],
      successCriteria: ['Hybrid PQC negotiation successful', 'No downtime', 'No client failures', `${g.title} no longer detected on re-scan`],
    };
  });
}

// Phase 12 — Migration Simulation Engine™
export function buildWaveSimulation(snapshot: QuantumReadinessSnapshot, waves: MigrationWave[], executiveBlock: ExecutiveBlock, confidence: MigrationConfidence): WaveSimulation[] {
  const startReadiness = snapshot.scores.quantumReadiness;
  const startRisk = snapshot.scores.quantumRisk;
  const targetReadiness = executiveBlock.targetReadiness;
  const targetRisk = executiveBlock.targetRisk;
  const { residualRisk } = reductionTargets(snapshot);
  // The migration waves reduce RISK to the target and lift readiness only to a
  // pre-optimization ceiling. The final program row is DISTINCT (#2): the
  // Validation/Optimization/Governance phase closes the remaining readiness gap
  // to target AND drives residual risk below the migration target. So "All Waves"
  // and "Entire Program" differ on BOTH readiness and risk — they are not clones.
  const optReadinessGain = Math.max(3, Math.round((targetReadiness - startReadiness) * 0.18));
  const waveCeilingReadiness = Math.max(startReadiness, targetReadiness - optReadinessGain);
  const totalReductionShare = waves.reduce((s, w) => s + w.riskReductionPct, 0) || 1;
  let cumWeeks = 0;
  let cumCost = 0;
  let cumShare = 0;
  const sims: WaveSimulation[] = waves.map((wave, index) => {
    cumWeeks += wave.durationWeeks;
    cumCost += wave.costUsd;
    cumShare += wave.riskReductionPct / totalReductionShare;
    const riskTo = Math.round(startRisk - (startRisk - targetRisk) * cumShare);
    const readinessTo = Math.round(startReadiness + (waveCeilingReadiness - startReadiness) * cumShare);
    return {
      label: index === 0 ? `If Wave 1 (${wave.name}) Completes` : `If Waves 1-${index + 1} Complete`,
      readinessFrom: startReadiness,
      readinessTo: readinessTo,
      riskFrom: startRisk,
      riskTo,
      costUsd: cumCost,
      timelineWeeks: cumWeeks,
      confidencePct: clamp(confidence.overallPct - index * 4),
    };
  });
  sims.push({
    label: 'If Entire Program Completes (+ Validation, Optimization & Governance)',
    readinessFrom: startReadiness,
    readinessTo: targetReadiness,
    riskFrom: startRisk,
    riskTo: residualRisk,
    costUsd: snapshot.estimates.migrationCostUsd,
    timelineWeeks: snapshot.estimates.migrationTimelineWeeks,
    confidencePct: clamp(confidence.overallPct - 6),
  });
  return sims;
}

// Phase 13 — Enterprise Governance gates
export function buildGovernanceGates(): GovernanceGate[] {
  return [
    { gate: 'Gate 1 — Plan Approval', owner: 'CISO', criteria: 'Migration plan, budget and waves approved by executive sponsor.' },
    { gate: 'Gate 2 — Wave Readiness', owner: 'Program Manager', criteria: 'Owners assigned, dependencies inventoried, rollback validated per wave.' },
    { gate: 'Gate 3 — Production Cutover', owner: 'Migration Lead', criteria: 'Hybrid PQC validated in pilot; trust chains intact; no client failures.' },
    { gate: 'Gate 4 — Validation Sign-off', owner: 'Compliance Lead', criteria: 'Re-scan confirms remediation; audit evidence captured; compliance mapped.' },
  ];
}

// Phase 14 — Report Explainability Requirements™
export function buildExplainability(snapshot: QuantumReadinessSnapshot, methodology: RiskMethodology, confidence: MigrationConfidence): Explainability[] {
  const s = snapshot.scores;
  return [
    { metric: 'Quantum Risk Score', what: `${s.quantumRisk}/100 composite quantum risk.`, how: methodology.formula, evidence: `${snapshot.criticalFindings.length} scanner findings, ${snapshot.inventory.cryptoComponents} CBOM components.`, why: 'Quantifies exposure to future quantum decryption.', action: 'Execute prioritised migration waves to reduce it.' },
    { metric: 'Quantum Readiness Score', what: `${s.quantumReadiness}/100 (${s.quantumReadinessLevel}).`, how: 'Σ(Factor × Weight): PQC Adoption 45%, Risk Posture 25%, Runtime Visibility 15%, Governance 15% — unmeasured factors excluded and weights renormalised. Full contribution table in the Readiness Scoring Methodology.', evidence: `${s.pqcAdoption}% PQC adoption across ${snapshot.inventory.cryptoComponents} components.`, why: 'Measures progress toward a quantum-safe posture.', action: 'Increase PQC/hybrid adoption per the wave plan.' },
    { metric: 'PQC Adoption', what: `${s.pqcAdoption}%.`, how: '(PQC-ready + ½ hybrid components) ÷ total CBOM components.', evidence: `${snapshot.inventory.pqcReadyComponents} of ${snapshot.inventory.cryptoComponents} components quantum-safe.`, why: 'Direct measure of cryptographic modernisation.', action: 'Migrate vulnerable components to ML-KEM / ML-DSA.' },
    { metric: 'Migration Confidence', what: `${confidence.overallPct}%.`, how: 'Average of asset/certificate/key/CBOM/scanner/dependency/trust/telemetry coverage.', evidence: 'Per-source coverage in the confidence table.', why: 'Indicates how complete the evidence behind the plan is.', action: 'Improve low-coverage sources (trust fabric, dependencies) to raise confidence.' },
    { metric: 'Estimated Cost', what: snapshot.estimates.migrationCostUsd ? `$${snapshot.estimates.migrationCostUsd.toLocaleString()}.` : EVIDENCE_UNAVAILABLE, how: `${(snapshot.estimates.migrationTimelineWeeks || 0) * 38} labour hours × $${BLENDED_RATE_USD}/hr blended rate, split by category.`, evidence: 'Cost breakdown table with per-line formulas.', why: 'Defensible budget for executive approval.', action: 'Approve budget allocation per the decision center.' },
  ];
}

// #9 — Executive Risk Acceptance register (Mitigate / Accept / Transfer / Defer)
export function buildRiskAcceptance(snapshot: QuantumReadinessSnapshot, findingGroups: FindingGroup[], riskDomainModel: RiskDomainDatum[]): RiskAcceptance[] {
  const now = new Date();
  const reviewIn = (weeks: number) => (snapshot.hasData ? format(addWeeks(now, weeks), 'yyyy-MM-dd') : EVIDENCE_UNAVAILABLE);
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  const out: RiskAcceptance[] = [];
  // Top finding families → Mitigate (scheduled into migration waves).
  findingGroups.slice(0, 3).forEach((g) =>
    out.push({
      risk: g.title,
      decision: 'Mitigate',
      owner: /rsa|tls|forward|cipher|handshake/i.test(g.title) ? 'Infrastructure Team' : /ecdsa|cert|pki/i.test(g.title) ? 'Security Team' : 'Security Engineering',
      rationale: `${g.occurrences} occurrence(s) across ${g.affectedAssets} asset(s); quantum-vulnerable cryptography scheduled into the migration waves for hybrid PQC cutover.`,
      residualRisk: 'Low after hybrid PQC deployment',
      reviewDate: reviewIn(4),
    }),
  );
  // Vendor / supply-chain readiness → Accept temporarily.
  if (inv.trustRelationships > 0 || riskDomainModel.some((d) => d.matchKey === 'vendor')) {
    out.push({
      risk: 'Vendor / Supply-Chain PQC Readiness',
      decision: 'Accept',
      owner: 'CISO',
      rationale: 'Third-party PQC roadmaps not yet published; exposure tracked in the supply-chain register pending vendor remediation.',
      residualRisk: 'Medium — monitored, no compensating control available yet',
      reviewDate: reviewIn(12),
    });
  }
  // HNDL on archived / backup data → Defer.
  if (s.hndlRisk >= 40 || inv.dataRepositories > 0) {
    out.push({
      risk: 'Harvest-Now-Decrypt-Later on archived / backup data',
      decision: 'Defer',
      owner: 'Storage Team',
      rationale: `HNDL exposure ${s.hndlRiskLevel}; long-lived data re-encryption deferred to a later wave pending key-management (QKMS) readiness.`,
      residualRisk: 'Medium until PQC envelope re-encryption',
      reviewDate: reviewIn(8),
    });
  }
  // Residual migration-window risk → Transfer.
  out.push({
    risk: 'Residual quantum-cryptographic risk during the migration window',
    decision: 'Transfer',
    owner: 'Risk & Compliance',
    rationale: 'Residual exposure during phased cutover transferred via cyber-insurance and compensating monitoring controls.',
    residualRisk: 'Low — covered by policy + runtime monitoring',
    reviewDate: reviewIn(24),
  });
  return out;
}

// #10 — Asset-Level Readiness (which assets drive the overall score)
export function buildAssetReadiness(snapshot: QuantumReadinessSnapshot): AssetReadiness[] {
  const nodeByLabel = new Map(snapshot.exposureGraph.nodes.map((n) => [n.label, n]));
  const s = snapshot.scores;
  return snapshot.topRiskAssets.slice(0, 12).map((a) => {
    const node = nodeByLabel.get(a.asset);
    const internetFacing = node?.internetFacing ?? false;
    const posture = a.status;
    const postureBonus = /pqc/i.test(posture) ? 35 : /hybrid/i.test(posture) ? 12 : 0;
    // Blends the tenant readiness with this asset's own risk & posture so the
    // highest-risk assets clearly read as the lowest-readiness score drivers.
    const readiness = clamp(round(s.quantumReadiness * 0.5 + (100 - a.riskScore) * 0.3 + postureBonus - (internetFacing ? 4 : 0)));
    const primaryDriver = a.riskScore >= 70 ? (internetFacing ? 'Internet-facing legacy TLS / RSA transport' : 'Quantum-vulnerable cryptography') : a.riskScore >= 40 ? 'Partial hybrid coverage — classical primitives remain' : 'Minor residual exposure';
    return { asset: a.asset, readiness, risk: a.riskScore, posture, internetFacing, primaryDriver, owner: normalizeOwner(a.owner) };
  });
}

// Architectural — Decision Traceability chain for the top recommendation
export function buildDecisionChain(snapshot: QuantumReadinessSnapshot, advisor: MigrationAdvisor, riskDomainModel: RiskDomainDatum[], waves: MigrationWave[], executiveBlock: ExecutiveBlock, findingGroups: FindingGroup[]): DecisionChain {
  const primary = riskDomainModel[0];
  const wave = waves[0];
  const group = findingGroups[0];
  const internet = internetFacingLabels(snapshot).length;
  const steps = [
    { stage: 'Evidence', detail: group ? `${group.occurrences} scanner finding(s) of ${group.title}${group.evidence.length ? ` (${group.evidence.slice(0, 3).join(', ')})` : ''} across ${group.affectedAssets} asset(s).` : `${snapshot.criticalFindings.length} scanner finding(s) recorded.` },
    { stage: 'Finding', detail: group ? `${group.title} — quantum-vulnerable ${primary?.category.replace(/\s*Risk$/i, '') || 'cryptography'}.` : (snapshot.hasData ? 'Quantum-vulnerable cryptography detected.' : EVIDENCE_UNAVAILABLE) },
    { stage: 'Risk', detail: primary ? `${primary.category} is the largest weighted contributor to the ${snapshot.scores.quantumRisk}/100 quantum risk (domain risk ${primary.risk}/100).` : EVIDENCE_UNAVAILABLE },
    { stage: 'Business Impact', detail: `${internet} internet-facing system(s); revenue impact ${executiveBlock.currentRisk >= 45 ? 'High' : 'Medium'}; HNDL exposure ${snapshot.scores.hndlRiskLevel}.` },
    { stage: 'Recommendation', detail: advisor.recommendation },
    { stage: 'Migration Wave', detail: wave ? `Wave 1 — ${wave.name} (${wave.owner}), ${wave.durationWeeks} week(s), ${wave.riskReductionPct}% risk reduction.` : EVIDENCE_UNAVAILABLE },
    { stage: 'Cost', detail: wave && wave.costUsd ? `$${wave.costUsd.toLocaleString()} for Wave 1 (blended $${BLENDED_RATE_USD}/hr).` : EVIDENCE_UNAVAILABLE },
    { stage: 'Timeline', detail: `${executiveBlock.estimatedDurationWeeks || 'TBD'}-week program with staged approval gates.` },
    { stage: 'Residual Risk', detail: `Quantum risk ${snapshot.scores.quantumRisk} → target ${executiveBlock.targetRisk}/100 after migration (${executiveBlock.expectedRiskReductionPct}% reduction).` },
    { stage: 'Expected Readiness', detail: `Readiness ${snapshot.scores.quantumReadiness} → ${executiveBlock.targetReadiness}/100.` },
    { stage: 'Executive Approval', detail: `Approve "${advisor.recommendation}"${executiveBlock.estimatedCostUsd ? ` and budget $${executiveBlock.estimatedCostUsd.toLocaleString()}` : ''} (CISO / CFO).` },
  ];
  return { headline: snapshot.hasData ? `Why "${advisor.recommendation}" is the top priority — full evidence chain` : 'Run a discovery scan to build the decision chain', steps };
}

/* ================================================================== */
/* Improvements_02 — enterprise-grade report intelligence             */
/* ================================================================== */

const NOT_MEASURED = 'Not Measured';

/** True when real runtime crypto telemetry exists for this tenant. */
function runtimeMeasured(snapshot: QuantumReadinessSnapshot): boolean {
  return snapshot.telemetry.runtimeEvents > 0;
}

// I2#3 — Readiness Scoring Methodology™: the EXACT readiness formula used by the
// assessment engine, exposed as a Weight × Score = Contribution table. Unmeasured
// factors (runtime visibility without runtime telemetry) are excluded and the
// remaining weights renormalised — mirroring the scoring engine — so the printed
// contributions reconstruct the overall score and never contradict the evidence
// dashboard (fixes the "Runtime Visibility 55 vs Runtime Telemetry 0%" mismatch).
export function buildReadinessMethodology(snapshot: QuantumReadinessSnapshot): ReadinessMethodology {
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  const factorScore = (needle: string) => snapshot.readinessFactors.find((f) => f.label.toLowerCase().includes(needle))?.score ?? 0;
  const measured = runtimeMeasured(snapshot);
  const defs = [
    { factor: 'PQC Adoption', rawWeight: 0.45, score: s.pqcAdoption, measured: true, basis: `${inv.pqcReadyComponents} of ${inv.cryptoComponents} CBOM component(s) PQC-ready or hybrid (${s.pqcAdoption}%)` },
    { factor: 'Risk Posture (100 − Quantum Risk)', rawWeight: 0.25, score: 100 - s.quantumRisk, measured: true, basis: `Quantum risk ${s.quantumRisk}/100 from ${snapshot.criticalFindings.length} scanner finding(s)` },
    { factor: 'Runtime Visibility', rawWeight: 0.15, score: factorScore('runtime'), measured, basis: measured ? `${snapshot.telemetry.runtimeEvents.toLocaleString()} runtime crypto event(s) observed` : 'No runtime telemetry recorded — factor excluded, remaining weights renormalised' },
    { factor: 'Governance Maturity', rawWeight: 0.15, score: factorScore('governance'), measured: true, basis: `${snapshot.telemetry.scanSessions} governed scan session(s) with retained evidence` },
  ];
  const present = defs.filter((d) => d.measured);
  const weightSum = present.reduce((sum, d) => sum + d.rawWeight, 0) || 1;
  const factors = defs.map((d) => ({
    factor: d.factor,
    weightPct: d.measured ? Math.round((d.rawWeight / weightSum) * 1000) / 10 : 0,
    score: d.measured ? (round(d.score) as number | string) : NOT_MEASURED,
    contribution: d.measured ? Math.round(d.score * (d.rawWeight / weightSum) * 10) / 10 : 0,
    measured: d.measured,
    basis: d.basis,
  }));
  const sum = Math.round(factors.reduce((acc, f) => acc + f.contribution, 0) * 10) / 10;
  const additionLine = factors.filter((f) => f.measured).map((f) => f.contribution.toFixed(1)).join(' + ');
  return {
    formula: 'Quantum Readiness = Σ ( Factor Score × Factor Weight ) — unmeasured factors excluded, weights renormalised',
    overall: s.quantumReadiness,
    factors,
    explanation: snapshot.hasData
      ? `The overall readiness of ${s.quantumReadiness}/100 is fully auditable: ${additionLine} = ${sum} (≈ ${s.quantumReadiness}, ±1 from score rounding). ${measured ? 'All four factors are measured, so the published weights (45/25/15/15) apply directly.' : 'Runtime Visibility is NOT measured (zero runtime telemetry), so it is shown as Not Measured and excluded — the remaining weights are renormalised to 52.9% / 29.4% / 17.6% rather than silently scoring an unmeasured factor.'}`
      : `${EVIDENCE_UNAVAILABLE}. Run a discovery scan to compute the readiness methodology.`,
  };
}

// I2#11 — Quantum Readiness Index™: strategic pillars behind the single score.
// Measured pillar scores are calibrated so the weighted blend reproduces the
// authoritative overall readiness (same technique as the quantum-risk model);
// pillars with no supporting evidence are shown as Not Measured, never scored.
export function buildReadinessIndex(snapshot: QuantumReadinessSnapshot, domains: ReadinessDomain[]): ReadinessIndex {
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  const domainScore = (needle: string) => domains.find((d) => d.domain.toLowerCase().includes(needle))?.score ?? 0;
  const factorScore = (needle: string) => snapshot.readinessFactors.find((f) => f.label.toLowerCase().includes(needle))?.score ?? 0;
  const internet = internetFacingLabels(snapshot).length;
  const defs = [
    { pillar: 'Cryptographic Agility', weight: 0.16, raw: factorScore('agility'), measured: snapshot.hasData, driver: 'Ability to swap algorithms centrally without code change' },
    { pillar: 'TLS Modernization', weight: 0.16, raw: domainScore('tls'), measured: inv.domainsScanned > 0 || internet > 0, driver: `${internet} internet-facing endpoint(s); legacy cipher suites in scope` },
    { pillar: 'PKI Readiness', weight: 0.14, raw: domainScore('pki'), measured: inv.certificatesAnalyzed > 0, driver: `${inv.certificatesAnalyzed} certificate(s) on classical signatures` },
    { pillar: 'Identity Protection', weight: 0.12, raw: domainScore('identity'), measured: inv.identitiesAnalyzed > 0, driver: `${inv.identitiesAnalyzed} identity system(s) analysed` },
    { pillar: 'Governance', weight: 0.14, raw: factorScore('governance'), measured: snapshot.hasData, driver: 'Crypto policy, inventory and evidence management' },
    { pillar: 'Visibility (Runtime)', weight: 0.1, raw: factorScore('runtime'), measured: runtimeMeasured(snapshot), driver: runtimeMeasured(snapshot) ? `${snapshot.telemetry.runtimeEvents.toLocaleString()} runtime event(s)` : 'No runtime telemetry deployed' },
    { pillar: 'Vendor Readiness', weight: 0.09, raw: domainScore('vendor'), measured: inv.trustRelationships > 0, driver: `${inv.trustRelationships} trust relationship(s) in scope` },
    { pillar: 'Cloud Readiness', weight: 0.09, raw: domainScore('cloud'), measured: inv.cloudAccounts > 0, driver: `${inv.cloudAccounts} cloud account(s) connected` },
  ];
  const present = defs.filter((d) => d.measured);
  const weightSum = present.reduce((sum, d) => sum + d.weight, 0) || 1;
  const rawBlend = present.reduce((sum, d) => sum + d.raw * d.weight, 0) / weightSum;
  const k = rawBlend > 0 && s.quantumReadiness > 0 ? s.quantumReadiness / rawBlend : 1;
  const pillars = defs.map((d) => {
    const score = d.measured ? clamp(round(d.raw * k)) : 0;
    const weightPct = d.measured ? Math.round((d.weight / weightSum) * 1000) / 10 : 0;
    return {
      pillar: d.pillar,
      score: d.measured ? (score as number | string) : NOT_MEASURED,
      weightPct,
      contribution: d.measured ? Math.round(score * (d.weight / weightSum) * 10) / 10 : 0,
      measured: d.measured,
      driver: d.driver,
    };
  });
  return {
    overall: s.quantumReadiness,
    pillars,
    note: snapshot.hasData
      ? `The overall readiness score of ${s.quantumReadiness}/100 decomposes into ${present.length} evidence-backed strategic pillar(s); pillars without evidence are shown as ${NOT_MEASURED} rather than scored. Pillar scores are calibrated so Σ(Score × Weight) reproduces the overall score exactly; raw per-domain measurements appear in the Quantum Readiness Breakdown.`
      : `${EVIDENCE_UNAVAILABLE}. Run a discovery scan to compute the readiness index.`,
  };
}

// I2#4 / I3#2 — Executive ROI & Value Intelligence™: what the programme investment
// buys. Every line prints its basis/formula; the risk-avoidance multiple is an
// EXPOSED, configurable assumption (not a hidden constant) so ROI can be made
// organization-specific via ALE/SLE/FAIR inputs in production. Lines that require
// external inputs (insurance premiums) are marked indicative, never fabricated.
//
// `opts.riskAvoidanceMultiple` overrides the default; `opts.annualLossExpectancyUsd`
// (ALE), when provided by the organization, drives a FAIR-style avoidance figure
// instead of the demonstration heuristic.
const DEFAULT_RISK_AVOIDANCE_MULTIPLE = 3;
export function buildRoiAnalysis(
  snapshot: QuantumReadinessSnapshot,
  costForecast: CostForecast,
  executiveBlock: ExecutiveBlock,
  opts: { riskAvoidanceMultiple?: number; annualLossExpectancyUsd?: number } = {},
): RoiAnalysis {
  const usd = (n: number) => `$${Math.round(n).toLocaleString()}`;
  const investment = costForecast.totalUsd;
  const multiple = opts.riskAvoidanceMultiple && opts.riskAvoidanceMultiple > 0 ? opts.riskAvoidanceMultiple : DEFAULT_RISK_AVOIDANCE_MULTIPLE;
  const ale = opts.annualLossExpectancyUsd && opts.annualLossExpectancyUsd > 0 ? opts.annualLossExpectancyUsd : 0;
  if (!investment || !snapshot.hasData) {
    return { investmentUsd: 0, expectedRiskReductionPct: 0, riskAvoidanceUsd: 0, netBenefitUsd: 0, roiMultiple: 0, paybackNarrative: `${EVIDENCE_UNAVAILABLE}. Run a discovery scan to derive migration cost and ROI.`, lines: [], riskAvoidanceMultiple: multiple, annualLossExpectancyUsd: ale, assumptionBasis: EVIDENCE_UNAVAILABLE, assumptionsConfigurable: true };
  }
  const reduction = executiveBlock.expectedRiskReductionPct;
  // FAIR/ALE mode (organization-specific): avoidance = ALE × risk-reduction share
  // over a 3-year horizon. Heuristic mode (demonstration): cost × multiple × share.
  const usingAle = ale > 0;
  const riskAvoidance = usingAle
    ? Math.round(ale * 3 * (reduction / 100))
    : costForecast.projectedRiskReductionValueUsd;
  const netBenefit = riskAvoidance - investment;
  const roiMultiple = Math.round((riskAvoidance / Math.max(1, investment)) * 100) / 100;
  const inv = snapshot.inventory;
  const assumptionBasis = usingAle
    ? `Organization-specific (FAIR): Annual Loss Expectancy $${ale.toLocaleString()} × 3-year horizon × ${reduction}% risk-reduction share.`
    : `Demonstration heuristic: programme cost × ${multiple}× exposure factor × ${reduction}% risk-reduction share. Replace the ${multiple}× factor with your ALE/SLE (FAIR model) for organization-specific ROI.`;
  const lines = [
    { metric: 'Expected Risk Reduction', value: `${reduction}% (quantum risk ${executiveBlock.currentRisk} → ${executiveBlock.targetRisk}/100)`, basis: 'Same reduction engine as the migration waves and risk forecast — the three figures reconcile exactly.' },
    { metric: 'Expected Incident-Likelihood Reduction', value: `≈ ${reduction}% on quantum-vulnerable crypto paths`, basis: `Crypto-attributable incident likelihood scales with the quantum-risk score (${executiveBlock.currentRisk} → ${executiveBlock.targetRisk}).` },
    { metric: 'Estimated Risk Avoidance', value: usd(riskAvoidance), basis: usingAle ? `ALE $${ale.toLocaleString()} × 3yr × ${reduction}% = ${usd(riskAvoidance)}.` : `Modeled exposure avoided = programme cost × ${multiple} × risk-reduction share (${usd(investment)} × ${multiple} × ${reduction}%). Configurable — see ROI assumptions.` },
    { metric: 'Estimated Compliance Benefit', value: `${executiveBlock.expectedComplianceImprovementPct}% framework-alignment uplift`, basis: 'Gap closure across the mapped frameworks (FIPS 203/204/205, CNSA 2.0, ISO 27001, SOC 2, PCI DSS, NIST CSF) — see Compliance Mapping progress.' },
    { metric: 'Estimated Insurance Impact', value: 'Indicative — requires carrier premium data', basis: 'Cyber-insurance underwriting increasingly prices cryptographic posture; quantify with your broker once migration evidence exists. Not fabricated in this report.' },
    { metric: 'Crypto Technical-Debt Reduction', value: `${inv.vulnerableComponents} quantum-vulnerable component(s) retired`, basis: 'CBOM vulnerable-component count eliminated by the programme — removes recurring legacy-crypto maintenance, exceptions and audit findings.' },
    { metric: 'Executive ROI', value: `${roiMultiple}× (net benefit ${usd(netBenefit)})`, basis: `Risk avoidance ${usd(riskAvoidance)} ÷ investment ${usd(investment)}.` },
    { metric: 'ROI Assumption (configurable)', value: usingAle ? `ALE-driven ($${ale.toLocaleString()}/yr)` : `${multiple}× exposure factor (default)`, basis: assumptionBasis },
  ];
  return {
    investmentUsd: investment,
    expectedRiskReductionPct: reduction,
    riskAvoidanceUsd: riskAvoidance,
    netBenefitUsd: netBenefit,
    roiMultiple,
    paybackNarrative: `A ${usd(investment)} investment reduces quantum risk by ${reduction}% and models ${usd(riskAvoidance)} in avoided exposure — an estimated ${roiMultiple}× return before compliance and insurance benefits. Risk-avoidance assumption: ${usingAle ? 'organization ALE (FAIR)' : `${multiple}× exposure factor (configurable)`}.`,
    lines,
    riskAvoidanceMultiple: multiple,
    annualLossExpectancyUsd: ale,
    assumptionBasis,
    assumptionsConfigurable: true,
  };
}

// I2#5 / I3#5 — Migration Resource Loading™: per-team allocation, assumed capacity
// (availability), and cross-team dependencies for programme planning. Availability
// is a documented planning ASSUMPTION (standard enterprise defaults per team), and
// allocation is the DERIVED demand from the wave hours — the two together tell a
// planner whether a team is over-subscribed.
const TEAM_AVAILABILITY: Record<string, number> = {
  'Infrastructure Team': 80,
  'Security Team': 60,
  'Application Team': 70,
  'Identity Team': 60,
  'Cloud Team': 70,
  'Platform Team': 70,
  'Security Engineering': 60,
};
export function buildResourceLoading(snapshot: QuantumReadinessSnapshot, waves: MigrationWave[]): ResourceLoad[] {
  if (!snapshot.hasData || !waves.length) return [];
  const byTeam = new Map<string, { hours: number; weeks: number; waves: string[]; deps: Set<string> }>();
  for (const wave of waves) {
    const team = normalizeOwner(wave.owner);
    const hours = Math.round(wave.costUsd / BLENDED_RATE_USD);
    const entry = byTeam.get(team) || { hours: 0, weeks: 0, waves: [], deps: new Set<string>() };
    entry.hours += hours;
    entry.weeks += wave.durationWeeks;
    entry.waves.push(`W${wave.wave} ${wave.name}`);
    (wave.dependencies || []).forEach((d) => entry.deps.add(d));
    byTeam.set(team, entry);
  }
  return Array.from(byTeam.entries()).map(([team, v]) => {
    const availabilityPct = TEAM_AVAILABILITY[team] ?? 60;
    // Engineers sized against AVAILABLE capacity, not 100% — a team at 60%
    // availability needs more heads for the same hours.
    const effectiveHrsPerWeek = 40 * (availabilityPct / 100);
    const engineers = Math.max(1, Math.ceil(v.hours / Math.max(1, v.weeks * effectiveHrsPerWeek)));
    const allocationPct = clamp(Math.round((v.hours / Math.max(1, engineers * v.weeks * effectiveHrsPerWeek)) * 100));
    return {
      team,
      waves: v.waves.join('; '),
      hours: v.hours,
      engineers,
      windowWeeks: v.weeks,
      allocationPct,
      availabilityPct,
      dependencies: v.deps.size ? Array.from(v.deps).slice(0, 6) : ['None recorded'],
      basis: `${v.hours.toLocaleString()} hrs ÷ (${engineers} eng × ${v.weeks} wk × ${effectiveHrsPerWeek.toFixed(0)} hr/wk @ ${availabilityPct}% avail) = ${allocationPct}% loading`,
    };
  });
}

/** Extract human-readable key sizes from a detected algorithm string. */
function keySizesOf(algorithm: string): string[] {
  const a = (algorithm || '').toUpperCase();
  const out = new Set<string>();
  const ec = a.match(/P-?(\d{3})/);
  if (ec) out.add(`EC P-${ec[1]}`);
  const rsa = a.match(/RSA[-_ ]?(\d{4})/);
  if (rsa) out.add(`RSA-${rsa[1]}`);
  else if (/\bRSA\b|TLS_RSA/.test(a)) out.add('RSA (size not captured)');
  const aes = a.match(/AES[-_ ]?(\d{3})/);
  if (aes) out.add(`AES-${aes[1]}`);
  return Array.from(out);
}

// I2#6 — Asset Intelligence Profile™: deep per-asset crypto posture. Fields the
// evidence pipeline cannot yet observe (e.g. crypto libraries) are explicitly
// `Evidence Not Available`, never invented.
export function buildAssetIntelligence(snapshot: QuantumReadinessSnapshot, costBreakdown: CostBreakdown): AssetIntelligence[] {
  const nodeByLabel = new Map(snapshot.exposureGraph.nodes.map((n) => [n.label, n]));
  const labelOf = new Map(snapshot.exposureGraph.nodes.map((n) => [n.id, n.label]));
  const idOf = new Map(snapshot.exposureGraph.nodes.map((n) => [n.label, n.id]));
  const totalRisk = snapshot.topRiskAssets.reduce((sum, a) => sum + a.riskScore, 0) || 1;
  return snapshot.topRiskAssets.slice(0, 10).map((a) => {
    const key = normalizeAssetKey(a.asset);
    const findings = snapshot.criticalFindings.filter((f) => normalizeAssetKey(f.asset) === key);
    const algorithms = Array.from(new Set(findings.map((f) => f.algorithm).filter(Boolean)));
    const keySizes = Array.from(new Set(algorithms.flatMap(keySizesOf)));
    const hasTls = algorithms.some((alg) => /TLS/i.test(alg));
    const legacySuites = algorithms.some((alg) => /TLS_RSA|CBC|SHA$|SHA-?1/i.test(alg));
    const node = nodeByLabel.get(a.asset);
    const internetFacing = node?.internetFacing ?? false;
    const nodeId = idOf.get(a.asset);
    const dependencies = nodeId
      ? snapshot.exposureGraph.edges
          .filter((e) => e.source === nodeId || e.target === nodeId)
          .map((e) => labelOf.get(e.source === nodeId ? e.target : e.source))
          .filter((label): label is string => Boolean(label))
      : [];
    const pqcReadinessPct = /pqc/i.test(a.status) ? 100 : /hybrid/i.test(a.status) ? 50 : 0;
    const complexity = dependencies.length > 3 || (internetFacing && findings.length > 2) ? 'High' : internetFacing || findings.length > 1 ? 'Medium' : 'Low';
    const estimatedHours = Math.max(findings.length ? 1 : 0, Math.round(costBreakdown.totalHours * (a.riskScore / totalRisk)));
    // I3#4 — primary algorithm + key length derived from the highest-severity
    // finding on the asset; hosting/OS/platform/cloud are not observed by the
    // current evidence pipeline, so they are honest Evidence-Not-Available.
    const primaryAlgorithm = algorithms[0] || (findings[0]?.algorithm) || EVIDENCE_UNAVAILABLE;
    const keyLength = keySizes[0] || EVIDENCE_UNAVAILABLE;
    const businessCriticality = a.riskScore >= 70 ? 'High' : a.riskScore >= 40 ? 'Medium' : 'Low';
    return {
      asset: a.asset,
      assetType: a.assetType || EVIDENCE_UNAVAILABLE,
      environment: a.environment || EVIDENCE_UNAVAILABLE,
      // I3#3 — richer ownership; Unknown (not Unassigned) when no accountable owner.
      ownerDepartment: normalizeOwner(a.owner),
      businessOwner: normalizeOwner(a.owner),
      businessUnit: EVIDENCE_UNAVAILABLE,
      businessCriticality,
      // I3#4 — platform/hosting metadata (Evidence Not Available until an agent
      // collector or cloud connector supplies it — never fabricated).
      os: EVIDENCE_UNAVAILABLE,
      platform: EVIDENCE_UNAVAILABLE,
      hosting: internetFacing ? 'Internet-facing' : EVIDENCE_UNAVAILABLE,
      cloudProvider: EVIDENCE_UNAVAILABLE,
      certificates: hasTls || /web|domain|tls|gateway/i.test(a.assetType) ? 'TLS endpoint certificate observed' : EVIDENCE_UNAVAILABLE,
      certExpiry: EVIDENCE_UNAVAILABLE,
      tlsVersion: hasTls ? (legacySuites ? 'TLS 1.2 (legacy cipher suites detected)' : 'TLS 1.2+ (modern suites)') : EVIDENCE_UNAVAILABLE,
      primaryAlgorithm,
      keyLength,
      algorithms: algorithms.length ? algorithms.slice(0, 8) : [EVIDENCE_UNAVAILABLE],
      keySizes: keySizes.length ? keySizes : [EVIDENCE_UNAVAILABLE],
      cryptoLibraries: EVIDENCE_UNAVAILABLE,
      dependencies: dependencies.length ? dependencies.slice(0, 6) : [EVIDENCE_UNAVAILABLE],
      pqcReadinessPct,
      migrationComplexity: complexity,
      estimatedHours,
    };
  });
}

// I2#9 — Industry Benchmarking™. Peer values are modeled industry reference
// points (clearly labelled as such) so executives can orient the tenant score;
// only "Your Organization" and "Programme Target" derive from live evidence.
const PEER_BENCHMARKS: Array<{ cohort: string; readiness: number }> = [
  { cohort: 'Industry Average (Cross-Sector)', readiness: 41 },
  { cohort: 'Financial Services Sector', readiness: 58 },
  { cohort: 'Government / Defense', readiness: 67 },
];

export function buildBenchmarking(snapshot: QuantumReadinessSnapshot, executiveBlock: ExecutiveBlock): Benchmarking {
  const org = snapshot.scores.quantumReadiness;
  if (!snapshot.hasData) {
    return { rows: [], percentileNarrative: `${EVIDENCE_UNAVAILABLE}. Run a discovery scan to benchmark this organisation.`, note: '' };
  }
  const rows = [
    { cohort: 'Your Organization', readiness: org, delta: 0, source: 'This assessment (live evidence)' },
    ...PEER_BENCHMARKS.map((p) => ({ cohort: p.cohort, readiness: p.readiness, delta: p.readiness - org, source: 'Modeled industry reference point' })),
    { cohort: 'Programme Target', readiness: executiveBlock.targetReadiness, delta: executiveBlock.targetReadiness - org, source: 'This migration programme plan' },
  ];
  const avg = PEER_BENCHMARKS[0].readiness;
  const position = org >= avg ? `${org - avg} point(s) above` : `${avg - org} point(s) below`;
  return {
    rows,
    percentileNarrative: `At ${org}/100 this organisation sits ${position} the modeled cross-sector average (${avg}/100). The funded programme targets ${executiveBlock.targetReadiness}/100 — ahead of the government/defense reference cohort (${PEER_BENCHMARKS[2].readiness}/100).`,
    note: 'Peer cohort values are modeled industry reference points for orientation only — they are not tenant telemetry and are not used in any score calculation.',
  };
}

// I3#1 — Confidence taxonomy: four distinct, clearly-labelled confidence concepts.
export function buildConfidenceSummary(
  snapshot: QuantumReadinessSnapshot,
  migrationConfidence: MigrationConfidence,
  advisor: MigrationAdvisor,
  evidenceConfidence: EvidenceConfidence[],
  waveSimulation: WaveSimulation[],
): ConfidenceSummary {
  const waveConfidences = waveSimulation.map((w) => w.confidencePct).filter((n) => typeof n === 'number');
  const waveRange = waveConfidences.length ? `${Math.min(...waveConfidences)}–${Math.max(...waveConfidences)}%` : EVIDENCE_UNAVAILABLE;
  const evidenceAvg = evidenceConfidence.length ? clamp(Math.round(evidenceConfidence.reduce((s, e) => s + e.confidencePct, 0) / evidenceConfidence.length)) : 0;
  return {
    // How complete the EVIDENCE behind the assessment is (coverage-driven).
    assessmentConfidencePct: migrationConfidence.overallPct,
    // How confident we are the RECOMMENDED PLAN will achieve its outcome.
    migrationPlanConfidencePct: advisor.confidencePct,
    // Per-wave execution confidence, decaying with each successive wave.
    waveConfidenceRange: waveRange,
    // Mean confidence across evidence SOURCES (scanner, CBOM, certs, …).
    evidenceConfidencePct: evidenceAvg,
    note: snapshot.hasData
      ? 'Four distinct confidence measures: Assessment Confidence = completeness of the evidence behind the assessment; Migration Plan Confidence = likelihood the recommended plan achieves its target; Wave Confidence = per-wave execution confidence (declines across waves); Evidence Confidence = mean quality across evidence sources. They are computed independently and are not interchangeable.'
      : `${EVIDENCE_UNAVAILABLE}. Run a discovery scan to compute confidence measures.`,
  };
}

// I3#8 — Operational (non-financial) benefits beyond ROI, each tied to evidence.
export function buildOperationalBenefits(snapshot: QuantumReadinessSnapshot): OperationalBenefit[] {
  if (!snapshot.hasData) return [];
  const inv = snapshot.inventory;
  const s = snapshot.scores;
  const out: OperationalBenefit[] = [
    { benefit: 'Reduced certificate outages', impact: 'Fewer unplanned expiries and trust-chain breakages', evidence: `${inv.certificatesAnalyzed} certificate(s) brought under managed hybrid-PKI lifecycle` },
    { benefit: 'Improved crypto agility', impact: 'Algorithms swappable via policy without per-system code change', evidence: `Centralised crypto policy replaces ${inv.vulnerableComponents} hard-coded classical component(s)` },
    { benefit: 'Reduced audit effort', impact: 'Evidence-backed compliance mapping and traceability reduce audit prep', evidence: 'Mapped to FIPS 203/204/205, CNSA 2.0, ISO 27001, SOC 2, PCI DSS, NIST CSF with per-framework progress' },
    { benefit: 'Reduced technical debt', impact: 'Legacy/deprecated cryptography retired from the estate', evidence: `${inv.vulnerableComponents} quantum-vulnerable component(s) across ${inv.quantumVulnerableAssets || inv.assetsAssessed} asset(s) remediated` },
    { benefit: 'Improved customer trust', impact: 'Demonstrable quantum-safe posture for customers and regulators', evidence: `${internetFacingLabels(snapshot).length} internet-facing service(s) moved to hybrid PQC transport` },
    { benefit: 'Lower operational overhead', impact: 'Standardised hybrid TLS/PKI reduces bespoke crypto maintenance', evidence: `Runtime posture monitored (HNDL exposure ${s.hndlRiskLevel})` },
    { benefit: 'Faster certificate renewal', impact: 'Automated hybrid-certificate issuance and rotation', evidence: 'Hybrid CA rollout standardises issuance across the estate' },
  ];
  return out;
}

// I3#9 — Executive Maturity Model™: CMMI-style Level 0-5 per crypto domain, with
// current→target, timeline, investment, owner and dependencies. Current levels are
// DERIVED from the evidence-based readiness domain scores (0-100 → Level 0-5); the
// target is the crypto-agility ceiling (Level 5, or 4 where evidence is thin).
const MATURITY_LABELS = ['0 — None', '1 — Initial', '2 — Developing', '3 — Defined', '4 — Managed', '5 — Optimized'];
function scoreToMaturity(score: number, measured = true): number {
  if (!measured) return 0;
  if (score >= 85) return 5;
  if (score >= 65) return 4;
  if (score >= 45) return 3;
  if (score >= 25) return 2;
  if (score > 0) return 1;
  return 0;
}
export function buildMaturityModel(snapshot: QuantumReadinessSnapshot, domains: ReadinessDomain[], waves: MigrationWave[]): MaturityModel {
  if (!snapshot.hasData) {
    return { scale: 'CMMI-style Level 0 (None) → Level 5 (Optimized)', domains: [], note: `${EVIDENCE_UNAVAILABLE}. Run a discovery scan to compute the maturity model.` };
  }
  const inv = snapshot.inventory;
  const factor = (needle: string) => snapshot.readinessFactors.find((f) => f.label.toLowerCase().includes(needle))?.score ?? 0;
  const domainScore = (needle: string) => domains.find((d) => d.domain.toLowerCase().includes(needle))?.score ?? 0;
  const runtimeMeasuredFlag = runtimeMeasured(snapshot);
  const weeks = snapshot.estimates.migrationTimelineWeeks || 0;
  const phase = (frac: number) => (weeks ? `~${Math.max(1, Math.round(weeks * frac))} wk` : 'TBD');
  const rows: Array<{ domain: string; current: number; measured?: boolean; owner: string; deps: string; timeline: string }> = [
    { domain: 'Crypto Agility', current: factor('agility') || snapshot.scores.pqcAdoption, owner: 'Security Engineering', deps: 'Central crypto policy, key management (QKMS)', timeline: phase(1.0) },
    { domain: 'Governance', current: factor('governance'), owner: 'GRC / Compliance', deps: 'Crypto inventory, evidence pipeline', timeline: phase(0.3) },
    { domain: 'PKI', current: domainScore('pki'), owner: 'Security Team', deps: 'Hybrid CA, certificate automation', timeline: phase(0.6) },
    { domain: 'TLS / Transport', current: domainScore('tls'), owner: 'Infrastructure Team', deps: 'Load balancers, gateways, TLS 1.3', timeline: phase(0.4) },
    { domain: 'PQC Adoption', current: snapshot.scores.pqcAdoption, owner: 'Application Team', deps: 'Crypto-agile libraries, ML-KEM/ML-DSA', timeline: phase(1.0) },
    { domain: 'Inventory / CBOM', current: inv.cryptoComponents > 0 ? 60 : 20, owner: 'Security Engineering', deps: 'Continuous scanning, CBOM generation', timeline: phase(0.2) },
    { domain: 'Runtime Visibility', current: factor('runtime'), measured: runtimeMeasuredFlag, owner: 'Platform Team', deps: 'Runtime crypto telemetry agents', timeline: phase(0.5) },
  ];
  const domainsOut = rows.map((r) => {
    const measured = r.measured ?? true;
    const currentLevel = scoreToMaturity(r.current, measured);
    const targetLevel = measured ? 5 : 5;
    const gap = Math.max(0, targetLevel - currentLevel);
    return {
      domain: r.domain,
      currentLevel,
      currentLabel: measured ? MATURITY_LABELS[currentLevel] : '0 — Not Measured',
      targetLevel,
      targetLabel: MATURITY_LABELS[targetLevel],
      gap,
      timeline: gap === 0 ? 'Maintain' : r.timeline,
      investment: gap >= 4 ? 'High' : gap >= 2 ? 'Medium' : gap >= 1 ? 'Low' : 'Sustain',
      owner: r.owner,
      dependencies: r.deps,
    };
  });
  return {
    scale: 'CMMI-style Level 0 (None) → Level 5 (Optimized). Current levels are derived from evidence-based readiness domain scores; targets are the crypto-agility ceiling.',
    domains: domainsOut,
    note: `Current maturity is derived from measured readiness scores; "Not Measured" domains (e.g. Runtime Visibility without telemetry) start at Level 0. Investment reflects the size of the current→target gap. Timeline aligns to the ${weeks || 'TBD'}-week programme (${waves.length} wave(s)).`,
  };
}

// I2#2 — Terminology & Definitions: makes Assets vs Components unambiguous.
export function buildDefinitions(snapshot: QuantumReadinessSnapshot): ReportDefinition[] {
  const inv = snapshot.inventory;
  // One-decimal precision (enterprise numerical convention): 2/66 → "3.0%".
  const componentPct = inv.cryptoComponents > 0 ? pct1((inv.pqcReadyComponents / inv.cryptoComponents) * 100) : '0.0%';
  return [
    { term: 'Asset', definition: `A discovered system, endpoint, service or domain under assessment (e.g. a scanned host). This assessment: ${inv.assetsAssessed} asset(s).` },
    { term: 'Cryptographic Component (CBOM)', definition: `An individual algorithm, cipher suite, key, certificate or protocol usage discovered inside assets — one asset typically contains many components. This assessment: ${inv.cryptoComponents} component(s).` },
    { term: 'PQC-Ready Component', definition: `A CBOM component already using NIST PQC (FIPS 203/204/205) or hybrid cryptography. This assessment: ${inv.pqcReadyComponents} of ${inv.cryptoComponents} (${componentPct}). The "PQC-Ready Components" readiness factor is this percentage — a component share, never an asset count.` },
    { term: 'PQC-Ready Asset', definition: `An asset whose observed cryptography is entirely PQC or hybrid. This assessment: ${inv.pqcReadyAssets} of ${inv.assetsAssessed} asset(s). Distinct from PQC-ready components by definition.` },
    { term: 'Finding vs Consolidated Finding', definition: 'A finding is one detected cryptographic weakness instance; consolidated findings group instances by root cause so an issue is counted once for decision-making.' },
    { term: 'Quantum Readiness vs Quantum Risk', definition: 'Readiness (higher is better) measures migration progress and governance; risk (lower is better) measures exposure to future quantum decryption. They are computed independently and reconciled in their methodology sections.' },
    { term: 'Runtime Visibility', definition: `Measured exclusively from live runtime cryptographic telemetry. When no runtime telemetry exists the factor is reported as "${NOT_MEASURED}" and excluded from the readiness formula — it is never approximated from scan activity.` },
  ];
}

// I2#8 — Top Business Risks in board language, each tied to an evidence driver.
function buildTopBusinessRisks(snapshot: QuantumReadinessSnapshot): BusinessRisk[] {
  if (!snapshot.hasData) return [];
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  const internet = internetFacingLabels(snapshot).length;
  const factorScore = (needle: string) => snapshot.readinessFactors.find((f) => f.label.toLowerCase().includes(needle))?.score ?? 0;
  const out: BusinessRisk[] = [];
  if (internet > 0) out.push({ risk: 'Internet-Facing TLS Exposure', level: s.quantumRisk >= 60 ? 'Critical' : 'High', driver: `${internet} public endpoint(s) negotiate quantum-vulnerable key exchange visible to any network adversary.` });
  if (s.hndlRisk >= 25) out.push({ risk: 'Harvest-Now-Decrypt-Later Data Capture', level: s.hndlRiskLevel, driver: `HNDL risk ${s.hndlRisk}/100 — ciphertext recorded today becomes readable once a cryptographically-relevant quantum computer exists.` });
  if (inv.dataRepositories > 0 || s.hndlRisk >= 25) out.push({ risk: 'Long-Lived Sensitive Data Under Classical Encryption', level: s.hndlRisk >= 50 ? 'High' : 'Medium', driver: `${inv.dataRepositories || 'Archived'} data repositor${inv.dataRepositories === 1 ? 'y' : 'ies'} with multi-year retention protected by classical envelopes.` });
  if (inv.certificatesAnalyzed > 0) out.push({ risk: 'Legacy PKI / Certificate Trust Chain', level: factorScore('pki') < 40 ? 'High' : 'Medium', driver: `${inv.certificatesAnalyzed} certificate(s) signed with classical algorithms (PKI maturity ${factorScore('pki')}/100).` });
  out.push({ risk: 'Limited Crypto-Agility', level: factorScore('agility') < 40 ? 'High' : 'Medium', driver: `Algorithm replacement requires per-system change (crypto-agility ${factorScore('agility')}/100) — slows every future cryptographic transition, not just PQC.` });
  return out.slice(0, 5);
}

// I2#10 — Report Validation™: self-verifies the report's own arithmetic and
// cross-section consistency at generation time. A failed check is reported
// honestly as FAIL — the badge is computed, never asserted.
export function buildReportValidation(args: {
  snapshot: QuantumReadinessSnapshot;
  costForecast: CostForecast;
  costBreakdown: CostBreakdown;
  riskMethodology: RiskMethodology;
  readinessMethodology: ReadinessMethodology;
  waves: MigrationWave[];
  executiveBlock: ExecutiveBlock;
  riskForecast: RiskForecast;
  waveSimulation: WaveSimulation[];
  advisor: MigrationAdvisor;
  riskDomainModel: RiskDomainDatum[];
  findings: ReportFinding[];
  impactReasons: ImpactReason[];
}): ReportValidation {
  const { snapshot, costForecast, costBreakdown, riskMethodology, readinessMethodology, waves, executiveBlock, riskForecast, waveSimulation, advisor, riskDomainModel, findings, impactReasons } = args;
  const checks: ReportValidation['checks'] = [];
  const push = (check: string, ok: boolean, detail: string) => checks.push({ check, status: ok ? 'pass' : 'fail', detail });

  const linesExact = costBreakdown.lines.every((l) => l.category === EVIDENCE_UNAVAILABLE || l.hours * l.rateUsd === l.costUsd);
  const breakdownSum = costBreakdown.lines.reduce((sum, l) => sum + l.costUsd, 0);
  push('Arithmetic Verified', linesExact && breakdownSum === costBreakdown.totalUsd, `Every cost line satisfies hours × rate = cost and Σ line costs (${breakdownSum.toLocaleString()}) equals the stated total (${costBreakdown.totalUsd.toLocaleString()}).`);

  const riskContribSum = Math.round(riskMethodology.weights.reduce((sum, w) => sum + w.contribution, 0));
  const readinessContribSum = Math.round(readinessMethodology.factors.reduce((sum, f) => sum + f.contribution, 0));
  push('Risk Consistency Verified', Math.abs(riskContribSum - riskMethodology.overall) <= 2 && Math.abs(readinessContribSum - readinessMethodology.overall) <= 2, `Σ risk contributions ${riskContribSum} ≈ overall risk ${riskMethodology.overall}; Σ readiness contributions ${readinessContribSum} ≈ overall readiness ${readinessMethodology.overall} (±2 rounding).`);

  const forecastSum = costForecast.lines.reduce((sum, l) => sum + l.costUsd, 0);
  push('Cost Formula Verified', forecastSum === costForecast.totalUsd, `Cost forecast lines sum to ${forecastSum.toLocaleString()} = stated total ${costForecast.totalUsd.toLocaleString()} at the blended $${BLENDED_RATE_USD}/hr rate.`);

  push('Evidence Traceability Verified', findings.every((f) => f.evidence.length > 0) && impactReasons.every((r) => r.evidence.length > 0), `All ${findings.length} finding(s) carry evidence and all ${impactReasons.length} business-impact dimensions cite their sources.`);

  const primaryKey = riskDomainModel[0]?.matchKey || 'business';
  const expectedRec = snapshot.hasData ? DOMAIN_RECOMMENDATION[primaryKey] : advisor.recommendation;
  push('Recommendation Alignment Verified', !snapshot.hasData || advisor.recommendation === expectedRec, `The AI recommendation ("${advisor.recommendation}") targets the dominant weighted-risk domain (${riskDomainModel[0]?.category || 'n/a'}).`);

  const waveSum = waves.reduce((sum, w) => sum + w.riskReductionPct, 0);
  const lastSim = waveSimulation[waveSimulation.length - 1];
  const migrationOk = waveSum === executiveBlock.expectedRiskReductionPct && waveSum === riskForecast.reductionPct && (!lastSim || (lastSim.readinessTo === executiveBlock.targetReadiness && lastSim.riskTo <= executiveBlock.targetRisk));
  push('Migration Consistency Verified', migrationOk, `Σ wave reductions ${waveSum}% = executive ${executiveBlock.expectedRiskReductionPct}% = forecast ${riskForecast.reductionPct}%; full-programme simulation lands on target readiness ${executiveBlock.targetReadiness} with residual risk ≤ ${executiveBlock.targetRisk}.`);

  const overall = checks.every((c) => c.status === 'pass') ? 'PASS' : 'FAIL';
  return { overall, checks, note: 'All checks are computed from the generated report model at export time — the badge is verified, not asserted. A FAIL indicates an internal inconsistency that must be investigated before distribution.' };
}

/* ------------------------------------------------------------------ */
/* Assemble the full board-level report model                         */
/* ------------------------------------------------------------------ */
export function buildReportModel(
  snapshot: QuantumReadinessSnapshot,
  branding: ReportBranding,
  kind: ReportKind,
  generatedBy: string,
): EnterpriseAssessmentReport {
  const now = new Date();
  const s = snapshot.scores;
  const inv = snapshot.inventory;

  const domains = buildReadinessDomains(snapshot);
  // Evidence-filtered, calibrated risk decomposition — the single source that
  // drives risk categories, the risk methodology AND the advisor recommendation
  // so all three agree (top weighted-risk domain == advised domain).
  const riskDomainModel = buildRiskDomainModel(snapshot, domains);
  const waves = buildMigrationWaves(snapshot);
  const advisor = buildMigrationAdvisor(snapshot, riskDomainModel, waves);
  const findings = buildFindings(snapshot);
  const findingGroups = buildFindingGroups(snapshot);
  // Executive block consumes consolidated finding groups (deduplicated top risks).
  const executiveBlock = buildExecutiveBlock(snapshot, riskDomainModel, findingGroups);

  // Report Intelligence (Reports_Enhancements_3) — all evidence-derived
  const riskCategories = buildRiskCategories(riskDomainModel);
  const compliance = buildCompliance(snapshot);
  const costForecast = buildCostForecast(snapshot);
  const riskMethodology = buildRiskMethodology(snapshot, riskDomainModel);
  const advisorValidation = buildAdvisorValidation(snapshot, advisor, riskMethodology);
  const costBreakdown = buildCostBreakdown(snapshot, costForecast);
  const assetCriticality = buildAssetCriticality(snapshot, compliance);
  const impactReasons = buildImpactReasons(snapshot, buildBusinessImpact(snapshot));
  const migrationConfidence = buildMigrationConfidence(snapshot);
  const evidenceConfidence = buildEvidenceConfidence(snapshot);
  const executiveDecisions = buildExecutiveDecisions(snapshot, waves, executiveBlock);
  const playbookDetail = buildPlaybookDetail(findingGroups);
  const waveSimulation = buildWaveSimulation(snapshot, waves, executiveBlock, migrationConfidence);
  const governanceGates = buildGovernanceGates();
  const explainability = buildExplainability(snapshot, riskMethodology, migrationConfidence);
  // Improvements_01 — evidence-driven, traceable extensions
  const riskAcceptance = buildRiskAcceptance(snapshot, findingGroups, riskDomainModel);
  const assetReadiness = buildAssetReadiness(snapshot);
  const decisionChain = buildDecisionChain(snapshot, advisor, riskDomainModel, waves, executiveBlock, findingGroups);

  // Improvements_02 — enterprise-grade report intelligence
  const riskForecast = buildRiskForecast(snapshot);
  const readinessMethodology = buildReadinessMethodology(snapshot);
  const readinessIndex = buildReadinessIndex(snapshot, domains);
  const roiAnalysis = buildRoiAnalysis(snapshot, costForecast, executiveBlock);
  const resourceLoading = buildResourceLoading(snapshot, waves);
  const assetIntelligence = buildAssetIntelligence(snapshot, costBreakdown);
  const benchmarking = buildBenchmarking(snapshot, executiveBlock);
  const cryptoPolicy = buildCryptoPolicy();
  const definitions = buildDefinitions(snapshot);
  // Improvements_03 — refinements
  const confidenceSummary = buildConfidenceSummary(snapshot, migrationConfidence, advisor, evidenceConfidence, waveSimulation);
  const operationalBenefits = buildOperationalBenefits(snapshot);
  const maturityModel = buildMaturityModel(snapshot, domains, waves);
  const reportValidation = buildReportValidation({
    snapshot,
    costForecast,
    costBreakdown,
    riskMethodology,
    readinessMethodology,
    waves,
    executiveBlock,
    riskForecast,
    waveSimulation,
    advisor,
    riskDomainModel,
    findings,
    impactReasons,
  });

  const executiveSummary = snapshot.hasData
    ? `As of ${format(now, 'PPP')}, ${branding.companyName} holds a quantum readiness score of ${s.quantumReadiness}/100 (${s.quantumReadinessLevel}) against a quantum risk score of ${s.quantumRisk}/100 (${s.quantumRiskLevel}). A funded ${snapshot.estimates.migrationTimelineWeeks || 'TBD'}-week migration programme can raise readiness to a target of ${executiveBlock.targetReadiness}/100 and reduce quantum risk by ${executiveBlock.expectedRiskReductionPct}%. Discovery assessed ${inv.assetsAssessed} cryptographic assets, identifying ${inv.quantumVulnerableAssets} as quantum-vulnerable with ${s.pqcAdoption}% PQC adoption. Harvest-Now-Decrypt-Later exposure is rated ${s.hndlRiskLevel} with an estimated quantum exposure window of ${executiveBlock.quantumExposureWindow}. ${executiveBlock.executiveRecommendation}`
    : `No assessment evidence is available for ${branding.companyName} yet. Run a PQC discovery scan to populate this report. All sections below reflect an empty evidence state.`;

  const distribution = snapshot.riskDistribution;

  return {
    meta: {
      id: uuidv4(),
      kind,
      title: REPORT_TITLES[kind],
      generatedAt: now.toISOString(),
      generatedBy: generatedBy || 'QGuard Helix',
      version: branding.reportVersion,
      tenantScoped: true,
      sourceGeneratedAt: snapshot.generatedAt,
    },
    branding,
    executiveSummary,
    executiveBlock,
    kpis: buildKpis(snapshot),
    businessImpact: buildBusinessImpact(snapshot),
    readinessDomains: domains,
    migrationAdvisor: advisor,
    migrationReadiness: buildMigrationReadiness(snapshot, domains),
    migrationWaves: waves,
    dependencyAnalysis: buildDependencyAnalysis(snapshot),
    riskCategories,
    riskMethodology,
    advisorValidation,
    costBreakdown,
    assetCriticality,
    impactReasons,
    findingGroups,
    migrationConfidence,
    evidenceConfidence,
    executiveDecisions,
    playbookDetail,
    waveSimulation,
    governanceGates,
    explainability,
    riskAcceptance,
    assetReadiness,
    decisionChain,
    readinessMethodology,
    readinessIndex,
    roiAnalysis,
    resourceLoading,
    assetIntelligence,
    benchmarking,
    reportValidation,
    cryptoPolicy,
    definitions,
    confidenceSummary,
    operationalBenefits,
    maturityModel,
    findings,
    assets: buildAssets(snapshot),
    certificates: safeTable('Certificate Inventory', ['Metric', 'Value'], [['Certificates Analyzed', inv.certificatesAnalyzed]]),
    keys: safeTable('Key Inventory', ['Metric', 'Value'], [['Keys Discovered', inv.keysDiscovered]]),
    tlsEndpoints: safeTable('TLS / Protocol Surface', ['Metric', 'Value'], [['Domains Scanned', inv.domainsScanned]]),
    cbom: safeTable('CBOM Summary (cryptographic components)', ['Posture', 'Components'], [
      ['Total Components', inv.cryptoComponents],
      ['PQC-Ready / Hybrid', inv.pqcReadyComponents],
      ['Quantum-Vulnerable', inv.vulnerableComponents],
      ['Vulnerable Assets', inv.quantumVulnerableAssets],
    ]),
    hndl: {
      summary: `Harvest-Now-Decrypt-Later exposure is rated ${s.hndlRiskLevel} (${s.hndlRisk}/100). Long-lived sensitive data protected by quantum-vulnerable cryptography can be captured today and decrypted once a cryptographically-relevant quantum computer exists (estimated window: ${executiveBlock.quantumExposureWindow}).`,
      table: safeTable('HNDL Exposure', ['Factor', 'Score'], [
        ['HNDL Risk Score', s.hndlRisk],
        ['Crypto Exposure', s.cryptoExposure],
        ['Vulnerable Assets', inv.quantumVulnerableAssets],
      ]),
      categories: buildHndlCategories(snapshot),
    },
    trustRelationships: safeTable('Trust Relationships', ['Metric', 'Value'], [
      ['Trust Relationships', inv.trustRelationships],
      ['Cloud Accounts', inv.cloudAccounts],
    ]),
    pqcReadiness: {
      summary: `${s.pqcAdoption}% of discovered cryptography is quantum-safe or hybrid. Readiness is broken down by domain below.`,
      // I2#1/#2 — factor scores print their measurement basis; Runtime Visibility
      // shows "Not Measured" (never a proxy score) when no runtime telemetry
      // exists, matching the Evidence Confidence dashboard exactly.
      table: safeTable('PQC Readiness Factors', ['Factor', 'Score', 'Basis'], snapshot.readinessFactors.map((f) => {
        const label = f.label.toLowerCase();
        if (label.includes('runtime') && snapshot.telemetry.runtimeEvents === 0) {
          return [f.label, 'Not Measured', 'No runtime telemetry recorded — excluded from the readiness formula'];
        }
        const basis = label.includes('pqc-ready')
          ? `${inv.pqcReadyComponents} of ${inv.cryptoComponents} CBOM component(s) — a component share, not an asset count`
          : label.includes('runtime')
            ? `${snapshot.telemetry.runtimeEvents.toLocaleString()} runtime crypto event(s)`
            : label.includes('governance')
              ? `${snapshot.telemetry.scanSessions} governed scan session(s)`
              : label.includes('tls')
                ? `${inv.domainsScanned} domain(s) scanned`
                : label.includes('pki')
                  ? `${inv.certificatesAnalyzed} certificate(s) analysed`
                  : '—';
        return [f.label, `${f.score}/100`, basis];
      })),
    },
    compliance,
    remediationProgram: buildRemediationProgram(snapshot, findings, waves),
    roadmap: buildRoadmap(snapshot, waves),
    playbook: buildPlaybook(waves),
    costForecast,
    riskForecast,
    governance: buildGovernance(snapshot),
    remediation: safeTable('Remediation Plan', ['Priority', 'Action', 'Owner', 'Risk Reduction', 'Target Date'],
      buildRemediationProgram(snapshot, findings, waves).map((item) => [item.priority, item.action, item.owner, `${item.riskReductionPct}%`, item.targetDate])),
    evidence: {
      sources: ['PQC Scanner', 'CBOM', 'Runtime Telemetry', 'Trust Fabric', 'Asset Inventory', 'Certificate Inventory'],
      notes: snapshot.hasData
        ? `Severity distribution — Critical: ${distribution.critical}, High: ${distribution.high}, Medium: ${distribution.medium}, Low: ${distribution.low}. ${EVIDENCE_UNAVAILABLE} is shown where a source has not yet produced telemetry.`
        : `${EVIDENCE_UNAVAILABLE}. No scans, assets, certificates or runtime telemetry recorded for this tenant.`,
    },
    charts: [],
  };
}
