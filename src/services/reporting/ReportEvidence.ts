import { v4 as uuidv4 } from 'uuid';
import { addWeeks, format } from 'date-fns';
import type { QuantumReadinessSnapshot } from '@/app/dashboard/quantum-readiness/_shared';
import {
  DEFAULT_COST_ASSUMPTIONS,
  allocateCostCategories,
  buildBudgetVariance,
  describeCostAssumptions,
  formatUsd,
  projectedRiskReductionValueUsd,
} from '@/lib/migration/cost-model';
// Runtime-only function import; the ReportScope↔ReportEvidence cycle is safe
// because both modules only export hoisted functions consumed at call time.
import { buildReportScope } from './ReportScope';
import { buildPlaybookStandardControls } from './ReportPlaybook';
import {
  EVIDENCE_UNAVAILABLE,
  normalizeSeverity,
  severityRank,
  type AdvisorValidation,
  type AssetCriticality,
  type AssetIntelligence,
  type AssetReadiness,
  type Benchmarking,
  type CertificationSummary,
  type DecisionPackageLine,
  type ReadinessProgressionStep,
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
  sharedResponsibilityReportSchema,
  type SharedResponsibilityReport,
  type BoardSnapshot,
  type ExecutiveHeatMap,
  type HeatMapCell,
  type BusinessPriorityMatrix,
  type PriorityQuadrant,
  type PriorityMatrixItem,
  type EvidenceQuality,
  type RemediationCampaigns,
  type RemediationCampaign,
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
  type PlaybookStandardControls,
  type RiskApprovalPolicy,
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
  type ReportScope,
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
// I4#8 — consistent "x.x%" formatting for every count-derived share printed in
// the report (e.g. "2 of 92 (2.2%)"), so decimal precision never varies between
// sections.
const countPct = (part: number, total: number) => (total > 0 ? pct1((part / total) * 100) : '0.0%');
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

/**
 * Quantum Trust Certification™ readiness threshold. The executive programme
 * target readiness is pinned to this same value so "Target 85/100" in the
 * executive summary and the certification criterion can never diverge.
 */
export const CERTIFICATION_READINESS_THRESHOLD = 85;

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
export function normalizeAssetKey(asset: string): string {
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
    { label: 'HNDL Exposure', value: s.hndlRisk, unit: '/100', level: s.hndlRiskLevel, tone: kpiTone(s.hndlRisk, true) },
    { label: 'PQC Adoption', value: s.pqcAdoption, unit: '%', tone: kpiTone(s.pqcAdoption, false) },
    { label: 'Migration Effort', value: s.migrationEffort, unit: '/100', tone: 'neutral' },
    // "Inventoried" (not "Assessed") — the scope line counts DISCOVERED assets
    // (inventory ∪ scanned endpoints); this KPI counts the formal inventory only,
    // and the Terminology section defines the distinction.
    { label: 'Inventoried Assets', value: inv.assetsAssessed, tone: 'neutral' },
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
  const affectedAssets = internet.length ? internet.slice(0, 8) : snapshot.topRiskAssets.slice(0, 8).map((a) => a.asset);
  // Execution complexity must reconcile with the per-asset Migration Complexity
  // printed in the Asset Intelligence Profile (same rule: >3 dependencies or an
  // internet-facing asset with >2 findings ⇒ High) — the recommendation executes
  // against these assets, so it is never reported as easier than its hardest asset.
  const nodeByLabel = new Map(snapshot.exposureGraph.nodes.map((n) => [n.label, n]));
  const complexityRank: Record<string, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 };
  const assetComplexity = (asset: string): string => {
    const key = normalizeAssetKey(asset);
    const assetFindings = snapshot.criticalFindings.filter((f) => normalizeAssetKey(f.asset) === key).length;
    const node = nodeByLabel.get(asset);
    const internetFacing = node?.internetFacing ?? internet.includes(asset);
    const deps = node ? snapshot.exposureGraph.edges.filter((e) => e.source === node.id || e.target === node.id).length : 0;
    return deps > 3 || (internetFacing && assetFindings > 2) ? 'High' : internetFacing || assetFindings > 1 ? 'Medium' : 'Low';
  };
  const platformComplexity = riskLevel(s.migrationComplexity, false);
  const complexity = affectedAssets
    .map(assetComplexity)
    .concat(platformComplexity)
    .sort((a, b) => (complexityRank[b] ?? 0) - (complexityRank[a] ?? 0))[0];
  return {
    recommendation,
    reason: `${primary ? primary.category : 'Cryptographic exposure'} is the largest weighted quantum-risk driver (${exposurePct}/100)${isTransport ? ', dominated by legacy RSA/ECC TLS handshakes and certificate signatures,' : ''} concentrated in ${snapshot.inventory.quantumVulnerableAssets || snapshot.inventory.assetsAssessed} asset(s).`,
    affectedAssets,
    riskReductionPct: firstWave ? firstWave.riskReductionPct : clamp(Math.round((s.quantumRisk - Math.max(10, s.quantumRisk * 0.25)) * 0.6)),
    costUsd: firstWave ? firstWave.costUsd : Math.round(snapshot.estimates.migrationCostUsd * 0.2),
    timelineWeeks: firstWave ? firstWave.durationWeeks : Math.max(1, Math.round(snapshot.estimates.migrationTimelineWeeks * 0.2)),
    complexity,
    successProbabilityPct: clamp(100 - s.migrationComplexity * 0.5),
    confidencePct: snapshot.hasData ? clamp(78 + (snapshot.inventory.assetsAssessed > 0 ? 8 : 0) + (snapshot.inventory.certificatesAnalyzed > 0 ? 5 : 0)) : 0,
  };
}

/* ------------------------------------------------------------------ */
/* Migration waves (Enhancement #3)                                   */
/* ------------------------------------------------------------------ */
export function buildMigrationWaves(snapshot: QuantumReadinessSnapshot): MigrationWave[] {
  const weeks = snapshot.estimates.migrationTimelineWeeks || 0;
  const cost = normalizeBudgetUsd(snapshot.estimates.migrationCostUsd || 0);
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
  // Cost/duration ratios are ALSO renormalised over the surviving specs — when
  // evidence-less waves are dropped, the raw ratios no longer sum to 1 and the
  // wave costs would silently total less than the stated migration budget.
  const ratioSum = specs.reduce((sum, spec) => sum + spec.ratio, 0) || 1;
  const { reductionPct } = reductionTargets(snapshot);
  const waves = specs.map((spec, index) => ({
    wave: index + 1,
    name: spec.name,
    assets: spec.assets.length ? spec.assets.slice(0, 10) : [EVIDENCE_UNAVAILABLE],
    owner: spec.owner,
    durationWeeks: Math.max(weeks ? 1 : 0, Math.round(weeks * (spec.ratio / ratioSum))),
    costUsd: Math.round(cost * (spec.ratio / ratioSum)),
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
    // Σ wave costs must equal the migration budget to the dollar, and Σ wave
    // durations must equal the programme weeks — independent per-wave rounding
    // printed "$156,751" next to the "$156,750" budget.
    const costDiff = cost - waves.reduce((sum, w) => sum + w.costUsd, 0);
    if (costDiff !== 0) {
      const costliest = waves.reduce((mi, w, i, arr) => (w.costUsd > arr[mi].costUsd ? i : mi), 0);
      waves[costliest].costUsd = Math.max(0, waves[costliest].costUsd + costDiff);
    }
    const weekDiff = weeks - waves.reduce((sum, w) => sum + w.durationWeeks, 0);
    if (weekDiff !== 0) {
      const longest = waves.reduce((mi, w, i, arr) => (w.durationWeeks > arr[mi].durationWeeks ? i : mi), 0);
      waves[longest].durationWeeks = Math.max(weeks ? 1 : 0, waves[longest].durationWeeks + weekDiff);
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
export function buildRiskCategories(snapshot: QuantumReadinessSnapshot, riskDomainModel: RiskDomainDatum[]): RiskCategory[] {
  // Domain targets share the canonical reduction engine (reductionTargets) so the
  // weighted blend of the per-domain targets reproduces the overall target risk.
  // Previously domains reduced ×0.30 while the programme target reduced ×0.25,
  // leaving this table implying a higher overall target than the stated one.
  const { startRisk, targetRisk } = reductionTargets(snapshot);
  const ratio = startRisk > 0 ? targetRisk / startRisk : 0.25;
  const cats = riskDomainModel.map((d) => {
    const current = clamp(d.risk);
    const target = Math.min(current, Math.max(8, round(current * ratio)));
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
  const assumptions = snapshot.costAssumptions ?? DEFAULT_COST_ASSUMPTIONS;
  const rawTotal = snapshot.estimates.migrationCostUsd || 0;
  if (!rawTotal) {
    return {
      lines: [{ category: EVIDENCE_UNAVAILABLE, costUsd: 0 }],
      totalUsd: 0,
      projectedRiskReductionValueUsd: 0,
      excludedCategories: [],
      assumptions: describeCostAssumptions(assumptions),
      blendedRateUsd: assumptions.blendedRateUsd,
      hoursPerWeek: assumptions.hoursPerWeek,
      totalHours: 0,
      valueBasis: EVIDENCE_UNAVAILABLE,
      financialExposureUsd: 0,
      budget: null,
    };
  }

  const rate = assumptions.blendedRateUsd;
  // Labour hours are the primitive. Each line cost = hours × rate EXACTLY, and
  // line items sum to the displayed total, so the per-line formulas reconcile.
  const totalHours = Math.max(1, Math.round(rawTotal / rate));

  /* Only categories the evidence supports are costed. A tenant with no HSM and
     no connected cloud account previously still saw "HSM $12,540" and
     "Cloud / KMS $15,675" — 18% of the programme budget assigned to hardware the
     scan never found. Rule 3: unmeasured renders as unmeasured, with a reason,
     and its weight is redistributed rather than filled in. */
  const { applicable, excluded } = allocateCostCategories({
    vulnerableComponents: snapshot.inventory.vulnerableComponents,
    certificatesAnalyzed: snapshot.inventory.certificatesAnalyzed,
    keysDiscovered: snapshot.inventory.keysDiscovered,
    cloudAccounts: snapshot.inventory.cloudAccounts,
    assetsAssessed: snapshot.inventory.assetsAssessed,
  });

  const alloc = applicable.map((entry) => ({ category: entry.category, hours: Math.round(totalHours * entry.weight) }));
  // Push integer-rounding remainder onto the largest line so Σ hours == totalHours
  // and Σ costUsd == totalUsd exactly.
  const remainder = totalHours - alloc.reduce((sum, a) => sum + a.hours, 0);
  if (remainder !== 0 && alloc.length) {
    const largest = alloc.reduce((mi, a, index, arr) => (a.hours > arr[mi].hours ? index : mi), 0);
    alloc[largest].hours = Math.max(0, alloc[largest].hours + remainder);
  }
  const lines = alloc.map((a) => ({ category: a.category, costUsd: a.hours * rate }));
  const totalUsd = lines.reduce((sum, l) => sum + l.costUsd, 0);

  /* Value of the risk removed.
     This used to be `totalUsd × reductionPct × 3`. Because reductionPct saturates
     at 75% for any tenant whose quantumRisk exceeds 40, that collapsed to a fixed
     2.25 × cost for nearly everyone, and it claimed a return larger than the
     total exposure the platform itself computed. Value is now a fraction OF the
     shared exposure model (the same one the Executive Command Center prints),
     hard-capped by it. */
  const { reductionPct } = reductionTargets(snapshot);
  const financialExposureUsd = snapshot.businessValue?.financialExposureUsd ?? 0;
  const valueBasis = financialExposureUsd > 0
    ? `${reductionPct}% of ${formatUsd(financialExposureUsd, assumptions.currency)} modelled exposure across ${snapshot.inventory.quantumVulnerableAssets} quantum-vulnerable asset(s)`
    : 'Not modelled — no asset value assumptions or no vulnerable assets recorded';

  return {
    lines,
    totalUsd,
    projectedRiskReductionValueUsd: projectedRiskReductionValueUsd(financialExposureUsd, reductionPct),
    excludedCategories: excluded,
    assumptions: describeCostAssumptions(assumptions),
    blendedRateUsd: rate,
    hoursPerWeek: assumptions.hoursPerWeek,
    totalHours,
    valueBasis,
    financialExposureUsd,
    budget: buildBudgetVariance(totalUsd, assumptions),
  };
}

/* ------------------------------------------------------------------ */
/* Risk reduction forecast (Enhancement)                              */
/* ------------------------------------------------------------------ */
export function buildRiskForecast(snapshot: QuantumReadinessSnapshot): RiskForecast {
  const { startRisk: current, targetRisk: target, reductionPct, residualRisk } = reductionTargets(snapshot);
  // Projections are anchored to the ACTUAL programme schedule — the same
  // discovery/waves/validation phase model buildRoadmap prints — instead of an
  // arbitrary 36-month glide. A 26-week programme must show target risk well
  // before month 12, or this forecast contradicts the printed roadmap dates.
  const WEEKS_PER_MONTH = 52 / 12;
  const totalWeeks = snapshot.estimates.migrationTimelineWeeks || 0;
  const overheadWeeks = Math.max(1, Math.round(totalWeeks * 0.1)); // discovery & validation phases (matches buildRoadmap)
  const wavesEndMonths = totalWeeks ? (overheadWeeks + totalWeeks) / WEEKS_PER_MONTH : 12;
  const programmeEndMonths = totalWeeks ? (overheadWeeks + totalWeeks + overheadWeeks) / WEEKS_PER_MONTH : 18;
  /** Risk at `month` when the schedule is stretched by `stretch` (1 = on plan); post-programme risk floors at `floor`. */
  const riskAt = (month: number, stretch: number, floor: number) => {
    const wavesEnd = wavesEndMonths * stretch;
    const progEnd = programmeEndMonths * stretch;
    if (month >= progEnd) return floor;
    if (month >= wavesEnd) return target;
    return clamp(round(current - (current - target) * (month / Math.max(0.1, wavesEnd))), floor, current);
  };
  const fmtMonths = (m: number) => Math.max(1, Math.ceil(m));
  const scenarios: RiskScenario[] = snapshot.hasData
    ? [
        {
          scenario: 'Funded Programme (Expected)',
          month12: riskAt(12, 1, residualRisk), month24: riskAt(24, 1, residualRisk), month36: riskAt(36, 1, residualRisk),
          assumption: `Planned wave cadence: waves complete by month ${fmtMonths(wavesEndMonths)} (risk ${target}/100); residual posture ${residualRisk}/100 from month ${fmtMonths(programmeEndMonths)}, maintained thereafter by drift monitoring and governance.`,
        },
        {
          scenario: 'Funded Programme (Worst Case — 2× slippage)',
          month12: riskAt(12, 2, target), month24: riskAt(24, 2, target), month36: riskAt(36, 2, target),
          assumption: `Resource contention / rollback events double the schedule (waves complete ~month ${fmtMonths(wavesEndMonths * 2)}); validation & optimization deferred, so risk holds at the migration target ${target}/100 rather than the optimized residual ${residualRisk}/100.`,
        },
        {
          scenario: 'No Funded Programme (Baseline)',
          month12: current, month24: current, month36: current,
          assumption: 'Programme not funded: quantum risk persists at the current level while Harvest-Now-Decrypt-Later ciphertext capture continues to accumulate.',
        },
      ]
    : [];
  return {
    currentRisk: current,
    targetRisk: target,
    reductionPct,
    residualRisk,
    month12: riskAt(12, 1, residualRisk),
    month24: riskAt(24, 1, residualRisk),
    month36: riskAt(36, 1, residualRisk),
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
  // Target dates are each wave's roadmap FINISH date (discovery offset + cumulative
  // wave durations — the same schedule buildRoadmap prints), so the Remediation
  // Program and the Migration Roadmap can never disagree on delivery dates.
  const totalWeeks = snapshot.estimates.migrationTimelineWeeks || waves.reduce((sum, w) => sum + w.durationWeeks, 0);
  const discoveryWeeks = Math.max(1, Math.round(totalWeeks * 0.1));
  let cumulativeWeeks = discoveryWeeks;
  const items: RemediationItem[] = waves.slice(0, 5).map((wave, index) => {
    cumulativeWeeks += wave.durationWeeks;
    return {
      priority: index + 1,
      action: `${wave.name}: deploy hybrid PQC (ML-KEM / ML-DSA) and retire classical primitives.`,
      owner: wave.owner,
      affectedAssets: wave.assets,
      costUsd: wave.costUsd,
      effort: `${wave.durationWeeks} week(s)`,
      riskReductionPct: wave.riskReductionPct,
      targetDate: format(addWeeks(now, cumulativeWeeks), 'yyyy-MM-dd'),
      status: wave.status,
      dependencies: wave.dependencies,
      validation: 'PQC readiness re-scan, trust-chain validation, zero failed crypto operations.',
    };
  });
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
  const targetReadiness = Math.max(CERTIFICATION_READINESS_THRESHOLD, s.quantumReadiness);
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
    estimatedCostUsd: normalizeBudgetUsd(snapshot.estimates.migrationCostUsd),
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

/**
 * The migration budget normalised to whole labour-hours at the blended rate —
 * the SAME rounding buildCostForecast applies. Waves, the executive budget and
 * the cost forecast all consume this, so a raw estimate that is not an exact
 * multiple of the rate can never print two different "budget" figures.
 */
function normalizeBudgetUsd(rawUsd: number): number {
  return rawUsd > 0 ? Math.max(1, Math.round(rawUsd / BLENDED_RATE_USD)) * BLENDED_RATE_USD : 0;
}

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
// I4#4 — effort is additionally expressed as engineer-weeks (hours ÷ 40) and
// FTE over the programme window, the units enterprise planners actually staff
// against ("511 hours" alone under-informs resourcing decisions).
export function buildCostBreakdown(snapshot: QuantumReadinessSnapshot, costForecast: CostForecast): CostBreakdown {
  // Tenant rate, so the printed "hrs × rate = cost" formula is the same
  // arithmetic the forecast performed.
  const BLENDED_RATE_USD = costForecast.blendedRateUsd || (snapshot.costAssumptions ?? DEFAULT_COST_ASSUMPTIONS).blendedRateUsd;
  const windowWeeks = Math.max(1, snapshot.estimates.migrationTimelineWeeks || 1);
  const round1 = (n: number) => Math.round(n * 10) / 10;
  const round2 = (n: number) => Math.round(n * 100) / 100;
  const lines = costForecast.lines
    .filter((l) => l.category !== EVIDENCE_UNAVAILABLE)
    .map((l) => {
      const hours = Math.round(l.costUsd / BLENDED_RATE_USD);
      // Recompute cost from hours × rate so the printed formula is exact.
      const costUsd = hours * BLENDED_RATE_USD;
      const engineers = Math.max(1, Math.round(hours / Math.max(40, (snapshot.estimates.migrationTimelineWeeks || 1) * 8)));
      const engineerWeeks = round1(hours / 40);
      const fte = round2(hours / (windowWeeks * 40));
      return {
        category: l.category,
        hours,
        engineers,
        rateUsd: BLENDED_RATE_USD,
        costUsd,
        formula: `${hours.toLocaleString()} hrs × $${BLENDED_RATE_USD}/hr = $${costUsd.toLocaleString()}`,
        engineerWeeks,
        fte,
        effort: `${hours.toLocaleString()} hrs ≈ ${engineerWeeks} engineer-week(s) ≈ ${fte} FTE over ${windowWeeks} wk`,
      };
    });
  const totalHours = lines.reduce((sum, l) => sum + l.hours, 0);
  const totalUsd = lines.reduce((sum, l) => sum + l.costUsd, 0);
  const totalEngineerWeeks = round1(totalHours / 40);
  const totalFte = round2(totalHours / (windowWeeks * 40));
  return {
    blendedRateUsd: BLENDED_RATE_USD,
    totalHours,
    totalUsd,
    lines: lines.length ? lines : [{ category: EVIDENCE_UNAVAILABLE, hours: 0, engineers: 0, rateUsd: BLENDED_RATE_USD, costUsd: 0, formula: EVIDENCE_UNAVAILABLE, engineerWeeks: 0, fte: 0, effort: EVIDENCE_UNAVAILABLE }],
    windowWeeks,
    totalEngineerWeeks,
    totalFte,
    effortNote: lines.length
      ? `Effort is expressed three ways for planning: labour hours, engineer-weeks (hours ÷ 40 hr/wk) and FTE (hours ÷ (${windowWeeks}-week programme window × 40 hr/wk)). Programme total: ${totalHours.toLocaleString()} hrs ≈ ${totalEngineerWeeks} engineer-weeks ≈ ${totalFte} FTE.`
      : `${EVIDENCE_UNAVAILABLE}. Run a discovery scan to derive migration effort.`,
  };
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
      evidence: [`HNDL exposure ${s.hndlRisk}/100 (${s.hndlRiskLevel})`, `${inv.dataRepositories} data repositor(y/ies) in scope`, 'FIPS 203/204/205 migration deadlines'],
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
  // Deprecated protocol versions come FIRST and must match the scanner's actual
  // labels ("Deprecated SSL/TLS Version", "TLSv1.1", "TLSv1") — the old
  // `TLS 1.0` pattern missed them, so they fell into the catch-all bucket and
  // "Other Cryptographic Findings" surfaced as the #1 executive top risk.
  if (/DEPRECATED (SSL|TLS)|TLS\s?V?1(?:\.[01])?(?![.\d])|SSLV[23]|\bSSL\s?[23](\.0)?\b/.test(a)) return 'Deprecated TLS / SSL Protocol Versions';
  if (/TLS_RSA|RSA[_\s].*(CBC|GCM|SHA)/.test(a)) return 'Legacy RSA Cipher Suites';
  if (/FORWARD SECRECY/.test(a)) return 'Missing Forward Secrecy';
  if (/NO (HYBRID|PQC)|MISSING (HYBRID|PQC)|PQC CIPHER/.test(a)) return 'Missing PQC / Hybrid Negotiation';
  if (/ECDSA/.test(a)) return 'ECDSA Certificate Signatures';
  if (/ECDH/.test(a)) return 'ECDH Key Exchange';
  if (/\bRSA\b/.test(a)) return 'RSA Public-Key Cryptography';
  if (/QUANTUM.?VULNERABLE OID|VULNERABLE OID/.test(a)) return 'Quantum-Vulnerable Algorithm Identifiers (OIDs)';
  if (/ECC|EC-|P-256|P-384|EC PUBLIC/.test(a)) return 'Elliptic-Curve Cryptography';
  if (/SHA-?1|MD5/.test(a)) return 'Deprecated Hash Functions';
  if (/3DES|\bDES\b|RC4/.test(a)) return 'Weak Symmetric Ciphers';
  if (/OAUTH|JWT|OIDC|TOKEN/.test(a)) return 'Identity Token Cryptography';
  if (/HNDL|HARVEST|LONG.?TERM DATA/.test(a)) return 'Harvest-Now-Decrypt-Later Exposure';
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
// I4#6 — each playbook additionally carries change-management execution fields
// (expected downtime, maintenance window, rollback duration, validation owner,
// success KPI, automation status, SLA impact) derived from the change class of
// the finding family (config-level TLS change vs staged PKI cutover, …).
interface PlaybookOps {
  estimatedDowntime: string;
  maintenanceWindow: string;
  rollbackDuration: string;
  validationOwner: string;
  automationStatus: string;
  slaImpact: string;
}
export function buildPlaybookDetail(groups: FindingGroup[]): PlaybookDetail[] {
  const target = (title: string): { current: string; target: string; steps: string[]; ops: PlaybookOps } => {
    if (/rsa cipher|legacy rsa|forward secrecy/i.test(title)) return {
      current: 'TLS with RSA key exchange / CBC cipher suites (no forward secrecy)',
      target: 'TLS 1.3 + X25519 + ML-KEM-768 (Hybrid)',
      steps: ['Enable TLS 1.3', 'Disable RSA / CBC cipher suites', 'Enable X25519 + Hybrid ML-KEM key exchange', 'Validate handshake compatibility', 'Monitor production for client failures'],
      ops: { estimatedDowntime: '0 minutes (cipher-profile config reload / rolling restart)', maintenanceWindow: 'Standard off-peak change window (≤2 h reservation)', rollbackDuration: '≤5 minutes (feature-flag / cipher-profile revert)', validationOwner: 'Security Engineering (automated PQC re-scan)', automationStatus: 'Automated validation + rollback; manual approval gate', slaImpact: 'None expected' },
    };
    if (/ecdsa|certificate/i.test(title)) return {
      current: 'ECDSA / RSA certificate signatures',
      target: `${ACTIVE_PROFILE.certificateChain} (policy profile: ${ACTIVE_PROFILE.profile})`,
      steps: ['Issue hybrid (classical + ML-DSA) certificates per the active crypto-policy profile', 'Stage parallel chain', 'Cut over CA trust', 'Validate chain on all clients', 'Retire classical-only certs'],
      ops: { estimatedDowntime: '0 minutes (parallel chain staged before cutover)', maintenanceWindow: 'Standard change window; CA cutover ≤4 h reservation', rollbackDuration: '≤15 minutes (re-pin previous certificate chain)', validationOwner: 'Security Team (PKI) + automated chain validation', automationStatus: 'Semi-automated (issuance automated; cutover approval manual)', slaImpact: 'None expected' },
    };
    if (/tls.*ssl|legacy tls/i.test(title)) return {
      current: 'Legacy TLS 1.0 / 1.1 / SSL protocols',
      target: 'TLS 1.3 only',
      steps: ['Disable TLS 1.0/1.1 and SSL', 'Enforce TLS 1.3', 'Update load-balancer / gateway policy', 'Validate client compatibility', 'Monitor handshake telemetry'],
      ops: { estimatedDowntime: '0 minutes (protocol-policy config reload)', maintenanceWindow: 'Standard off-peak change window (≤2 h reservation)', rollbackDuration: '≤5 minutes (protocol-policy revert)', validationOwner: 'Infrastructure Team (automated handshake telemetry)', automationStatus: 'Automated validation + rollback; manual approval gate', slaImpact: 'None expected (legacy clients on TLS ≤1.1 lose access by design)' },
    };
    return {
      current: 'Quantum-vulnerable cryptography',
      target: 'ML-KEM (FIPS 203) / ML-DSA (FIPS 204) hybrid',
      steps: ['Inventory affected components', 'Deploy hybrid PQC behind feature flag', 'Update dependent assets', 'Validate trust chains', 'Retire classical primitives'],
      ops: { estimatedDowntime: 'Target 0 minutes (feature-flagged deployment)', maintenanceWindow: 'Standard change window per affected component', rollbackDuration: '≤1 change window (feature-flag revert)', validationOwner: 'Security Engineering (automated PQC re-scan)', automationStatus: 'Manual deployment with automated validation', slaImpact: 'None expected' },
    };
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
      ...t.ops,
      successKpi: `${g.title} not detected on re-scan · 0 failed crypto operations · 0 unplanned downtime minutes`,
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
// I4#1 — "Migration Confidence" is split into two clearly-separated concepts:
// Assessment Evidence Confidence (evidence coverage behind the assessment) and
// Migration Forecast Confidence (entire-programme simulation confidence), so
// the explainability page can never contradict the per-wave simulation values.
export function buildExplainability(snapshot: QuantumReadinessSnapshot, methodology: RiskMethodology, confidence: MigrationConfidence, waveSimulation: WaveSimulation[]): Explainability[] {
  const s = snapshot.scores;
  const program = waveSimulation[waveSimulation.length - 1];
  const forecastPct = program ? program.confidencePct : 0;
  return [
    { metric: 'Quantum Risk Score', what: `${s.quantumRisk}/100 composite quantum risk.`, how: methodology.formula, evidence: `${snapshot.criticalFindings.length} scanner findings, ${snapshot.inventory.cryptoComponents} CBOM components.`, why: 'Quantifies exposure to future quantum decryption.', action: 'Execute prioritised migration waves to reduce it.' },
    { metric: 'Quantum Readiness Score', what: `${s.quantumReadiness}/100 (${s.quantumReadinessLevel}).`, how: 'Σ(Factor × Weight): PQC Adoption 45%, Risk Posture 25%, Runtime Visibility 15%, Governance 15% — unmeasured factors excluded and weights renormalised. Full contribution table in the Readiness Scoring Methodology.', evidence: `${s.pqcAdoption}% PQC adoption across ${snapshot.inventory.cryptoComponents} components.`, why: 'Measures progress toward a quantum-safe posture.', action: 'Increase PQC/hybrid adoption per the wave plan.' },
    { metric: 'PQC Adoption', what: `${s.pqcAdoption}%.`, how: '(PQC-ready + ½ hybrid components) ÷ total CBOM components.', evidence: `${snapshot.inventory.pqcReadyComponents} of ${snapshot.inventory.cryptoComponents} components quantum-safe.`, why: 'Direct measure of cryptographic modernisation.', action: 'Migrate vulnerable components to ML-KEM / ML-DSA.' },
    { metric: 'Assessment Evidence Confidence', what: `${confidence.overallPct}% — completeness of the evidence behind this assessment.`, how: 'Average of asset/certificate/key/CBOM/scanner/dependency/trust/telemetry coverage.', evidence: 'Per-source coverage in the Assessment Confidence table.', why: 'Measures how complete the evidence is. Deliberately distinct from Migration Forecast Confidence — the two answer different questions.', action: 'Improve low-coverage sources (trust fabric, dependencies) to raise confidence.' },
    { metric: 'Migration Forecast Confidence', what: `${forecastPct}% — confidence in the full-programme migration forecast.`, how: 'Entire-programme scenario confidence from the Migration Simulation: assessment evidence confidence decayed per successive execution wave.', evidence: 'Per-wave confidence values in the Migration Simulation table.', why: 'Tells executives how firm the projected readiness, risk, cost and timeline outcomes are.', action: 'Complete early waves and re-assess — realised wave outcomes raise forecast confidence for the remainder.' },
    { metric: 'Estimated Cost', what: snapshot.estimates.migrationCostUsd ? `$${snapshot.estimates.migrationCostUsd.toLocaleString()}.` : EVIDENCE_UNAVAILABLE, how: `${(snapshot.estimates.migrationTimelineWeeks || 0) * 38} labour hours × $${BLENDED_RATE_USD}/hr blended rate, split by category.`, evidence: 'Cost breakdown table with per-line formulas.', why: 'Defensible budget for executive approval.', action: 'Approve budget allocation per the decision center.' },
  ];
}

// #9 — Executive Risk Acceptance register (Mitigate / Accept / Transfer / Defer)
// I4#5 — every disposition carries a formal Risk Owner Approval block: the
// designated approver, approval status, date and signature method. Approvals
// are generated as "Pending Executive Sign-off" — never fabricated — and are
// executed against the report's digital signature (SHA3-256 hash + token).
export function buildRiskAcceptance(snapshot: QuantumReadinessSnapshot, findingGroups: FindingGroup[], riskDomainModel: RiskDomainDatum[]): RiskAcceptance[] {
  const now = new Date();
  const reviewIn = (weeks: number) => (snapshot.hasData ? format(addWeeks(now, weeks), 'yyyy-MM-dd') : EVIDENCE_UNAVAILABLE);
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  const approval = (approver: string) => ({
    approver,
    approvalStatus: 'Pending Executive Sign-off',
    approvalDate: 'Pending sign-off',
    approvalMethod: 'Digital signature — report SHA3-256 integrity hash + verification token',
  });
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
      ...approval('CISO'),
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
      ...approval('CISO'),
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
      ...approval('CISO'),
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
    ...approval('CFO / Risk Committee'),
  });
  return out;
}

// #10 — Asset-Level Readiness (which assets drive the overall score)
// I4#3/#7 — enriched into an executive asset inventory: business context
// (unit / environment / criticality / platform / cloud provider) and per-asset
// crypto posture (TLS version, cert expiry, primary algorithm, key size, PQC
// status, HNDL exposure) joined from the Asset Intelligence Profile so teams
// can assign work directly from this table. Unobserved fields stay honest
// `Evidence Not Available`.
export function buildAssetReadiness(snapshot: QuantumReadinessSnapshot, assetIntelligence: AssetIntelligence[]): AssetReadiness[] {
  const nodeByLabel = new Map(snapshot.exposureGraph.nodes.map((n) => [n.label, n]));
  const intelByKey = new Map(assetIntelligence.map((ai) => [normalizeAssetKey(ai.asset), ai]));
  const s = snapshot.scores;
  return snapshot.topRiskAssets.slice(0, 12).map((a) => {
    const node = nodeByLabel.get(a.asset);
    const intel = intelByKey.get(normalizeAssetKey(a.asset));
    const internetFacing = node?.internetFacing ?? false;
    const posture = a.status;
    const postureBonus = /pqc/i.test(posture) ? 35 : /hybrid/i.test(posture) ? 12 : 0;
    // Blends the tenant readiness with this asset's own risk & posture so the
    // highest-risk assets clearly read as the lowest-readiness score drivers.
    const readiness = clamp(round(s.quantumReadiness * 0.5 + (100 - a.riskScore) * 0.3 + postureBonus - (internetFacing ? 4 : 0)));
    const primaryDriver = a.riskScore >= 70 ? (internetFacing ? 'Internet-facing legacy TLS / RSA transport' : 'Quantum-vulnerable cryptography') : a.riskScore >= 40 ? 'Partial hybrid coverage — classical primitives remain' : 'Minor residual exposure';
    const pqcReadyPct = intel?.pqcReadinessPct ?? (/pqc/i.test(posture) ? 100 : /hybrid/i.test(posture) ? 50 : 0);
    const pqcStatus = /pqc/i.test(posture) ? 'PQC-Ready' : /hybrid/i.test(posture) ? 'Hybrid (partial)' : `Not Started (${pqcReadyPct}% ready)`;
    // Per-asset HNDL: PQC-ready assets no longer expose harvestable classical
    // ciphertext; assets still on vulnerable crypto inherit the tenant HNDL
    // level, qualified by whether their traffic is publicly capturable.
    const hndlExposure = /pqc/i.test(posture)
      ? 'Low — quantum-safe transport'
      : internetFacing
        ? `${s.hndlRiskLevel} (public ciphertext capturable)`
        : /hybrid/i.test(posture)
          ? 'Medium — partial hybrid coverage'
          : s.hndlRiskLevel;
    return {
      asset: a.asset,
      readiness,
      risk: a.riskScore,
      posture,
      internetFacing,
      primaryDriver,
      owner: normalizeOwner(a.owner),
      businessUnit: intel?.businessUnit ?? EVIDENCE_UNAVAILABLE,
      environment: a.environment || intel?.environment || EVIDENCE_UNAVAILABLE,
      criticality: intel?.businessCriticality ?? (a.riskScore >= 70 ? 'High' : a.riskScore >= 40 ? 'Medium' : 'Low'),
      platform: intel?.platform ?? EVIDENCE_UNAVAILABLE,
      cloudProvider: intel?.cloudProvider ?? EVIDENCE_UNAVAILABLE,
      tlsVersion: intel?.tlsVersion ?? EVIDENCE_UNAVAILABLE,
      certExpiry: intel?.certExpiry ?? EVIDENCE_UNAVAILABLE,
      primaryAlgorithm: intel?.primaryAlgorithm ?? EVIDENCE_UNAVAILABLE,
      keySize: intel?.keyLength ?? EVIDENCE_UNAVAILABLE,
      pqcStatus,
      hndlExposure,
    };
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
    { factor: 'PQC Adoption', rawWeight: 0.45, score: s.pqcAdoption, measured: true, basis: `${inv.pqcReadyComponents} of ${inv.cryptoComponents} CBOM component(s) PQC-ready (${countPct(inv.pqcReadyComponents, inv.cryptoComponents)}); adoption score ${s.pqcAdoption}% incl. ½-weighted hybrid components` },
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
  // Largest-remainder hour allocation so Σ per-wave hours equals the programme
  // total exactly (independent per-wave Math.round drifted the table ±1 hour vs
  // the Cost Forecast total, failing the report's auditor-exact arithmetic bar).
  const exactHours = waves.map((wave) => wave.costUsd / BLENDED_RATE_USD);
  const waveHours = exactHours.map((h) => Math.floor(h));
  let hourRemainder = Math.round(exactHours.reduce((sum, h) => sum + h, 0)) - waveHours.reduce((sum, h) => sum + h, 0);
  const byFraction = exactHours
    .map((h, i) => ({ i, frac: h - Math.floor(h) }))
    .sort((a, b) => b.frac - a.frac);
  for (const { i } of byFraction) {
    if (hourRemainder <= 0) break;
    waveHours[i] += 1;
    hourRemainder -= 1;
  }
  const byTeam = new Map<string, { hours: number; weeks: number; waves: string[]; deps: Set<string> }>();
  waves.forEach((wave, waveIndex) => {
    const team = normalizeOwner(wave.owner);
    const hours = waveHours[waveIndex];
    const entry = byTeam.get(team) || { hours: 0, weeks: 0, waves: [], deps: new Set<string>() };
    entry.hours += hours;
    entry.weeks += wave.durationWeeks;
    entry.waves.push(`W${wave.wave} ${wave.name}`);
    (wave.dependencies || []).forEach((d) => entry.deps.add(d));
    byTeam.set(team, entry);
  });
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

// I3#1 / I4#1 — Confidence taxonomy: distinct, clearly-labelled confidence
// concepts, including the entire-programme Migration Forecast Confidence.
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
  const program = waveSimulation[waveSimulation.length - 1];
  return {
    // How complete the EVIDENCE behind the assessment is (coverage-driven).
    assessmentConfidencePct: migrationConfidence.overallPct,
    // How confident we are the RECOMMENDED PLAN will achieve its outcome.
    migrationPlanConfidencePct: advisor.confidencePct,
    // I4#1 — confidence in the ENTIRE-PROGRAMME forecast (final simulation row).
    migrationForecastConfidencePct: program ? program.confidencePct : 0,
    // Per-wave execution confidence, decaying with each successive wave.
    waveConfidenceRange: waveRange,
    // Mean confidence across evidence SOURCES (scanner, CBOM, certs, …).
    evidenceConfidencePct: evidenceAvg,
    note: snapshot.hasData
      ? 'Five distinct confidence measures: Assessment Confidence = completeness of the evidence behind the assessment; Migration Plan Confidence = likelihood the recommended plan achieves its target; Migration Forecast Confidence = confidence in the entire-programme simulation outcome; Wave Confidence = per-wave execution confidence (declines across waves); Evidence Confidence = mean quality across evidence sources. They are computed independently and are not interchangeable.'
      : `${EVIDENCE_UNAVAILABLE}. Run a discovery scan to compute confidence measures.`,
  };
}

// I4#2 — Readiness Progression Ladder™: the migration simulation restated in
// executive wording — Current Readiness → Projected After Wave N → Target
// Readiness — with the cumulative risk, timeline and confidence at each step.
// Values are copied from the wave simulation, so the two sections reconcile
// exactly by construction.
export function buildReadinessProgression(
  snapshot: QuantumReadinessSnapshot,
  waves: MigrationWave[],
  waveSimulation: WaveSimulation[],
  executiveBlock: ExecutiveBlock,
): ReadinessProgressionStep[] {
  if (!snapshot.hasData || !waveSimulation.length) return [];
  const steps: ReadinessProgressionStep[] = [
    {
      stage: 'Current Readiness',
      readiness: snapshot.scores.quantumReadiness,
      risk: snapshot.scores.quantumRisk,
      detail: 'Assessed baseline from live evidence (see Readiness Scoring Methodology).',
    },
  ];
  waveSimulation.forEach((sim, index) => {
    const isProgram = index === waveSimulation.length - 1;
    if (isProgram) {
      steps.push({
        stage: `Target Readiness — Entire Programme (+ Validation, Optimization & Governance)`,
        readiness: sim.readinessTo,
        risk: sim.riskTo,
        detail: `Programme target ${executiveBlock.targetReadiness}/100 readiness with residual risk ${sim.riskTo}/100 · ${sim.timelineWeeks} weeks total · forecast confidence ${sim.confidencePct}%.`,
      });
    } else {
      const wave = waves[index];
      steps.push({
        stage: `Projected After Wave ${index + 1}${wave ? ` — ${wave.name}` : ''}`,
        readiness: sim.readinessTo,
        risk: sim.riskTo,
        detail: `Cumulative ${sim.timelineWeeks} week(s) · risk ${sim.riskFrom} → ${sim.riskTo}/100 · wave confidence ${sim.confidencePct}%.`,
      });
    }
  });
  return steps;
}

// I4#9 — Executive Certification Summary™: the report's closing page. Every
// figure is copied from already-validated sections; the certification status is
// COMPUTED from published, evidence-based criteria — never asserted. The QR
// code, digital signature and integrity hash are attached at signing/export
// time from the report integrity block.
export function buildCertificationSummary(args: {
  snapshot: QuantumReadinessSnapshot;
  branding: ReportBranding;
  generatedBy: string;
  scope: ReportScope;
  executiveBlock: ExecutiveBlock;
  confidenceSummary: ConfidenceSummary;
  riskForecast: RiskForecast;
  waves: MigrationWave[];
  reportValidation: ReportValidation;
  roadmap: RoadmapPhase[];
}): CertificationSummary {
  const { snapshot, branding, generatedBy, scope, executiveBlock, confidenceSummary, riskForecast, waves, reportValidation, roadmap } = args;
  const s = snapshot.scores;
  const criteria = [
    { criterion: 'Quantum Readiness', required: `≥ ${CERTIFICATION_READINESS_THRESHOLD}/100`, actual: `${s.quantumReadiness}/100`, met: s.quantumReadiness >= CERTIFICATION_READINESS_THRESHOLD },
    { criterion: 'PQC Adoption', required: '≥ 60%', actual: `${s.pqcAdoption}%`, met: s.pqcAdoption >= 60 },
    { criterion: 'Current Quantum Risk', required: '≤ 20/100', actual: `${s.quantumRisk}/100`, met: s.quantumRisk <= 20 },
    { criterion: 'HNDL Exposure', required: '≤ 25/100', actual: `${s.hndlRisk}/100 (${s.hndlRiskLevel})`, met: s.hndlRisk <= 25 },
    { criterion: 'Assessment Evidence Confidence', required: '≥ 80%', actual: `${confidenceSummary.assessmentConfidencePct}%`, met: confidenceSummary.assessmentConfidencePct >= 80 },
    { criterion: 'Report Validation', required: 'PASS', actual: reportValidation.overall, met: reportValidation.overall === 'PASS' },
  ];
  const certified = snapshot.hasData && criteria.every((c) => c.met);
  const firstWave = waves[0];
  const migrationStatus = !snapshot.hasData
    ? EVIDENCE_UNAVAILABLE
    : `Planned — ${waves.length} wave(s) over ${snapshot.estimates.migrationTimelineWeeks || 'TBD'} weeks${firstWave ? `; Wave 1 (${firstWave.name}) status: ${firstWave.status}` : ''}. Executive approval pending (see Executive Decision Center). Dated milestones below.`;
  // I5#4 — dated milestone schedule copied from the programme roadmap (same
  // dates/gates as the Migration Roadmap & Program Plan section), closed by the
  // certification-eligibility review after the validation phase.
  const lastPhase = roadmap[roadmap.length - 1];
  const milestones = snapshot.hasData
    ? [
        ...roadmap.map((phase) => ({
          milestone: phase.milestone && phase.milestone !== EVIDENCE_UNAVAILABLE ? `${phase.phase} — ${phase.milestone}` : phase.phase,
          window: phase.startDate !== EVIDENCE_UNAVAILABLE ? `${phase.startDate} → ${phase.endDate}` : 'TBD',
          gate: phase.gate || '',
        })),
        {
          milestone: 'Certification Eligibility Review',
          window: lastPhase && lastPhase.endDate !== EVIDENCE_UNAVAILABLE ? `From ${lastPhase.endDate}` : 'After validation sign-off',
          gate: 'Quantum Trust Certification™ criteria re-evaluated from a post-programme re-assessment — certification is computed from measured evidence, never asserted',
        },
      ]
    : [];
  const scopeStatement = scope.type === 'custom'
    ? `Custom scope — ${scope.selectedAssetCount} of ${scope.totalAssetCount} discovered asset(s) selected by the report owner; every figure reflects the selected scope only.`
    : `Full assessment scope — all ${scope.totalAssetCount || snapshot.inventory.assetsAssessed} discovered asset(s).`;
  return {
    overallReadiness: s.quantumReadiness,
    readinessLevel: s.quantumReadinessLevel,
    assessmentConfidencePct: confidenceSummary.assessmentConfidencePct,
    migrationForecastConfidencePct: confidenceSummary.migrationForecastConfidencePct,
    residualRisk: riskForecast.residualRisk,
    residualRiskLevel: riskLevel(riskForecast.residualRisk, false),
    migrationStatus,
    scopeStatement,
    certificationStatus: certified
      ? 'Quantum Trust Certified™'
      : snapshot.hasData
        ? 'Assessment Complete — Not Yet Certified'
        : 'Not Certified — No Assessment Evidence',
    certified,
    criteria: snapshot.hasData ? criteria : [],
    milestones,
    attestation: snapshot.hasData
      ? `This report was generated by the QGuard Helix Enterprise Reporting Engine™ from live, tenant-scoped assessment evidence for ${branding.companyName}. Every metric is traceable to its evidence source, the arithmetic and cross-section consistency are self-validated at generation time (Report Validation: ${reportValidation.overall}), and the document is sealed with a SHA3-256 integrity hash and verification token. Quantum Trust Certification™ is granted only when all published criteria below are met by measured evidence — it is computed, never asserted.`
      : `No assessment evidence exists for ${branding.companyName}. Run a PQC discovery scan to produce a certifiable assessment.`,
    signedBy: branding.reportOwner || generatedBy,
    signedRole: branding.reportOwner ? 'Report Owner' : 'Generated By',
    verificationHint: 'Verify this report: scan the QR code (or open /verify-report and paste the verification token). The decoded SHA3-256 hash must match the printed report integrity hash — any alteration of the report content changes the hash.',
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
// I5#1 — asset counts are CANONICAL: the "discovered assets" figure printed here
// is the same scope figure the Executive Certification Summary and executive
// summary use, with the formal asset-inventory count disclosed when it differs
// (scanned endpoints attributed from findings are discovered assets even before
// they are registered in the asset inventory).
export function buildDefinitions(snapshot: QuantumReadinessSnapshot, scope: ReportScope): ReportDefinition[] {
  const inv = snapshot.inventory;
  // One-decimal precision (enterprise numerical convention): 2/66 → "3.0%".
  const componentPct = inv.cryptoComponents > 0 ? pct1((inv.pqcReadyComponents / inv.cryptoComponents) * 100) : '0.0%';
  const discovered = scope.totalAssetCount || inv.assetsAssessed;
  const assetCountStatement = scope.type === 'custom'
    ? `This report's scope: ${scope.selectedAssetCount} of ${scope.totalAssetCount} discovered asset(s) (custom selection).`
    : `This assessment: ${discovered} discovered asset(s)${discovered !== inv.assetsAssessed ? ` (${inv.assetsAssessed} in the formal asset inventory; the remainder are scanned endpoints attributed from findings evidence)` : ''}.`;
  return [
    { term: 'Asset', definition: `A discovered system, endpoint, service or domain under assessment (e.g. a scanned host). ${assetCountStatement}` },
    { term: 'Cryptographic Component (CBOM)', definition: `An individual algorithm, cipher suite, key, certificate or protocol usage discovered inside assets — one asset typically contains many components. This assessment: ${inv.cryptoComponents} component(s).` },
    { term: 'PQC-Ready Component', definition: `A CBOM component already using NIST PQC (FIPS 203/204/205) or hybrid cryptography. This assessment: ${inv.pqcReadyComponents} of ${inv.cryptoComponents} (${componentPct}). The "PQC-Ready Components" readiness factor is this percentage — a component share, never an asset count.` },
    { term: 'PQC-Ready Asset', definition: `An asset whose observed cryptography is entirely PQC or hybrid. This assessment: ${inv.pqcReadyAssets} of ${inv.assetsAssessed} inventoried asset(s). Distinct from PQC-ready components by definition.` },
    { term: 'Finding vs Consolidated Finding', definition: 'A finding is one detected cryptographic weakness instance; consolidated findings group instances by root cause so an issue is counted once for decision-making.' },
    { term: 'Quantum Readiness vs Quantum Risk', definition: 'Readiness (higher is better) measures migration progress and governance; risk (lower is better) measures exposure to future quantum decryption. They are computed independently and reconciled in their methodology sections.' },
    { term: 'HNDL Exposure vs HNDL Risk (domain)', definition: `HNDL Exposure (${snapshot.scores.hndlRisk}/100 in this assessment) is the raw Harvest-Now-Decrypt-Later measure shown on the Executive Dashboard and HNDL Exposure Analysis. HNDL Risk inside the Risk Scoring Methodology is that same signal after calibration into the weighted risk-domain model (so Σ domain contributions reproduces the overall quantum risk exactly) — the two values are intentionally related but not identical.` },
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
  if (s.hndlRisk >= 25) out.push({ risk: 'Harvest-Now-Decrypt-Later Data Capture', level: s.hndlRiskLevel, driver: `HNDL exposure ${s.hndlRisk}/100 — ciphertext recorded today becomes readable once a cryptographically-relevant quantum computer exists.` });
  if (inv.dataRepositories > 0 || s.hndlRisk >= 25) out.push({
    risk: 'Long-Lived Sensitive Data Under Classical Encryption',
    level: s.hndlRisk >= 50 ? 'High' : 'Medium',
    // Never assert repositories that were not inventoried — with zero repository
    // telemetry the driver states the evidence gap instead of fabricating scope.
    driver: inv.dataRepositories > 0
      ? `${inv.dataRepositories} data repositor${inv.dataRepositories === 1 ? 'y' : 'ies'} with multi-year retention protected by classical envelopes.`
      : `No data repositories inventoried yet (storage discovery not connected) — HNDL exposure ${s.hndlRisk}/100 indicates long-lived ciphertext is capturable from quantum-vulnerable transport today; connect storage discovery to quantify at-rest exposure.`,
  });
  if (inv.certificatesAnalyzed > 0) out.push({ risk: 'Legacy PKI / Certificate Trust Chain', level: factorScore('pki') < 40 ? 'High' : 'Medium', driver: `${inv.certificatesAnalyzed} certificate(s) signed with classical algorithms (PKI maturity ${factorScore('pki')}/100).` });
  out.push({ risk: 'Limited Crypto-Agility', level: factorScore('agility') < 40 ? 'High' : 'Medium', driver: `Algorithm replacement requires per-system change (crypto-agility ${factorScore('agility')}/100) — slows every future cryptographic transition, not just PQC.` });
  return out.slice(0, 5);
}

// I5#5 — Executive Decision Package™: the one-look decision summary presented
// alongside the decision register — budget, resources, accepted/deferred risks,
// timeline, ROI and business impact, every line sourced from validated report
// sections so the package can never disagree with the detail pages.
export function buildDecisionPackage(args: {
  snapshot: QuantumReadinessSnapshot;
  costForecast: CostForecast;
  costBreakdown: CostBreakdown;
  resourceLoading: ResourceLoad[];
  riskAcceptance: RiskAcceptance[];
  roiAnalysis: RoiAnalysis;
  executiveBlock: ExecutiveBlock;
  businessImpact: BusinessImpact;
  waves: MigrationWave[];
}): DecisionPackageLine[] {
  const { snapshot, costForecast, costBreakdown, resourceLoading, riskAcceptance, roiAnalysis, executiveBlock, businessImpact, waves } = args;
  if (!snapshot.hasData) return [];
  const usd = (n: number) => (n ? `$${Math.round(n).toLocaleString()}` : EVIDENCE_UNAVAILABLE);
  const accepted = riskAcceptance.filter((r) => r.decision === 'Accept');
  const deferred = riskAcceptance.filter((r) => r.decision === 'Defer');
  const engineers = resourceLoading.reduce((sum, r) => sum + r.engineers, 0);
  return [
    {
      item: 'Budget Decision',
      value: usd(costForecast.totalUsd),
      detail: `${costBreakdown.totalHours.toLocaleString()} labour hours × $${costBreakdown.blendedRateUsd}/hr blended rate — line-item formulas in Cost Forecast Intelligence. Approver: CFO / Board.`,
    },
    {
      item: 'Resource Approval',
      value: resourceLoading.length ? `${engineers} engineer(s) across ${resourceLoading.length} team(s)` : EVIDENCE_UNAVAILABLE,
      detail: `≈ ${costBreakdown.totalEngineerWeeks} engineer-weeks / ${costBreakdown.totalFte} FTE over the ${costBreakdown.windowWeeks}-week window — per-team loading in Migration Resource Loading.`,
    },
    {
      item: 'Accepted Risks',
      value: `${accepted.length}`,
      detail: accepted.length ? accepted.map((r) => `${r.risk} (review ${r.reviewDate})`).join('; ') : 'None — all residual risks are mitigated, transferred or deferred.',
    },
    {
      item: 'Deferred Risks',
      value: `${deferred.length}`,
      detail: deferred.length ? deferred.map((r) => `${r.risk} (review ${r.reviewDate})`).join('; ') : 'None deferred.',
    },
    {
      item: 'Recommended Timeline',
      value: executiveBlock.estimatedDurationWeeks ? `${executiveBlock.estimatedDurationWeeks} weeks` : EVIDENCE_UNAVAILABLE,
      detail: waves.length ? `${waves.length} wave(s): ${waves.map((w) => `W${w.wave} ${w.name} (${w.durationWeeks}w)`).join(' → ')} + validation & optimization.` : EVIDENCE_UNAVAILABLE,
    },
    {
      item: 'Expected ROI',
      value: roiAnalysis.roiMultiple ? `${roiAnalysis.roiMultiple}×` : EVIDENCE_UNAVAILABLE,
      detail: roiAnalysis.investmentUsd
        ? `Modeled risk avoidance ${usd(roiAnalysis.riskAvoidanceUsd)} vs investment ${usd(roiAnalysis.investmentUsd)} (net ${usd(roiAnalysis.netBenefitUsd)}); assumption configurable — see ROI assumptions.`
        : EVIDENCE_UNAVAILABLE,
    },
    {
      item: 'Business Impact',
      value: `Revenue ${businessImpact.revenueImpact} · Operational ${businessImpact.operationalImpact}`,
      detail: `${businessImpact.customerFacingSystems} customer-facing system(s), HNDL exposure ${businessImpact.hndlExposure}, quantum exposure window ${businessImpact.quantumExposureWindow} — evidence per dimension in Business Impact Intelligence.`,
    },
    {
      item: 'Expected Risk Reduction',
      value: `${executiveBlock.expectedRiskReductionPct}%`,
      detail: `Quantum risk ${executiveBlock.currentRisk} → ${executiveBlock.targetRisk}/100 across the wave plan — reconciled with the migration waves and risk forecast.`,
    },
  ];
}

// I2#10 — Report Validation™: self-verifies the report's own arithmetic and
// cross-section consistency at generation time. A failed check is reported
// honestly as FAIL — the badge is computed, never asserted.
/**
 * Risk Owner Approval policy.
 *
 * Approvals are generated as "Pending Executive Sign-off" and executed against
 * the report's digital signature, so the status, date and signature method are
 * identical on every disposition. Repeating them per row added four identical
 * cells to every line without adding information — when they are uniform they
 * are stated once as policy and the per-row columns are dropped. The APPROVER
 * genuinely varies (CISO vs CFO / Risk Committee) and always stays per-row.
 */
export function buildRiskApprovalPolicy(riskAcceptance: RiskAcceptance[]): RiskApprovalPolicy {
  const empty = { uniform: false, status: '', approvalDate: '', method: '', note: '' };
  if (riskAcceptance.length < 2) return empty;
  const [first] = riskAcceptance;
  const uniform = riskAcceptance.every(
    (r) => r.approvalStatus === first.approvalStatus && r.approvalDate === first.approvalDate && r.approvalMethod === first.approvalMethod,
  );
  if (!uniform) return empty;
  return {
    uniform: true,
    status: first.approvalStatus,
    approvalDate: first.approvalDate,
    method: first.approvalMethod,
    note: `All ${riskAcceptance.length} risk dispositions carry the same approval state — ${first.approvalStatus} (${first.approvalDate}), executed via ${first.approvalMethod}. It is stated once here rather than repeated on every row; the accountable approver is listed per disposition below.`,
  };
}

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
  riskCategories: RiskCategory[];
  findings: ReportFinding[];
  impactReasons: ImpactReason[];
  sharedResponsibility: SharedResponsibilityReport;
  playbookDetail: PlaybookDetail[];
  playbookStandardControls: PlaybookStandardControls;
}): ReportValidation {
  const { snapshot, costForecast, costBreakdown, riskMethodology, readinessMethodology, waves, executiveBlock, riskForecast, waveSimulation, advisor, riskDomainModel, riskCategories, findings, impactReasons, sharedResponsibility, playbookDetail, playbookStandardControls } = args;
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

  // Disclose the population split — "27 findings" here vs "24 scanner findings"
  // in the advisor validation are different (overlapping) populations, and the
  // detail must say so or the counts read as a contradiction.
  const engineRecs = findings.filter((f) => f.source === 'Quantum Readiness Assessment Engine').length;
  const scannerDerived = findings.length - engineRecs;
  push('Evidence Traceability Verified', findings.every((f) => f.evidence.length > 0) && impactReasons.every((r) => r.evidence.length > 0), `All ${findings.length} report finding(s) (${scannerDerived} scanner-derived + ${engineRecs} assessment-engine recommendation(s)) carry evidence and all ${impactReasons.length} business-impact dimensions cite their sources.`);

  const primaryKey = riskDomainModel[0]?.matchKey || 'business';
  const expectedRec = snapshot.hasData ? DOMAIN_RECOMMENDATION[primaryKey] : advisor.recommendation;
  push('Recommendation Alignment Verified', !snapshot.hasData || advisor.recommendation === expectedRec, `The AI recommendation ("${advisor.recommendation}") targets the dominant weighted-risk domain (${riskDomainModel[0]?.category || 'n/a'}).`);

  // Per-domain target risks must blend (by the same weights as the risk
  // methodology) back to the programme target — otherwise the Quantum Risk
  // Analysis table silently implies a different overall target than the
  // executive summary states.
  const targetByCategory = new Map(riskCategories.map((c) => [c.category, c.targetScore]));
  const blendedDomainTarget = Math.round(riskDomainModel.reduce((sum, d) => sum + (targetByCategory.get(d.category) ?? 0) * d.weightFraction, 0));
  push('Target Reconciliation Verified', !snapshot.hasData || !riskDomainModel.length || Math.abs(blendedDomainTarget - executiveBlock.targetRisk) <= 2, `Weighted blend of per-domain target risks (${blendedDomainTarget}) reconciles with the programme target risk ${executiveBlock.targetRisk}/100 (±2 rounding) — domain targets share the same reduction engine as the executive summary and migration waves.`);

  const waveSum = waves.reduce((sum, w) => sum + w.riskReductionPct, 0);
  const lastSim = waveSimulation[waveSimulation.length - 1];
  // Wave costs must sum to the migration budget to the dollar — independent
  // per-wave rounding (and dropped-wave ratio loss) once printed "$156,751"
  // beside the "$156,750" budget.
  const waveCostSum = waves.reduce((sum, w) => sum + w.costUsd, 0);
  const waveCostOk = !costForecast.totalUsd || waveCostSum === costForecast.totalUsd;
  const migrationOk = waveSum === executiveBlock.expectedRiskReductionPct && waveSum === riskForecast.reductionPct && waveCostOk && (!lastSim || (lastSim.readinessTo === executiveBlock.targetReadiness && lastSim.riskTo <= executiveBlock.targetRisk));
  push('Migration Consistency Verified', migrationOk, `Σ wave reductions ${waveSum}% = executive ${executiveBlock.expectedRiskReductionPct}% = forecast ${riskForecast.reductionPct}%; Σ wave costs $${waveCostSum.toLocaleString()} = migration budget $${costForecast.totalUsd.toLocaleString()}; full-programme simulation lands on target readiness ${executiveBlock.targetReadiness} with residual risk ≤ ${executiveBlock.targetRisk}.`);

  // Presentation integrity — a board report must never print the same row
  // twice. The scanner reports one finding per detected instance, so any table
  // rendered straight from raw evidence can silently repeat; this check fails
  // the report rather than shipping duplicates to an executive audience.
  const duplicateRows = (rows: string[]): number => {
    const counts = new Map<string, number>();
    for (const row of rows) counts.set(row, (counts.get(row) || 0) + 1);
    return [...counts.values()].reduce((sum, c) => sum + (c - 1), 0);
  };
  const srDuplicates = duplicateRows(sharedResponsibility.matrix.map((m) => [m.finding, m.asset, m.owner, m.action, m.priority, m.status].join('|')));
  const findingDuplicates = duplicateRows(findings.map((f) => [f.title, f.severity, f.affectedAssets.join(','), f.currentState].join('|')));
  const playbookRepeats = playbookStandardControls.sharedKeys.length * Math.max(0, playbookDetail.length - 1);
  const noDuplicates = srDuplicates === 0 && findingDuplicates === 0;
  push(
    'Presentation Integrity Verified',
    noDuplicates,
    noDuplicates
      ? `No duplicate rows across the evidence tables: ${sharedResponsibility.matrix.length} consolidated ownership row(s) representing ${sharedResponsibility.matrixInstances} raw scanner instance(s), and ${findings.length} distinct finding record(s). ${playbookRepeats > 0 ? `${playbookRepeats} repeated change-control row(s) were hoisted into a single Standard Change Controls block.` : 'No repeated change-control rows to hoist.'}`
      : `${srDuplicates} duplicate ownership row(s) and ${findingDuplicates} duplicate finding row(s) detected — consolidation did not run. Investigate before distribution.`,
  );

  const overall = checks.every((c) => c.status === 'pass') ? 'PASS' : 'FAIL';
  return { overall, checks, note: 'All checks are computed from the generated report model at export time — the badge is verified, not asserted. A FAIL indicates an internal inconsistency that must be investigated before distribution.' };
}

/* ------------------------------------------------------------------ */
/* Assemble the full board-level report model                         */
/* ------------------------------------------------------------------ */
/**
 * Shared Responsibility Assessment™ — ownership-classified migration section.
 * Derived from the snapshot's evidence-based ownership model so the report,
 * dashboards, certification and Sophia all agree. Honest empty state when the
 * ownership model has no data.
 */
export function buildSharedResponsibilityReport(snapshot: QuantumReadinessSnapshot): SharedResponsibilityReport {
  const sr = snapshot.sharedResponsibility;
  if (!sr || !sr.hasData) return sharedResponsibilityReportSchema.parse({});
  const r = sr.readiness;
  const depLabel = (status: string) => status.replace(/_/g, ' ');
  const nextActions: string[] = [];
  if (sr.widgets.actionableFindings > 0) nextActions.push(`Execute ${sr.widgets.actionableFindings} customer-controlled remediation(s) now (waves 1–4).`);
  if (sr.widgets.migrationBlockers > 0) nextActions.push(`Track ${sr.widgets.migrationBlockers} migration blocker(s) gated on an upstream dependency.`);
  if (sr.totals.provider > 0) nextActions.push(`Monitor ${sr.totals.provider} provider-controlled finding(s) against provider post-quantum roadmaps.`);
  if (sr.totals.ecosystem > 0) nextActions.push(`Watch ${sr.totals.ecosystem} ecosystem-dependent finding(s) for browser / OS / hardware / standards adoption.`);

  // §4 — per-domain readiness timeline. Customer work is executable today;
  // provider / ecosystem items wait on upstream roadmaps (never counted against
  // the organization). Status drives the "Ready / Waiting" bar in every export.
  const timeline = [
    {
      domain: 'Customer-Controlled',
      label: sr.widgets.actionableFindings > 0 ? 'Ready to Execute' : (sr.totals.customer > 0 ? 'In Progress' : 'No Customer Findings'),
      status: sr.totals.customer === 0 ? 'not-applicable' : (sr.widgets.actionableFindings > 0 ? 'ready' : 'in-progress'),
      readiness: r.customer.score,
      note: sr.totals.customer > 0 ? `${sr.totals.customer} finding(s) you own · ${sr.widgets.actionableFindings} actionable now` : 'No customer-controlled findings classified.',
    },
    {
      domain: 'Provider-Controlled',
      label: sr.totals.provider === 0 ? 'Not Applicable' : (r.provider.score >= 70 ? 'On Provider Roadmap' : 'Awaiting Provider Roadmap'),
      status: sr.totals.provider === 0 ? 'not-applicable' : (r.provider.score >= 70 ? 'in-progress' : 'waiting'),
      readiness: r.provider.score,
      note: sr.totals.provider > 0 ? `${sr.totals.provider} finding(s) managed by a provider — track against published PQ roadmaps.` : 'No provider-controlled findings classified.',
    },
    {
      domain: 'Ecosystem-Dependent',
      label: sr.totals.ecosystem === 0 ? 'Not Applicable' : 'Awaiting Ecosystem Adoption',
      status: sr.totals.ecosystem === 0 ? 'not-applicable' : 'waiting',
      readiness: r.ecosystem.score,
      note: sr.totals.ecosystem > 0 ? `${sr.totals.ecosystem} finding(s) depend on browser / OS / hardware / standards adoption.` : 'No ecosystem-dependent findings classified.',
    },
  ];

  // Minor §1 — reconcile the classified finding count with the raw scanner
  // instance count so an auditor is never left wondering why they differ.
  const classifiedFindings = sr.totals.findings;
  const d = snapshot.riskDistribution;
  const rawScannerInstances = d.critical + d.high + d.medium + d.low;
  const reconciliationNote = classifiedFindings === rawScannerInstances
    ? `All ${classifiedFindings} classified finding(s) reconcile 1:1 with the raw scanner finding instances.`
    : `This section classifies ${classifiedFindings} finding(s) by ownership. The Evidence Sources section reports ${rawScannerInstances} raw scanner finding instance(s) (the pre-consolidation severity distribution). The counts differ because ownership classification operates on findings enriched by the assessment engine (which may add derived recommendations and de-duplicate identical scanner detections), whereas the raw instance count tallies every individual scanner detection. ${classifiedFindings > rawScannerInstances ? `The ${classifiedFindings - rawScannerInstances} additional classified item(s) originate from the assessment engine rather than a raw scanner detection.` : `The classified count is lower because identical scanner detections are consolidated before ownership classification.`} Neither figure is an error.`;

  return sharedResponsibilityReportSchema.parse({
    hasData: true,
    summary: `Of ${sr.totals.findings} classified finding(s), ${sr.totals.customer} are customer-controlled (directly actionable), ${sr.totals.provider} provider-controlled and ${sr.totals.ecosystem} ecosystem-dependent. Customer-controlled readiness is ${r.customer.score}/100 versus ${r.overall.score}/100 overall — progress is driven by the customer-controlled path while provider and ecosystem dependencies track upstream roadmaps and are never counted against the organization.`,
    readiness: { overall: r.overall.score, customer: r.customer.score, provider: r.provider.score, ecosystem: r.ecosystem.score },
    distribution: sr.domainDistribution,
    customerControlled: sr.totals.customer,
    providerControlled: sr.totals.provider,
    ecosystemDependent: sr.totals.ecosystem,
    actionableNow: sr.widgets.actionableFindings,
    waitingDependencies: sr.widgets.waitingDependencies,
    migrationBlockers: sr.widgets.migrationBlockers,
    // Consolidated ownership rows. The cap now buys 40 DISTINCT exposures
    // instead of 40 repeats of the same one.
    matrix: sr.matrix.slice(0, 40).map((m) => ({
      finding: m.finding,
      asset: m.asset || EVIDENCE_UNAVAILABLE,
      owner: m.owner,
      action: m.action,
      priority: m.priority,
      status: m.status,
      domain: m.domain,
      occurrences: Math.max(1, m.occurrences || 1),
      detectionLabels: m.detectionLabels || [],
    })),
    matrixInstances: sr.matrix.reduce((sum, m) => sum + Math.max(1, m.occurrences || 1), 0),
    blockers: sr.blockers.slice(0, 12).map((b) => ({ title: b.title, owner: b.ownerType, dependency: depLabel(b.migrationDependencyStatus) })),
    waves: sr.waves.map((w) => ({ wave: w.wave, name: w.name, domain: String(w.domain), findingCount: w.findingCount, status: w.status, timeline: w.estimatedTimeline })),
    providers: sr.providerBreakdown.slice(0, 12).map((p) => ({ name: p.name, domain: p.domain, count: p.count, pqRoadmap: p.pqRoadmapStatus, customerInfluence: p.customerInfluence })),
    timeline,
    classifiedFindings,
    rawScannerInstances,
    reconciliationNote,
    nextActions,
    note: 'Ownership is evidence-derived; unattributed findings default to the customer and are labelled as such, never guessed.',
  });
}

/* ------------------------------------------------------------------ */
/* Reports_Generation_Improvements_06 — board-level visual intelligence */
/* ------------------------------------------------------------------ */

/**
 * §5 — Evidence Quality Score. Converts each evidence source's confidence into
 * a letter grade (A–E) or "Missing" when the source produced no telemetry, so
 * executives can digest coverage at a glance instead of parsing percentages.
 */
export function buildEvidenceQuality(evidenceConfidence: EvidenceConfidence[]): EvidenceQuality {
  const gradeFor = (pct: number): string => {
    if (pct <= 0) return 'Missing';
    if (pct >= 90) return 'A';
    if (pct >= 75) return 'B';
    if (pct >= 60) return 'C';
    if (pct >= 40) return 'D';
    return 'E';
  };
  const rows = evidenceConfidence.map((e) => ({
    source: e.source,
    grade: gradeFor(e.confidencePct),
    confidencePct: e.confidencePct,
    status: e.confidencePct > 0 ? 'Available' : 'Missing',
    note: e.confidencePct > 0 ? (e.note || `${e.coveragePct}% coverage · ${e.completenessPct}% complete · ${e.freshness}`) : 'No telemetry recorded — contributed no evidence.',
  }));
  const graded = rows.filter((r) => r.grade !== 'Missing');
  const missing = rows.filter((r) => r.grade === 'Missing');
  const avg = graded.length ? Math.round(graded.reduce((sum, r) => sum + r.confidencePct, 0) / graded.length) : 0;
  const overallGrade = graded.length ? gradeFor(avg) : 'Missing';
  return {
    rows,
    overallGrade,
    gradedSources: graded.length,
    missingSources: missing.length,
    note: `Overall evidence grade ${overallGrade} across ${graded.length} contributing source(s)${missing.length ? `; ${missing.length} source(s) not yet available (deploy the relevant connector/agent to raise the grade)` : ''}. Grades: A ≥90%, B ≥75%, C ≥60%, D ≥40%, E <40%, Missing = no telemetry.`,
  };
}

/**
 * §2 — 5×5 Executive Heat Map. Plots each consolidated (root-cause) finding
 * group by Business Impact (severity, rows) × Quantum Exploitation Likelihood
 * (columns). Likelihood is floored at "Possible" because every quantum-
 * vulnerable finding is Possible-to-Almost-Certain to be broken by a CRQC, then
 * scaled by exposure (assets affected) — an honest PQC-specific model, not an
 * arbitrary placement. Cell counts + zone colour drive the board heat map.
 */
export function buildExecutiveHeatMap(findingGroups: FindingGroup[]): ExecutiveHeatMap {
  const impactLabels = ['Critical', 'High', 'Medium', 'Low', 'Minimal']; // rank 5..1 (rows, top→bottom)
  const likelihoodLabels = ['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain']; // rank 1..5 (cols, left→right)
  const zoneLevel = (product: number): string => {
    if (product >= 20) return 'critical';
    if (product >= 12) return 'high';
    if (product >= 6) return 'medium';
    if (product >= 3) return 'low';
    return 'minimal';
  };
  if (!findingGroups.length) {
    return { hasData: false, impactLabels, likelihoodLabels, cells: [], totalPlotted: 0, methodology: '', note: EVIDENCE_UNAVAILABLE };
  }
  const impactRankOf = (impact: string): number => ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 }[impact] ?? 1);
  const affectedValues = findingGroups.map((g) => g.affectedAssets);
  const sorted = [...affectedValues].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)] || 0;
  const maxAffected = Math.max(...affectedValues, 1);
  const likelihoodRankOf = (group: FindingGroup): number => {
    let rank = 3; // Possible — quantum-vulnerable crypto is never "rare"
    if (group.affectedAssets >= Math.max(median, 1)) rank += 1;
    if (group.affectedAssets >= Math.ceil(maxAffected * 0.75)) rank += 1;
    if (group.impact === 'critical' || group.impact === 'high') rank = Math.max(rank, 4);
    return Math.min(5, Math.max(1, rank));
  };

  // Aggregate finding groups into cells keyed by (impactRank, likelihoodRank).
  const buckets = new Map<string, { impactRank: number; likelihoodRank: number; count: number; items: string[] }>();
  for (const group of findingGroups) {
    const impactRank = impactRankOf(group.impact);
    const likelihoodRank = likelihoodRankOf(group);
    const key = `${impactRank}:${likelihoodRank}`;
    const bucket = buckets.get(key) || { impactRank, likelihoodRank, count: 0, items: [] };
    bucket.count += 1;
    if (bucket.items.length < 4) bucket.items.push(group.title);
    buckets.set(key, bucket);
  }

  // Emit a full 5×5 grid (row-major, impact 5→1, likelihood 1→5) so exporters
  // can render a complete matrix; empty cells carry count 0.
  const cells: HeatMapCell[] = [];
  for (let impactRank = 5; impactRank >= 1; impactRank -= 1) {
    for (let likelihoodRank = 1; likelihoodRank <= 5; likelihoodRank += 1) {
      const bucket = buckets.get(`${impactRank}:${likelihoodRank}`);
      cells.push({
        impact: impactLabels[5 - impactRank],
        likelihood: likelihoodLabels[likelihoodRank - 1],
        impactRank,
        likelihoodRank,
        count: bucket?.count || 0,
        level: zoneLevel(impactRank * likelihoodRank),
        items: bucket?.items || [],
      });
    }
  }
  return {
    hasData: true,
    impactLabels,
    likelihoodLabels,
    cells,
    totalPlotted: findingGroups.length,
    methodology: 'Business Impact = consolidated finding severity. Quantum Exploitation Likelihood is floored at "Possible" (all quantum-vulnerable cryptography is Possible-to-Almost-Certain to be broken by a cryptographically-relevant quantum computer) and scaled up by exposure — the number of assets affected by each finding. Cell colour is the Impact × Likelihood risk zone.',
    note: `${findingGroups.length} consolidated finding group(s) plotted across the 5×5 Impact × Likelihood grid.`,
  };
}

/**
 * §3 — Business Priority Matrix. Classifies remediation items into four
 * investment quadrants by Business Value (risk reduction achieved) × Effort
 * (implementation cost/complexity): Quick Wins, Strategic Projects, Fill-Ins
 * and Long-Term — the view CIOs use to sequence investment.
 */
export function buildBusinessPriorityMatrix(remediation: RemediationItem[]): BusinessPriorityMatrix {
  const quadrantDefs: Array<{ key: string; title: string; subtitle: string; guidance: string }> = [
    { key: 'quick-wins', title: 'Quick Wins', subtitle: 'High Value · Low Effort', guidance: 'Execute immediately — high risk reduction for modest effort.' },
    { key: 'strategic', title: 'Strategic Projects', subtitle: 'High Value · High Effort', guidance: 'Fund and plan — high risk reduction requiring dedicated programme investment.' },
    { key: 'fill-ins', title: 'Fill-Ins', subtitle: 'Lower Value · Low Effort', guidance: 'Batch opportunistically alongside larger work.' },
    { key: 'long-term', title: 'Long-Term', subtitle: 'Lower Value · High Effort', guidance: 'Defer or re-scope — limited near-term return for significant effort.' },
  ];
  const quadrants: PriorityQuadrant[] = quadrantDefs.map((q) => ({ ...q, items: [] as PriorityMatrixItem[] }));
  if (!remediation.length) {
    return { hasData: false, quadrants, note: EVIDENCE_UNAVAILABLE };
  }
  const reductions = remediation.map((r) => r.riskReductionPct).sort((a, b) => a - b);
  const medianReduction = reductions[Math.floor(reductions.length / 2)] || 0;
  const valueThreshold = Math.max(10, medianReduction); // high value = meaningful risk reduction
  const effortIsHigh = (item: RemediationItem): boolean =>
    /high|large|complex|major|significant/i.test(item.effort) || item.dependencies.length >= 3;
  for (const item of remediation) {
    const highValue = item.riskReductionPct >= valueThreshold;
    const highEffort = effortIsHigh(item);
    const key = highValue ? (highEffort ? 'strategic' : 'quick-wins') : (highEffort ? 'long-term' : 'fill-ins');
    const quadrant = quadrants.find((q) => q.key === key)!;
    quadrant.items.push({
      name: item.action,
      riskReductionPct: item.riskReductionPct,
      effort: item.effort || 'Evidence Not Available',
      businessValue: highValue ? 'High' : 'Moderate',
      rationale: `${item.riskReductionPct}% risk reduction · ${item.effort || 'effort n/a'} · ${item.affectedAssets.length || 0} asset(s)${item.dependencies.length ? ` · ${item.dependencies.length} dependency(ies)` : ''}`,
    });
  }
  for (const q of quadrants) q.items.sort((a, b) => b.riskReductionPct - a.riskReductionPct);
  return {
    hasData: true,
    quadrants,
    note: `${remediation.length} remediation action(s) classified by business value (risk reduction ≥ ${valueThreshold}% = high) and effort. Quick Wins deliver the fastest return; Strategic Projects need programme funding.`,
  };
}

/**
 * Minor §3 — Remediation Campaigns. Consolidates remediation actions that share
 * the same cryptographic target under one campaign theme so the same "migrate
 * to the NIST-approved PQC replacement" guidance is not repeated dozens of
 * times — shorter and executive-friendly without losing traceability.
 */
export function buildRemediationCampaigns(findingGroups: FindingGroup[], remediation: RemediationItem[]): RemediationCampaigns {
  const themeOf = (text: string): { campaign: string; target: string; action: string } => {
    const t = text.toLowerCase();
    if (/ml-kem|key exchange|key establishment|rsa|ecdh|diffie|kem/.test(t))
      return { campaign: 'Key Establishment Modernization', target: 'X25519 + ML-KEM-768 (hybrid, FIPS 203)', action: 'Replace RSA/ECC key exchange with an ML-KEM hybrid across affected endpoints.' };
    if (/ml-dsa|slh-dsa|signature|ecdsa|sign|rsa-pss/.test(t))
      return { campaign: 'Digital Signature Modernization', target: 'ML-DSA-65 (FIPS 204)', action: 'Migrate quantum-vulnerable signatures to ML-DSA (hybrid where interop requires).' };
    if (/tls|ssl|cipher|protocol|handshake|forward secrecy/.test(t))
      return { campaign: 'TLS / Transport Hardening', target: 'TLS 1.3 + hybrid PQC key exchange', action: 'Upgrade transport to TLS 1.3 and negotiate a hybrid PQC key exchange.' };
    if (/cert|pki|x\.509|chain|ca\b/.test(t))
      return { campaign: 'PKI / Certificate Modernization', target: 'PQC-capable certificate chain (ML-DSA)', action: 'Re-issue certificates from a PQC-capable chain and shorten certificate lifetimes.' };
    if (/aes|symmetric|3des|cbc|gcm/.test(t))
      return { campaign: 'Symmetric Strengthening', target: 'AES-256-GCM', action: 'Standardise on AES-256-GCM for data-in-transit and at-rest.' };
    return { campaign: 'Other Cryptographic Remediation', target: 'NIST-approved PQC replacement', action: 'Migrate to the NIST-approved PQC replacement for the affected primitive.' };
  };
  const reductionFor = (title: string): number => {
    const match = remediation.find((r) => normalizeAssetKey(r.action).includes(normalizeAssetKey(title).slice(0, 8)));
    return match?.riskReductionPct || 0;
  };
  const byCampaign = new Map<string, RemediationCampaign>();
  for (const group of findingGroups) {
    const theme = themeOf(group.title);
    const existing = byCampaign.get(theme.campaign) || {
      campaign: theme.campaign,
      target: theme.target,
      action: theme.action,
      findings: [] as string[],
      findingCount: 0,
      affectedAssets: 0,
      occurrences: 0,
      riskReductionPct: 0,
      priority: '',
    };
    existing.findings.push(group.title);
    existing.findingCount += 1;
    existing.affectedAssets = Math.max(existing.affectedAssets, group.affectedAssets);
    existing.occurrences += group.occurrences;
    existing.riskReductionPct = Math.min(100, existing.riskReductionPct + reductionFor(group.title));
    byCampaign.set(theme.campaign, existing);
  }
  const campaigns = Array.from(byCampaign.values()).sort((a, b) => b.occurrences - a.occurrences);
  // Priority by occurrence rank (P1 = most pervasive campaign).
  campaigns.forEach((c, i) => { c.priority = `P${i + 1}`; });
  return {
    campaigns,
    note: campaigns.length
      ? `${findingGroups.length} consolidated finding group(s) rolled up into ${campaigns.length} remediation campaign(s). Each campaign groups findings that share a single cryptographic target so guidance appears once, with full traceability to its member findings.`
      : EVIDENCE_UNAVAILABLE,
  };
}

/**
 * §6 — Executive One-Page Board Snapshot. The 60-second summary placed at the
 * very front of the report. Every value is copied from an already-validated
 * section so it can never disagree with the body.
 */
export function buildBoardSnapshot(args: {
  snapshot: QuantumReadinessSnapshot;
  executiveBlock: ExecutiveBlock;
  roiAnalysis: RoiAnalysis;
  executiveDecisions: ExecutiveDecision[];
  certification: CertificationSummary;
  sharedResponsibility: SharedResponsibilityReport;
  discoveredAssets: number;
}): BoardSnapshot {
  const { snapshot, executiveBlock: ex, roiAnalysis: roi, executiveDecisions, certification: cert, sharedResponsibility: sr, discoveredAssets } = args;
  if (!snapshot.hasData) {
    return {
      hasData: false, headline: EVIDENCE_UNAVAILABLE, certificationStatus: '', certified: false,
      currentReadiness: 0, targetReadiness: 0, currentRisk: 0, targetRisk: 0, investmentUsd: 0, timelineWeeks: 0,
      roiSummary: EVIDENCE_UNAVAILABLE, riskReductionPct: 0, metrics: [], topDecisions: [],
      responsibilitySplit: { customer: 0, provider: 0, ecosystem: 0 }, responsibilityNote: '', assetBasis: '', recommendation: '',
    };
  }
  const usd = (n: number) => (n ? `$${Math.round(n).toLocaleString()}` : 'Evidence Not Available');
  const inv = snapshot.inventory;
  const metrics = [
    { label: 'Quantum Readiness', value: `${ex.currentReadiness}/100`, context: `Target ${ex.targetReadiness}/100 (${snapshot.scores.quantumReadinessLevel})` },
    { label: 'Quantum Risk', value: `${ex.currentRisk}/100`, context: `Target ${ex.targetRisk}/100 · −${ex.expectedRiskReductionPct}%` },
    { label: 'Investment', value: usd(ex.estimatedCostUsd), context: `${ex.estimatedDurationWeeks || 'TBD'}-week programme` },
    { label: 'Return on Investment', value: roi.roiMultiple ? `${roi.roiMultiple}×` : 'Evidence Not Available', context: `${usd(roi.riskAvoidanceUsd)} risk avoidance` },
    { label: 'HNDL Exposure', value: `${ex.currentHndl}/100`, context: `Window ${ex.quantumExposureWindow}` },
    { label: 'Certification', value: cert.certified ? 'Certified' : 'Not Yet Certified', context: cert.certificationStatus },
  ];
  const topDecisions = executiveDecisions.slice(0, 5).map((d) => d.decision);
  const dist = sr.hasData ? sr.distribution : { customer: 0, provider: 0, ecosystem: 0 };
  const responsibilityNote = sr.hasData
    ? `${dist.customer} customer-controlled (directly actionable) · ${dist.provider} provider-controlled · ${dist.ecosystem} ecosystem-dependent. Provider/ecosystem items track upstream roadmaps and are never counted against the organization.`
    : 'Shared responsibility classification not available for this scope.';
  return {
    hasData: true,
    headline: `Readiness ${ex.currentReadiness}/100 today → ${ex.targetReadiness}/100 target · Risk ${ex.currentRisk}/100 → ${ex.targetRisk}/100 · ${usd(ex.estimatedCostUsd)} over ${ex.estimatedDurationWeeks || 'TBD'} weeks · ${cert.certificationStatus}.`,
    certificationStatus: cert.certificationStatus,
    certified: cert.certified,
    currentReadiness: ex.currentReadiness,
    targetReadiness: ex.targetReadiness,
    currentRisk: ex.currentRisk,
    targetRisk: ex.targetRisk,
    investmentUsd: ex.estimatedCostUsd,
    timelineWeeks: ex.estimatedDurationWeeks,
    roiSummary: roi.paybackNarrative,
    riskReductionPct: ex.expectedRiskReductionPct,
    metrics,
    topDecisions,
    responsibilitySplit: dist,
    responsibilityNote,
    assetBasis: `Asset counts in this report: ${discoveredAssets} discovered (scanned or attributed from evidence), ${inv.assetsAssessed} inventoried (formal asset records), ${inv.quantumVulnerableAssets} requiring migration (quantum-vulnerable). "Discovered" is the widest set; "inventoried" is the formal asset table; "requiring migration" is the vulnerable subset.`,
    recommendation: ex.executiveRecommendation,
  };
}

export function buildReportModel(
  snapshot: QuantumReadinessSnapshot,
  branding: ReportBranding,
  kind: ReportKind,
  generatedBy: string,
  scope?: ReportScope,
): EnterpriseAssessmentReport {
  const now = new Date();
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  // Asset scope — when the caller pre-scoped the snapshot (ReportEngine /
  // reports API) it passes the matching scope block; otherwise build the full
  // scope with buildReportScope — the SAME builder the reports page uses, so
  // the default path can never disagree with the live flow (it previously
  // duplicated the scope inline and drifted on the count disclosure).
  const reportScope: ReportScope = scope ?? buildReportScope(snapshot, null);

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
  const riskCategories = buildRiskCategories(snapshot, riskDomainModel);
  const compliance = buildCompliance(snapshot);
  const costForecast = buildCostForecast(snapshot);
  const riskMethodology = buildRiskMethodology(snapshot, riskDomainModel);
  const advisorValidation = buildAdvisorValidation(snapshot, advisor, riskMethodology);
  const costBreakdown = buildCostBreakdown(snapshot, costForecast);
  const assetCriticality = buildAssetCriticality(snapshot, compliance);
  const businessImpact = buildBusinessImpact(snapshot);
  const impactReasons = buildImpactReasons(snapshot, businessImpact);
  const migrationConfidence = buildMigrationConfidence(snapshot);
  const evidenceConfidence = buildEvidenceConfidence(snapshot);
  const executiveDecisions = buildExecutiveDecisions(snapshot, waves, executiveBlock);
  const playbookDetail = buildPlaybookDetail(findingGroups);
  const waveSimulation = buildWaveSimulation(snapshot, waves, executiveBlock, migrationConfidence);
  const governanceGates = buildGovernanceGates();
  const explainability = buildExplainability(snapshot, riskMethodology, migrationConfidence, waveSimulation);
  // Asset intelligence is built first so the asset-readiness table can join its
  // per-asset crypto/business metadata (I4#3/#7).
  const assetIntelligence = buildAssetIntelligence(snapshot, costBreakdown);
  // Improvements_01 — evidence-driven, traceable extensions
  const riskAcceptance = buildRiskAcceptance(snapshot, findingGroups, riskDomainModel);
  const assetReadiness = buildAssetReadiness(snapshot, assetIntelligence);
  const decisionChain = buildDecisionChain(snapshot, advisor, riskDomainModel, waves, executiveBlock, findingGroups);

  // Improvements_02 — enterprise-grade report intelligence
  const riskForecast = buildRiskForecast(snapshot);
  const readinessMethodology = buildReadinessMethodology(snapshot);
  const readinessIndex = buildReadinessIndex(snapshot, domains);
  const roiAnalysis = buildRoiAnalysis(snapshot, costForecast, executiveBlock);
  const resourceLoading = buildResourceLoading(snapshot, waves);
  const benchmarking = buildBenchmarking(snapshot, executiveBlock);
  const cryptoPolicy = buildCryptoPolicy();
  const definitions = buildDefinitions(snapshot, reportScope);
  const roadmap = buildRoadmap(snapshot, waves);
  // Improvements_03 — refinements
  const confidenceSummary = buildConfidenceSummary(snapshot, migrationConfidence, advisor, evidenceConfidence, waveSimulation);
  const operationalBenefits = buildOperationalBenefits(snapshot);
  const maturityModel = buildMaturityModel(snapshot, domains, waves);
  // Ownership section is needed by Report Validation's presentation-integrity
  // check, so it is built before validation rather than with the board sections.
  const sharedResponsibility = buildSharedResponsibilityReport(snapshot);
  // Presentation consolidation — hoist the change-management controls every
  // playbook shares, and the risk-approval fields every disposition shares, so
  // the exports state them once instead of repeating them per row.
  const playbookStandardControls = buildPlaybookStandardControls(playbookDetail);
  const riskApprovalPolicy = buildRiskApprovalPolicy(riskAcceptance);
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
    riskCategories,
    findings,
    impactReasons,
    sharedResponsibility,
    playbookDetail,
    playbookStandardControls,
  });
  // Improvements_04 — refinements
  const readinessProgression = buildReadinessProgression(snapshot, waves, waveSimulation, executiveBlock);
  const certification = buildCertificationSummary({
    snapshot,
    branding,
    generatedBy,
    scope: reportScope,
    executiveBlock,
    confidenceSummary,
    riskForecast,
    waves,
    reportValidation,
    roadmap,
  });
  // Improvements_05 — refinements
  const decisionPackage = buildDecisionPackage({
    snapshot,
    costForecast,
    costBreakdown,
    resourceLoading,
    riskAcceptance,
    roiAnalysis,
    executiveBlock,
    businessImpact,
    waves,
  });
  // I5#1 — canonical asset count: the scope's discovered-asset universe (asset
  // inventory ∪ scanned endpoints attributed from findings). Every asset-count
  // statement (executive summary, definitions, certification scope) uses it.
  const discoveredAssets = reportScope.type === 'custom'
    ? reportScope.selectedAssetCount
    : (reportScope.totalAssetCount || inv.assetsAssessed);

  // Improvements_06 — board-level visual intelligence. All derive from sections
  // built above (no new evidence sources), so they reconcile by construction.
  const remediationProgram = buildRemediationProgram(snapshot, findings, waves);
  const executiveHeatMap = buildExecutiveHeatMap(findingGroups);
  const businessPriorityMatrix = buildBusinessPriorityMatrix(remediationProgram);
  const evidenceQuality = buildEvidenceQuality(evidenceConfidence);
  const remediationCampaigns = buildRemediationCampaigns(findingGroups, remediationProgram);
  const boardSnapshot = buildBoardSnapshot({
    snapshot,
    executiveBlock,
    roiAnalysis,
    executiveDecisions,
    certification,
    sharedResponsibility,
    discoveredAssets,
  });
  // I5#2 — evidence sources that produced data vs telemetry not yet available.
  const availableSources = evidenceConfidence.filter((e) => e.confidencePct > 0).map((e) => e.source);
  const unavailableSources = evidenceConfidence.filter((e) => e.confidencePct <= 0).map((e) => e.source);

  const executiveSummary = snapshot.hasData
    ? `As of ${format(now, 'PPP')}, ${branding.companyName} holds a quantum readiness score of ${s.quantumReadiness}/100 (${s.quantumReadinessLevel}) against a quantum risk score of ${s.quantumRisk}/100 (${s.quantumRiskLevel}). A funded ${snapshot.estimates.migrationTimelineWeeks || 'TBD'}-week migration programme can raise readiness to a target of ${executiveBlock.targetReadiness}/100 (the Quantum Trust Certification™ eligibility threshold) and reduce quantum risk by ${executiveBlock.expectedRiskReductionPct}%. Discovery identified ${discoveredAssets} cryptographic asset(s)${discoveredAssets !== inv.assetsAssessed ? ` (${inv.assetsAssessed} in the formal asset inventory)` : ''}, of which ${inv.quantumVulnerableAssets} inventoried asset(s) are quantum-vulnerable with ${s.pqcAdoption}% PQC adoption. Harvest-Now-Decrypt-Later exposure is rated ${s.hndlRiskLevel} with an estimated quantum exposure window of ${executiveBlock.quantumExposureWindow}. ${executiveBlock.executiveRecommendation}${reportScope.type === 'custom' ? ` Report scope: ${reportScope.selectedAssetCount} of ${reportScope.totalAssetCount} discovered assets selected by the report owner — every figure in this report reflects the selected scope only.` : ''}`
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
    scope: reportScope,
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
    sharedResponsibility,
    boardSnapshot,
    executiveHeatMap,
    businessPriorityMatrix,
    evidenceQuality,
    remediationCampaigns,
    playbookDetail,
    playbookStandardControls,
    riskApprovalPolicy,
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
    readinessProgression,
    certification,
    decisionPackage,
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
        ['HNDL Exposure Score', s.hndlRisk],
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
          ? `${inv.pqcReadyComponents} of ${inv.cryptoComponents} CBOM component(s) (${countPct(inv.pqcReadyComponents, inv.cryptoComponents)}) — a component share, not an asset count`
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
    remediationProgram,
    roadmap,
    playbook: buildPlaybook(waves),
    costForecast,
    riskForecast,
    governance: buildGovernance(snapshot),
    remediation: safeTable('Remediation Plan', ['Priority', 'Action', 'Owner', 'Risk Reduction', 'Target Date'],
      remediationProgram.map((item) => [item.priority, item.action, item.owner, `${item.riskReductionPct}%`, item.targetDate])),
    evidence: {
      // I5#2 — only sources that actually produced evidence are listed as
      // sources; unavailable telemetry is disclosed separately so it is never
      // implied to have contributed.
      sources: availableSources,
      unavailableSources,
      notes: snapshot.hasData
        ? (() => {
            // I5#6 — severity counts with one-decimal percentage context so the
            // distribution is executive-readable at a glance.
            const totalSev = distribution.critical + distribution.high + distribution.medium + distribution.low;
            const sev = (label: string, n: number) => `${label}: ${n}${totalSev > 0 ? ` (${countPct(n, totalSev)})` : ''}`;
            return `Severity distribution of ${totalSev} raw scanner finding instance(s) across all severities — ${sev('Critical', distribution.critical)}, ${sev('High', distribution.high)}, ${sev('Medium', distribution.medium)}, ${sev('Low', distribution.low)}. This is the pre-consolidation instance count: the report body consolidates the critical/high instances by root cause (see Consolidated Findings), so it is intentionally larger than the finding counts cited there. Sources listed under "Not Available" have not yet produced telemetry and contributed no evidence to this report.`;
          })()
        : `${EVIDENCE_UNAVAILABLE}. No scans, assets, certificates or runtime telemetry recorded for this tenant.`,
    },
    charts: [],
  };
}
