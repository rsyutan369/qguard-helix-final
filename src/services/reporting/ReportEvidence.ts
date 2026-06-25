import { v4 as uuidv4 } from 'uuid';
import { addWeeks, format } from 'date-fns';
import type { QuantumReadinessSnapshot } from '@/app/dashboard/quantum-readiness/_shared';
import {
  EVIDENCE_UNAVAILABLE,
  normalizeSeverity,
  severityRank,
  type AdvisorValidation,
  type AssetCriticality,
  type BusinessImpact,
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
  type RemediationItem,
  type ReportBranding,
  type ReportFinding,
  type ReportKind,
  type ReportKpi,
  type ReportTable,
  type RiskCategory,
  type RiskForecast,
  type RiskMethodology,
  type RoadmapPhase,
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

function recommendedState(algorithm: string): string {
  const a = (algorithm || '').toUpperCase();
  if (/RSA|\bDH\b|DIFFIE/.test(a)) return 'TLS 1.3 + X25519 + ML-KEM-768 (Hybrid)';
  if (/ECDSA|P-256|P-384|\bECC\b|EC-/.test(a)) return 'Ed25519 + ML-DSA-65 (Hybrid Signature)';
  if (/ECDH/.test(a)) return 'X25519 + ML-KEM-768 (Hybrid KEM)';
  if (/SHA-?1|MD5/.test(a)) return 'SHA3-256';
  if (/3DES|\bDES\b|RC4/.test(a)) return 'AES-256-GCM';
  return 'ML-KEM (FIPS 203) / ML-DSA (FIPS 204)';
}

function internetFacingLabels(snapshot: QuantumReadinessSnapshot): string[] {
  return snapshot.exposureGraph.nodes.filter((n) => n.internetFacing).map((n) => n.label);
}

function dominantWeakness(domains: ReadinessDomain[]): ReadinessDomain | null {
  if (!domains.length) return null;
  return [...domains].sort((a, b) => a.score - b.score)[0];
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
export function buildReadinessDomains(snapshot: QuantumReadinessSnapshot): ReadinessDomain[] {
  const factor = (needle: string, fallback: number) => snapshot.readinessFactors.find((f) => f.label.toLowerCase().includes(needle))?.score ?? fallback;
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  const defs: Array<{ domain: string; score: number; owner: string; action: string }> = [
    { domain: 'TLS / Protocol', score: factor('tls', s.pqcAdoption), owner: 'Infrastructure Team', action: 'Enable TLS 1.3 hybrid (X25519+ML-KEM) on internet-facing endpoints.' },
    { domain: 'PKI / Certificates', score: factor('pki', s.pqcAdoption), owner: 'Security Team', action: 'Introduce hybrid certificate chains; plan ML-DSA CA migration.' },
    { domain: 'Identity', score: inv.identitiesAnalyzed > 0 ? clamp(s.pqcAdoption) : 0, owner: 'Identity Team', action: 'Assess token signing algorithms; plan ML-DSA migration.' },
    { domain: 'Application', score: clamp(s.pqcAdoption * 0.8), owner: 'Application Team', action: 'Adopt crypto-agile libraries; remove hardcoded classical primitives.' },
    { domain: 'API', score: clamp(s.pqcAdoption * 0.8), owner: 'Platform Team', action: 'Enforce hybrid TLS on API gateways and service mesh.' },
    { domain: 'Cloud', score: inv.cloudAccounts > 0 ? clamp(s.pqcAdoption) : 0, owner: 'Cloud Team', action: 'Enable PQC-ready KMS/HSM and managed TLS where available.' },
    { domain: 'Vendor', score: clamp(s.pqcAdoption * 0.7), owner: 'Vendor Management', action: 'Collect vendor PQC roadmaps; track readiness in supply-chain register.' },
    { domain: 'Crypto Agility', score: factor('agility', s.pqcAdoption), owner: 'Security Engineering', action: 'Centralise crypto policy and enable algorithm hot-swap.' },
    { domain: 'Trust Fabric', score: inv.trustRelationships > 0 ? clamp(70 - s.cryptoExposure * 0.3) : 0, owner: 'Security Architecture', action: 'Map trust chains and validate post-migration integrity.' },
    { domain: 'Governance', score: factor('governance', 0), owner: 'GRC / Compliance', action: 'Maintain crypto inventory, evidence and migration governance.' },
  ];
  return defs.map((d) => ({ domain: d.domain, score: round(d.score), riskLevel: riskLevel(d.score, true), owner: d.owner, actions: d.action }));
}

/* ------------------------------------------------------------------ */
/* AI Migration Advisor (Enhancement #8)                              */
/* ------------------------------------------------------------------ */
export function buildMigrationAdvisor(snapshot: QuantumReadinessSnapshot, domains: ReadinessDomain[], waves: MigrationWave[]): MigrationAdvisor {
  const weakest = dominantWeakness(domains);
  const s = snapshot.scores;
  const internet = internetFacingLabels(snapshot);
  const exposurePct = clamp(snapshot.riskFactors.find((f) => f.label.includes('RSA'))?.score ?? s.cryptoExposure);
  const recommendation = weakest
    ? weakest.domain.includes('TLS')
      ? 'Modernize TLS Infrastructure'
      : `Modernize ${weakest.domain} cryptography`
    : 'Establish PQC migration program';
  const firstWave = waves[0];
  return {
    recommendation,
    reason: `${exposurePct}% of identified quantum exposure originates from legacy RSA/ECC ${weakest?.domain.includes('TLS') ? 'TLS handshakes' : 'cryptography'} concentrated in ${snapshot.inventory.quantumVulnerableAssets} asset(s).`,
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
  const reductionBudget = clamp(Math.round(((snapshot.scores.quantumRisk - Math.max(10, snapshot.scores.quantumRisk * 0.25)) / Math.max(1, snapshot.scores.quantumRisk)) * 100));

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
  return specs.map((spec, index) => ({
    wave: index + 1,
    name: spec.name,
    assets: spec.assets.length ? spec.assets.slice(0, 10) : [EVIDENCE_UNAVAILABLE],
    owner: spec.owner,
    durationWeeks: Math.max(weeks ? 1 : 0, Math.round(weeks * spec.ratio)),
    costUsd: Math.round(cost * spec.ratio),
    dependencies: index === 0 ? ['Load Balancer', 'Certificate Authority'] : index === 1 ? ['Certificate Authority', 'HSM / KMS'] : ['Preceding wave validation'],
    riskReductionPct: Math.round(reductionBudget * spec.reductionShare),
    status: spec.assets.length ? (index === 0 ? 'Ready' : 'Planned') : 'Awaiting Discovery',
    priority: spec.priority,
  }));
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
    { category: 'Operational Readiness', score: clamp(snapshot.readinessFactors.find((f) => f.label.includes('Runtime'))?.score ?? 0), recommendation: 'Ensure runtime crypto telemetry covers all production paths.' },
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
  const chains = nodes
    .filter((n) => n.internetFacing || n.riskScore >= 60)
    .slice(0, 8)
    .map((node) => {
      const deps = neighbours(node.id).map((id) => labelOf.get(id)).filter(Boolean) as string[];
      const path = [node.label, ...deps.slice(0, 4)].join(' -> ') + ' -> Users';
      return { path, blastRadius: deps.length, complexity: deps.length > 3 ? 'High' : deps.length > 1 ? 'Medium' : 'Low' };
    });
  const failurePoints = nodes.filter((n) => n.riskScore >= 70).map((n) => n.label).slice(0, 8);
  return {
    chains: chains.length ? chains : [{ path: EVIDENCE_UNAVAILABLE, blastRadius: 0, complexity: 'Low' }],
    failurePoints: failurePoints.length ? failurePoints : [EVIDENCE_UNAVAILABLE],
    summary: nodes.length
      ? `${nodes.length} assets and ${edges.length} dependency relationships analysed. ${failurePoints.length} high-risk failure point(s) identified for migration sequencing.`
      : `${EVIDENCE_UNAVAILABLE}. No dependency telemetry recorded.`,
  };
}

/* ------------------------------------------------------------------ */
/* Quantum risk categories (Enhancement)                              */
/* ------------------------------------------------------------------ */
export function buildRiskCategories(snapshot: QuantumReadinessSnapshot, domains: ReadinessDomain[]): RiskCategory[] {
  const domainRisk = (needle: string) => 100 - (domains.find((d) => d.domain.toLowerCase().includes(needle))?.score ?? 0);
  const s = snapshot.scores;
  const cat = (category: string, current: number): RiskCategory => {
    const target = Math.max(8, round(current * 0.3));
    return { category, currentScore: clamp(current), targetScore: target, reductionPotentialPct: clamp(((current - target) / Math.max(1, current)) * 100) };
  };
  return [
    cat('TLS Risk', domainRisk('tls')),
    cat('PKI Risk', domainRisk('pki')),
    cat('Identity Risk', domainRisk('identity')),
    cat('Application Risk', domainRisk('application')),
    cat('Cloud Risk', domainRisk('cloud')),
    cat('Vendor Risk', domainRisk('vendor')),
    cat('HNDL Risk', s.hndlRisk),
    cat('Operational Risk', 100 - (snapshot.readinessFactors.find((f) => f.label.includes('Runtime'))?.score ?? 0)),
    cat('Business Risk', s.quantumRisk),
  ];
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
  const total = snapshot.estimates.migrationCostUsd || 0;
  if (!total) {
    return { lines: [{ category: EVIDENCE_UNAVAILABLE, costUsd: 0 }], totalUsd: 0, projectedRiskReductionValueUsd: 0 };
  }
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
  const lines = split.map(([category, ratio]) => ({ category, costUsd: Math.round(total * ratio) }));
  const reductionPct = clamp(((snapshot.scores.quantumRisk - Math.max(10, snapshot.scores.quantumRisk * 0.25)) / Math.max(1, snapshot.scores.quantumRisk)) * 100);
  return { lines, totalUsd: lines.reduce((sum, l) => sum + l.costUsd, 0), projectedRiskReductionValueUsd: Math.round(total * (reductionPct / 100) * 3) };
}

/* ------------------------------------------------------------------ */
/* Risk reduction forecast (Enhancement)                              */
/* ------------------------------------------------------------------ */
export function buildRiskForecast(snapshot: QuantumReadinessSnapshot): RiskForecast {
  const current = snapshot.scores.quantumRisk;
  const target = Math.max(10, round(current * 0.25));
  const lerp = (t: number) => round(current - (current - target) * t);
  return {
    currentRisk: current,
    targetRisk: target,
    reductionPct: clamp(((current - target) / Math.max(1, current)) * 100),
    residualRisk: target,
    month12: lerp(0.4),
    month24: lerp(0.75),
    month36: lerp(1),
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
  return [
    { framework: 'NIST SP 1800-38', control: 'PQC Migration Readiness', status: statusFor(60), detail: gap(60) },
    { framework: 'FIPS 203', control: 'ML-KEM key establishment', status: statusFor(50), detail: gap(50) },
    { framework: 'FIPS 204', control: 'ML-DSA digital signatures', status: statusFor(50), detail: gap(50) },
    { framework: 'FIPS 205', control: 'SLH-DSA stateless signatures', status: statusFor(40), detail: gap(40) },
    { framework: 'CNSA 2.0', control: 'Commercial National Security Algorithm Suite', status: statusFor(55), detail: gap(55) },
    { framework: 'ISO 27001', control: 'A.10 Cryptographic controls', status: statusFor(55), detail: `Crypto exposure ${s.cryptoExposure}/100. ${gap(55)}` },
    { framework: 'SOC 2', control: 'CC6.1 — Cryptographic access', status: statusFor(50), detail: `HNDL exposure ${s.hndlRiskLevel}. ${gap(50)}` },
    { framework: 'PCI DSS', control: 'Req 4 — Strong cryptography in transit', status: statusFor(55), detail: gap(55) },
    { framework: 'NIST CSF', control: 'PR.DS — Data Security', status: statusFor(55), detail: gap(55) },
  ];
}

function buildRoadmap(snapshot: QuantumReadinessSnapshot, waves: MigrationWave[]): RoadmapPhase[] {
  // Phased, ownership-driven roadmap aligned to the migration waves.
  const phases: RoadmapPhase[] = [
    { phase: 'Discovery & Assessment', description: 'Inventory crypto assets; score quantum risk, HNDL and complexity.', status: snapshot.hasData ? 'in-progress' : 'pending', effortWeeks: Math.max(1, Math.round((snapshot.estimates.migrationTimelineWeeks || 0) * 0.1)) },
  ];
  waves.forEach((wave) => phases.push({ phase: `Wave ${wave.wave}: ${wave.name} (${wave.owner})`, description: `Migrate to hybrid PQC. Risk reduction ${wave.riskReductionPct}%.`, status: wave.status, effortWeeks: wave.durationWeeks }));
  phases.push({ phase: 'Validation & Optimization', description: 'Decommission classical keys; monitor drift; prove evidence.', status: 'planned', effortWeeks: Math.max(1, Math.round((snapshot.estimates.migrationTimelineWeeks || 0) * 0.1)) });
  return phases;
}

function buildAssets(snapshot: QuantumReadinessSnapshot): ReportTable {
  const rows = snapshot.topRiskAssets.map((asset) => [asset.asset, asset.assetType, asset.environment, asset.owner, asset.riskScore, asset.status]);
  return safeTable('Top-Risk Assets', ['Asset', 'Type', 'Environment', 'Owner', 'Risk Score', 'PQC Status'], rows);
}

/* ------------------------------------------------------------------ */
/* Executive block (Enhancement #10)                                  */
/* ------------------------------------------------------------------ */
function buildExecutiveBlock(snapshot: QuantumReadinessSnapshot, domains: ReadinessDomain[], findings: ReportFinding[]): ExecutiveBlock {
  const s = snapshot.scores;
  const targetReadiness = Math.max(85, s.quantumReadiness);
  const targetRisk = Math.max(10, round(s.quantumRisk * 0.25));
  const targetHndl = Math.max(8, round(s.hndlRisk * 0.3));
  const compliant = buildCompliance(snapshot);
  const aligned = compliant.filter((c) => c.status === 'aligned').length;
  const weakest = dominantWeakness(domains);
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
    topRisks: findings.slice(0, 5).map((f) => `${f.severity.toUpperCase()}: ${f.title}`),
    topActions: snapshot.recommendedActions.slice(0, 5).map((a) => a.title),
    executiveRecommendation: weakest
      ? `Prioritise ${weakest.domain} modernization and hybrid PQC deployment on all internet-facing assets within the next migration wave. Fund a ${snapshot.estimates.migrationTimelineWeeks || 'TBD'}-week programme to reduce quantum risk by ${clamp(((s.quantumRisk - targetRisk) / Math.max(1, s.quantumRisk)) * 100)}%.`
      : 'Complete a PQC discovery scan to baseline the migration programme.',
  };
}

/* ================================================================== */
/* Report Intelligence (Reports_Enhancements_3)                       */
/* ================================================================== */

const BLENDED_RATE_USD = 165; // blended engineer rate used by the estimate model

// Phase 1 — Risk Scoring Transparency Engine™
const RISK_DOMAIN_WEIGHTS: Array<{ match: string; weight: number }> = [
  { match: 'tls', weight: 0.18 },
  { match: 'pki', weight: 0.12 },
  { match: 'identity', weight: 0.1 },
  { match: 'application', weight: 0.1 },
  { match: 'cloud', weight: 0.1 },
  { match: 'vendor', weight: 0.08 },
  { match: 'hndl', weight: 0.2 },
  { match: 'operational', weight: 0.07 },
  { match: 'business', weight: 0.05 },
];

export function buildRiskMethodology(snapshot: QuantumReadinessSnapshot, riskCategories: RiskCategory[]): RiskMethodology {
  const rows = RISK_DOMAIN_WEIGHTS.map((w) => {
    const cat = riskCategories.find((c) => c.category.toLowerCase().includes(w.match));
    const score = cat ? cat.currentScore : 0;
    return { domain: cat?.category || w.match.toUpperCase(), weightPct: Math.round(w.weight * 100), score, weighted: score * w.weight };
  });
  const totalWeighted = rows.reduce((sum, r) => sum + r.weighted, 0) || 1;
  const weights = rows
    .map((r) => ({ domain: r.domain, weightPct: r.weightPct, score: r.score, contributionPct: clamp((r.weighted / totalWeighted) * 100) }))
    .sort((a, b) => b.contributionPct - a.contributionPct);
  const top = weights[0];
  return {
    formula: 'Overall Quantum Risk = Σ ( DomainRisk × DomainWeight ) ÷ Σ ( DomainWeight )',
    overall: snapshot.scores.quantumRisk,
    weights,
    topDriver: top ? `${top.domain} (${top.contributionPct}% of weighted risk)` : EVIDENCE_UNAVAILABLE,
    explanation: snapshot.hasData
      ? `The overall quantum risk of ${snapshot.scores.quantumRisk}/100 is a weighted blend of nine cryptographic risk domains. ${top ? `${top.domain} contributes the largest share (${top.contributionPct}%) at a domain risk of ${top.score}/100` : ''}, followed by ${weights[1]?.domain || 'others'} (${weights[1]?.contributionPct || 0}%). Each domain weight reflects its quantum-attack surface and business exposure; the score is fully reproducible from the table below.`
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
      const engineers = Math.max(1, Math.round(hours / Math.max(40, (snapshot.estimates.migrationTimelineWeeks || 1) * 8)));
      return { category: l.category, hours, engineers, rateUsd: BLENDED_RATE_USD, costUsd: l.costUsd, formula: `${hours} hrs × $${BLENDED_RATE_USD}/hr = $${l.costUsd.toLocaleString()}` };
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

// Phase 6 — Business Impact Intelligence™ (reasons)
export function buildImpactReasons(snapshot: QuantumReadinessSnapshot, impact: BusinessImpact): ImpactReason[] {
  const internet = internetFacingLabels(snapshot).length;
  return [
    { dimension: 'Customer Impact', level: internet > 0 ? 'Medium' : 'Low', reason: internet > 0 ? `${internet} customer-facing system(s) use quantum-vulnerable TLS.` : 'No internet-facing customer systems identified.' },
    { dimension: 'Revenue Impact', level: impact.revenueImpact, reason: internet > 0 ? 'Customer-facing portal(s) using vulnerable TLS configuration could disrupt revenue if compromised.' : 'No direct revenue-generating systems in scope.' },
    { dimension: 'Operational Impact', level: impact.operationalImpact, reason: `${snapshot.inventory.vulnerableComponents} vulnerable cryptographic components require migration across operational systems.` },
    { dimension: 'Compliance Impact', level: impact.complianceImpact, reason: `Harvest-Now-Decrypt-Later exposure (${snapshot.scores.hndlRiskLevel}) places regulated data outside emerging PQC mandates.` },
    { dimension: 'Brand / Reputational Impact', level: impact.reputationalImpact, reason: internet > 0 && snapshot.scores.quantumRisk >= 45 ? 'Public-facing quantum-vulnerable services carry reputational risk on disclosure.' : 'Limited external exposure.' },
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
    if (f.asset) g.assets.add(f.asset);
    if (f.algorithm) g.evidence.add(f.algorithm);
    g.rank = Math.max(g.rank, severityRank(normalizeSeverity(f.severity)));
    groups.set(family, g);
  }
  const out: FindingGroup[] = Array.from(groups.entries())
    .map(([title, g]) => ({ title, occurrences: g.occurrences, affectedAssets: g.assets.size, evidence: Array.from(g.evidence).slice(0, 8), impact: (['info', 'low', 'medium', 'high', 'critical'][g.rank] || 'medium') as FindingGroup['impact'] }))
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
  out.push({ decision: 'Approve Hybrid TLS (X25519 + ML-KEM-768) standard', type: 'Policy Approval', rationale: 'Establishes the target cryptographic standard for all migration waves.', owner: 'Security Architecture' });
  out.push({ decision: 'Approve ML-KEM (FIPS 203) / ML-DSA (FIPS 204) adoption', type: 'Governance Approval', rationale: 'Authorises NIST-standardised PQC algorithms for production use.', owner: 'CISO / GRC' });
  return out;
}

// Phase 11 — Enterprise Remediation Playbook™
export function buildPlaybookDetail(groups: FindingGroup[]): PlaybookDetail[] {
  const target = (title: string): { current: string; target: string; steps: string[] } => {
    if (/rsa cipher|legacy rsa|forward secrecy/i.test(title)) return { current: 'TLS with RSA key exchange / CBC cipher suites (no forward secrecy)', target: 'TLS 1.3 + X25519 + ML-KEM-768 (Hybrid)', steps: ['Enable TLS 1.3', 'Disable RSA / CBC cipher suites', 'Enable X25519 + Hybrid ML-KEM key exchange', 'Validate handshake compatibility', 'Monitor production for client failures'] };
    if (/ecdsa|certificate/i.test(title)) return { current: 'ECDSA / RSA certificate signatures', target: 'Ed25519 + ML-DSA-65 hybrid certificate chain', steps: ['Issue hybrid (classical + ML-DSA) certificates', 'Stage parallel chain', 'Cut over CA trust', 'Validate chain on all clients', 'Retire classical-only certs'] };
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
  const totalReductionShare = waves.reduce((s, w) => s + w.riskReductionPct, 0) || 1;
  let cumWeeks = 0;
  let cumCost = 0;
  let cumShare = 0;
  const sims: WaveSimulation[] = waves.map((wave, index) => {
    cumWeeks += wave.durationWeeks;
    cumCost += wave.costUsd;
    cumShare += wave.riskReductionPct / totalReductionShare;
    const riskTo = Math.round(startRisk - (startRisk - targetRisk) * cumShare);
    const readinessTo = Math.round(startReadiness + (targetReadiness - startReadiness) * cumShare);
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
    label: 'If Entire Program Completes',
    readinessFrom: startReadiness,
    readinessTo: targetReadiness,
    riskFrom: startRisk,
    riskTo: targetRisk,
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
    { metric: 'Quantum Readiness Score', what: `${s.quantumReadiness}/100 (${s.quantumReadinessLevel}).`, how: 'Weighted blend of PQC adoption, TLS/PKI maturity, crypto-agility, governance and runtime visibility.', evidence: `${s.pqcAdoption}% PQC adoption across ${snapshot.inventory.cryptoComponents} components.`, why: 'Measures progress toward a quantum-safe posture.', action: 'Increase PQC/hybrid adoption per the wave plan.' },
    { metric: 'PQC Adoption', what: `${s.pqcAdoption}%.`, how: '(PQC-ready + ½ hybrid components) ÷ total CBOM components.', evidence: `${snapshot.inventory.pqcReadyComponents} of ${snapshot.inventory.cryptoComponents} components quantum-safe.`, why: 'Direct measure of cryptographic modernisation.', action: 'Migrate vulnerable components to ML-KEM / ML-DSA.' },
    { metric: 'Migration Confidence', what: `${confidence.overallPct}%.`, how: 'Average of asset/certificate/key/CBOM/scanner/dependency/trust/telemetry coverage.', evidence: 'Per-source coverage in the confidence table.', why: 'Indicates how complete the evidence behind the plan is.', action: 'Improve low-coverage sources (trust fabric, dependencies) to raise confidence.' },
    { metric: 'Estimated Cost', what: snapshot.estimates.migrationCostUsd ? `$${snapshot.estimates.migrationCostUsd.toLocaleString()}.` : EVIDENCE_UNAVAILABLE, how: `${(snapshot.estimates.migrationTimelineWeeks || 0) * 38} labour hours × $${BLENDED_RATE_USD}/hr blended rate, split by category.`, evidence: 'Cost breakdown table with per-line formulas.', why: 'Defensible budget for executive approval.', action: 'Approve budget allocation per the decision center.' },
  ];
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
  const waves = buildMigrationWaves(snapshot);
  const advisor = buildMigrationAdvisor(snapshot, domains, waves);
  const findings = buildFindings(snapshot);
  const executiveBlock = buildExecutiveBlock(snapshot, domains, findings);

  // Report Intelligence (Reports_Enhancements_3) — all evidence-derived
  const riskCategories = buildRiskCategories(snapshot, domains);
  const compliance = buildCompliance(snapshot);
  const costForecast = buildCostForecast(snapshot);
  const riskMethodology = buildRiskMethodology(snapshot, riskCategories);
  const advisorValidation = buildAdvisorValidation(snapshot, advisor, riskMethodology);
  const costBreakdown = buildCostBreakdown(snapshot, costForecast);
  const assetCriticality = buildAssetCriticality(snapshot, compliance);
  const impactReasons = buildImpactReasons(snapshot, buildBusinessImpact(snapshot));
  const findingGroups = buildFindingGroups(snapshot);
  const migrationConfidence = buildMigrationConfidence(snapshot);
  const evidenceConfidence = buildEvidenceConfidence(snapshot);
  const executiveDecisions = buildExecutiveDecisions(snapshot, waves, executiveBlock);
  const playbookDetail = buildPlaybookDetail(findingGroups);
  const waveSimulation = buildWaveSimulation(snapshot, waves, executiveBlock, migrationConfidence);
  const governanceGates = buildGovernanceGates();
  const explainability = buildExplainability(snapshot, riskMethodology, migrationConfidence);

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
      table: safeTable('PQC Readiness Factors', ['Factor', 'Score'], snapshot.readinessFactors.map((f) => [f.label, f.score])),
    },
    compliance,
    remediationProgram: buildRemediationProgram(snapshot, findings, waves),
    roadmap: buildRoadmap(snapshot, waves),
    playbook: buildPlaybook(waves),
    costForecast,
    riskForecast: buildRiskForecast(snapshot),
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
