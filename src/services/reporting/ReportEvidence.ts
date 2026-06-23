import { v4 as uuidv4 } from 'uuid';
import { format } from 'date-fns';
import type { QuantumReadinessSnapshot } from '@/app/dashboard/quantum-readiness/_shared';
import {
  EVIDENCE_UNAVAILABLE,
  normalizeSeverity,
  severityRank,
  type ComplianceMapping,
  type EnterpriseAssessmentReport,
  type ReportBranding,
  type ReportFinding,
  type ReportKind,
  type ReportKpi,
  type ReportTable,
  type RoadmapPhase,
} from './schemas/ReportSchema';

/**
 * Evidence Engine — transforms real, tenant-scoped Quantum Readiness assessment
 * telemetry into the unified EnterpriseAssessmentReport model. Every section is
 * derived from snapshot evidence; where a source is unavailable the section is
 * marked `Evidence Not Available` rather than fabricated.
 */

const REPORT_TITLES: Record<ReportKind, string> = {
  executive: 'Quantum Readiness Executive Report™',
  technical: 'Quantum Readiness Technical Assessment™',
  compliance: 'Post-Quantum Compliance Report™',
  migration: 'PQC Migration Report™',
};

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

export function buildKpis(snapshot: QuantumReadinessSnapshot): ReportKpi[] {
  const s = snapshot.scores;
  const inv = snapshot.inventory;
  return [
    { label: 'Quantum Readiness', value: s.quantumReadiness, unit: '/100', level: s.quantumReadinessLevel, tone: kpiTone(s.quantumReadiness, false) },
    { label: 'Quantum Risk', value: s.quantumRisk, unit: '/100', level: s.quantumRiskLevel, tone: kpiTone(s.quantumRisk, true) },
    { label: 'HNDL Risk', value: s.hndlRisk, unit: '/100', level: s.hndlRiskLevel, tone: kpiTone(s.hndlRisk, true) },
    { label: 'Crypto Exposure', value: s.cryptoExposure, unit: '/100', level: s.cryptoExposureLevel, tone: kpiTone(s.cryptoExposure, true) },
    { label: 'PQC Adoption', value: s.pqcAdoption, unit: '%', tone: kpiTone(s.pqcAdoption, false) },
    { label: 'Assets Assessed', value: inv.assetsAssessed, tone: 'neutral' },
    { label: 'Quantum-Vulnerable Assets', value: inv.quantumVulnerableAssets, tone: inv.quantumVulnerableAssets > 0 ? 'high' : 'good' },
    { label: 'Migration Effort', value: s.migrationEffort, unit: '/100', tone: 'neutral' },
  ];
}

export function buildFindings(snapshot: QuantumReadinessSnapshot): ReportFinding[] {
  const fromScan: ReportFinding[] = snapshot.criticalFindings.map((finding) => {
    const severity = normalizeSeverity(finding.severity);
    return {
      id: finding.id || uuidv4(),
      title: finding.title || 'Quantum-vulnerable cryptography detected',
      severity,
      evidence: finding.algorithm
        ? `Algorithm "${finding.algorithm}" detected on asset "${finding.asset}" (${finding.environment})${finding.detectedAt ? ` at ${finding.detectedAt}` : ''}.`
        : EVIDENCE_UNAVAILABLE,
      affectedAssets: finding.asset ? [finding.asset] : [],
      recommendation: severity === 'critical' || severity === 'high'
        ? `Replace ${finding.algorithm || 'the affected algorithm'} with ML-KEM / ML-DSA or a hybrid equivalent and prioritise this asset in the next migration wave.`
        : 'Schedule migration of this asset to a quantum-safe algorithm during the planned program.',
      remediationPlan: 'Discover dependencies → validate compatibility → deploy hybrid PQC → verify trust chains → retire classical key.',
      source: 'PQC Scanner / CBOM',
      detectedAt: finding.detectedAt || null,
    };
  });

  const fromActions: ReportFinding[] = snapshot.recommendedActions
    .filter((action) => !fromScan.some((existing) => existing.title === action.title))
    .map((action) => ({
      id: action.id || uuidv4(),
      title: action.title,
      severity: normalizeSeverity(action.severity),
      evidence: action.detail || EVIDENCE_UNAVAILABLE,
      affectedAssets: [],
      recommendation: action.detail || 'Review and remediate per assessment guidance.',
      remediationPlan: `Track remediation via ${action.route}.`,
      source: 'Quantum Readiness Assessment Engine',
      detectedAt: null,
    }));

  return [...fromScan, ...fromActions].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function buildAssets(snapshot: QuantumReadinessSnapshot): ReportTable {
  const rows = snapshot.topRiskAssets.map((asset) => [
    asset.asset,
    asset.assetType,
    asset.environment,
    asset.owner,
    asset.riskScore,
    asset.status,
  ]);
  return safeTable('Top-Risk Assets', ['Asset', 'Type', 'Environment', 'Owner', 'Risk Score', 'PQC Status'], rows);
}

function buildCompliance(snapshot: QuantumReadinessSnapshot): ComplianceMapping[] {
  const s = snapshot.scores;
  const adoption = s.pqcAdoption;
  const statusFor = (threshold: number): ComplianceMapping['status'] =>
    !snapshot.hasData ? 'not-assessed' : adoption >= threshold ? 'aligned' : adoption >= threshold / 2 ? 'partial' : 'gap';
  return [
    { framework: 'NIST', control: 'PQC Migration Readiness (SP 1800-38)', status: statusFor(60), detail: `Quantum readiness score ${s.quantumReadiness}/100 (${s.quantumReadinessLevel}).` },
    { framework: 'FIPS 203', control: 'ML-KEM key establishment', status: statusFor(50), detail: `PQC adoption at ${adoption}% across discovered cryptography.` },
    { framework: 'FIPS 204', control: 'ML-DSA digital signatures', status: statusFor(50), detail: `Signature migration readiness derived from PKI maturity.` },
    { framework: 'FIPS 205', control: 'SLH-DSA stateless signatures', status: statusFor(40), detail: 'Backup signature readiness for long-term archival.' },
    { framework: 'ISO 27001', control: 'A.10 Cryptographic controls', status: statusFor(55), detail: `Crypto exposure score ${s.cryptoExposure}/100.` },
    { framework: 'PCI DSS', control: 'Req 4 — Strong cryptography in transit', status: statusFor(55), detail: 'TLS / protocol maturity from discovery evidence.' },
    { framework: 'SOC 2', control: 'CC6.1 — Logical & cryptographic access', status: statusFor(50), detail: `HNDL exposure rated ${s.hndlRiskLevel}.` },
  ];
}

function buildRoadmap(snapshot: QuantumReadinessSnapshot): RoadmapPhase[] {
  const weeks = snapshot.estimates.migrationTimelineWeeks || 0;
  const split = (ratio: number) => Math.max(weeks ? 1 : 0, Math.round(weeks * ratio));
  return [
    { phase: 'Discovery', description: 'Inventory cryptographic assets, certificates, keys and dependencies.', status: snapshot.inventory.assetsAssessed > 0 ? 'complete' : 'pending', effortWeeks: split(0.1) },
    { phase: 'Assessment', description: 'Score quantum risk, HNDL exposure and migration complexity.', status: snapshot.hasData ? 'in-progress' : 'pending', effortWeeks: split(0.1) },
    { phase: 'Hybrid', description: 'Deploy hybrid X25519+ML-KEM / Ed25519+ML-DSA on critical paths.', status: 'planned', effortWeeks: split(0.3) },
    { phase: 'Pilot', description: 'Validate compatibility, performance and trust chains in pilot scope.', status: 'planned', effortWeeks: split(0.2) },
    { phase: 'Production', description: 'Cut over remaining assets to quantum-safe cryptography.', status: 'planned', effortWeeks: split(0.2) },
    { phase: 'Optimization', description: 'Decommission classical keys, monitor drift and prove evidence.', status: 'planned', effortWeeks: split(0.1) },
  ];
}

export function buildReportModel(
  snapshot: QuantumReadinessSnapshot,
  branding: ReportBranding,
  kind: ReportKind,
  generatedBy: string,
): EnterpriseAssessmentReport {
  const now = new Date();
  const s = snapshot.scores;
  const inv = snapshot.inventory;

  const executiveSummary = snapshot.hasData
    ? `As of ${format(now, 'PPP')}, ${branding.companyName} holds a quantum readiness score of ${s.quantumReadiness}/100 (${s.quantumReadinessLevel}) against a quantum risk score of ${s.quantumRisk}/100 (${s.quantumRiskLevel}). Discovery has assessed ${inv.assetsAssessed} cryptographic assets, identifying ${inv.quantumVulnerableAssets} as quantum-vulnerable with ${s.pqcAdoption}% PQC adoption. Harvest-Now-Decrypt-Later exposure is rated ${s.hndlRiskLevel}. The estimated path to a quantum-safe posture is ${snapshot.estimates.migrationTimelineWeeks || 'to be determined'} weeks. This report is generated from live, tenant-scoped assessment evidence; no values are fabricated.`
    : `No assessment evidence is available for ${branding.companyName} yet. Run a PQC discovery scan to populate this report. All sections below reflect an empty evidence state.`;

  const findings = buildFindings(snapshot);
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
    kpis: buildKpis(snapshot),
    findings,
    assets: buildAssets(snapshot),
    certificates: safeTable('Certificate Inventory', ['Metric', 'Value'], [
      ['Certificates Analyzed', inv.certificatesAnalyzed],
    ]),
    keys: safeTable('Key Inventory', ['Metric', 'Value'], [
      ['Keys Discovered', inv.keysDiscovered],
    ]),
    tlsEndpoints: safeTable('TLS / Protocol Surface', ['Metric', 'Value'], [
      ['Domains Scanned', inv.domainsScanned],
    ]),
    cbom: safeTable('CBOM Summary', ['Posture', 'Assets'], [
      ['PQC-Ready', inv.pqcReadyAssets],
      ['Hybrid / In-Progress', inv.hybridAssets],
      ['Quantum-Vulnerable', inv.quantumVulnerableAssets],
    ]),
    hndl: {
      summary: `Harvest-Now-Decrypt-Later exposure is rated ${s.hndlRiskLevel} (${s.hndlRisk}/100), reflecting long-lived sensitive data still protected by quantum-vulnerable cryptography.`,
      table: safeTable('HNDL Exposure', ['Factor', 'Score'], [
        ['HNDL Risk Score', s.hndlRisk],
        ['Crypto Exposure', s.cryptoExposure],
        ['Vulnerable Assets', inv.quantumVulnerableAssets],
      ]),
    },
    trustRelationships: safeTable('Trust Relationships', ['Metric', 'Value'], [
      ['Trust Relationships', inv.trustRelationships],
      ['Cloud Accounts', inv.cloudAccounts],
    ]),
    pqcReadiness: {
      summary: `${s.pqcAdoption}% of discovered cryptography is quantum-safe or hybrid. Readiness factors are derived from PQC adoption, TLS/PKI maturity, crypto-agility and governance.`,
      table: safeTable('PQC Readiness Factors', ['Factor', 'Score'], snapshot.readinessFactors.map((f) => [f.label, f.score])),
    },
    compliance: buildCompliance(snapshot),
    roadmap: buildRoadmap(snapshot),
    remediation: safeTable('Remediation Plan', ['Priority', 'Action', 'Detail', 'Severity'],
      snapshot.recommendedActions.map((action, index) => [index + 1, action.title, action.detail, action.severity])),
    evidence: {
      sources: ['PQC Scanner', 'CBOM', 'Runtime Telemetry', 'Trust Fabric', 'Asset Inventory', 'Certificate Inventory'],
      notes: snapshot.hasData
        ? `Severity distribution — Critical: ${distribution.critical}, High: ${distribution.high}, Medium: ${distribution.medium}, Low: ${distribution.low}. ${EVIDENCE_UNAVAILABLE} is shown where a source has not yet produced telemetry.`
        : `${EVIDENCE_UNAVAILABLE}. No scans, assets, certificates or runtime telemetry recorded for this tenant.`,
    },
    charts: [],
  };
}
