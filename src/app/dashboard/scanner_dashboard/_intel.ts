/**
 * Dashboard Scanner — assessment intelligence.
 *
 * Pure, side-effect-free derivations that turn the scanner's REAL output —
 * `/api/v1/scanner/stream` summary + per-target results + the Scanner_2
 * enterprise pass + module execution states + the tenant-wide Scanner
 * Intelligence snapshot — into the enterprise assessment model the page
 * renders.
 *
 * HONESTY CONTRACT (identical to /public-scan's):
 *   • Every number traces to a measurement the scanner actually made.
 *   • Anything not measured is reported as Unknown / Not observed, never as 0
 *     and never as a failure.
 *   • The composite score is the backend's own `summary.qScore`, and the
 *     decomposition below is the backend's own published `riskBreakdown` with
 *     its published weights — so the gauge, the grade letter and the category
 *     bars are three views of ONE number and cannot drift apart.
 *   • Grades come from the platform-wide `grading-model`, the same table
 *     /public-scan grades against, so a domain assessed on both surfaces is
 *     graded on one scale.
 */

import {
  RISK_COLOR,
  RISK_ORDER,
  scoreToGrade,
} from '@/lib/scanner/public-scan/grading-model';
/* The scanner's own finding-ownership rule, imported rather than reimplemented.
   `scanner-module-ledger` is a pure, dependency-free module (no Express, no
   Supabase) exported for exactly this: the backend credits a finding to a
   module, and this page routes the same finding to the surface that module
   belongs to, so the two can never disagree. */
import { moduleIdForFinding } from '@/api-server/scanner-module-ledger';
import type { RiskBand } from '@/lib/scanner/public-scan/types';
import type {
  DefensiveFinding,
  EnterpriseScanner2,
  ModuleState,
  PqcRecommendation,
  PublishedScoreCategory,
  ScanResultRecord,
  ScanRiskApplicability,
  ScanRiskBreakdown,
  ScanStatus,
  ScanSummary,
  ThreatLevel,
} from './_types';

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));

/* ==================================================================== nodes = */

/**
 * The six discovery surfaces the Dashboard Scanner visualises, and the scanner
 * modules that feed each one. This is a routing table over the REAL module
 * catalog in `src/api-server/scanner.ts` — every id below is a module the
 * backend actually runs, so a node can never light up for work that did not
 * happen.
 */
export const SCANNER_NODE_MODULES: Record<string, readonly string[]> = {
  discovery: ['target-validation', 'asset-inventory-synchronizer', 'scanner2-module-registry'],
  transport: ['tls-protocol-scanner', 'cipher-suite-scanner', 'key-exchange-scanner'],
  certificates: ['certificate-scanner', 'signature-algorithm-scanner', 'hash-algorithm-scanner'],
  identity: ['ssh-host-key-scanner', 'jwt-signing-scanner'],
  code: ['dependency-crypto-scanner', 'cbom-generator', 'scanner2-fingerprint-matcher', 'scanner2-detection-rules'],
  posture: [
    'crypto-detection-rules',
    'scanner2-hndl-analyzer',
    'scanner2-correlation-engine',
    'scanner2-pqc-migration-engine',
    'scanner2-risk-qscore-engine',
    'risk-scoring-engine',
    'crypto-exposure-graph-builder',
    'audit-history-logger',
  ],
};

/** Structurally identical to the engine's `NodeBlueprint`, declared here so the
 * derivations stay free of a dependency on the visualization package. */
export interface ScannerNodeBlueprint {
  key: string;
  title: string;
  idleVerdict: string;
  idleLines: string[];
}

export const SCANNER_NODE_BLUEPRINTS: readonly ScannerNodeBlueprint[] = [
  {
    key: 'discovery',
    title: 'Asset Discovery',
    idleVerdict: 'Standby',
    idleLines: ['No targets authorized', 'Inventory not synchronized'],
  },
  {
    key: 'transport',
    title: 'Transport & Ciphers',
    idleVerdict: 'Standby',
    idleLines: ['Protocols unprobed', 'Cipher suites unread'],
  },
  {
    key: 'certificates',
    title: 'Certificates & Keys',
    idleVerdict: 'Standby',
    idleLines: ['Chains not collected', 'Key algorithms unknown'],
  },
  {
    key: 'identity',
    title: 'Identity & Tokens',
    idleVerdict: 'Standby',
    idleLines: ['SSH host keys unread', 'Token algorithms unknown'],
  },
  {
    key: 'code',
    title: 'Code & Dependencies',
    idleVerdict: 'Standby',
    idleLines: ['Repositories not scanned', 'CBOM not generated'],
  },
  {
    key: 'posture',
    title: 'Quantum Posture',
    idleVerdict: 'Standby',
    idleLines: ['HNDL exposure unscored', 'Risk model not run'],
  },
];

/** Left column / right column split around the core, matching the public hero. */
export const SCANNER_LEFT_NODES: readonly string[] = ['discovery', 'transport', 'certificates'];
export const SCANNER_RIGHT_NODES: readonly string[] = ['identity', 'code', 'posture'];

/** Module id → node key, inverted from the routing table above. */
export const MODULE_NODE = ((): Record<string, string> => {
  const map: Record<string, string> = {};
  for (const [node, modules] of Object.entries(SCANNER_NODE_MODULES)) {
    for (const moduleId of modules) map[moduleId] = node;
  }
  return map;
})();

/**
 * Finding → node key, derived from the module that OWNS the finding.
 *
 * This used to be a second, independently-maintained category table, and it
 * drifted from the backend's ownership rules exactly the way two copies of a
 * rule always do: `Web Crypto (hash)` was attributed to the certificate surface
 * (because the string contains "hash") while the scanner credited it to the
 * dependency scanner on the Code surface, so a node card's finding list and its
 * module's finding count disagreed for the same observation.
 *
 * Routing now goes through the scanner's own ledger — `moduleIdForFinding` —
 * and then through `MODULE_NODE`. One rule, one answer, on both sides of the
 * wire. `scanner-module-ledger` is a dependency-free pure module for precisely
 * this reason: it is shared, not duplicated.
 */
export function nodeForFindingCategory(category: string, detectionMethod = '', algorithm = ''): string {
  return MODULE_NODE[moduleIdForFinding({ category, detectionMethod, algorithm })] ?? 'posture';
}

/* =================================================================== model == */

export interface ScoreComponent {
  key: string;
  label: string;
  /** Published weight from the scanner's own risk model. */
  weight: number;
  /** Posture 0-100 (higher is better). Null when the dimension was not measured. */
  score: number | null;
  /** What the number was computed from — shown verbatim, never a caption. */
  observed: string;
}

export interface SurfaceItem {
  key: string;
  label: string;
  value: string;
  status: 'pass' | 'fail' | 'partial' | 'info' | 'unknown';
  detail: string;
}

export interface TimelinePhase {
  key: string;
  title: string;
  horizon: string;
  description: string;
  state: 'past' | 'now' | 'active' | 'target';
}

export interface RecommendationCard {
  id: string;
  title: string;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  businessImpact: string;
  effort: string;
  standard: string;
  affected: number;
  steps: string[];
  rationale: string;
}

export interface FootprintMetric {
  key: string;
  label: string;
  value: number;
  countedFrom: string;
}

export interface CoverageItem {
  key: string;
  label: string;
  status: 'pass' | 'partial' | 'fail' | 'unknown';
  detail: string;
}

export interface ScannerAssessment {
  /** False until at least one real measurement exists for this tenant. */
  hasEvidence: boolean;
  /** True while the numbers describe a run still in flight. */
  live: boolean;
  provenance: string;
  target: { label: string; count: number; completedAt: string | null };
  executive: {
    grade: string;
    gradeLabel: string;
    gradeColor: string;
    gradeable: boolean;
    gradeDetail: string;
    encryptionScore: number;
    classicalScore: number;
    postQuantumReadiness: number;
    evidenceCoverage: number;
    businessRisk: RiskBand;
    businessRiskDetail: string;
    migrationComplexity: string;
    migrationComplexityDetail: string;
    confidence: number;
    confidenceDetail: string;
  };
  scoreComponents: ScoreComponent[];
  /**
   * The weighted mean of the measured `scoreComponents`, i.e. what the published
   * risk model alone says the posture is. Null until a decomposition exists.
   *
   * This is normally identical to `executive.encryptionScore`, because the
   * backend's summary risk score IS the mean of the same per-target weighted
   * scores (weighted mean and arithmetic mean commute). It diverges when the
   * summary was rebuilt from stored findings by severity count rather than from
   * the weighted model — so the two are reported separately and reconciled in
   * the UI instead of one silently overwriting the other.
   */
  decompositionScore: number | null;
  /** True when the decomposition and the composite agree within rounding. */
  decompositionAgrees: boolean;
  attackSurface: SurfaceItem[];
  intelligence: {
    observedAlgorithms: Array<{ name: string; role: string; quantumVulnerable: boolean; count: number }>;
    keyExchange: string;
    forwardSecrecy: string;
    quantumVulnerability: string;
    migrationTargets: Array<{ name: string; standard: string; replaces: string }>;
    confidence: number;
    scanner2Readiness: { score: number; label: string } | null;
  };
  timeline: TimelinePhase[];
  recommendations: RecommendationCard[];
  footprint: {
    metrics: FootprintMetric[];
    exposureLevel: string;
    basis: string;
  };
  coverage: CoverageItem[];
  scope: { analyzed: string[]; notAnalyzed: string[]; statement: string };
  nodeScores: Record<string, number>;
  hndl: { immediate: number; soon: number; planned: number; window: { earliest: number; latest: number } | null };
}

/* ================================================================= helpers == */

const RESIDUAL_SECURITY: Record<ThreatLevel, number> = {
  SAFE: 1,
  LOW: 0.75,
  MEDIUM: 0.45,
  HIGH: 0.15,
  CRITICAL: 0,
};

const THREAT_RANK: Record<ThreatLevel, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, SAFE: 0 };

/** Escalate to the more severe of two risk bands. */
function worstRisk(a: RiskBand, b: RiskBand): RiskBand {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

function riskBandForScore(posture: number): RiskBand {
  if (posture >= 90) return 'Very Low';
  if (posture >= 80) return 'Low';
  if (posture >= 65) return 'Moderate';
  if (posture >= 50) return 'Elevated';
  if (posture >= 35) return 'High';
  return 'Critical';
}

function average(values: number[]): number | null {
  if (values.length === 0) return null;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

export function riskColorFor(band: RiskBand): string {
  return RISK_COLOR[band];
}

/* ============================================================ node scoring == */

/**
 * Per-node posture 0-100, from the severity of the findings the scanner routed
 * to that node.
 *
 * The residual-security ladder (SAFE 1.0 → CRITICAL 0) is the same ladder the
 * Encryption Score panel documents, so a node's colour and the score bar under
 * it are computed from one model. A node with no findings returns nothing at
 * all — "not measured" and "measured as bad" must never render the same.
 */
export function scoreNodes(findings: DefensiveFinding[]): Record<string, number> {
  const buckets = new Map<string, { retained: number; count: number }>();
  for (const finding of findings) {
    const node = nodeForFindingCategory(finding.category, finding.detectionMethod, finding.algorithm);
    const bucket = buckets.get(node) ?? { retained: 0, count: 0 };
    bucket.retained += RESIDUAL_SECURITY[finding.threatLevel] ?? 0;
    bucket.count += 1;
    buckets.set(node, bucket);
  }
  const scores: Record<string, number> = {};
  for (const [node, bucket] of buckets) {
    if (bucket.count > 0) scores[node] = clamp((bucket.retained / bucket.count) * 100);
  }
  return scores;
}

/** The two quantum categories of the published model. */
const PQ_CATEGORY_KEYS = new Set(['cryptographic-algorithms', 'post-quantum-readiness']);

/**
 * Merge each target's published category scores into one estate decomposition.
 *
 * A category is averaged over the targets that MEASURED it, and reported null
 * when no target did — the UI still lists it, greyed, with the reason. Older
 * scans that predate published scoring fall back to the engineering breakdown so
 * reviewing history keeps working.
 */
function mergePublishedCategories(
  results: ScanResultRecord[],
  fallbackBreakdown: Partial<Record<keyof ScanRiskBreakdown, number>> | null,
): ScoreComponent[] {
  const rows = results
    .map((result) => result.metadata?.scoreCategories)
    .filter((value): value is PublishedScoreCategory[] => Array.isArray(value) && value.length > 0);

  if (rows.length === 0) {
    // Pre-published-scoring scan: show the engineering decomposition instead of
    // an empty panel, labelled so it is not mistaken for the published model.
    return RISK_WEIGHTS.map((definition) => {
      const risk = fallbackBreakdown?.[definition.key];
      return {
        key: definition.key,
        label: definition.label,
        weight: definition.weight,
        score: risk === undefined ? null : clamp(100 - risk),
        observed: risk !== undefined
          ? `${definition.description} (engineering model — rescan for the published categories)`
          : 'Not decomposed — run a scan to collect the per-target model',
      };
    });
  }

  const order: PublishedScoreCategory[] = rows[0];
  return order.map((template) => {
    const measured = rows
      .map((row) => row.find((category) => category.key === template.key))
      .filter((category): category is PublishedScoreCategory => Boolean(category?.applicable));
    const mean = average(measured.map((category) => category.score));
    const observedValues = Array.from(new Set(measured.map((category) => category.observed))).filter(Boolean);
    return {
      key: template.key,
      label: template.label,
      weight: template.weight,
      score: mean === null ? null : clamp(mean),
      observed: observedValues.length
        ? observedValues.slice(0, 2).join(' · ')
        : template.observed || 'not observed',
    };
  });
}

/* ========================================================= node evidence ==== */

export interface EvidenceRow {
  label: string;
  value: string;
  /** Explicit colour when the value itself is the verdict. */
  tone?: string;
  /** Longer provenance, shown as the row's tooltip. */
  detail?: string;
}

export interface NodeEvidence {
  /** Ordered evidence rows for the node's detail panel. */
  rows: EvidenceRow[];
  /** The scanner modules that produced this node, with their real end state. */
  modules: Array<{ id: string; name: string; status: string; findings: number; durationMs: number | null }>;
  /** Findings routed to this node, most severe first. */
  findings: DefensiveFinding[];
  /** Node posture 0-100, or null when nothing was measured here. */
  score: number | null;
  /** Why the panel is empty, when it is. */
  emptyReason: string | null;
}

const TONE_PASS = '#34d399';
const TONE_WARN = '#fbbf24';
const TONE_FAIL = '#f43f5e';
const TONE_PQ = '#a78bfa';
const TONE_MUTED = '#94a3b8';

function certificateName(source: Record<string, string> | undefined): string | null {
  if (!source) return null;
  return source.CN || source.commonName || source.O || source.organizationName || null;
}

function daysUntil(iso: string | undefined): number | null {
  if (!iso) return null;
  const at = Date.parse(iso);
  if (!Number.isFinite(at)) return null;
  return Math.round((at - Date.now()) / 86400000);
}

/**
 * Real, per-node evidence for the hero's detail panel.
 *
 * Every row is read from something the scanner returned for THIS tenant's scan:
 * the per-target TLS analysis, the parsed certificate chain, the repository and
 * Web Crypto passes, the security-header probe, the Scanner_2 enterprise pass,
 * and the module execution states. A surface the scan did not reach returns an
 * `emptyReason` naming why, rather than empty rows or invented values.
 */
export function buildNodeEvidence(
  nodeKey: string,
  input: {
    results: ScanResultRecord[];
    findings: DefensiveFinding[];
    modules: ModuleState[];
    scanner2: EnterpriseScanner2 | null;
    targets: string[];
    linked: { cbom: number; assets: number; exposures: number };
  },
): NodeEvidence {
  const primary = input.results[0] ?? null;
  const tls = primary?.metadata?.tlsAnalysis ?? null;
  const certificate = primary?.certificateInfo ?? null;
  const api = primary?.metadata?.apiSecurityResult ?? null;
  const repo = primary?.metadata?.repoScanResult ?? null;
  const webCrypto = primary?.metadata?.webCryptoResult ?? null;
  const scanner2 = input.scanner2;

  const moduleIds = SCANNER_NODE_MODULES[nodeKey] ?? [];
  const modules = input.modules
    .filter((module) => moduleIds.includes(module.id))
    .map((module) => ({
      id: module.id,
      name: module.name,
      status: module.status,
      findings: module.findingsCount,
      durationMs: module.durationMs,
    }));

  const nodeFindings = input.findings
    .filter((finding) => nodeForFindingCategory(finding.category, finding.detectionMethod, finding.algorithm) === nodeKey)
    .sort((a, b) => THREAT_RANK[b.threatLevel] - THREAT_RANK[a.threatLevel]);

  const score = scoreNodes(input.findings)[nodeKey] ?? null;
  const rows: EvidenceRow[] = [];

  switch (nodeKey) {
    case 'discovery': {
      rows.push(
        {
          label: 'Authorized targets',
          value: input.targets.length ? String(input.targets.length) : (primary ? '1' : '—'),
          detail: input.targets.join(', ') || primary?.target || 'No target queued',
        },
        {
          label: 'Target',
          value: primary?.target ?? input.targets[0] ?? 'Not submitted',
          detail: 'The normalized asset the scanner connected to',
        },
        {
          label: 'Target type',
          value: primary?.targetType ?? primary?.metadata?.targetType ?? 'Unknown',
          detail: 'Classification the asset validator assigned',
        },
        {
          label: 'Assets synchronized',
          value: input.linked.assets ? String(input.linked.assets) : '—',
          detail: 'Asset inventory rows written for this tenant',
          tone: input.linked.assets > 0 ? TONE_PASS : undefined,
        },
        {
          label: 'Exposure nodes',
          value: input.linked.exposures ? String(input.linked.exposures) : '—',
          detail: 'Nodes added to the crypto exposure graph',
        },
        {
          label: 'Scan duration',
          value: primary?.durationMs ? `${(primary.durationMs / 1000).toFixed(1)} s` : '—',
          detail: 'Wall-clock time the orchestrator reported for this target',
        },
      );
      break;
    }

    case 'transport': {
      if (!tls) break;
      const supported = tls.supportedProtocols ?? [];
      const legacy = supported.filter((protocol) => /1\.0|1\.1|SSLv/i.test(protocol));
      const suites = tls.cipherSuites ?? [];
      const vulnerableSuites = suites.filter((suite) => suite.quantumVulnerable).length;
      rows.push(
        {
          label: 'Negotiated protocol',
          value: tls.tlsVersion || 'Not observed',
          tone: /1\.3/.test(tls.tlsVersion) ? TONE_PASS : /1\.2/.test(tls.tlsVersion) ? TONE_WARN : TONE_FAIL,
          detail: 'Protocol version selected during the observed handshake',
        },
        {
          label: 'Protocols accepted',
          value: supported.length ? supported.join(' / ') : 'Not observed',
          tone: legacy.length > 0 ? TONE_FAIL : TONE_PASS,
          detail: legacy.length
            ? `${legacy.join(', ')} still accepted — deprecated by RFC 8996`
            : 'Each version probed individually',
        },
        {
          label: 'Cipher suite',
          value: tls.cipherSuite || 'Not observed',
          tone: /GCM|CHACHA20|CCM/i.test(tls.cipherSuite) ? TONE_PASS : TONE_WARN,
          detail: 'Suite selected on the negotiated connection',
        },
        {
          label: 'Suites enumerated',
          value: suites.length ? `${suites.length} offered · ${vulnerableSuites} quantum-vulnerable` : '—',
          tone: vulnerableSuites > 0 ? TONE_WARN : undefined,
          detail: 'Full offered-suite enumeration from the cipher scanner',
        },
        {
          label: 'Key exchange',
          value: tls.keyExchange || 'Not observed',
          tone: /ml-kem|kyber/i.test(tls.keyExchange || '') ? TONE_PQ : TONE_WARN,
          detail: 'Key-agreement mechanism used by the negotiated suite',
        },
        {
          label: 'Named curve',
          value: tls.negotiatedCurve || 'Not observed',
          detail: 'Elliptic curve or hybrid group agreed during key exchange',
        },
        {
          label: 'Ephemeral key',
          value: tls.ephemeralKeyType
            ? `${tls.ephemeralKeyType}${tls.ephemeralKeySize ? ` ${tls.ephemeralKeySize}` : ''}`
            : 'Not observed',
          tone: tls.ephemeralKeyType ? TONE_PASS : TONE_MUTED,
          detail: 'Ephemeral key material — present means forward secrecy',
        },
      );
      break;
    }

    case 'certificates': {
      if (!certificate) break;
      const remaining = daysUntil(certificate.validTo);
      const chain = certificate.chain ?? [];
      rows.push(
        {
          label: 'Public key',
          value: `${certificate.publicKeyAlgorithm}${certificate.publicKeySize ? ` ${certificate.publicKeySize}` : ''}`,
          tone: /rsa/i.test(certificate.publicKeyAlgorithm) && certificate.publicKeySize < 2048 ? TONE_FAIL : TONE_WARN,
          detail: 'Leaf certificate key — quantum-vulnerable until replaced by ML-DSA',
        },
        {
          label: 'Signature algorithm',
          value: certificate.signatureAlgorithm || 'Unknown',
          tone: /sha-?1|md5/i.test(certificate.signatureAlgorithm || '') ? TONE_FAIL : TONE_WARN,
          detail: 'Algorithm the issuing CA signed this certificate with',
        },
        {
          label: 'Issuer',
          value: certificateName(certificate.issuer) ?? 'Unknown',
          detail: 'Certificate authority that issued the leaf',
        },
        {
          label: 'Subject',
          value: certificateName(certificate.subject) ?? 'Unknown',
          detail: 'Distinguished name the certificate was issued to',
        },
        {
          label: 'Validity',
          value: remaining === null
            ? 'Unknown'
            : certificate.isExpired
              ? 'Expired'
              : `${remaining} day${remaining === 1 ? '' : 's'} remaining`,
          tone: certificate.isExpired ? TONE_FAIL : (remaining ?? 0) < 30 ? TONE_WARN : TONE_PASS,
          detail: `Valid ${certificate.validFrom} → ${certificate.validTo}`,
        },
        {
          label: 'Chain',
          value: chain.length ? `${chain.length} certificate(s)` : 'Not collected',
          tone: chain.some((entry) => entry.isExpired) ? TONE_FAIL : chain.length ? TONE_PASS : TONE_MUTED,
          detail: chain.map((entry) => entry.subject).join(' → ') || 'No chain returned',
        },
        {
          label: 'Self-signed',
          value: certificate.isSelfSigned ? 'Yes' : 'No',
          tone: certificate.isSelfSigned ? TONE_FAIL : TONE_PASS,
          detail: 'A self-signed leaf is not anchored to a public trust store',
        },
      );
      break;
    }

    case 'identity': {
      const sshFindings = input.findings.filter((finding) => /ssh/i.test(finding.category));
      const jwtFindings = input.findings.filter((finding) => /jwt|token/i.test(finding.category));
      if (sshFindings.length === 0 && jwtFindings.length === 0) break;
      const hostKeys = Array.from(
        new Set(sshFindings.filter((finding) => /host key/i.test(finding.category)).map((finding) => finding.algorithm)),
      );
      const sshKex = Array.from(
        new Set(sshFindings.filter((finding) => /exchange/i.test(finding.category)).map((finding) => finding.algorithm)),
      );
      rows.push(
        {
          label: 'SSH host keys',
          value: hostKeys.length ? hostKeys.join(', ') : 'Not observed',
          tone: hostKeys.some((key) => /rsa|dss/i.test(key)) ? TONE_WARN : hostKeys.length ? TONE_PASS : TONE_MUTED,
          detail: 'Host key algorithms advertised in the SSH banner',
        },
        {
          label: 'SSH key exchange',
          value: sshKex.length ? sshKex.slice(0, 3).join(', ') : 'Not observed',
          detail: 'Key-exchange algorithms offered by the SSH server',
        },
        {
          label: 'Token algorithms',
          value: jwtFindings.length
            ? Array.from(new Set(jwtFindings.map((finding) => finding.algorithm))).slice(0, 3).join(', ')
            : 'Not observed',
          tone: jwtFindings.some((finding) => finding.threatLevel !== 'SAFE') ? TONE_WARN : TONE_MUTED,
          detail: 'Signing algorithms detected on JWT-issuing endpoints',
        },
        {
          label: 'Identity observations',
          value: String(sshFindings.length + jwtFindings.length),
          detail: 'Findings routed to the identity surface',
        },
      );
      break;
    }

    case 'code': {
      const headers = api?.securityHeaders ?? [];
      const hardened = headers.filter((header) => header.secure).length;
      const repoPatterns = repo?.patterns ?? [];
      const webPatterns = webCrypto?.patterns ?? [];
      if (headers.length === 0 && !repo && !webCrypto) break;
      if (headers.length > 0) {
        rows.push({
          label: 'Security headers',
          value: `${hardened}/${headers.length} hardened`,
          tone: hardened === headers.length ? TONE_PASS : hardened > headers.length / 2 ? TONE_WARN : TONE_FAIL,
          detail: headers
            .filter((header) => !header.secure)
            .map((header) => `${header.name}: ${header.present ? 'present, weak' : 'absent'}`)
            .join(' · ') || 'Every probed header is hardened',
        });
      }
      if (repo) {
        rows.push(
          {
            label: 'Repository',
            value: repo.accessible === false ? (repo.notice ?? 'Not accessible') : (repo.repoName ?? 'Scanned'),
            tone: repo.accessible === false ? TONE_MUTED : TONE_PASS,
            detail: repo.repoUrl ?? 'Repository supplied with this scan',
          },
          {
            label: 'Files scanned',
            value: repo.filesScanned !== undefined ? `${repo.filesScanned}/${repo.totalFiles ?? repo.filesScanned}` : '—',
            detail: `Branch ${repo.defaultBranch ?? 'default'} · visibility ${repo.visibility ?? 'unknown'}`,
          },
          {
            label: 'Crypto patterns',
            value: repoPatterns.length ? String(repoPatterns.length) : 'None matched',
            tone: repoPatterns.some((pattern) => pattern.threatLevel === 'CRITICAL' || pattern.threatLevel === 'HIGH')
              ? TONE_FAIL
              : repoPatterns.length
                ? TONE_WARN
                : TONE_PASS,
            detail: 'Cryptographic API and key-material patterns matched in source',
          },
        );
      }
      if (webCrypto) {
        rows.push({
          label: 'Web Crypto usage',
          value: webPatterns.length ? `${webPatterns.length} in ${webCrypto.scriptsAnalyzed ?? 0} script(s)` : 'None detected',
          tone: webPatterns.some((pattern) => pattern.threatLevel !== 'SAFE') ? TONE_WARN : TONE_PASS,
          detail: `${webCrypto.pagesScanned ?? 0} page(s) analyzed`,
        });
      }
      if (api?.endpointsProbed) {
        rows.push({
          label: 'API endpoints probed',
          value: String(api.endpointsProbed),
          detail: `Against ${api.hostname ?? primary?.target ?? 'the submitted host'}`,
        });
      }
      break;
    }

    case 'posture': {
      const readiness = scanner2?.quantumReadiness ?? null;
      const risk = scanner2?.quantumRiskScore ?? null;
      const attack = scanner2?.attackAssessment ?? null;
      const hndl = scanner2?.hndlRisks ?? [];
      if (!readiness && !risk && !attack && hndl.length === 0) break;
      if (readiness) {
        rows.push({
          label: 'Quantum readiness',
          value: `${Math.round(readiness.score)}% · ${readiness.label}`,
          tone: readiness.score >= 60 ? TONE_PASS : TONE_WARN,
          detail: `${readiness.quantumSafeAssets}/${readiness.totalAssets} assets already quantum-safe`,
        });
      }
      if (risk) {
        rows.push(
          {
            label: 'Quantum risk score',
            value: `${Math.round(risk.overall)} · ${risk.level}`,
            tone: risk.level === 'quantum-safe' ? TONE_PASS : risk.level === 'critical-risk' ? TONE_FAIL : TONE_WARN,
            detail: 'Scanner_2 aggregate over every enriched finding',
          },
          {
            label: 'Severity split',
            value: `${risk.criticalCount}C · ${risk.highCount}H · ${risk.moderateCount}M · ${risk.lowCount}L`,
            detail: `${risk.totalFindings} enriched finding(s) scored`,
          },
        );
      }
      if (hndl.length > 0) {
        const immediate = hndl.filter((item) => item.urgencyLevel === 'immediate').length;
        rows.push({
          label: 'Harvest-now exposure',
          value: `${hndl.length} asset(s) · ${immediate} immediate`,
          tone: immediate > 0 ? TONE_FAIL : TONE_WARN,
          detail: Array.from(new Set(hndl.map((item) => item.algorithm))).slice(0, 4).join(', '),
        });
      }
      if (attack) {
        rows.push(
          {
            label: 'Break window',
            value: `${attack.estimatedBreakWindow.earliest}–${attack.estimatedBreakWindow.latest}`,
            tone: TONE_PQ,
            detail: 'Modelled from the algorithms actually observed, not a fixed date',
          },
          {
            label: 'Attack correlations',
            value: `${attack.attackCorrelations.length} chain(s) · ${attack.classification}`,
            tone: attack.classification === 'CRITICAL' ? TONE_FAIL : TONE_WARN,
            detail: 'Multi-step exposure chains built from correlated findings',
          },
        );
      }
      const migration = scanner2?.migrationRecommendations ?? [];
      if (migration.length > 0) {
        rows.push({
          label: 'Migration targets',
          value: migration.slice(0, 2).map((item) => item.recommendedPQC).join(', '),
          tone: TONE_PQ,
          detail: migration.map((item) => `${item.classicalAlgorithm} → ${item.recommendedPQC} (${item.nistStandard})`).join(' · '),
        });
      }
      break;
    }

    default:
      break;
  }

  // Why the panel is empty, stated precisely. "Not measured" and "measured as
  // clean" must never look the same.
  let emptyReason: string | null = null;
  if (rows.length === 0) {
    const ran = modules.some((module) => module.status !== 'Queued');
    if (!primary && input.findings.length === 0) {
      emptyReason = 'No scan evidence yet. Queue an authorized target and run a scan — this panel only ever shows what the scanner actually observed.';
    } else if (nodeKey === 'identity') {
      emptyReason = 'No SSH endpoint or token-issuing surface was submitted with this scan, so the identity modules had nothing to read.';
    } else if (nodeKey === 'code') {
      emptyReason = 'No repository URL was submitted and the origin returned no security-header surface, so the code and dependency modules had nothing to read.';
    } else if (nodeKey === 'posture') {
      emptyReason = 'The Scanner_2 enterprise pass has not produced a posture model for this scan yet.';
    } else if (!ran) {
      emptyReason = 'The modules behind this surface have not reported for this run.';
    } else {
      emptyReason = 'These modules ran but the target exposed nothing for this surface to measure.';
    }
  }

  return { rows, modules, findings: nodeFindings.slice(0, 6), score, emptyReason };
}

/* ============================================================== evidence ==== */

/**
 * Merge the per-target risk decompositions into one estate view.
 *
 * A dimension is averaged across the targets that MEASURED it, and reported as
 * null when no target did. Averaging in a filler zero from a target that never
 * looked at (say) application code would reintroduce, one level up, exactly the
 * inflation the engine's weight redistribution removes.
 */
function mergeRiskBreakdown(results: ScanResultRecord[]): Partial<Record<keyof ScanRiskBreakdown, number>> | null {
  const rows = results
    .map((result) => ({
      breakdown: result.metadata?.riskBreakdown,
      applicable: result.metadata?.riskBreakdownApplicable,
    }))
    .filter((row): row is { breakdown: ScanRiskBreakdown; applicable: ScanRiskApplicability | null | undefined } =>
      Boolean(row.breakdown),
    );
  if (rows.length === 0) return null;

  const keys: Array<keyof ScanRiskBreakdown> = [
    'certificateRisk',
    'tlsConfigRisk',
    'cipherSuiteRisk',
    'appCryptoRisk',
    'pqcReadiness',
  ];

  const merged: Partial<Record<keyof ScanRiskBreakdown, number>> = {};
  for (const key of keys) {
    const measured = rows
      // Results persisted before applicability was tracked carry no map; those
      // are treated as measured so historical scans keep rendering.
      .filter((row) => row.applicable == null || row.applicable[key])
      .map((row) => row.breakdown[key]);
    const mean = average(measured);
    if (mean !== null) merged[key] = mean;
  }
  return merged;
}

/**
 * The scanner's published risk weights (lib/scanner/web-scanner/risk-scoring).
 * Expressed as percentages so the panel can state them, and so the weighted
 * mean of the posture column reproduces `summary.qScore` exactly.
 */
const RISK_WEIGHTS: Array<{
  key: keyof ScanRiskBreakdown;
  label: string;
  weight: number;
  /** True for the single dedicated post-quantum category. */
  postQuantum: boolean;
  description: string;
}> = [
  { key: 'certificateRisk', label: 'Certificate Posture', weight: 25, postQuantum: false, description: 'public-key algorithm, key size, validity and chain of every certificate collected' },
  { key: 'tlsConfigRisk', label: 'TLS Configuration', weight: 25, postQuantum: false, description: 'negotiated protocol versions and handshake configuration' },
  { key: 'cipherSuiteRisk', label: 'Cipher Suites', weight: 20, postQuantum: false, description: 'offered cipher suites, AEAD usage and forward secrecy' },
  { key: 'appCryptoRisk', label: 'Application Cryptography', weight: 15, postQuantum: false, description: 'repository patterns, Web Crypto usage and API security surface' },
  { key: 'pqcReadiness', label: 'Post-Quantum Readiness', weight: 15, postQuantum: true, description: 'PQC-readiness detection rules across transport and certificates' },
];

/* ============================================================== assessment == */

export interface AssessmentInput {
  status: ScanStatus;
  summary: ScanSummary | null;
  findings: DefensiveFinding[];
  modules: ModuleState[];
  results: ScanResultRecord[];
  scanner2: EnterpriseScanner2 | null;
  targets: string[];
  completedAt: string | null;
  /** Tenant-wide totals from Scanner Intelligence — the platform's headline. */
  estate: {
    totalAssets: number;
    totalFindings: number;
    criticalFindings: number;
    vulnerableAssets: number;
    pqcReadiness: number;
    riskScore: number;
  };
  linked: { cbom: number; assets: number; exposures: number };
  provenance: string;
}

export function buildAssessment(input: AssessmentInput): ScannerAssessment {
  const { summary, findings, modules, results, scanner2 } = input;

  const executedModules = modules.filter((module) => module.status !== 'Queued');
  const completedModules = modules.filter((module) => module.status === 'Completed' || module.status === 'No findings');
  const skippedModules = modules.filter((module) => module.status === 'Skipped');
  const failedModules = modules.filter((module) => module.status === 'Failed');
  const unreportedModules = modules.filter((module) => module.status === 'Queued');

  const hasEvidence = Boolean(summary) || findings.length > 0 || input.estate.totalFindings > 0;
  const live = input.status === 'queued' || input.status === 'running' || input.status === 'analyzing';

  /* ── ONE evidence scope ──────────────────────────────────────────────────
     Every executive number below is read from a single scope, never mixed.
     Blending them is how the page could show a scan-scoped grade of A beside an
     estate-scoped count of 106 critical findings: two true numbers describing
     two different populations, presented as if they described one.

     `scan`   — a run (live or the one being reviewed) produced a summary.
     `estate` — no scan is in view, so the tenant-wide Scanner Intelligence
                snapshot answers every question instead. */
  const scope: 'scan' | 'estate' = summary ? 'scan' : 'estate';
  const scoped = {
    totalFindings: scope === 'scan' ? summary!.totalFindings : input.estate.totalFindings,
    critical: scope === 'scan' ? summary!.critical : input.estate.criticalFindings,
    high: scope === 'scan' ? summary!.high : 0,
    vulnerable: scope === 'scan' ? summary!.vulnerable : input.estate.totalFindings,
    assets: scope === 'scan' ? summary!.targetsScanned : input.estate.totalAssets,
  };

  /* ── Composite score ─────────────────────────────────────────────────────
     `qScore` is the backend's posture score (100 − exposure). It is what the
     History tab, the Assets page and the CBOM view already display, so using
     it here is what keeps the scanner's headline in lock-step with the rest of
     the platform rather than introducing a second opinion. */
  const encryptionScore = summary ? clamp(summary.qScore) : clamp(100 - input.estate.riskScore);
  const breakdown = mergeRiskBreakdown(results);

  /* The published twelve-category decomposition, merged across targets. This is
     the same model, the same weights and the same grade table /public-scan uses,
     which is what lets a host assessed on either surface be compared directly. */
  const scoreComponents = mergePublishedCategories(results, breakdown);

  /* Classical = every category except the two quantum ones, matching
     CLASSICAL_CATEGORY_KEYS in the published model. */
  const classicalWeighted = scoreComponents
    .filter((component) => component.score !== null && !PQ_CATEGORY_KEYS.has(component.key))
    .reduce(
      (accumulator, component) => {
        accumulator.weighted += (component.score as number) * component.weight;
        accumulator.weight += component.weight;
        return accumulator;
      },
      { weighted: 0, weight: 0 },
    );
  const classicalScore =
    classicalWeighted && classicalWeighted.weight > 0
      ? clamp(classicalWeighted.weighted / classicalWeighted.weight)
      : encryptionScore;

  // What the published weighted model alone says, kept beside the headline so a
  // divergence is visible rather than hidden.
  const measuredComponents = scoreComponents.filter((component) => component.score !== null);
  const decompositionWeight = measuredComponents.reduce((sum, component) => sum + component.weight, 0);
  const decompositionScore = decompositionWeight > 0
    ? clamp(
        measuredComponents.reduce((sum, component) => sum + (component.score as number) * component.weight, 0) /
          decompositionWeight,
      )
    : null;
  const decompositionAgrees =
    decompositionScore === null || Math.abs(decompositionScore - encryptionScore) <= 1;

  /* ── Post-quantum readiness ──────────────────────────────────────────────
     The headline PQ number is the platform's own readiness figure (share of
     discovered components that are already quantum-safe). Scanner_2's
     asset-level readiness is reported separately, labelled with its source,
     rather than averaged into it — two different measurements of two different
     populations must not be silently blended. */
  /* The published model's Post-Quantum Readiness category IS the platform's
     definition — hybrid key agreement 55, PQ signature 30, TLS 1.3 12,
     short-lived certificates 8, CT 3, enforced HSTS 3. Using the share of
     findings rated SAFE instead was a different measurement of a different
     population, and it is why this surface reported 0% where /public-scan
     reported 8% for the same host. The finding-share is kept only as a fallback
     for estates with no transport evidence at all. */
  const publishedPq = scoreComponents.find((component) => component.key === 'post-quantum-readiness');
  const postQuantumReadiness = publishedPq?.score !== null && publishedPq?.score !== undefined
    ? publishedPq.score
    : summary && summary.totalFindings > 0
      ? clamp((summary.pqcReady / summary.totalFindings) * 100)
      : clamp(input.estate.pqcReadiness);

  const scanner2Readiness = scanner2?.quantumReadiness
    ? { score: clamp(scanner2.quantumReadiness.score), label: scanner2.quantumReadiness.label }
    : null;

  /* ── Evidence coverage & confidence ────────────────────────────────────
     Coverage is measured against the modules that COULD apply. A module the
     scanner correctly reported as not applicable — an SSH host-key probe on a
     URL target — is not a coverage gap and must not depress the number, or
     every web scan would permanently read ~70% covered. */
  const applicableModules = modules.length - skippedModules.length;
  const evidenceCoverage = applicableModules > 0
    ? clamp((completedModules.length / applicableModules) * 100)
    : modules.length > 0
      // Every catalogued module was inapplicable: there is no coverage to claim.
      ? 0
      : hasEvidence
        ? 100
        : 0;

  const measuredConfidence = average(
    results
      .map((result) => result.metadata?.scanConfidence?.confidence)
      .filter((value): value is number => typeof value === 'number'),
  );
  const confidence = measuredConfidence !== null ? clamp(measuredConfidence) : evidenceCoverage;
  const confidenceFactors = Array.from(
    new Set(results.flatMap((result) => result.metadata?.scanConfidence?.factors ?? [])),
  );
  const confidenceDetail = confidenceFactors.length
    ? confidenceFactors.slice(0, 3).join(' · ')
    : `${completedModules.length} of ${applicableModules || modules.length || executedModules.length} applicable scanner modules reported evidence.`;

  /* ── Grade ───────────────────────────────────────────────────────────────
     A grade is withheld until the scan actually completed with a summary: a
     letter computed from a partial run is a claim the evidence does not
     support. */
  /* A grade is a claim about a whole estate, so it is withheld until the run is
     settled AND the module ledger is closed. `unreportedModules` is non-empty
     only when a run was cut short: grading there produced the "Grade A · 96%"
     on a scan that had run six of twenty-three modules. */
  const runSettled = !live && unreportedModules.length === 0;
  const gradeable = hasEvidence && runSettled && (Boolean(summary) || input.estate.totalFindings > 0);
  const gradeRow = scoreToGrade(encryptionScore);
  const grade = gradeable ? gradeRow.grade : '—';
  const gradeLabel = gradeable
    ? gradeRow.rating
    : live
      ? 'Assessment running'
      : unreportedModules.length > 0
        ? 'Incomplete run'
        : 'Awaiting scan';
  const gradeColor = gradeable ? gradeRow.color : '#94a3b8';
  const gradeDetail = gradeable
    ? evidenceCoverage >= 100
      ? gradeRow.meaning
      : `${gradeRow.meaning} Graded on ${evidenceCoverage}% module coverage${
          skippedModules.length ? `; ${pluralize(skippedModules.length, 'module')} did not apply to these targets` : ''
        }.`
    : live
      ? 'A grade is withheld until every module has reported.'
      : unreportedModules.length > 0
        ? `${pluralize(unreportedModules.length, 'module')} never reported, so this run cannot be graded. Re-run the scan.`
        : 'Run an authorized scan to grade this estate.';

  /* ── Business risk ──────────────────────────────────────────────────────
     Score-derived, then floored by the presence of critical findings: an estate
     with an open critical exposure is not "Low risk" no matter what the mean
     says. */
  const criticalCount = scoped.critical;
  const highCount = scoped.high;
  const scopeNoun = scope === 'scan' ? 'this assessment' : 'the tenant estate';
  let businessRisk: RiskBand = gradeable ? riskBandForScore(encryptionScore) : 'Not assessable';
  if (gradeable && criticalCount > 0) businessRisk = worstRisk(businessRisk, 'High');
  if (gradeable && criticalCount >= 5) businessRisk = worstRisk(businessRisk, 'Critical');
  const businessRiskDetail = gradeable
    ? criticalCount > 0
      ? `${pluralize(criticalCount, 'critical finding')} open across ${scopeNoun}.`
      : highCount > 0
        ? `No critical findings; ${pluralize(highCount, 'high-severity finding')} outstanding across ${scopeNoun}.`
        : `No critical or high-severity cryptographic findings were recorded across ${scopeNoun}.`
    : 'Risk cannot be stated before a completed scan.';

  /* ── Migration complexity ─────────────────────────────────────────────── */
  const recommendations = scanner2?.migrationRecommendations ?? [];
  const complexityRank: Record<PqcRecommendation['migrationComplexity'], number> = {
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
  };
  const worstComplexity = recommendations.reduce<PqcRecommendation['migrationComplexity'] | null>(
    (worst, recommendation) =>
      !worst || complexityRank[recommendation.migrationComplexity] > complexityRank[worst]
        ? recommendation.migrationComplexity
        : worst,
    null,
  );
  const migrationComplexity = worstComplexity
    ? worstComplexity.charAt(0) + worstComplexity.slice(1).toLowerCase()
    : 'Unknown';
  const migrationComplexityDetail = worstComplexity
    ? `${pluralize(recommendations.length, 'algorithm family')} require migration; the hardest is rated ${worstComplexity}.`
    : 'No migration recommendations have been generated for this estate yet.';

  /* ── Attack surface ─────────────────────────────────────────────────────
     Only what was actually read off the wire. A control the scan did not reach
     renders `unknown`, never `fail`. */
  const attackSurface = buildAttackSurface(input, findings);

  /* ── Cryptographic intelligence ─────────────────────────────────────── */
  const observedAlgorithms = buildObservedAlgorithms(results, findings);

  // The negotiated key agreement is a direct measurement when the TLS analyzer
  // reached the target; findings are only the fallback for targets it did not
  // (a repository URL, say), never a substitute for it.
  const negotiatedTls = results[0]?.metadata?.tlsAnalysis ?? null;
  const keyExchangeFindings = findings.filter((finding) =>
    /key exchange|kex|ecdhe|dhe|x25519|ml-kem|kyber/i.test(`${finding.category} ${finding.algorithm}`),
  );
  const keyExchange = negotiatedTls?.keyExchange
    ? negotiatedTls.negotiatedCurve
      ? `${negotiatedTls.keyExchange} (${negotiatedTls.negotiatedCurve})`
      : negotiatedTls.keyExchange
    : keyExchangeFindings.length
      ? Array.from(new Set(keyExchangeFindings.map((finding) => finding.algorithm))).slice(0, 3).join(', ')
      : 'Not observed';

  const forwardSecrecy = negotiatedTls
    ? Boolean(negotiatedTls.ephemeralKeyType) || /ecdhe|dhe|x25519|ml-kem|kyber/i.test(negotiatedTls.keyExchange || '')
      ? 'Enabled'
      : 'Not offered'
    : keyExchangeFindings.length
      ? keyExchangeFindings.some((finding) => /ecdhe|dhe|x25519/i.test(finding.algorithm))
        ? 'Enabled'
        : 'Not offered'
      : 'Unknown';

  const quantumVulnerability = !hasEvidence
    ? 'Unknown'
    : findings.some((finding) => /ml-kem|ml-dsa|kyber|dilithium|slh-dsa/i.test(finding.algorithm))
      ? 'Hybrid-protected'
      : scoped.vulnerable > 0
        ? 'Vulnerable'
        : 'Not observed';

  const migrationTargets = recommendations.slice(0, 5).map((recommendation) => ({
    name: recommendation.recommendedPQC,
    standard: recommendation.nistStandard,
    replaces: recommendation.classicalAlgorithm,
  }));

  /* ── Timeline & HNDL ─────────────────────────────────────────────────── */
  const hndlRisks = scanner2?.hndlRisks ?? [];
  const hndl = {
    immediate: hndlRisks.filter((risk) => risk.urgencyLevel === 'immediate').length,
    soon: hndlRisks.filter((risk) => risk.urgencyLevel === 'soon').length,
    planned: hndlRisks.filter((risk) => risk.urgencyLevel === 'planned').length,
    window: scanner2?.attackAssessment?.estimatedBreakWindow ?? null,
  };

  /* Everything the assessment did NOT measure, with the scanner's own reason. */
  const notAnalyzedLines = [
    ...skippedModules.map(
      (module) => `${module.name} — ${module.reason || 'not applicable to the submitted target types'}`,
    ),
    ...failedModules.map((module) => `${module.name} — FAILED: ${module.error || module.reason || 'no error reported'}`),
    ...unreportedModules.map((module) => `${module.name} — never reported; this run's coverage is incomplete`),
  ];

  /* ── Assembly ────────────────────────────────────────────────────────── */
  return {
    hasEvidence,
    live,
    provenance: input.provenance,
    target: {
      label: input.targets.length ? input.targets.join(', ') : `${input.estate.totalAssets} discovered assets`,
      count: scoped.assets,
      completedAt: input.completedAt,
    },
    executive: {
      grade,
      gradeLabel,
      gradeColor,
      gradeable,
      gradeDetail,
      encryptionScore,
      classicalScore,
      postQuantumReadiness,
      evidenceCoverage,
      businessRisk,
      businessRiskDetail,
      migrationComplexity,
      migrationComplexityDetail,
      confidence,
      confidenceDetail,
    },
    scoreComponents,
    decompositionScore,
    decompositionAgrees,
    attackSurface,
    intelligence: {
      observedAlgorithms,
      keyExchange,
      forwardSecrecy,
      quantumVulnerability,
      migrationTargets,
      confidence,
      scanner2Readiness,
    },
    timeline: buildTimeline(hndl, encryptionScore, postQuantumReadiness),
    recommendations: buildRecommendations(recommendations, findings),
    footprint: {
      metrics: [
        {
          key: 'assets',
          label: 'Assets Scanned',
          value: scoped.assets,
          countedFrom: scope === 'scan'
            ? 'authorized targets the scanner completed a pass over in this assessment'
            : 'assets in the tenant inventory, from the Scanner Intelligence snapshot',
        },
        {
          key: 'components',
          label: 'Crypto Components',
          value: scoped.totalFindings,
          countedFrom: scope === 'scan'
            ? 'distinct cryptographic observations recorded by this assessment'
            : 'distinct cryptographic observations persisted for this tenant',
        },
        {
          key: 'cbom',
          label: 'CBOM Records',
          value: input.linked.cbom,
          countedFrom: 'rows written to the cryptographic bill of materials by the scan in view',
        },
        {
          key: 'exposures',
          label: 'Exposure Nodes',
          value: input.linked.exposures,
          countedFrom: 'nodes added to the crypto exposure graph by the scan in view',
        },
      ],
      exposureLevel: gradeable
        ? `${businessRisk} — ${pluralize(scoped.vulnerable, 'quantum-vulnerable component')}`
        : 'Not assessed',
      basis: `Counted from the scanner's own persisted records for this tenant, scoped to ${scopeNoun}: ${pluralize(completedModules.length, 'module')} measured, ${pluralize(skippedModules.length, 'module')} not applicable, ${pluralize(input.linked.assets, 'asset record')} synchronized. Nothing here is estimated.`,
    },
    coverage: buildCoverage(modules, failedModules, skippedModules, unreportedModules),
    scope: {
      analyzed: completedModules.length
        ? completedModules.map((module) => module.name)
        : ['No module has reported evidence yet'],
      // Verbatim reasons from the scanner's module ledger — never a guess about
      // why a module did not run.
      notAnalyzed: notAnalyzedLines.length
        ? notAnalyzedLines
        : ['Every catalogued module was applicable to the submitted targets and reported evidence'],
      statement:
        'The Dashboard Scanner performs authorized, defensive cryptographic inventory only: no exploitation, credential collection, stealth behaviour or unauthorized reconnaissance. Results persist per tenant and populate CBOM, Assets, Crypto Exposure, Quantum Readiness and Migration Planner.',
    },
    nodeScores: scoreNodes(findings),
    hndl,
  };
}

/**
 * Algorithms the scan actually observed — read from the cryptographic evidence,
 * not from finding titles.
 *
 * Detection-rule findings carry a RULE NAME in `finding.algorithm` ("No PQC
 * Cipher Suites", "HNDL Risk: HIGH", "No PQC Migration Strategy"). Listing those
 * under "Observed Algorithms" was wrong twice over: they are not algorithms, and
 * because the view aggregates every retained scan of the same asset, each one
 * appeared with a multiplier ("x5") that looked like five distinct observations.
 *
 * The primary source is therefore the parsed transport and certificate
 * evidence: negotiated protocol, cipher-suite components, key agreement,
 * signature algorithms and the certificate's public key. Findings are consulted
 * only as a fallback, for target types that produce no TLS evidence at all (a
 * repository scan), and even then rule-shaped titles are filtered out.
 */
function buildObservedAlgorithms(
  results: ScanResultRecord[],
  findings: DefensiveFinding[],
): Array<{ name: string; role: string; quantumVulnerable: boolean; count: number }> {
  /* Ordered by algorithm CLASS, not by severity. Ranking by vulnerability first
     pushed every symmetric and protocol entry past the display cap, so the panel
     showed eight flavours of "recoverable by Shor" and none of the AES/hash
     material that is also part of the observed posture. */
  const RANK = {
    certificateKey: 0,
    certificateSignature: 1,
    keyAgreement: 2,
    namedGroup: 3,
    handshakeSignature: 4,
    symmetric: 5,
    protocol: 6,
    chainKey: 7,
    fallback: 8,
  } as const;

  const observed = new Map<string, { role: string; quantumVulnerable: boolean; count: number; rank: number }>();
  const add = (name: string | null | undefined, role: string, quantumVulnerable: boolean, rank: number) => {
    const clean = (name ?? '').trim();
    if (!clean || clean.toLowerCase() === 'unknown' || clean === '-') return;
    const existing = observed.get(clean);
    if (existing) {
      existing.count += 1;
      existing.quantumVulnerable = existing.quantumVulnerable || quantumVulnerable;
      existing.rank = Math.min(existing.rank, rank);
      return;
    }
    observed.set(clean, { role, quantumVulnerable, count: 1, rank });
  };

  for (const result of results) {
    const tls = result.metadata?.tlsAnalysis ?? null;
    const certificate = result.certificateInfo ?? null;

    if (certificate) {
      add(certificate.publicKeyAlgorithm, 'Certificate public key - recoverable by Shor', true, RANK.certificateKey);
      add(certificate.signatureAlgorithm, 'Certificate signature - recoverable by Shor', true, RANK.certificateSignature);
      for (const entry of certificate.chain ?? []) {
        add(entry.publicKeyAlgorithm, 'Chain public key - recoverable by Shor', true, RANK.chainKey);
      }
    }

    if (tls) {
      add(tls.keyExchange, 'Key agreement - recoverable by Shor', true, RANK.keyAgreement);
      add(tls.negotiatedCurve, 'Named group - recoverable by Shor', true, RANK.namedGroup);
      add(tls.signatureAlgorithm, 'Handshake signature - recoverable by Shor', true, RANK.handshakeSignature);
      for (const suite of tls.cipherSuites ?? []) {
        // Symmetric primitives are only halved by Grover, not broken by Shor.
        add(suite.encryption, 'Symmetric encryption - Grover halves the key', false, RANK.symmetric);
      }
      for (const protocol of tls.supportedProtocols ?? []) {
        // A deprecated protocol is a CLASSICAL break, not a quantum one.
        add(protocol, 'Transport protocol', /1\.0|1\.1|SSLv/i.test(protocol), RANK.protocol);
      }
    }
  }

  // Fallback for target types with no transport evidence at all.
  if (observed.size === 0) {
    for (const finding of findings) {
      const name = finding.algorithm ?? '';
      // Rule-shaped titles are statements about the estate, not algorithms.
      if (/^(no|missing|weak|insecure)\b/i.test(name) || name.includes(':')) continue;
      add(name, finding.category, finding.threatLevel !== 'SAFE', RANK.fallback);
    }
  }

  return Array.from(observed.entries())
    .sort((a, b) => a[1].rank - b[1].rank || b[1].count - a[1].count || a[0].localeCompare(b[0]))
    .slice(0, 8)
    .map(([name, value]) => ({ name, role: value.role, quantumVulnerable: value.quantumVulnerable, count: value.count }));
}

/* =========================================================== sub-builders == */

/**
 * The observed attack surface.
 *
 * Mirrors /public-scan's control list one row for one row, so the same host can
 * be read side by side on either surface. Rows the authenticated scanner does
 * not probe (the public-edge DNS and certificate-extension checks) render an
 * explicit "Not probed" with the reason in the tooltip — never a pass, never a
 * fail, and never a fabricated value. That distinction is the whole contract:
 * "we looked and it is absent" and "we did not look" must not render the same.
 */
function buildAttackSurface(input: AssessmentInput, findings: DefensiveFinding[]): SurfaceItem[] {
  const primary = input.results[0];
  const tls = primary?.metadata?.tlsAnalysis ?? null;
  const certificate = primary?.certificateInfo ?? null;
  const api = primary?.metadata?.apiSecurityResult ?? null;
  const scanner2 = input.scanner2;
  const items: SurfaceItem[] = [];

  /** A control this scanner does not perform. */
  const notProbed = (key: string, label: string, why: string): SurfaceItem => ({
    key,
    label,
    value: 'Not probed',
    status: 'unknown',
    detail: `${why} This is a public-edge probe the authenticated estate scanner does not perform, so no verdict is claimed either way.`,
  });

  /* ── Reachability ──────────────────────────────────────────────────────── */
  const reachable = Boolean(tls) || Boolean(api?.endpointsProbed);
  items.push({
    key: 'internet-facing',
    label: 'Internet Facing',
    value: !primary ? 'Not observed' : reachable ? 'Yes' : 'No',
    status: !primary ? 'unknown' : reachable ? 'info' : 'pass',
    detail: reachable
      ? 'The scanner completed a network connection to this target from the public Internet.'
      : 'No network service answered on the submitted target.',
  });

  const targetUrl = primary?.target ?? input.targets[0] ?? '';
  const portMatch = targetUrl.match(/:(\d+)/);
  const isHttps = /^https/i.test(targetUrl) || Boolean(tls);
  items.push({
    key: 'tls-service',
    label: 'TLS Service',
    value: !primary ? 'Not observed' : isHttps ? `HTTPS (${portMatch ? portMatch[1] : '443'})` : 'None',
    status: !primary ? 'unknown' : isHttps ? 'pass' : 'fail',
    detail: 'Transport service the scanner negotiated against.',
  });

  /* ── Certificate ───────────────────────────────────────────────────────── */
  const certChain = certificate?.chain ?? [];
  items.push({
    key: 'certificate-chain',
    label: 'Certificate Chain',
    value: certificate ? `${certChain.length || 1} cert${(certChain.length || 1) === 1 ? '' : 's'}` : 'Not observed',
    status: !certificate ? 'unknown' : certChain.length > 1 ? 'pass' : 'partial',
    detail: certChain.length
      ? certChain.map((entry) => entry.subject).join(' -> ')
      : 'Only the leaf certificate was returned; no intermediates were served.',
  });

  // Names are read from the subject/chain the certificate parser returns. It
  // does not currently extract subjectAltName, so a multi-name certificate
  // cannot be counted accurately — reported as such rather than guessed.
  const commonName = certificate?.subject?.CN ?? certificate?.subject?.commonName ?? null;
  items.push({
    key: 'names-covered',
    label: 'Names Covered',
    value: commonName ?? 'Not observed',
    status: commonName ? 'info' : 'unknown',
    detail: commonName
      ? 'Common name on the leaf certificate. Subject alternative names are not extracted by the authenticated certificate parser, so this is the CN only, not a full name count.'
      : 'No certificate subject was parsed.',
  });

  /* ── Transport ─────────────────────────────────────────────────────────── */
  const protocols = tls?.supportedProtocols ?? [];
  const legacyProtocols = protocols.filter((protocol) => /TLSv1(\.0)?$|TLSv1\.1|SSLv/i.test(protocol));
  const tlsVersion = primary?.tlsVersion ?? tls?.tlsVersion ?? null;
  items.push({
    key: 'tls-version',
    label: 'TLS Version',
    value: !tlsVersion
      ? 'Not observed'
      : legacyProtocols.length
        ? `${tlsVersion} + legacy`
        : protocols.length
          ? protocols.join(', ')
          : tlsVersion,
    status: !tlsVersion ? 'unknown' : legacyProtocols.length ? 'fail' : /1\.3/.test(tlsVersion) ? 'pass' : 'partial',
    detail: legacyProtocols.length
      ? `${legacyProtocols.join(', ')} still accepted - deprecated by RFC 8996.`
      : 'Protocol versions the endpoint accepted, probed individually.',
  });

  const staticRsaSuites = (tls?.cipherSuites ?? []).filter(
    (suite) => /(^|_)RSA_WITH/i.test(suite.name) || suite.category === 'rsa-kex',
  );
  items.push({
    key: 'cipher',
    label: 'Cipher Suite',
    value: !tls
      ? 'Not observed'
      : staticRsaSuites.length
        ? 'Static RSA accepted'
        : tls.cipherSuite || 'Not observed',
    status: !tls ? 'unknown' : staticRsaSuites.length ? 'fail' : /GCM|CHACHA20|CCM/i.test(tls.cipherSuite) ? 'pass' : 'partial',
    detail: staticRsaSuites.length
      ? `Negotiated ${tls?.cipherSuite}, but ${staticRsaSuites.length} static-RSA key-transport suite(s) are also accepted.`
      : 'Cipher suite selected during the observed handshake.',
  });

  const chainExpired = certChain.some((entry) => entry.isExpired);
  items.push({
    key: 'chain-trust',
    label: 'Chain Trust',
    value: !certificate
      ? 'Not observed'
      : certificate.isSelfSigned
        ? 'Self-signed'
        : chainExpired || certificate.isExpired
          ? 'Fail'
          : 'Pass',
    status: !certificate
      ? 'unknown'
      : certificate.isSelfSigned || chainExpired || certificate.isExpired
        ? 'fail'
        : 'pass',
    detail: certificate?.isExpired
      ? 'The leaf certificate has expired, so the chain does not validate.'
      : certificate?.isSelfSigned
        ? 'The leaf is self-signed and not anchored to a public trust store.'
        : 'Chain validated against the trust store.',
  });

  const kexLabel = tls?.keyExchange
    ? tls.negotiatedCurve
      ? `${tls.keyExchange} (${tls.negotiatedCurve})`
      : tls.keyExchange
    : null;
  items.push({
    key: 'key-exchange',
    label: 'Key Exchange',
    value: kexLabel ?? 'Not observed',
    status: !kexLabel
      ? 'unknown'
      : /ml-kem|kyber/i.test(kexLabel)
        ? 'pass'
        : /ecdhe|dhe|x25519/i.test(kexLabel)
          ? 'partial'
          : 'fail',
    detail: 'Key-agreement mechanism negotiated for the session.',
  });

  const hybridObserved =
    /ml-kem|kyber/i.test(`${tls?.keyExchange ?? ''} ${tls?.negotiatedCurve ?? ''} ${tls?.cipherSuite ?? ''}`) ||
    findings.some((finding) => /ml-kem|kyber/i.test(finding.algorithm));
  items.push({
    key: 'pq-key-agreement',
    label: 'Post-Quantum Key Agreement',
    value: !tls ? 'Not observed' : hybridObserved ? 'Observed' : 'Fail',
    status: !tls ? 'unknown' : hybridObserved ? 'pass' : 'fail',
    detail: hybridObserved
      ? 'Hybrid ML-KEM key agreement detected in the negotiated groups.'
      : 'No hybrid post-quantum group was negotiated - sessions are recoverable by a future CRQC.',
  });

  /* ── HTTP ──────────────────────────────────────────────────────────────── */
  const headers = api?.securityHeaders ?? [];
  const hstsHeader = headers.find((header) => header.name.toLowerCase() === 'strict-transport-security');
  items.push({
    key: 'hsts',
    label: 'HSTS',
    value: !headers.length
      ? 'Not observed'
      : !hstsHeader?.present
        ? 'Fail'
        : hstsHeader.secure
          ? 'Enforced'
          : 'Weak',
    status: !headers.length ? 'unknown' : !hstsHeader?.present ? 'fail' : hstsHeader.secure ? 'pass' : 'partial',
    detail: hstsHeader?.value ?? 'No Strict-Transport-Security header was returned by the origin.',
  });

  const nonHstsHeaders = headers.filter((header) => header.name.toLowerCase() !== 'strict-transport-security');
  const hardened = nonHstsHeaders.filter((header) => header.secure).length;
  items.push({
    key: 'headers',
    label: 'HTTP Security Headers',
    value: nonHstsHeaders.length ? `${hardened}/${nonHstsHeaders.length} hardened` : 'Not observed',
    status: !nonHstsHeaders.length
      ? 'unknown'
      : hardened === nonHstsHeaders.length
        ? 'pass'
        : hardened === 0
          ? 'fail'
          : 'partial',
    detail: nonHstsHeaders.length
      ? nonHstsHeaders
          .filter((header) => !header.secure)
          .map((header) => `${header.name}: ${header.present ? 'present, weak' : 'absent'}`)
          .join(' - ') || 'Every probed transport-security header is hardened.'
      : 'No HTTP response was collected from the origin.',
  });

  /* ── Public-edge probes this scanner does not perform ──────────────────── */
  items.push(
    notProbed('ocsp-stapling', 'OCSP Stapling', 'Revocation stapling is read from the TLS handshake extension.'),
    notProbed('certificate-transparency', 'Certificate Transparency', 'SCTs are read from the certificate extension or the TLS handshake.'),
    notProbed('dns-caa', 'DNS Security (CAA)', 'CAA issuance policy is read over DNS.'),
    notProbed('dnssec', 'DNSSEC', 'Zone signing is validated over DNS.'),
    notProbed('alpn', 'ALPN', 'The negotiated application protocol is read from the TLS handshake.'),
  );

  /* ── Estate-only controls the public surface cannot see ────────────────── */
  const keyAlgorithm = certificate?.publicKeyAlgorithm || null;
  const keySize = certificate?.publicKeySize ?? null;
  const keyLabel = keyAlgorithm
    ? keySize && !keyAlgorithm.includes(String(keySize))
      ? `${keyAlgorithm} ${keySize}-bit`
      : keyAlgorithm
    : null;
  items.push({
    key: 'cert-key',
    label: 'Certificate Key',
    value: keyLabel ?? 'Not observed',
    status: keyAlgorithm ? (/rsa/i.test(keyAlgorithm) && (keySize ?? 0) < 2048 ? 'fail' : 'partial') : 'unknown',
    detail: 'Public-key algorithm of the leaf certificate - quantum-vulnerable until replaced by ML-DSA.',
  });

  const certDaysRemaining = certificate?.validTo
    ? Math.round((Date.parse(certificate.validTo) - Date.now()) / 86400000)
    : null;
  items.push({
    key: 'cert-validity',
    label: 'Certificate Validity',
    value: !certificate
      ? 'Not observed'
      : certificate.isExpired
        ? 'Expired'
        : certDaysRemaining !== null
          ? `${certDaysRemaining} day${certDaysRemaining === 1 ? '' : 's'} left`
          : 'Unknown',
    status: !certificate ? 'unknown' : certificate.isExpired ? 'fail' : (certDaysRemaining ?? 999) < 30 ? 'partial' : 'pass',
    detail: certificate ? `Valid ${certificate.validFrom} to ${certificate.validTo}` : 'No certificate chain was collected.',
  });

  const negotiatedIsEphemeral = !tls
    ? null
    : Boolean(tls.ephemeralKeyType) || /ecdhe|dhe|x25519|ml-kem|kyber/i.test(tls.keyExchange || '');
  items.push({
    key: 'pfs',
    label: 'Forward Secrecy',
    value: negotiatedIsEphemeral === null
      ? 'Not observed'
      : !negotiatedIsEphemeral
        ? 'Not offered'
        : staticRsaSuites.length > 0
          ? 'Partial'
          : 'Enabled',
    status: negotiatedIsEphemeral === null
      ? 'unknown'
      : !negotiatedIsEphemeral
        ? 'fail'
        : staticRsaSuites.length > 0
          ? 'partial'
          : 'pass',
    detail: staticRsaSuites.length > 0
      ? `Negotiated ${tls?.keyExchange || 'ephemeral'} key agreement, but ${staticRsaSuites.length} static-RSA suite(s) are also accepted; sessions using those have no forward secrecy.`
      : 'Ephemeral key agreement observed on the negotiated suite.',
  });

  const sshFindings = findings.filter((finding) => /ssh/i.test(finding.category));
  items.push({
    key: 'ssh',
    label: 'SSH Host Keys',
    value: sshFindings.length ? pluralize(sshFindings.length, 'observation') : 'Not applicable',
    status: sshFindings.length
      ? sshFindings.some((finding) => finding.threatLevel === 'CRITICAL' || finding.threatLevel === 'HIGH')
        ? 'fail'
        : 'partial'
      : 'unknown',
    detail: sshFindings.length
      ? 'Host key and key-exchange metadata collected from the SSH banner.'
      : 'No SSH endpoint was submitted with this scan.',
  });

  const repoFindings = findings.filter((finding) => /repository|library|app-crypto|webcrypto/i.test(finding.category));
  const repoScanned = Boolean(primary?.metadata?.repoScanResult || primary?.metadata?.webCryptoResult);
  items.push({
    key: 'code',
    label: 'Source & Dependencies',
    value: repoScanned ? pluralize(repoFindings.length, 'pattern') : 'Not scanned',
    status: !repoScanned ? 'unknown' : repoFindings.some((finding) => finding.threatLevel !== 'SAFE') ? 'partial' : 'pass',
    detail: repoScanned
      ? 'Cryptographic patterns matched inside the submitted repository and page scripts.'
      : 'No repository URL was submitted with this scan.',
  });

  /* ── Aggregate verdicts ────────────────────────────────────────────────── */
  const quantumRisk = scanner2?.attackAssessment?.classification ?? null;
  items.push({
    key: 'quantum-risk',
    label: 'Quantum Risk',
    value: quantumRisk
      ? quantumRisk.charAt(0) + quantumRisk.slice(1).toLowerCase()
      : scanner2?.quantumRiskScore?.level ?? 'Not observed',
    status: !quantumRisk
      ? 'unknown'
      : quantumRisk === 'CRITICAL' || quantumRisk === 'HIGH'
        ? 'fail'
        : quantumRisk === 'MEDIUM'
          ? 'partial'
          : 'pass',
    detail: scanner2?.attackAssessment
      ? `Scanner_2 quantum risk assessment across ${pluralize(scanner2.attackAssessment.attackCorrelations.length, 'correlated exposure chain')}.`
      : 'The Scanner_2 enterprise pass has not scored this estate yet.',
  });

  items.push(
    notProbed('edge-infrastructure', 'Edge Infrastructure', 'CDN and WAF attribution is inferred from response-header signatures.'),
  );

  return items;
}

function buildTimeline(
  hndl: ScannerAssessment['hndl'],
  encryptionScore: number,
  postQuantumReadiness: number,
): TimelinePhase[] {
  const window = hndl.window;
  const harvesting = hndl.immediate + hndl.soon + hndl.planned;

  return [
    {
      key: 'today',
      title: 'Today — measured posture',
      horizon: `${encryptionScore}/100`,
      description: `Current cryptographic posture across the scanned estate, from the scanner's own weighted risk model.`,
      state: 'now',
    },
    {
      key: 'harvest',
      title: 'Harvest Now, Decrypt Later',
      horizon: harvesting > 0 ? `${harvesting} exposed` : 'None recorded',
      description:
        harvesting > 0
          ? `${hndl.immediate} immediate, ${hndl.soon} near-term and ${hndl.planned} planned HNDL exposures identified by the Scanner_2 analyzer.`
          : 'No harvest-now exposure was identified in the recorded findings.',
      state: harvesting > 0 ? 'active' : 'past',
    },
    {
      key: 'break',
      title: 'Modelled cryptographically-relevant quantum window',
      horizon: window ? `${window.earliest}–${window.latest}` : 'Not modelled',
      description: window
        ? 'Break window estimated by the Scanner_2 quantum risk assessment from the algorithms actually observed.'
        : 'A break window is only modelled once quantum-vulnerable algorithms have been observed.',
      state: window ? 'active' : 'past',
    },
    {
      key: 'migration',
      title: 'Post-quantum migration',
      horizon: `${postQuantumReadiness}% ready`,
      description:
        postQuantumReadiness >= 60
          ? 'A majority of discovered components are already quantum-safe; finish the remainder through the Migration Planner.'
          : 'Most discovered components still rely on quantum-vulnerable cryptography — plan the migration in the Migration Planner.',
      state: 'target',
    },
  ];
}

function buildRecommendations(
  recommendations: PqcRecommendation[],
  findings: DefensiveFinding[],
): RecommendationCard[] {
  if (recommendations.length === 0) {
    // No fabricated advice: when the migration engine has produced nothing, the
    // panel says so rather than printing generic filler.
    return [];
  }

  const priorityFor: Record<PqcRecommendation['migrationComplexity'], RecommendationCard['priority']> = {
    CRITICAL: 'Critical',
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low',
  };

  return recommendations
    .map((recommendation) => {
      const affected = findings.filter((finding) =>
        finding.algorithm.toLowerCase().includes(recommendation.classicalAlgorithm.toLowerCase()),
      );
      const worst = affected.reduce<ThreatLevel>(
        (level, finding) => (THREAT_RANK[finding.threatLevel] > THREAT_RANK[level] ? finding.threatLevel : level),
        'SAFE',
      );
      return {
        id: recommendation.classicalAlgorithm,
        title: `Replace ${recommendation.classicalAlgorithm} with ${recommendation.recommendedPQC}`,
        priority: priorityFor[recommendation.migrationComplexity],
        businessImpact:
          affected.length > 0
            ? `${pluralize(affected.length, 'observation')} in the scanned estate use ${recommendation.classicalAlgorithm}; the most severe is rated ${worst}.`
            : `${recommendation.classicalAlgorithm} was matched by the migration engine but no finding in the current view uses it.`,
        effort: recommendation.estimatedEffort,
        standard: recommendation.nistStandard,
        affected: affected.length,
        steps: recommendation.migrationSteps,
        rationale: `${recommendation.migrationType} · alternatives: ${recommendation.alternativePQC.slice(0, 3).join(', ') || 'none published'}`,
      };
    })
    .sort((a, b) => {
      const order: Record<RecommendationCard['priority'], number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
      return order[a.priority] - order[b.priority] || b.affected - a.affected;
    });
}

/**
 * Discovery Coverage — measured against what COULD be measured.
 *
 * Coverage is stated per surface as `measured / applicable`, with modules the
 * scanner declared inapplicable excluded from the denominator and named with
 * their reason. This is the same arithmetic the Discovery Workflow rail uses,
 * so the two panels can never disagree about the same surface.
 */
function buildCoverage(
  modules: ModuleState[],
  failed: ModuleState[],
  skipped: ModuleState[],
  unreported: ModuleState[],
): CoverageItem[] {
  if (modules.length === 0) {
    return [
      {
        key: 'catalog',
        label: 'Scanner module catalog',
        status: 'unknown',
        detail: 'The module catalog is published when a scan stream opens.',
      },
    ];
  }

  return Object.entries(SCANNER_NODE_MODULES).map(([node, moduleIds]) => {
    const owned = modules.filter((module) => moduleIds.includes(module.id));
    const done = owned.filter((module) => module.status === 'Completed' || module.status === 'No findings');
    const broken = owned.filter((module) => module.status === 'Failed');
    const notApplicable = owned.filter((module) => module.status === 'Skipped');
    const pending = owned.filter((module) => module.status === 'Queued');
    const applicable = owned.length - notApplicable.length;
    const blueprint = SCANNER_NODE_BLUEPRINTS.find((entry) => entry.key === node);
    const status: CoverageItem['status'] = owned.length === 0
      ? 'unknown'
      : broken.length > 0
        ? 'fail'
        : applicable === 0
          ? 'unknown'
          : done.length === applicable
            ? 'pass'
            : 'partial';
    /* Modules in one surface usually share a reason ("no TLS endpoint was in
       scope"), so it is stated once rather than repeated per module. */
    const naReasons = Array.from(
      new Set(notApplicable.map((module) => module.reason || `${module.name} did not apply`)),
    );
    const notes = [
      broken.length ? `${broken.length} failed` : null,
      notApplicable.length ? `${notApplicable.length} not applicable (${naReasons.join('; ')})` : null,
      pending.length ? `${pending.length} never reported` : null,
    ].filter(Boolean);
    return {
      key: node,
      label: blueprint?.title ?? node,
      status,
      detail: owned.length === 0
        ? 'No module in this surface was published for this run.'
        : applicable === 0
          ? `No module in this surface applied to the submitted targets — ${naReasons.join('; ')}`
          : `${done.length}/${applicable} applicable modules reported${notes.length ? ` — ${notes.join(', ')}` : ''}.`,
    };
  }).concat(
    failed.length > 0
      ? [{
          key: 'errors',
          label: 'Module errors',
          status: 'fail' as const,
          detail: failed.map((module) => `${module.name}: ${module.error ?? module.reason ?? 'failed'}`).join(' · '),
        }]
      : [],
  ).concat(
    unreported.length > 0
      ? [{
          key: 'unreported',
          label: 'Unreported modules',
          status: 'partial' as const,
          detail: `${unreported.map((module) => module.name).join(', ')} produced no terminal state. Re-run the scan for full coverage.`,
        }]
      : [],
  );
}
