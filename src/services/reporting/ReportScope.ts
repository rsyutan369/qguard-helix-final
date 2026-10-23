import type { QuantumReadinessSnapshot } from '@/app/dashboard/quantum-readiness/_shared';
import {
  blendQuantumReadiness,
  estimateMigrationSchedule,
  levelFromReadiness,
  levelFromRisk,
  quantumRiskFrom,
  severityPressureFrom,
  severityWeight,
} from '@/lib/migration/asset-intelligence';
import { migrationCostUsd as migrationCostUsdFor } from '@/lib/migration/cost-model';
import { normalizeAssetKey } from './ReportEvidence';
import type { ReportScope } from './schemas/ReportSchema';

/**
 * ReportScope — asset-level report scoping for the Enterprise Reporting Engine™.
 *
 * `listSnapshotAssets` builds the deduplicated universe of assets present in a
 * QuantumReadinessSnapshot (top-risk assets ∪ exposure-graph nodes ∪ finding
 * locations, collapsed via `normalizeAssetKey`).
 *
 * `scopeSnapshotToAssets` produces a NEW snapshot restricted to a selected
 * asset subset. Asset-attributed evidence (findings, risk scores, posture,
 * internet exposure, dependency edges) is filtered directly; the aggregate
 * scores are then recomputed with the SAME formulas the assessment backend
 * uses (`src/api-server/quantum-readiness.ts`), so every downstream report
 * section — methodology tables, validation badge, waves, costs — reconciles
 * exactly for the selected scope. Tenant-level inventory that cannot be
 * attributed to individual assets (certificates, keys, cloud accounts, data
 * repositories) is allocated proportionally to the selected asset share; the
 * report scope section discloses this attribution method.
 *
 * The module is pure and isomorphic: it is used by the Report Center UI and
 * can be reused server-side by the reports API.
 */

export interface ScopeAssetOption {
  /** Normalised identity key (scheme/port/path/www/case stripped). */
  key: string;
  /** Display label — the richest name seen for this asset. */
  name: string;
  assetType: string;
  environment: string;
  owner: string;
  riskScore: number;
  posture: 'pqc' | 'hybrid' | 'vulnerable' | 'unknown';
  internetFacing: boolean;
  /** Collapsed critical/high finding rows attributed to this asset. */
  findingsCount: number;
  /** exposure-graph node ids that resolve to this asset (for edge filtering). */
  nodeIds: string[];
}

function clamp(value: number, min = 0, max = 100): number {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, value));
}


function postureFromStatus(status: string): ScopeAssetOption['posture'] {
  const s = (status || '').toLowerCase();
  if (s.includes('pqc')) return 'pqc';
  if (s.includes('vulnerable')) return 'vulnerable';
  if (s.includes('hybrid') || s.includes('progress')) return 'hybrid';
  return 'unknown';
}

// Domain/web-shaped assets count toward the scoped `domainsScanned` inventory —
// same heuristic family the backend uses for domain assets.
function isDomainish(option: ScopeAssetOption): boolean {
  if (/web|domain|tls|endpoint|site|host|gateway|cdn|proxy|load|dns|ingress|api/i.test(option.assetType)) return true;
  return /\.[a-z]{2,}$/i.test(option.key);
}

/**
 * Deduplicated asset universe present in the snapshot, sorted by risk score
 * (highest first) so the Report Center's first page shows the top-risk assets.
 */
export function listSnapshotAssets(snapshot: QuantumReadinessSnapshot): ScopeAssetOption[] {
  const registry = new Map<string, ScopeAssetOption>();
  const upsert = (name: string): ScopeAssetOption | null => {
    const key = normalizeAssetKey(name);
    if (!key) return null;
    let entry = registry.get(key);
    if (!entry) {
      entry = {
        key,
        name: name.trim(),
        assetType: 'asset',
        environment: 'unknown',
        owner: 'Unknown',
        riskScore: 0,
        posture: 'unknown',
        internetFacing: false,
        findingsCount: 0,
        nodeIds: [],
      };
      registry.set(key, entry);
    }
    return entry;
  };

  for (const node of snapshot.exposureGraph.nodes) {
    const entry = upsert(node.label);
    if (!entry) continue;
    entry.nodeIds.push(node.id);
    if (node.type) entry.assetType = node.type;
    if (node.environment && node.environment !== 'unknown') entry.environment = node.environment;
    entry.riskScore = Math.max(entry.riskScore, Math.round(node.riskScore || 0));
    if (node.posture === 'pqc' || node.posture === 'hybrid' || node.posture === 'vulnerable') entry.posture = node.posture;
    if (node.internetFacing) entry.internetFacing = true;
  }

  for (const asset of snapshot.topRiskAssets) {
    const entry = upsert(asset.asset);
    if (!entry) continue;
    if (asset.assetType && entry.assetType === 'asset') entry.assetType = asset.assetType;
    if (asset.environment && asset.environment !== 'unknown' && entry.environment === 'unknown') entry.environment = asset.environment;
    if (asset.owner && !/^(unassigned|unknown)$/i.test(asset.owner)) entry.owner = asset.owner;
    entry.riskScore = Math.max(entry.riskScore, Math.round(asset.riskScore || 0));
    if (entry.posture === 'unknown') entry.posture = postureFromStatus(asset.status);
  }

  for (const finding of snapshot.criticalFindings) {
    const entry = upsert(finding.asset);
    if (!entry) continue;
    entry.findingsCount += 1;
    if (finding.assetType && entry.assetType === 'asset') entry.assetType = finding.assetType;
    if (finding.environment && finding.environment !== 'unknown' && entry.environment === 'unknown') entry.environment = finding.environment;
    entry.riskScore = Math.max(entry.riskScore, severityWeight(finding.severity || ''));
    const sev = (finding.severity || '').toLowerCase();
    if (entry.posture === 'unknown' && (sev.includes('critical') || sev.includes('high'))) entry.posture = 'vulnerable';
  }

  return Array.from(registry.values()).sort((a, b) => b.riskScore - a.riskScore || a.name.localeCompare(b.name));
}

/** Normalise arbitrary asset names/keys into the canonical selection key set. */
export function toScopeKeySet(assetKeys: string[]): Set<string> {
  return new Set(assetKeys.map(normalizeAssetKey).filter(Boolean));
}

/**
 * Build the report-model scope block. `selectedKeys === null` ⇒ full scope.
 */
export function buildReportScope(snapshot: QuantumReadinessSnapshot, selectedKeys: string[] | null): ReportScope {
  const universe = listSnapshotAssets(snapshot);
  // `universe` is the top-risk asset DETAIL the snapshot carries (the backend
  // caps it for payload size). The tenant-wide asset count must come from the
  // inventory tally — a 4,800-asset estate must never print "full assessment
  // (140 assets)" just because the detail list is capped.
  const tenantAssetCount = Math.max(universe.length, snapshot.inventory?.assetsAssessed || 0);
  const keySet = selectedKeys ? toScopeKeySet(selectedKeys) : null;
  const selected = keySet ? universe.filter((a) => keySet.has(a.key)) : universe;
  const custom = keySet !== null && selected.length > 0 && selected.length < universe.length;
  return {
    type: custom ? 'custom' : 'full',
    selectedAssetCount: custom ? selected.length : tenantAssetCount,
    totalAssetCount: tenantAssetCount,
    assets: custom
      ? selected.map((a) => ({
          name: a.name,
          key: a.key,
          assetType: a.assetType,
          environment: a.environment,
          riskScore: a.riskScore,
          posture: a.posture,
        }))
      : [],
    note: custom
      ? `This report covers ${selected.length} of ${tenantAssetCount} discovered assets, selected by the report owner. All scores, findings, migration waves, timelines and costs are recomputed for the selected scope only.`
      : `This report covers the full assessment scope (${tenantAssetCount} discovered asset${tenantAssetCount === 1 ? '' : 's'}${universe.length < tenantAssetCount ? `; per-asset detail tables cover the top ${universe.length} assets by risk` : ''}).`,
    methodology: custom
      ? 'Asset-attributed evidence (findings, per-asset risk scores, cryptographic posture, internet exposure, dependency relationships) is filtered to the selected assets and all scores are recomputed with the platform scoring formulas. Tenant-level inventory that is not attributed to individual assets (certificates, keys, cloud accounts, data repositories) is allocated proportionally to the selected asset share.'
      : '',
  };
}

/**
 * Restrict a snapshot to the selected assets and recompute every aggregate
 * with the backend scoring formulas so the scoped report stays internally
 * consistent (methodology sums, validation badge, wave/cost reconciliation).
 * Returns the original snapshot when the selection is empty or covers the
 * whole universe.
 */
export function scopeSnapshotToAssets(snapshot: QuantumReadinessSnapshot, assetKeys: string[]): QuantumReadinessSnapshot {
  const universe = listSnapshotAssets(snapshot);
  const keySet = toScopeKeySet(assetKeys);
  const selected = universe.filter((a) => keySet.has(a.key));
  if (!selected.length || selected.length >= universe.length) return snapshot;

  const inv = snapshot.inventory;
  const selCount = selected.length;
  const tenantAssets = Math.max(inv.assetsAssessed, universe.length, 1);
  const ratio = Math.min(1, selCount / tenantAssets);

  // ---- Filter asset-attributed evidence ---------------------------------
  const criticalFindings = snapshot.criticalFindings.filter((f) => keySet.has(normalizeAssetKey(f.asset)));
  const topRiskAssets = snapshot.topRiskAssets.filter((a) => keySet.has(normalizeAssetKey(a.asset)));
  const nodes = snapshot.exposureGraph.nodes.filter((n) => keySet.has(normalizeAssetKey(n.label)));
  const keptNodeIds = new Set(nodes.map((n) => n.id));
  const edges = snapshot.exposureGraph.edges.filter((e) => keptNodeIds.has(e.source) && keptNodeIds.has(e.target));

  // ---- Asset-level tallies ----------------------------------------------
  const quantumVulnerableAssets = selected.filter((a) => a.posture === 'vulnerable').length;
  const pqcReadyAssets = selected.filter((a) => a.posture === 'pqc').length;
  const hybridAssets = selCount - quantumVulnerableAssets - pqcReadyAssets;
  const internetFacing = selected.filter((a) => a.internetFacing).length;

  // ---- Severity distribution --------------------------------------------
  // Critical/high counts come from asset-attributed finding evidence (per-
  // instance counts when the backend supplied them). Medium/low findings are
  // not asset-attributed in the snapshot, so they are allocated by asset share
  // — the scope section discloses the attribution method.
  let critical = 0;
  let high = 0;
  for (const f of criticalFindings) {
    const raw = (f as { instances?: unknown }).instances;
    const instances = Math.max(1, Math.round(Number(raw)) || 1);
    const sev = (f.severity || '').toLowerCase();
    if (sev.includes('critical')) critical += instances;
    else if (sev.includes('high')) high += instances;
  }
  critical = Math.min(critical, snapshot.riskDistribution.critical);
  high = Math.min(high, snapshot.riskDistribution.high);
  const medium = Math.round(snapshot.riskDistribution.medium * ratio);
  const low = Math.round(snapshot.riskDistribution.low * ratio);
  const totalFindings = critical + high + medium + low;

  // ---- CBOM component attribution ----------------------------------------
  const tenantVulnComps = inv.vulnerableComponents;
  const tenantPqcComps = inv.pqcReadyComponents;
  const tenantHybridComps = Math.max(0, inv.cryptoComponents - tenantVulnComps - tenantPqcComps);
  // Each collapsed finding row ≈ one vulnerable component on one asset; every
  // vulnerable asset carries at least one vulnerable component.
  const vulnerableComponents = Math.min(tenantVulnComps, Math.max(criticalFindings.length, quantumVulnerableAssets));
  const pqcReadyComponents = inv.pqcReadyAssets > 0
    ? Math.min(tenantPqcComps, Math.round(tenantPqcComps * (pqcReadyAssets / inv.pqcReadyAssets)))
    : Math.round(tenantPqcComps * ratio);
  const hybridComponents = Math.round(tenantHybridComps * ratio);
  const cryptoComponents = Math.max(1, vulnerableComponents + pqcReadyComponents + hybridComponents);
  const totalCrypto = cryptoComponents;

  // ---- Proportionally attributed tenant-level inventory -------------------
  const certificatesAnalyzed = Math.round(inv.certificatesAnalyzed * ratio);
  const keysDiscovered = Math.round(inv.keysDiscovered * ratio);
  const cloudAccounts = Math.round(inv.cloudAccounts * ratio);
  const dataRepositories = Math.round(inv.dataRepositories * ratio);
  const identitiesAnalyzed = Math.round(inv.identitiesAnalyzed * ratio);
  // Dependency edges among the selected assets are real relationship evidence;
  // fall back to the proportional share when the graph carries no edges.
  const trustRelationships = Math.max(edges.length, Math.round(inv.trustRelationships * ratio));
  const domainsScanned = Math.min(inv.domainsScanned, selected.filter(isDomainish).length);

  // ---- Scoring model — THE shared composites (asset-intelligence.ts) -------
  // This block used to be a hand-maintained copy of the backend formulas, and
  // it had drifted: it still summed components + assets into one migration
  // scope, priced it at a hardcoded rate instead of the tenant's assumptions,
  // and carried the constant governance term the engine no longer has.
  const severityPressure = severityPressureFrom({ critical, high, medium, low });
  const vulnerableShare = totalCrypto > 0 ? (vulnerableComponents / totalCrypto) * 100 : 0;
  const internetShare = selCount > 0 ? (internetFacing / selCount) * 100 : 0;
  const quantumRisk = quantumRiskFrom({ severityPressure, vulnerableSharePct: vulnerableShare, internetSharePct: internetShare });

  const pqcAdoption = totalCrypto > 0 ? ((pqcReadyComponents + hybridComponents * 0.5) / totalCrypto) * 100 : 0;
  const runtimeMeasured = snapshot.telemetry.runtimeEvents > 0;
  const quantumReadiness = blendQuantumReadiness({ pqcAdoption, quantumRisk, runtimeMeasured });

  // HNDL: the runtime/vault terms are tenant-level and not in the snapshot, so
  // recover them as the residual of the published tenant score, then re-blend
  // with the scoped vulnerable/internet shares (the tenant shares are published
  // in riskFactors, so the residual is reproducible from snapshot data alone).
  const tenantFactor = (needle: string) => snapshot.riskFactors.find((f) => f.label.toLowerCase().includes(needle))?.score ?? 0;
  const tenantVulnerableShare = tenantFactor('rsa');
  const tenantInternetShare = tenantFactor('internet');
  const hndlResidual = Math.max(0, snapshot.scores.hndlRisk - tenantVulnerableShare * 0.4 - tenantInternetShare * 0.15);
  const hndlRisk = Math.round(clamp(vulnerableShare * 0.4 + hndlResidual + internetShare * 0.15));

  const cryptoExposure = Math.round(clamp(vulnerableShare * 0.6 + internetShare * 0.4));

  const dependencyDepth = selCount > 0 ? clamp((trustRelationships / selCount) * 40) : 0;
  const footprint = clamp((selCount / 50) * 20 + (certificatesAnalyzed / 50) * 15 + (cloudAccounts / 5) * 15);
  const migrationComplexity = Math.round(clamp(dependencyDepth * 0.4 + footprint * 0.4 + vulnerableShare * 0.2));

  // Same units as the engine: migration scope is COMPONENTS (it used to add
  // assets in too), effort is the remaining share of quantum-relevant components.
  const migrationEffort = Math.round(clamp((vulnerableComponents / Math.max(1, totalCrypto)) * 100));
  const { parallelWorkstreams, migrationTimelineWeeks } = estimateMigrationSchedule({
    vulnerableComponents,
    vulnerableAssets: quantumVulnerableAssets,
    migrationComplexity,
    hasData: true,
  });
  const migrationCostUsd = migrationCostUsdFor(migrationTimelineWeeks, parallelWorkstreams, snapshot.costAssumptions);

  // ---- Factor breakdowns (same labels/order as the backend) ---------------
  // Factors measured over populations the snapshot does not attribute to
  // assets (key exchanges, certificate signatures, runtime events) are carried
  // from the tenant figure and SAY so in their basis — a proportional share
  // would invent a measurement. Component-share factors are recomputed.
  const tenantReadinessFactor = (needle: string) => snapshot.readinessFactors.find((f) => f.label.toLowerCase().includes(needle));
  const carried = (needle: string, label: string) => {
    const f = tenantReadinessFactor(needle);
    return f
      ? { label: f.label, score: f.score, measured: f.measured, basis: f.basis ? `${f.basis} (tenant-wide — not attributable to the selected assets)` : undefined }
      : { label, score: 0, measured: false, basis: 'Not measured for this scope' };
  };
  const readinessFactors: QuantumReadinessSnapshot['readinessFactors'] = [
    {
      label: 'PQC-Ready Components',
      score: Math.round(clamp(totalCrypto > 0 ? (pqcReadyComponents / totalCrypto) * 100 : 0)),
      measured: totalCrypto > 0,
      basis: `${pqcReadyComponents} of ${totalCrypto} attributed CBOM component(s) in the selected scope`,
    },
    {
      label: 'Hybrid Crypto Adoption',
      score: Math.round(clamp(totalCrypto > 0 ? (hybridComponents / totalCrypto) * 100 : 0)),
      measured: totalCrypto > 0,
      basis: `${hybridComponents} of ${totalCrypto} attributed CBOM component(s) in the selected scope`,
    },
    carried('tls', 'TLS / Key Exchange PQC Coverage'),
    carried('pki', 'PKI Quantum Readiness'),
    carried('agility', 'Crypto-Agility Readiness'),
    carried('governance', 'Governance Maturity'),
    carried('runtime', 'Runtime Visibility'),
  ];
  const riskFactors = [
    { label: 'RSA / ECC Exposure', score: Math.round(clamp(vulnerableShare)), severity: levelFromRisk(vulnerableShare) },
    { label: 'HNDL Exposure', score: hndlRisk, severity: levelFromRisk(hndlRisk) },
    { label: 'Internet-Facing Exposure', score: Math.round(clamp(internetShare)), severity: levelFromRisk(internetShare) },
    { label: 'Critical Asset Dependency', score: Math.round(clamp(dependencyDepth)), severity: levelFromRisk(dependencyDepth) },
    { label: 'Severity Pressure', score: Math.round(severityPressure), severity: levelFromRisk(severityPressure) },
  ];

  // ---- Recommended actions (same rules as the backend, scoped counts) -----
  const recommendedActions: QuantumReadinessSnapshot['recommendedActions'] = [];
  if (vulnerableComponents > 0) {
    recommendedActions.push({
      id: 'rec-vuln',
      // Same wording as the backend snapshot: the count is CBOM components.
      title: `Remediate ${vulnerableComponents} quantum-vulnerable CBOM component${vulnerableComponents === 1 ? '' : 's'}`,
      detail: 'Replace RSA/ECC primitives with ML-KEM / ML-DSA or hybrid equivalents.',
      severity: 'critical',
      route: '/dashboard/crypto-agility',
    });
  }
  if (quantumVulnerableAssets > 0) {
    recommendedActions.push({
      id: 'rec-assets',
      title: `Prioritise ${quantumVulnerableAssets} quantum-vulnerable asset${quantumVulnerableAssets === 1 ? '' : 's'}`,
      detail: 'Sequence these into the next migration wave via the AI Migration Advisor.',
      severity: 'high',
      route: '/dashboard/quantum-readiness/ai-migration-advisor',
    });
  }
  if (hndlRisk >= 40) {
    recommendedActions.push({
      id: 'rec-hndl',
      title: 'Mitigate Harvest-Now-Decrypt-Later exposure',
      detail: 'Re-encrypt long-lived sensitive data under PQC envelopes.',
      severity: 'high',
      route: '/dashboard/harvest-now',
    });
  }
  if (certificatesAnalyzed === 0) {
    recommendedActions.push({
      id: 'rec-pki',
      title: 'Connect PKI / certificate inventory',
      detail: 'Certificate evidence is required to score PKI maturity accurately.',
      severity: 'medium',
      route: '/dashboard/pki-visibility',
    });
  }

  return {
    ...snapshot,
    scores: {
      quantumReadiness,
      quantumReadinessLevel: levelFromReadiness(quantumReadiness),
      quantumRisk,
      quantumRiskLevel: levelFromRisk(quantumRisk),
      hndlRisk,
      hndlRiskLevel: levelFromRisk(hndlRisk),
      cryptoExposure,
      cryptoExposureLevel: levelFromRisk(cryptoExposure),
      migrationComplexity,
      migrationComplexityLevel: levelFromRisk(migrationComplexity),
      migrationEffort,
      pqcAdoption: Math.round(clamp(pqcAdoption)),
    },
    inventory: {
      assetsAssessed: selCount,
      certificatesAnalyzed,
      keysDiscovered,
      trustRelationships,
      domainsScanned,
      identitiesAnalyzed,
      cloudAccounts,
      dataRepositories,
      pqcReadyAssets,
      hybridAssets,
      quantumVulnerableAssets,
      cryptoComponents,
      vulnerableComponents,
      pqcReadyComponents,
    },
    riskDistribution: { critical, high, medium, low },
    readinessFactors,
    riskFactors,
    criticalFindings,
    recommendedActions,
    topRiskAssets,
    exposureGraph: { nodes, edges },
    estimates: { migrationTimelineWeeks, migrationCostUsd, parallelWorkstreams },
    telemetry: {
      ...snapshot.telemetry,
      certificates: certificatesAnalyzed,
      keys: keysDiscovered,
      assets: selCount,
    },
  };
}
