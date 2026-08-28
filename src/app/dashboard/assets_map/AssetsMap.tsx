import { Fragment, useMemo, useState } from 'react';
import { Search, Filter, Shield, AlertTriangle, ChevronRight, ChevronDown, Globe, Server, Loader2, RefreshCw, ExternalLink, Eye } from 'lucide-react';
import { motion } from 'framer-motion';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';
import { InventoryExportMenu } from '../_components/InventoryExportMenu';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { useMigrationWorkflow } from '@/hooks/use-migration-workflow';
import { useQuantumReadiness } from '@/app/dashboard/quantum-readiness/_shared';
import {
  DiscoveryPage,
  DiscoveryHeader,
  DiscoveryMetric,
  StaleAssessmentBanner,
  TruncationNote,
  panelClass,
  subtlePanelClass,
} from '../_components/discovery/shell';

type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

type CryptoInventoryItem = {
  id?: string;
  name?: string | null;
  item_type?: string | null;
  algorithm?: string | null;
  key_size?: number | string | null;
  protocol?: string | null;
  exposure_level?: string | null;
  is_vulnerable?: boolean;
  is_quantum_safe?: boolean;
  instances?: number;
  discovered_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
};

type AssetRecord = {
  id: string;
  name: string;
  type: string;
  domain: string;
  ipAddress: string | null;
  url: string | null;
  cryptography: string[];
  cryptoInventory: CryptoInventoryItem[];
  riskScore: number;
  qScore: number;
  riskLevel: string;
  complianceStatus: string;
  lastScanned: string;
  status: string;
  findingsCount: number;
  vulnerableCount: number;
  vulnerabilities?: CryptoInventoryItem[];
  metadata: Record<string, unknown>;
};

const riskLevels: RiskLevel[] = ['critical', 'high', 'medium', 'low'];

/* Discovery-suite surface — identical to CBOM Explorer. */
const GLASS_PANEL_CLASSES = panelClass;

function riskColor(score: number) {
  if (score >= 80) return 'text-red-600 dark:text-red-400';
  if (score >= 60) return 'text-orange-600 dark:text-orange-400';
  if (score >= 40) return 'text-amber-600 dark:text-yellow-400';
  return 'text-emerald-600 dark:text-green-400';
}

function riskBar(score: number) {
  if (score >= 80) return 'bg-red-500';
  if (score >= 60) return 'bg-orange-500';
  if (score >= 40) return 'bg-yellow-500';
  return 'bg-green-500';
}

function severityClasses(value?: string | null, vulnerable?: boolean) {
  const level = String(value || '').toLowerCase();
  if (level.includes('critical')) return 'border-red-500/35 bg-red-500/10 text-red-600 dark:border-red-400/45 dark:bg-red-500/12 dark:text-red-300';
  if (level.includes('high')) return 'border-orange-500/35 bg-orange-500/10 text-orange-600 dark:border-orange-400/45 dark:bg-orange-500/12 dark:text-orange-300';
  if (level.includes('medium') || vulnerable) return 'border-amber-500/35 bg-amber-500/10 text-amber-700 dark:border-yellow-400/45 dark:bg-yellow-500/12 dark:text-yellow-200';
  return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:border-emerald-400/35 dark:bg-emerald-500/10 dark:text-emerald-300';
}

function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function normalizeRiskLevel(value?: unknown): RiskLevel | null {
  const level = String(value || '').toLowerCase();
  if (level.includes('critical')) return 'critical';
  if (level.includes('high')) return 'high';
  if (level.includes('medium') || level.includes('moderate')) return 'medium';
  if (level.includes('low') || level.includes('safe')) return 'low';
  return null;
}

function riskRank(level: RiskLevel) {
  return { low: 1, medium: 2, high: 3, critical: 4 }[level];
}

function highestRiskLevel(levels: Array<RiskLevel | null | undefined>) {
  return levels.reduce<RiskLevel>((highest, level) => {
    if (!level) return highest;
    return riskRank(level) > riskRank(highest) ? level : highest;
  }, 'low');
}

function labelize(value?: string | null) {
  return String(value || 'Unknown')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function cryptoLabel(item: CryptoInventoryItem) {
  const algorithm = String(item.algorithm || item.name || 'Unknown cryptography');
  const baseLabel = item.key_size ? `${algorithm} (${item.key_size})` : algorithm;
  const instances = Number(item.instances || item.metadata?.instances || 0);
  return instances > 1 ? `${baseLabel} x${instances}` : baseLabel;
}

function metadataText(item: CryptoInventoryItem, key: string, fallback: string) {
  const value = item.metadata?.[key];
  return typeof value === 'string' && value.trim() ? value : fallback;
}

function assetTarget(asset: AssetRecord) {
  return asset.url || asset.domain || asset.ipAddress || 'N/A';
}

function itemSeverityRank(item: CryptoInventoryItem) {
  const text = String(item.exposure_level || item.metadata?.severity || item.metadata?.threatLevel || '').toLowerCase();
  if (text.includes('critical')) return 5;
  if (text.includes('high')) return 4;
  if (text.includes('moderate') || text.includes('medium')) return 3;
  if (text.includes('low')) return 2;
  if (text.includes('safe')) return 0;
  return item.is_vulnerable ? 3 : 1;
}

function itemTimestamp(item: CryptoInventoryItem) {
  return Date.parse(String(item.updated_at || item.discovered_at || item.created_at || item.metadata?.detectedAt || item.metadata?.timestamp || '')) || 0;
}

function vulnerabilityKey(item: CryptoInventoryItem) {
  return [
    item.item_type || item.metadata?.category,
    item.algorithm || item.metadata?.algorithm || item.name,
    item.key_size || item.metadata?.keySize,
    item.protocol || item.metadata?.protocol,
  ].map((value) => String(value || '').trim().toLowerCase()).join(':');
}

function mergeVulnerabilityItems(items: CryptoInventoryItem[]) {
  const grouped = new Map<string, CryptoInventoryItem>();

  for (const item of items) {
    const key = vulnerabilityKey(item);
    const existing = grouped.get(key);
    if (!existing) {
      grouped.set(key, item);
      continue;
    }

    const shouldReplace = itemSeverityRank(item) > itemSeverityRank(existing) ||
      (itemSeverityRank(item) === itemSeverityRank(existing) && itemTimestamp(item) > itemTimestamp(existing));
    grouped.set(key, {
      ...(shouldReplace ? item : existing),
      instances: Number(existing.instances || 1) + Number(item.instances || 1),
      metadata: {
        ...(existing.metadata || {}),
        ...(item.metadata || {}),
      },
    });
  }

  return Array.from(grouped.values()).sort((a, b) => {
    const severityDelta = itemSeverityRank(b) - itemSeverityRank(a);
    if (severityDelta) return severityDelta;
    return itemTimestamp(b) - itemTimestamp(a);
  });
}

// Vulnerable CRYPTO COMPONENTS for an asset — counted the same way the CBOM
// Explorer and the Quantum Readiness & Assessment Engine count them
// (is_vulnerable && !is_quantum_safe on the grouped crypto inventory). This is
// the single, platform-consistent unit of "vulnerability". The raw finding rows
// (per-rule / per-cipher detections that previously inflated the headline to
// numbers like 113) are preserved as "detection signals" and folded into their
// parent component via signalsForComponent — evidence without double-counting.
function vulnerableComponents(asset: AssetRecord) {
  const inventory = Array.isArray(asset.cryptoInventory)
    ? asset.cryptoInventory.filter((item) => Boolean(item.is_vulnerable && !item.is_quantum_safe))
    : [];
  // `cryptoInventory` arrives ALREADY grouped, and the backend's
  // `asset.vulnerableCount` — which the tenant-wide headline sums — is exactly
  // this filter over that grouping. Re-merging here (on a narrower key that
  // drops the component name) would silently collapse rows the backend counted
  // separately, so the per-row count and the headline would drift apart.
  if (inventory.length > 0) {
    return [...inventory].sort((a, b) => itemSeverityRank(b) - itemSeverityRank(a) || itemTimestamp(b) - itemTimestamp(a));
  }
  // Tenants whose scans produced only finding-level rows (no grouped inventory)
  // still get a real, component-granular count by merging those raw findings.
  const explicit = Array.isArray(asset.vulnerabilities) ? asset.vulnerabilities : [];
  return mergeVulnerabilityItems(explicit);
}

// Raw detection signals (rule / cipher-suite level findings) that back the
// vulnerable components — surfaced as premium context ("N detection signals
// across M components"), never as the headline vulnerability count.
function detectionSignals(asset: AssetRecord) {
  return Array.isArray(asset.vulnerabilities) ? asset.vulnerabilities : [];
}

// Detection signals that map to a specific vulnerable component (same dedupe key
// the backend groups by) — used to show the underlying evidence in the detail
// card without re-expanding the count.
function signalsForComponent(asset: AssetRecord, component: CryptoInventoryItem) {
  const key = vulnerabilityKey(component);
  return detectionSignals(asset).filter((signal) => vulnerabilityKey(signal) === key);
}

// Per-asset severity distribution over the vulnerable COMPONENTS (drives the
// premium severity chips and matches the exposure taxonomy the QR Engine uses).
function componentSeverityCounts(components: CryptoInventoryItem[]) {
  const counts: Record<RiskLevel, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of components) {
    const level =
      normalizeRiskLevel(item.exposure_level) ||
      normalizeRiskLevel(item.metadata?.severity) ||
      normalizeRiskLevel(item.metadata?.threatLevel) ||
      'medium';
    counts[level] += 1;
  }
  return counts;
}

function remediationRouteFor(item: CryptoInventoryItem) {
  const text = [
    item.item_type,
    item.protocol,
    item.algorithm,
    item.name,
    item.metadata?.source,
    item.metadata?.description,
    item.metadata?.evidence,
  ].map((value) => String(value || '').toLowerCase()).join(' ');

  if (/hndl|harvest|runtime|shadow|downgrade/.test(text)) return '/dashboard/live-migration';
  if (/certificate|pki|x509|issuer|subject/.test(text)) return '/dashboard/certificate-telemetry';
  if (/tls|ssl|protocol|cipher|handshake|dhe|ecdhe/.test(text)) return '/dashboard/quantum-readiness/remediation';
  if (/library|dependency|package|source|repo|github|client crypto/.test(text)) return '/dashboard/migration-planner';
  if (/policy|compliance|regulatory|nist/.test(text)) return '/dashboard/quantum-governance';
  return '/dashboard/pqc-orchestration';
}

function remediationHref(asset: AssetRecord, item: CryptoInventoryItem) {
  const params = new URLSearchParams({
    source: 'assets',
    action: 'remediate',
    assetId: asset.id,
    asset: asset.name,
    findingId: String(item.metadata?.scanResultId || item.metadata?.vulnerabilityId || item.metadata?.exposureId || item.id || ''),
    algorithm: String(item.algorithm || item.name || 'unknown'),
    severity: labelize(String(item.exposure_level || item.metadata?.severity || 'vulnerable')),
  });

  return `${remediationRouteFor(item)}?${params.toString()}`;
}

/**
 * The asset's risk band — a PROJECTION of its risk score, not a second opinion.
 *
 * This used to be the worst severity found across the asset's components, taken
 * as the max against the score band. That is a different aggregation of the same
 * evidence, and the two disagreed on screen: an asset scoring 23/100 (rendered
 * in green, band "Low") was filtered and badged as CRITICAL because one of its
 * 23 components carried a critical exposure level. A displayed band and the
 * number it sits beside must come from ONE derivation of ONE input.
 *
 * The worst component severity is still real and still shown — as its own
 * labelled figure (`worstComponentSeverity`), never as the asset's band.
 */
function assetRiskLevel(asset: AssetRecord): RiskLevel {
  return normalizeRiskLevel(asset.riskLevel) || riskLevelFromScore(Number(asset.riskScore || 0));
}

/** Highest exposure level recorded on any of the asset's components. */
function worstComponentSeverity(asset: AssetRecord): RiskLevel | null {
  const inventory = Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory : [];
  const levels = inventory.map((item) => (
    normalizeRiskLevel(item.exposure_level) ||
    normalizeRiskLevel(item.metadata?.severity) ||
    normalizeRiskLevel(item.metadata?.threatLevel) ||
    normalizeRiskLevel(item.metadata?.riskSeverity) ||
    (item.is_vulnerable ? ('medium' as RiskLevel) : null)
  )).filter(Boolean) as RiskLevel[];
  return levels.length === 0 ? null : highestRiskLevel(levels);
}

function formatDate(value: string) {
  if (!value) return 'N/A';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function typeIcon(type: string) {
  const lower = type.toLowerCase();
  if (lower.includes('api') || lower.includes('web') || lower.includes('tls')) return Globe;
  if (lower.includes('ssh')) return ChevronRight;
  return Server;
}

export default function AssetsMap() {
  const { data, loading, error, connected, refresh } = useScannerIntelligence();
  const assets = (data.assets.assets || []) as AssetRecord[];
  // Canonical tenant-wide figures straight from the shared scanner-intelligence
  // snapshot — the SAME numbers the CBOM Explorer and the Quantum Readiness &
  // Assessment Engine render. The Assets page reconciles against these so its
  // headline never disagrees with the rest of the platform.
  const summary = data.summary;
  const severityCounts = data.severityCounts;
  // The header claimed "Reconciled with Quantum Readiness Engine" without ever
  // reading it, and labelled the component PQC-ready share "Quantum Readiness" —
  // the name the QR Engine's composite score carries on every other page, with a
  // different value. The QR snapshot is now actually read, so the two figures
  // appear side by side under their own names instead of one borrowing the
  // other's label.
  const qr = useQuantumReadiness();
  const qrHasData = qr.snapshot.hasData;
  const qrResolved = qr.state === 'success';
  // Findings graded on the severity ladder. `totalFindings` also counts SAFE
  // observations, so quoting it above a bar chart of critical/high/medium/low
  // showed a total the bars could never add up to.
  const gradedFindings = severityCounts.critical + severityCounts.high + severityCounts.medium + severityCounts.low;
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | null>(null);
  const [expandedAssetId, setExpandedAssetId] = useState<string | null>(null);
  const [expandedCryptoAssetIds, setExpandedCryptoAssetIds] = useState<Set<string>>(() => new Set());
  const [selectedAssetIds, setSelectedAssetIds] = useState<Set<string>>(() => new Set());

  // Per-asset lifecycle position from the platform workflow engine (same
  // source of truth the WorkflowRail renders) — merged by asset name.
  const { workflow } = useMigrationWorkflow();
  const lifecycleByAsset = useMemo(() => {
    const map = new Map<string, NonNullable<typeof workflow>['assetStates'][number]>();
    for (const state of workflow?.assetStates || []) map.set(state.asset.toLowerCase(), state);
    return map;
  }, [workflow]);

  const filteredAssets = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();
    return assets.filter((asset) => {
      if (query) {
        const values = [
          asset.name,
          asset.type,
          asset.domain,
          asset.ipAddress,
          asset.url,
          asset.complianceStatus,
          assetRiskLevel(asset),
          ...asset.cryptography,
          ...(Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory.flatMap((item) => [
            cryptoLabel(item),
            item.exposure_level,
            metadataText(item, 'evidence', ''),
            metadataText(item, 'recommendation', ''),
          ]) : []),
        ];
        if (!values.some((value) => String(value || '').toLowerCase().includes(query))) return false;
      }
      if (riskFilter && assetRiskLevel(asset) !== riskFilter) return false;
      return true;
    });
  }, [assets, riskFilter, searchQuery]);

  const riskSummary = useMemo(() => riskLevels.reduce<Record<RiskLevel, number>>((summary, level) => {
    summary[level] = assets.filter((asset) => assetRiskLevel(asset) === level).length;
    return summary;
  }, { critical: 0, high: 0, medium: 0, low: 0 }), [assets]);

  const selectedAssets = useMemo(() => assets.filter((asset) => selectedAssetIds.has(asset.id)), [assets, selectedAssetIds]);
  const exportAssets = selectedAssets.length > 0 ? selectedAssets : filteredAssets;
  const allVisibleSelected = filteredAssets.length > 0 && filteredAssets.every((asset) => selectedAssetIds.has(asset.id));

  const toggleAssetSelection = (assetId: string) => {
    setSelectedAssetIds((current) => {
      const next = new Set(current);
      if (next.has(assetId)) next.delete(assetId);
      else next.add(assetId);
      return next;
    });
  };

  const toggleVisibleSelection = () => {
    setSelectedAssetIds((current) => {
      const next = new Set(current);
      if (allVisibleSelected) {
        filteredAssets.forEach((asset) => next.delete(asset.id));
      } else {
        filteredAssets.forEach((asset) => next.add(asset.id));
      }
      return next;
    });
  };

  const toggleCryptoExpansion = (assetId: string) => {
    setExpandedCryptoAssetIds((current) => {
      const next = new Set(current);
      if (next.has(assetId)) next.delete(assetId);
      else next.add(assetId);
      return next;
    });
  };

  return (
    <DiscoveryPage>
      <WorkflowRail activeStage="discovery" tone="adaptive" />
      <DiscoveryHeader
        title="Asset Inventory"
        subtitle="Authorized cryptographic assets discovered from real scanner results."
        connected={connected}
        measuredAt={data.generatedAt || null}
        actions={
          <>
        {/* The QR reconciliation state is kept EXACTLY as it was — it is the
            page's own accuracy contract, and it states divergence rather than
            hiding it. Only the surrounding chrome changed. */}
        <span className="hidden" />
          <InventoryExportMenu
            label={`Export ${selectedAssets.length > 0 ? `${selectedAssets.length} selected` : `${filteredAssets.length} shown`}`}
            disabled={exportAssets.length === 0}
            build={() => {
              // The CBOM rows carried BY the exported assets, so an asset export
              // is auditable down to the component without pulling the estate.
              const exportedIds = new Set(exportAssets.map((asset) => String(asset.id)));
              const scopedCbom = (data.cbom?.entries ?? []).filter((entry: { sourceAssetId?: unknown; sourceAsset?: unknown }) =>
                exportedIds.has(String(entry.sourceAssetId ?? '')) ||
                exportAssets.some((asset) => String(asset.name) === String(entry.sourceAsset ?? '')),
              );
              const filtered = exportAssets.length !== assets.length;
              return {
                kind: 'assets' as const,
                summary: {
                  totalAssets: data.summary.totalAssets,
                  totalComponents: data.summary.totalComponents,
                  vulnerableAssets: data.summary.vulnerableAssets,
                  vulnerableComponents: data.summary.vulnerableComponents,
                  pqcReadyComponents: data.summary.pqcReadyComponents,
                  criticalFindings: data.summary.criticalFindings,
                  totalFindings: data.summary.totalFindings,
                  riskScore: data.summary.riskScore,
                  qScore: data.summary.qScore,
                },
                assets: exportAssets,
                cbom: scopedCbom,
                totalAssetsBeforeFilter: assets.length,
                totalCbomBeforeFilter: data.cbom?.entries?.length ?? 0,
                generatedAt: new Date().toISOString(),
                lastScanAt: data.generatedAt || null,
                filtered,
                filterDescription: selectedAssets.length > 0 ? 'user selection' : searchQuery ? `search "${searchQuery}"` : 'active filters',
              };
            }}
          />
          <button
            type="button"
            onClick={refresh}
            className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-4 py-2 text-xs font-bold text-[var(--qg-dashboard-text-soft)] transition hover:border-[var(--qg-amber)]/45"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
          </>
        }
      />

      {/* Reconciliation state against the Quantum Readiness Engine. Preserved
          verbatim: it reports "Diverged" when the two disagree instead of
          quietly showing one of the two numbers. */}
      <div className="flex flex-wrap items-center gap-2 text-[10px] font-black uppercase tracking-widest">
        {(() => {
          const inSync = qrHasData &&
            Number(qr.snapshot.inventory.cryptoComponents) === Number(summary.totalComponents) &&
            Number(qr.snapshot.inventory.vulnerableComponents) === Number(summary.vulnerableComponents);
          const label = !qrResolved ? 'Awaiting Quantum Readiness Engine'
            : !qrHasData ? 'No QR assessment evidence'
              : inSync ? 'Reconciled with Quantum Readiness Engine'
                : 'Diverged from Quantum Readiness Engine';
          const tone = inSync ? 'border-[var(--qg-cyan)]/25 bg-[var(--qg-cyan)]/10 text-[var(--qg-cyan)]'
            : qrHasData ? 'border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]'
              : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]';
          return (
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${tone}`}
              title={qrHasData ? `QR Engine: ${qr.snapshot.inventory.cryptoComponents} components · ${qr.snapshot.inventory.vulnerableComponents} vulnerable` : undefined}
            >
              <Shield className="h-3 w-3" /> {label}
            </span>
          );
        })()}
      </div>

      <StaleAssessmentBanner measuredAt={data.generatedAt || null} />

      {error && <div className="rounded-md border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-600 dark:text-red-300">{error}</div>}

      <div className="flex flex-col lg:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--qg-text-muted)]" />
          <input
            type="text"
            placeholder="Search assets, algorithms, domains, IP addresses..."
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            className="w-full rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] py-2.5 pl-10 pr-4 text-sm text-[var(--qg-dashboard-text)] outline-none transition placeholder:text-[var(--qg-text-muted)] focus:border-[var(--qg-amber)]/50 dark:border-[var(--qg-amber)]/25  dark:text-white dark:placeholder:text-white/25"
          />
        </div>
        <div className="flex gap-2 flex-wrap text-[var(--qg-amber)]">
          {riskLevels.map((level) => (
            <button key={level} onClick={() => setRiskFilter(riskFilter === level ? null : level)} className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-[10px] font-black uppercase tracking-widest transition-colors ${riskFilter === level ? 'border-[var(--qg-amber)]/60 bg-[var(--qg-amber)]/15 text-[var(--qg-amber)]' : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-dashboard-text-soft)] hover:border-[var(--qg-amber)]/40 hover:text-[var(--qg-dashboard-text)]   text-[var(--qg-text-muted)] dark:hover:text-white/70'}`}>
              <Filter className="h-3.5 w-3.5" /> {level} <span className="font-mono text-[var(--qg-text-muted)]">{riskSummary[level]}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          {
            label: 'Authorized Assets',
            value: summary.totalAssets || assets.length,
            sub: `${summary.vulnerableAssets} with vulnerable crypto`,
            tone: 'cyan' as const,
            icon: Server,
          },
          {
            label: 'Quantum-Vulnerable Components',
            value: summary.vulnerableComponents,
            sub: 'Matches QR Engine & CBOM',
            tone: 'red' as const,
            icon: AlertTriangle,
          },
          {
            label: 'Cryptographic Components',
            value: summary.totalComponents,
            sub: `${summary.pqcReadyComponents} PQC-ready`,
            tone: 'amber' as const,
            icon: Shield,
          },
          {
            label: 'Quantum Readiness (QR Engine)',
            value: qrHasData ? `${qr.snapshot.scores.quantumReadiness}/100` : '—',
            sub: qrHasData
              ? `${qr.snapshot.scores.quantumReadinessLevel} · risk ${qr.snapshot.scores.quantumRisk}/100`
              : qrResolved ? 'No assessment evidence yet' : 'Awaiting assessment',
            tone: qrHasData ? ('green' as const) : ('muted' as const),
            icon: Shield,
          },
        ].map((item) => (
          <DiscoveryMetric
            key={item.label}
            label={item.label}
            value={item.value}
            detail={item.sub}
            icon={item.icon}
            tone={item.tone}
          />
        ))}
      </div>

      {/* Platform Posture — canonical tenant-wide crypto posture straight from the
          shared scanner-intelligence snapshot. These are the exact figures the
          Quantum Readiness & Assessment Engine renders, so the Assets page can be
          reconciled against QR at a glance. */}
      <div className={GLASS_PANEL_CLASSES + ' p-5'}>
        <div className="relative z-10 grid gap-6 lg:grid-cols-[1.1fr_1.3fr_1.3fr]">
          <div>
            <div className="text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">PQC Component Coverage</div>
            <div className="mt-2 flex items-end gap-2">
              <span className="text-4xl font-black text-emerald-600 dark:text-green-400">{summary.pqcReadiness}%</span>
              <span className="mb-1 text-[10px] font-mono text-[var(--qg-text-muted)]">of {summary.totalComponents} components</span>
            </div>
            <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-[var(--qg-muted-panel)] dark:bg-white/10">
              <div className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-green-400" style={{ width: `${Math.min(100, summary.pqcReadiness)}%` }} />
            </div>
            <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-[var(--qg-text-muted)]">
              <span>{summary.pqcReadyComponents} PQC-ready</span>
              <span className="text-red-600 dark:text-red-400">{summary.vulnerableComponents} vulnerable</span>
            </div>
          </div>

          <div>
            <div className="text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Risk Posture</div>
            <div className="mt-3 grid grid-cols-2 gap-3">
              {[
                { label: 'Risk Score', value: `${summary.riskScore}/100`, color: riskColor(summary.riskScore) },
                { label: 'Q-Score', value: `${summary.qScore}/100`, color: 'text-cyan-600 dark:text-cyan-300' },
                { label: 'Vulnerable Assets', value: `${summary.vulnerableAssets}/${summary.totalAssets || assets.length}`, color: 'text-red-600 dark:text-red-400' },
                { label: 'Critical Findings', value: summary.criticalFindings, color: 'text-orange-600 dark:text-orange-400' },
              ].map((metric) => (
                <div key={metric.label} className="rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-3 dark:border-white/8 dark:bg-white/[0.02]">
                  <div className="text-[9px] font-black uppercase tracking-widest text-[var(--qg-text-muted)]">{metric.label}</div>
                  <div className={`mt-1 text-lg font-black ${metric.color}`}>{metric.value}</div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between">
              <div className="text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Finding Severity</div>
              <span
                className="text-[10px] font-mono text-[var(--qg-text-muted)]"
                title={`${summary.totalFindings} de-duplicated findings in total, ${severityCounts.safe} graded Safe`}
              >
                {gradedFindings} graded
              </span>
            </div>
            <div className="mt-3 space-y-2">
              {([
                ['critical', 'Critical', 'bg-red-500', 'text-red-600 dark:text-red-400'],
                ['high', 'High', 'bg-orange-500', 'text-orange-600 dark:text-orange-400'],
                ['medium', 'Medium', 'bg-amber-500', 'text-amber-600 dark:text-yellow-400'],
                ['low', 'Low', 'bg-emerald-500', 'text-emerald-600 dark:text-green-400'],
              ] as const).map(([key, label, bar, text]) => {
                const count = severityCounts[key] || 0;
                const max = Math.max(1, severityCounts.critical + severityCounts.high + severityCounts.medium + severityCounts.low);
                return (
                  <div key={key} className="flex items-center gap-3">
                    <span className="w-14 shrink-0 text-[10px] font-black uppercase tracking-widest text-[var(--qg-text-muted)]">{label}</span>
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-[var(--qg-muted-panel)] dark:bg-white/10">
                      <div className={`h-full rounded-full ${bar}`} style={{ width: `${(count / max) * 100}%` }} />
                    </div>
                    <span className={`w-7 shrink-0 text-right text-[11px] font-black ${text}`}>{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      <div className={GLASS_PANEL_CLASSES}>
        <div className="overflow-x-auto relative z-10 p-3">
          <table className="w-full min-w-[1040px] border-separate border-spacing-y-2 text-left">
            <thead>
              <tr>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text-soft)]">
                  <div className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={allVisibleSelected}
                      onChange={toggleVisibleSelection}
                      disabled={filteredAssets.length === 0}
                      aria-label="Select all visible assets"
                      className="h-4 w-4 rounded border-[var(--qg-card-border)] bg-white accent-[#FFD36B] dark:border-[var(--qg-amber)]/35 dark:bg-[#050816]"
                    />
                    Asset Name
                  </div>
                </th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text-soft)]">Type</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text-soft)]">Domain / URL / IP</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text-soft)]">Findings</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text-soft)]">Risk Score</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text-soft)]">Compliance</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text-soft)]">Lifecycle</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text-soft)]">Last Scanned</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text-soft)]">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={9} className="p-12 text-center text-[var(--qg-amber)]/50 font-black uppercase tracking-widest">
                    <Loader2 className="h-5 w-5 animate-spin inline mr-2" /> Loading Asset Inventory
                  </td>
                </tr>
              ) : assets.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-14 text-center">
                    <div className="mb-4 text-xs font-black uppercase tracking-widest text-[var(--qg-text-muted)]">
                      No authorized assets scanned yet. Start a scan to build your cryptographic asset inventory.
                    </div>
                    <a href="/dashboard/scanner" className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)] text-[10px] font-black uppercase tracking-wider">
                      <ExternalLink className="h-3.5 w-3.5" /> Start Authorized Scan
                    </a>
                  </td>
                </tr>
              ) : filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-12 text-center uppercase tracking-widest text-[var(--qg-text-muted)]">No assets match the current search or filter.</td>
                </tr>
              ) : filteredAssets.map((asset) => {
                const Icon = typeIcon(asset.type);
                const cryptoInventory = Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory : [];
                // Component-level count (aligned with QR/CBOM); the raw finding
                // rows become supporting "detection signals".
                const vulnerable = vulnerableComponents(asset);
                const signalCount = detectionSignals(asset).length;
                const severity = componentSeverityCounts(vulnerable);
                const pqcReadyCount = cryptoInventory.filter((item) => Boolean(item.is_quantum_safe)).length;
                const isExpanded = expandedAssetId === asset.id;
                const cryptoListExpanded = expandedCryptoAssetIds.has(asset.id);
                const visibleCryptoInventory = cryptoListExpanded ? cryptoInventory : cryptoInventory.slice(0, 18);
                const hiddenCryptoCount = Math.max(0, cryptoInventory.length - 18);
                return (
                  <Fragment key={asset.id}>
                    <motion.tr
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      onClick={() => setExpandedAssetId(isExpanded ? null : asset.id)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          setExpandedAssetId(isExpanded ? null : asset.id);
                        }
                      }}
                      tabIndex={0}
                      aria-expanded={isExpanded}
                      className={`group cursor-pointer rounded-xl bg-white/82 outline-none transition-all hover:bg-cyan-50/90 focus-visible:ring-2 focus-visible:ring-gold/50 dark:bg-[#080d1c]/72 dark:hover:bg-[#111934]/86 ${isExpanded ? 'bg-cyan-50/95 shadow-[0_0_0_1px_rgba(0,197,235,0.24),0_18px_45px_rgba(15,23,42,0.12)] dark:bg-[#111934]/90 dark:shadow-[0_0_0_1px_rgba(255,211,107,0.20),0_18px_50px_rgba(0,0,0,0.28)]' : ''}`}
                    >
                      <td className="rounded-l-xl border-y border-l border-[var(--qg-card-border)] p-4 dark:border-white/8">
                        <div className="flex items-center gap-3">
                          <input
                            type="checkbox"
                            checked={selectedAssetIds.has(asset.id)}
                            onClick={(event) => event.stopPropagation()}
                            onChange={() => toggleAssetSelection(asset.id)}
                            aria-label={`Select ${asset.name} for export`}
                            className="h-4 w-4 shrink-0 rounded border-[var(--qg-card-border)] bg-white accent-[#FFD36B] dark:border-[var(--qg-amber)]/35 dark:bg-[#050816]"
                          />
                          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-[var(--qg-amber)]/25 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)] shadow-[0_0_20px_rgba(255,211,107,0.10)]">
                            <Icon className="h-4 w-4" />
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <div className="truncate text-sm font-black text-[var(--qg-dashboard-text)] transition-colors group-hover:text-[var(--qg-amber)] dark:text-white">{asset.name}</div>
                              <ChevronDown className={`h-3.5 w-3.5 shrink-0 text-[var(--qg-amber)]/70 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                            </div>
                            <div className="mt-1 flex items-center gap-2 text-[10px] font-mono text-[var(--qg-text-muted)]">
                              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/80" />
                              {asset.status || 'active'}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="border-y border-[var(--qg-card-border)] p-4 dark:border-white/8">
                        <span className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-2 py-1 text-[10px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)]   dark:text-white/62">
                          {labelize(asset.type)}
                        </span>
                      </td>
                      <td className="border-y border-[var(--qg-card-border)] p-4 text-xs font-mono text-[var(--qg-dashboard-text-soft)] dark:border-white/8 dark:text-white/50">
                        <div className="max-w-[260px] truncate">{assetTarget(asset)}</div>
                      </td>
                      <td className="border-y border-[var(--qg-card-border)] p-4 dark:border-white/8">
                        <div className="flex items-center gap-3">
                          <span className={`inline-flex min-w-10 justify-center rounded-md border px-2 py-1 text-[10px] font-black ${vulnerable.length ? 'border-red-500/30 bg-red-500/10 text-red-600 dark:border-red-400/35 dark:text-red-300' : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:border-emerald-400/30 dark:text-emerald-300'}`}>
                            {vulnerable.length}
                          </span>
                          <div className="min-w-0">
                            <div className="text-[10px] font-black uppercase tracking-widest text-[var(--qg-dashboard-text-soft)] dark:text-white/58">
                              vulnerable of {cryptoInventory.length}
                            </div>
                            <div className="mt-1 truncate text-[10px] font-mono text-[var(--qg-text-muted)]" title="Raw detection rows backing these components, before de-duplication">
                              {signalCount > 0
                                ? `${signalCount} raw detection row${signalCount === 1 ? '' : 's'}`
                                : `${cryptoInventory.length} observed component${cryptoInventory.length === 1 ? '' : 's'}`}
                            </div>
                            {vulnerable.length > 0 && (
                              <div className="mt-1.5 flex flex-wrap gap-1">
                                {([
                                  ['critical', 'C', 'bg-red-500/15 text-red-600 dark:text-red-300 border-red-500/25'],
                                  ['high', 'H', 'bg-orange-500/15 text-orange-600 dark:text-orange-300 border-orange-500/25'],
                                  ['medium', 'M', 'bg-amber-500/15 text-amber-600 dark:text-yellow-200 border-amber-500/25'],
                                  ['low', 'L', 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-300 border-emerald-500/25'],
                                ] as const).filter(([key]) => severity[key] > 0).map(([key, glyph, cls]) => (
                                  <span key={key} className={`rounded border px-1.5 py-0.5 text-[9px] font-black ${cls}`} title={`${severity[key]} ${key}`}>
                                    {glyph} {severity[key]}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="border-y border-[var(--qg-card-border)] p-4 dark:border-white/8">
                        <div className="flex items-center gap-2">
                          <div className={`text-xs font-black ${riskColor(asset.riskScore)}`}>{asset.riskScore}/100</div>
                          <div className="h-1.5 w-20 overflow-hidden rounded-full bg-[var(--qg-muted-panel)] dark:bg-white/10">
                            <div className={`h-full ${riskBar(asset.riskScore)}`} style={{ width: `${asset.riskScore}%` }} />
                          </div>
                        </div>
                        <div className="mt-1 text-[9px] text-[var(--qg-text-muted)]">Q-Score {asset.qScore}/100</div>
                      </td>
                      <td className="border-y border-[var(--qg-card-border)] p-4 dark:border-white/8">
                        <span className={`rounded-md border px-2 py-1 text-[9px] font-black uppercase tracking-widest ${vulnerable.length > 0 ? 'border-red-500/25 bg-red-500/8 text-red-600 dark:border-red-400/25 dark:text-red-300' : 'border-emerald-500/25 bg-emerald-500/8 text-emerald-600 dark:border-emerald-400/25 dark:text-emerald-300'}`}>
                          {asset.complianceStatus}
                        </span>
                      </td>
                      <td className="border-y border-[var(--qg-card-border)] p-4 dark:border-white/8">
                        {(() => {
                          const lifecycle = lifecycleByAsset.get(String(asset.name || '').toLowerCase());
                          if (!lifecycle) return <span className="text-[10px] text-[var(--qg-text-muted)]">—</span>;
                          const stageTone =
                            lifecycle.stageId === 'monitoring'
                              ? 'border-emerald-500/25 bg-emerald-500/8 text-emerald-600 dark:border-emerald-400/25 dark:text-emerald-300'
                              : lifecycle.stageId === 'execution'
                                ? 'border-cyan-500/25 bg-cyan-500/8 text-cyan-600 dark:border-cyan-400/25 dark:text-cyan-300'
                                : lifecycle.stageId === 'validation'
                                  ? 'border-blue-500/25 bg-blue-500/8 text-blue-600 dark:border-blue-400/25 dark:text-blue-300'
                                  : 'border-amber-500/25 bg-amber-500/8 text-amber-600 dark:border-amber-400/25 dark:text-amber-300';
                          return (
                            <div className="space-y-1">
                              <span className={`inline-block rounded-md border px-2 py-0.5 text-[9px] font-black uppercase tracking-widest ${stageTone}`}>
                                {lifecycle.stageId === 'monitoring' ? 'Monitored' : lifecycle.stageId === 'execution' ? 'Migrating' : lifecycle.stageId === 'validation' ? 'Validating' : 'Remediation'}
                              </span>
                              <div className="text-[9px] text-[var(--qg-text-muted)]">
                                {lifecycle.openActions > 0 ? `${lifecycle.openActions} action${lifecycle.openActions === 1 ? '' : 's'}` : lifecycle.validationStatus}
                                {lifecycle.certificationImpactPct > 0 ? ` · +${lifecycle.certificationImpactPct}% cert` : ''}
                              </div>
                            </div>
                          );
                        })()}
                      </td>
                      <td className="border-y border-[var(--qg-card-border)] p-4 text-[10px] font-mono text-[var(--qg-text-muted)] dark:border-white/8 dark:text-white/42">{formatDate(asset.lastScanned)}</td>
                      <td className="rounded-r-xl border-y border-r border-[var(--qg-card-border)] p-4 dark:border-white/8">
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            aria-expanded={isExpanded}
                            onClick={(event) => {
                              event.stopPropagation();
                              setExpandedAssetId(isExpanded ? null : asset.id);
                            }}
                            className="inline-flex items-center gap-1 rounded-md border border-[var(--qg-amber)]/25 bg-[var(--qg-amber)]/10 px-2 py-1 text-[10px] font-black uppercase text-[var(--qg-amber)] transition hover:border-[var(--qg-amber)]/60"
                          >
                            <Eye className="h-3 w-3" /> {isExpanded ? 'Hide' : 'Details'}
                          </button>
                          <a onClick={(event) => event.stopPropagation()} href="/dashboard/cbom" className="text-[10px] font-black uppercase text-[var(--qg-amber)] hover:underline">CBOM</a>
                          <a onClick={(event) => event.stopPropagation()} href="/dashboard/scanner" className="text-[10px] font-black uppercase text-[var(--qg-text-muted)] hover:text-[var(--qg-amber)] dark:text-white/40">Rescan</a>
                        </div>
                      </td>
                    </motion.tr>

                    {isExpanded && (
                      <motion.tr initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
                        <td colSpan={9} className="p-0">
                          <div className="mx-2 mb-3 rounded-xl border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.95),0_20px_45px_rgba(15,23,42,0.10)] dark:border-[var(--qg-amber)]/18 dark:bg-[#070b18]/92 dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.06),0_20px_60px_rgba(0,0,0,0.32)]">
                            <div className="grid gap-5 xl:grid-cols-[0.9fr_2.1fr]">
                              <div className="rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-4 dark:border-white/8 dark:bg-white/[0.025]">
                                <div className="mb-4 flex items-center justify-between gap-3">
                                  <div>
                                    <div className="text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Asset Profile</div>
                                    <div className="mt-1 text-lg font-black text-[var(--qg-dashboard-text)]">{asset.name}</div>
                                  </div>
                                  <div className="flex shrink-0 flex-col items-end gap-1">
                                    <span className={`rounded-md border px-2 py-1 text-[10px] font-black uppercase ${severityClasses(assetRiskLevel(asset), vulnerable.length > 0)}`}>
                                      Asset risk: {labelize(assetRiskLevel(asset))}
                                    </span>
                                    {(() => {
                                      const worst = worstComponentSeverity(asset);
                                      if (!worst) return null;
                                      return (
                                        <span className={`rounded-md border px-2 py-1 text-[9px] font-black uppercase ${severityClasses(worst, true)}`}>
                                          Worst component: {labelize(worst)}
                                        </span>
                                      );
                                    })()}
                                  </div>
                                </div>
                                <div className="grid gap-3 text-xs">
                                  {[
                                    ['Target', assetTarget(asset)],
                                    ['Type', labelize(asset.type)],
                                    ['Status', asset.status || 'active'],
                                    ['Last scanned', formatDate(asset.lastScanned)],
                                  ].map(([label, value]) => (
                                    <div key={label} className="flex items-start justify-between gap-4 border-t border-[var(--qg-card-border)] pt-3 dark:border-white/6">
                                      <span className="font-black uppercase tracking-widest text-[var(--qg-text-muted)]">{label}</span>
                                      <span className="max-w-[220px] text-right font-mono text-[var(--qg-dashboard-text-soft)] dark:text-white/68">{value}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>

                              <div>
                                <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                                  <div>
                                    <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text)]">Vulnerable Cryptographic Components</h3>
                                    <p className="mt-1 text-xs text-[var(--qg-text-muted)] text-[var(--qg-text-muted)]">
                                      Counted at the component level — the same unit the CBOM Explorer and Quantum Readiness Engine use.
                                      {signalCount > 0 ? ` Backed by ${signalCount} raw detection signal${signalCount === 1 ? '' : 's'}.` : ''}
                                    </p>
                                  </div>
                                  <div className="flex flex-wrap gap-2">
                                    <span className="rounded-md border border-red-500/25 bg-red-500/8 px-2 py-1 text-[10px] font-black uppercase text-red-600 dark:border-red-400/25 dark:text-red-300">{vulnerable.length} vulnerable</span>
                                    <span className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-2 py-1 text-[10px] font-black uppercase text-[var(--qg-text-muted)]   dark:text-white/42">{cryptoInventory.length} total</span>
                                    {pqcReadyCount > 0 && (
                                      <span className="rounded-md border border-emerald-500/25 bg-emerald-500/8 px-2 py-1 text-[10px] font-black uppercase text-emerald-600 dark:border-emerald-400/25 dark:text-emerald-300">{pqcReadyCount} PQC-ready</span>
                                    )}
                                    {signalCount > 0 && (
                                      <span className="rounded-md border border-cyan-500/25 bg-cyan-500/8 px-2 py-1 text-[10px] font-black uppercase text-cyan-600 dark:border-cyan-400/25 dark:text-cyan-300">{signalCount} signals</span>
                                    )}
                                  </div>
                                </div>

                                {vulnerable.length === 0 ? (
                                  <div className="rounded-lg border border-emerald-500/25 bg-emerald-500/8 p-4 text-sm font-semibold text-emerald-700 dark:border-emerald-400/25 dark:text-emerald-200">
                                    No vulnerable cryptographic components are currently detected for this asset. Continue monitoring and rescan after configuration changes.
                                  </div>
                                ) : (
                                  <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
                                    {vulnerable.slice(0, 12).map((item, index) => {
                                      const componentSignals = signalsForComponent(asset, item);
                                      return (
                                      <div key={item.id || `${asset.id}-vuln-${index}`} className="rounded-lg border border-red-300/50 bg-red-50/80 p-4 dark:border-red-400/18 dark:bg-red-500/[0.055]">
                                        <div className="mb-3 flex items-start justify-between gap-3">
                                          <div className="min-w-0">
                                            <div className="truncate text-sm font-black text-[var(--qg-dashboard-text)]">{cryptoLabel(item)}</div>
                                            <div className="mt-1 text-[10px] font-bold uppercase tracking-widest text-[var(--qg-text-muted)]">{labelize(item.item_type || item.protocol || 'cryptography')}</div>
                                          </div>
                                          <div className="flex shrink-0 flex-wrap justify-end gap-2">
                                            <span className={`rounded border px-2 py-0.5 text-[9px] font-black uppercase ${severityClasses(item.exposure_level, item.is_vulnerable)}`}>
                                              {labelize(item.exposure_level || 'vulnerable')}
                                            </span>
                                            <a
                                              href={remediationHref(asset, item)}
                                              onClick={(event) => event.stopPropagation()}
                                              className="inline-flex items-center gap-1 rounded border border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 px-2 py-0.5 text-[9px] font-black uppercase tracking-wider text-[var(--qg-amber)] transition hover:border-[var(--qg-amber)]/70 hover:bg-[var(--qg-amber)]/15"
                                            >
                                              <ExternalLink className="h-3 w-3" /> Remediate
                                            </a>
                                          </div>
                                        </div>
                                        <p className="line-clamp-2 text-xs leading-relaxed text-[var(--qg-dashboard-text-soft)] dark:text-white/58">
                                          {metadataText(item, 'evidence', 'Scanner marked this cryptographic component as vulnerable or migration-sensitive.')}
                                        </p>
                                        <div className="mt-3 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-3 dark:border-white/8 dark:bg-black/18">
                                          <div className="text-[9px] font-black uppercase tracking-widest text-[var(--qg-amber)]/70">Recommended action</div>
                                          <div className="mt-1 text-xs font-semibold leading-relaxed text-[var(--qg-dashboard-text-soft)] dark:text-white/68">
                                            {metadataText(item, 'recommendation', 'Review against the NIST PQC migration policy and assign remediation ownership.')}
                                          </div>
                                        </div>
                                        {componentSignals.length > 0 && (
                                          <div className="mt-2 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-[var(--qg-text-muted)]">
                                            <AlertTriangle className="h-2.5 w-2.5" />
                                            {componentSignals.length} detection signal{componentSignals.length === 1 ? '' : 's'} across scanner, exposures & CBOM
                                          </div>
                                        )}
                                      </div>
                                      );
                                    })}
                                  </div>
                                )}

                                {vulnerable.length > 12 && (
                                  <div className="mt-3 text-[10px] font-black uppercase tracking-widest text-[var(--qg-text-muted)]">
                                    +{vulnerable.length - 12} additional vulnerable component{vulnerable.length - 12 === 1 ? '' : 's'} available in CBOM.
                                  </div>
                                )}
                              </div>
                            </div>

                            <div className="mt-5 border-t border-[var(--qg-card-border)] pt-4 dark:border-white/8">
                              <div className="mb-3 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Observed Cryptography</div>
                              <div className="flex flex-wrap gap-2">
                                {cryptoInventory.length === 0 ? (
                                  <span className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-3 py-1.5 text-[10px] font-bold text-[var(--qg-text-muted)]   dark:text-white/40">Manual review required</span>
                                ) : visibleCryptoInventory.map((item, index) => (
                                  <span key={item.id || `${asset.id}-crypto-${index}`} className={`rounded-md border px-3 py-1.5 text-[10px] font-bold ${item.is_vulnerable ? 'border-red-500/25 bg-red-500/8 text-red-600 dark:border-red-400/25 dark:text-red-300' : 'border-emerald-500/25 bg-emerald-500/8 text-emerald-600 dark:border-emerald-400/25 dark:text-emerald-300'}`}>
                                    {cryptoLabel(item)}
                                  </span>
                                ))}
                                {hiddenCryptoCount > 0 && (
                                  <button
                                    type="button"
                                    onClick={(event) => {
                                      event.stopPropagation();
                                      toggleCryptoExpansion(asset.id);
                                    }}
                                    aria-expanded={cryptoListExpanded}
                                    className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)] transition hover:border-[var(--qg-amber)]/45 hover:text-[var(--qg-amber)]   text-[var(--qg-text-muted)] dark:hover:border-[var(--qg-amber)]/45 dark:hover:text-[var(--qg-amber)]"
                                  >
                                    {cryptoListExpanded ? 'Show less' : `+${hiddenCryptoCount} more`}
                                  </button>
                                )}
                              </div>
                            </div>
                          </div>
                        </td>
                      </motion.tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </DiscoveryPage>
  );
}
