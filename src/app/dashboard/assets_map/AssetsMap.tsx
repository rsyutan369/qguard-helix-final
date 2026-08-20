/**
 * Assets & CBOM — the tenant's authorized cryptographic asset register.
 *
 * Presentation is deliberately identical to the CBOM Explorer: the same
 * `--qg-*` design tokens, the same panel/metric/section grammar, the same
 * command-bar header and the same Quantum Readiness reconciliation block. The
 * two pages describe ONE estate from two angles (assets vs. components), so a
 * user moving between them should never have to re-learn the surface — and,
 * because both read the same shared scanner-intelligence snapshot and the same
 * QR Engine snapshot, the figures on each are the same numbers under the same
 * names.
 *
 * Every figure below originates from authenticated scanner APIs, the workflow
 * engine, or the Quantum Readiness & Assessment Engine. Nothing here is
 * synthesised: when a source has no evidence the surface says so instead of
 * rendering a zero that reads like a measurement.
 */
import { Fragment, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  ExternalLink,
  Eye,
  Filter,
  GitCompareArrows,
  Globe,
  Info,
  Layers,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';
import { InventoryExportMenu } from '../_components/InventoryExportMenu';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { useMigrationWorkflow } from '@/hooks/use-migration-workflow';
import { useQuantumReadiness, readinessTone } from '@/app/dashboard/quantum-readiness/_shared';

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

/**
 * Register views — filters over the SAME authorized asset list, never a
 * different data source. "All Assets" always shows the complete register, so no
 * view can hide an asset from the operator; the others narrow it by a stated,
 * measured criterion which is printed above the table.
 */
const VIEWS = ['All Assets', 'Vulnerable', 'No Vulnerable Crypto', 'High Risk', 'In Migration'] as const;

type AssetView = (typeof VIEWS)[number];

const VIEW_COPY: Record<AssetView, { title: string; description: string; criterion: string }> = {
  'All Assets': {
    title: 'Authorized Asset Register',
    description: 'Every cryptographic asset discovered by an authorized scan of this tenant, with its component inventory, risk band, compliance state and migration lifecycle position.',
    criterion: 'No filter — the complete authorized register.',
  },
  Vulnerable: {
    title: 'Quantum-Vulnerable Assets',
    description: 'Assets carrying at least one cryptographic component the scanner graded vulnerable and not quantum safe. These are the remediation candidates behind the tenant-wide vulnerable-component count.',
    criterion: 'Criterion — one or more components with is_vulnerable and not is_quantum_safe.',
  },
  'No Vulnerable Crypto': {
    title: 'Assets With No Vulnerable Cryptography',
    description: 'Assets whose scanned components currently carry no vulnerable cryptography. This is an observation from the latest scan, not a certification of PQC readiness — validation is owned by the Quantum Readiness Engine.',
    criterion: 'Criterion — zero vulnerable components in the latest scanned inventory.',
  },
  'High Risk': {
    title: 'High And Critical Risk Assets',
    description: 'Assets whose risk band, projected from their measured risk score, is High or Critical. Use this view to sequence the first migration waves.',
    criterion: 'Criterion — asset risk band is High or Critical.',
  },
  'In Migration': {
    title: 'Assets In The Migration Lifecycle',
    description: 'Assets the platform workflow engine is currently tracking through remediation, execution, validation or monitoring — the same lifecycle state the Workflow Rail renders.',
    criterion: 'Criterion — a workflow-engine lifecycle state exists for the asset.',
  },
};

/**
 * Shared panel grammar with the CBOM Explorer. Both pages compose from these two
 * classes only, so a change to the platform surface lands on both at once
 * instead of drifting apart into two hand-tuned themes.
 */
const panelClass =
  'relative overflow-hidden rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] shadow-[var(--qg-panel-shadow)] backdrop-blur-xl transition-all duration-300';

const subtlePanelClass =
  'rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)]';

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(Number(value) || 0)));
}

function riskColor(score: number) {
  if (score >= 80) return 'text-red-600 dark:text-red-300';
  if (score >= 60) return 'text-orange-600 dark:text-orange-300';
  if (score >= 40) return 'text-amber-700 dark:text-amber-300';
  return 'text-emerald-600 dark:text-emerald-300';
}

function riskBar(score: number) {
  if (score >= 80) return 'bg-red-500';
  if (score >= 60) return 'bg-orange-500';
  if (score >= 40) return 'bg-amber-500';
  return 'bg-emerald-500';
}

function severityClasses(value?: string | null, vulnerable?: boolean) {
  const level = String(value || '').toLowerCase();
  if (level.includes('critical')) return 'border-red-500/25 bg-red-500/15 text-red-600 dark:text-red-300';
  if (level.includes('high')) return 'border-orange-500/25 bg-orange-500/15 text-orange-600 dark:text-orange-300';
  if (level.includes('medium') || vulnerable) return 'border-amber-500/25 bg-amber-500/15 text-amber-700 dark:text-amber-300';
  return 'border-emerald-500/25 bg-emerald-500/12 text-emerald-600 dark:text-emerald-300';
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

/** Header-bar timestamp, in the CBOM Explorer's wording and format. */
function formatScanStamp(value?: string | null) {
  if (!value) return 'Awaiting scan';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  if (date.getFullYear() < 2000) return 'Awaiting scan';
  return date.toLocaleString([], {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

/** Latest authorized scan behind this view — same derivation the CBOM Explorer uses. */
function latestScanAt(history: any[], generatedAt?: string) {
  const latest = history[0];
  const fallback = generatedAt && new Date(generatedAt).getFullYear() >= 2000 ? generatedAt : null;
  return latest?.completedAt || latest?.startedAt || latest?.created_at || fallback;
}

function typeIcon(type: string) {
  const lower = type.toLowerCase();
  if (lower.includes('api') || lower.includes('web') || lower.includes('tls')) return Globe;
  if (lower.includes('ssh')) return ChevronRight;
  return Server;
}

/** Tenant-scope KPI tile — the CBOM Explorer's metric card, same geometry and tones. */
function MetricCard({
  label,
  value,
  detail,
  icon: Icon,
  tone,
  index,
}: {
  label: string;
  value: string | number;
  detail: string;
  icon: LucideIcon;
  tone: 'blue' | 'green' | 'orange' | 'red' | 'cyan';
  index: number;
}) {
  const toneClass =
    tone === 'green' ? 'from-emerald-500/25 text-emerald-600 dark:text-emerald-300' :
    tone === 'orange' ? 'from-orange-500/25 text-orange-600 dark:text-orange-300' :
    tone === 'red' ? 'from-red-500/25 text-red-600 dark:text-red-300' :
    tone === 'cyan' ? 'from-cyan-500/25 text-cyan-600 dark:text-cyan-300' :
    'from-blue-500/25 text-blue-600 dark:text-blue-300';

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
      className={`${panelClass} p-4`}
    >
      <div className="flex items-center gap-3">
        <div className={`grid h-12 w-12 shrink-0 place-items-center rounded-full bg-gradient-to-br ${toneClass} to-transparent`}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--qg-text-muted)]">{label}</div>
          <div className="text-2xl font-black text-[var(--qg-dashboard-text)]">{typeof value === 'number' ? numberFmt(value) : value}</div>
          <div className="mt-0.5 truncate text-[10px] text-[var(--qg-text-muted)]" title={detail}>{detail}</div>
        </div>
      </div>
    </motion.div>
  );
}

export default function AssetsMap() {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const { data, loading, error, connected, refresh } = useScannerIntelligence({ live: autoRefresh });
  const assets = (data.assets.assets || []) as AssetRecord[];
  // Canonical tenant-wide figures straight from the shared scanner-intelligence
  // snapshot — the SAME numbers the CBOM Explorer and the Quantum Readiness &
  // Assessment Engine render. The Assets page reconciles against these so its
  // headline never disagrees with the rest of the platform.
  const summary = data.summary;
  const severityCounts = data.severityCounts;
  const history = data.history.history || [];
  const latestScan = latestScanAt(history, data.generatedAt);
  // The header claimed "Reconciled with Quantum Readiness Engine" without ever
  // reading it, and labelled the component PQC-ready share "Quantum Readiness" —
  // the name the QR Engine's composite score carries on every other page, with a
  // different value. The QR snapshot is now actually read, so the two figures
  // appear side by side under their own names instead of one borrowing the
  // other's label.
  const qr = useQuantumReadiness();
  const qrHasData = qr.snapshot.hasData;
  const qrResolved = qr.state === 'success';
  const qrScores = qr.snapshot.scores;
  const qrInventory = qr.snapshot.inventory;
  const qrLive = qr.sseConnected;
  const readinessLevel = qrHasData
    ? qrScores.quantumReadinessLevel
    : qrResolved ? 'No assessment evidence' : 'Awaiting assessment';
  // Findings graded on the severity ladder. `totalFindings` also counts SAFE
  // observations, so quoting it above a bar chart of critical/high/medium/low
  // showed a total the bars could never add up to.
  const gradedFindings = severityCounts.critical + severityCounts.high + severityCounts.medium + severityCounts.low;
  const [activeView, setActiveView] = useState<AssetView>('All Assets');
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

  // Per-asset facts every view, badge and count is decided from, derived ONCE
  // per snapshot. Recomputing `vulnerableComponents` inside each view predicate
  // would re-group and re-sort every asset's inventory five times per render on
  // an estate that can run to thousands of assets — and, worse, would leave the
  // tab counts and the table free to drift apart if the two ever computed it
  // differently. One derivation, read everywhere.
  const assetFacts = useMemo(() => {
    const facts = new Map<string, { vulnerable: number; risk: RiskLevel; inLifecycle: boolean }>();
    for (const asset of assets) {
      facts.set(asset.id, {
        vulnerable: vulnerableComponents(asset).length,
        risk: assetRiskLevel(asset),
        inLifecycle: lifecycleByAsset.has(String(asset.name || '').toLowerCase()),
      });
    }
    return facts;
  }, [assets, lifecycleByAsset]);

  const matchesView = useMemo(() => (asset: AssetRecord, view: AssetView) => {
    if (view === 'All Assets') return true;
    const fact = assetFacts.get(asset.id);
    if (!fact) return false;
    if (view === 'Vulnerable') return fact.vulnerable > 0;
    if (view === 'No Vulnerable Crypto') return fact.vulnerable === 0;
    if (view === 'High Risk') return riskRank(fact.risk) >= riskRank('high');
    return fact.inLifecycle;
  }, [assetFacts]);

  const viewCounts = useMemo(() => VIEWS.reduce<Record<AssetView, number>>((counts, view) => {
    counts[view] = assets.filter((asset) => matchesView(asset, view)).length;
    return counts;
  }, {} as Record<AssetView, number>), [assets, matchesView]);

  const filteredAssets = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();
    return assets.filter((asset) => {
      if (!matchesView(asset, activeView)) return false;
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
      if (riskFilter && assetFacts.get(asset.id)?.risk !== riskFilter) return false;
      return true;
    });
  }, [activeView, assetFacts, assets, matchesView, riskFilter, searchQuery]);

  const riskSummary = useMemo(() => riskLevels.reduce<Record<RiskLevel, number>>((counts, level) => {
    counts[level] = assets.filter((asset) => assetFacts.get(asset.id)?.risk === level).length;
    return counts;
  }, { critical: 0, high: 0, medium: 0, low: 0 }), [assetFacts, assets]);

  const selectedAssets = useMemo(() => assets.filter((asset) => selectedAssetIds.has(asset.id)), [assets, selectedAssetIds]);
  const exportAssets = selectedAssets.length > 0 ? selectedAssets : filteredAssets;
  const allVisibleSelected = filteredAssets.length > 0 && filteredAssets.every((asset) => selectedAssetIds.has(asset.id));
  const filtersActive = Boolean(searchQuery.trim()) || riskFilter !== null || activeView !== 'All Assets';
  // The first load has no cached snapshot to fall back on; every later refresh
  // re-renders over data that is already on screen.
  const isInitialSyncing = loading && assets.length === 0 && !error;

  // Does the asset register's component scope agree with the QR Engine's
  // inventory? Both derive from the same authorized scans, so this is an
  // explicit integrity check rather than an assumption — and it is stated as
  // "pending" or "no evidence" until the QR Engine has actually answered.
  const withinTolerance = (a: number, b: number) => Math.abs(a - b) <= Math.max(1, Math.round(Math.max(a, b) * 0.02));
  const reconciliation = [
    { label: 'Crypto Components', local: Number(summary.totalComponents || 0), qr: Number(qrInventory.cryptoComponents || 0) },
    { label: 'Vulnerable', local: Number(summary.vulnerableComponents || 0), qr: Number(qrInventory.vulnerableComponents || 0) },
    { label: 'PQC-Ready', local: Number(summary.pqcReadyComponents || 0), qr: Number(qrInventory.pqcReadyComponents || 0) },
  ].map((row) => ({ ...row, match: qrHasData ? withinTolerance(row.local, row.qr) : null }));
  const reconciliationState: 'match' | 'diverged' | 'pending' | 'no-evidence' = !qrHasData
    ? (qrResolved ? 'no-evidence' : 'pending')
    : reconciliation.every((row) => row.match) ? 'match' : 'diverged';

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

  const exportMenu = (
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
          lastScanAt: latestScan || data.generatedAt || null,
          filtered,
          filterDescription: selectedAssets.length > 0
            ? 'user selection'
            : [activeView !== 'All Assets' && `view "${activeView}"`, searchQuery && `search "${searchQuery}"`, riskFilter && `risk ${riskFilter}`]
              .filter(Boolean).join(', ') || 'no filters',
        };
      }}
    />
  );

  return (
    <div
      className="min-h-screen space-y-4 p-4 text-[var(--qg-dashboard-text)] md:p-6"
      style={{
        background:
          'radial-gradient(circle at 18% 8%, color-mix(in srgb, var(--qg-cyan) 14%, transparent), transparent 34%), radial-gradient(circle at 82% 18%, color-mix(in srgb, var(--qg-amber) 10%, transparent), transparent 30%), linear-gradient(180deg, var(--qg-dashboard-bg), var(--qg-dashboard-bg-soft))',
      }}
    >
      <WorkflowRail activeStage="discovery" tone="adaptive" />

      <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-black tracking-tight text-[var(--qg-dashboard-text)] md:text-3xl">
              Asset Inventory
            </h1>
            <Info className="h-4 w-4 text-[var(--qg-text-muted)]" />
          </div>
          <p className="mt-1 text-sm text-[var(--qg-dashboard-text-soft)]">
            Authorized cryptographic assets discovered from real scanner results - component inventory, risk band, and migration lifecycle.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] font-black uppercase tracking-widest">
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${connected ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300' : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-[var(--qg-text-muted)]'}`} />
              {connected ? 'Live Telemetry' : 'Cached'}
            </span>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${
                reconciliationState === 'match' ? 'border-[var(--qg-cyan)]/25 bg-[var(--qg-cyan)]/10 text-[var(--qg-cyan)]'
                  : reconciliationState === 'diverged' ? 'border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]'
                    : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'
              }`}
              title={qrHasData ? `QR Engine: ${numberFmt(qrInventory.cryptoComponents)} components - ${numberFmt(qrInventory.vulnerableComponents)} vulnerable` : undefined}
            >
              <Sparkles className="h-3 w-3" />
              {reconciliationState === 'match' ? 'Reconciled with Quantum Readiness Engine'
                : reconciliationState === 'diverged' ? 'Diverged from Quantum Readiness Engine'
                  : reconciliationState === 'no-evidence' ? 'No QR assessment evidence' : 'Awaiting Quantum Readiness Engine'}
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Link to="/dashboard/cbom" className="inline-flex items-center gap-2 rounded-md border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-xs font-bold text-blue-600 transition hover:border-blue-400/60 dark:text-blue-300">
            <Layers className="h-4 w-4" />
            Open CBOM
          </Link>
          <Link to="/dashboard/scanner" className="inline-flex items-center gap-2 rounded-md border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-xs font-bold text-blue-600 transition hover:border-blue-400/60 dark:text-blue-300">
            <Target className="h-4 w-4" />
            Scan Targets
          </Link>
          <Link to="/dashboard/scanner" className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-amber)]/40 bg-[var(--qg-amber)] px-4 py-2 text-xs font-black text-[var(--qg-on-accent)] shadow-[0_0_18px_color-mix(in_srgb,var(--qg-amber)_28%,transparent)] transition hover:brightness-110">
            <Plus className="h-4 w-4" />
            Add Target
          </Link>
          {exportMenu}
          <button type="button" className="relative inline-flex h-9 w-9 items-center justify-center rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] text-[var(--qg-dashboard-text-soft)]">
            <Bell className="h-4 w-4" />
            {summary.vulnerableAssets > 0 && (
              <span
                title={`${numberFmt(summary.vulnerableAssets)} assets carrying vulnerable cryptography`}
                className="absolute -right-1 -top-1 rounded-full bg-[var(--qg-amber)] px-1.5 text-[9px] font-black text-[var(--qg-on-accent)]"
              >
                {summary.vulnerableAssets > 9 ? '9+' : summary.vulnerableAssets}
              </span>
            )}
          </button>
          <button type="button" className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] text-[var(--qg-dashboard-text-soft)]">
            <CircleHelp className="h-4 w-4" />
          </button>
        </div>
      </header>

      <div className="flex flex-col gap-3 border-b border-[var(--qg-card-border)] pb-3 xl:flex-row xl:items-center xl:justify-between">
        <nav className="flex gap-1 overflow-x-auto">
          {VIEWS.map((view) => (
            <button
              type="button"
              key={view}
              onClick={() => setActiveView(view)}
              className={`inline-flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2 text-xs font-bold transition ${
                activeView === view
                  ? 'border-[var(--qg-amber)] text-[var(--qg-amber)]'
                  : 'border-transparent text-[var(--qg-text-muted)] hover:text-[var(--qg-dashboard-text)]'
              }`}
            >
              {view}
              <span className={`rounded px-1.5 py-0.5 text-[9px] font-black ${activeView === view ? 'bg-[var(--qg-amber)]/15 text-[var(--qg-amber)]' : 'bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'}`}>
                {numberFmt(viewCounts[view] || 0)}
              </span>
            </button>
          ))}
        </nav>
        <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--qg-text-muted)]">
          <span>Last Scan: {formatScanStamp(latestScan)}</span>
          <button type="button" onClick={refresh} aria-label="Refresh asset inventory" className="inline-flex items-center gap-1 text-[var(--qg-dashboard-text-soft)]">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <span className="h-5 w-px bg-[var(--qg-card-border)]" />
          <button type="button" onClick={() => setAutoRefresh((value) => !value)} className="inline-flex items-center gap-2">
            Auto Refresh
            <span className={`relative h-5 w-9 rounded-full border transition ${autoRefresh ? 'border-[var(--qg-amber)] bg-[var(--qg-amber)]/30' : 'border-[var(--qg-card-border)] bg-[var(--qg-card-bg)]'}`}>
              <span className={`absolute top-0.5 h-4 w-4 rounded-full transition ${autoRefresh ? 'left-4 bg-[var(--qg-amber)]' : 'left-0.5 bg-[var(--qg-text-muted)]'}`} />
            </span>
          </button>
          <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-bold uppercase ${autoRefresh && connected ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300' : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${autoRefresh && connected ? 'bg-emerald-400' : 'bg-[var(--qg-text-muted)]'}`} />
            {autoRefresh && connected ? 'Live SSE' : 'Manual'}
          </span>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-600 dark:text-red-300">
          {error}
        </div>
      )}

      {isInitialSyncing && (
        <div className="flex flex-col gap-2 rounded-lg border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 p-3 text-xs font-bold text-[var(--qg-dashboard-text-soft)] md:flex-row md:items-center md:justify-between">
          <span className="inline-flex items-center gap-2">
            <Loader2 className="h-4 w-4 animate-spin text-[var(--qg-amber)]" />
            Synchronizing authorized asset inventory from authenticated scanner APIs and live scanner events.
          </span>
          <span className="text-[10px] uppercase tracking-wider text-[var(--qg-text-muted)]">Register remains usable while sync completes</span>
        </div>
      )}

      <section className="grid gap-3 lg:grid-cols-5">
        <MetricCard
          index={0}
          icon={Server}
          tone="blue"
          label="Authorized Assets"
          value={summary.totalAssets || assets.length}
          detail={`${numberFmt(summary.vulnerableAssets)} with vulnerable crypto`}
        />
        <MetricCard
          index={1}
          icon={Layers}
          tone="cyan"
          label="Cryptographic Components"
          value={summary.totalComponents}
          detail={`${numberFmt(summary.pqcReadyComponents)} PQC-ready`}
        />
        <MetricCard
          index={2}
          icon={AlertTriangle}
          tone="red"
          label="Quantum-Vulnerable"
          value={summary.vulnerableComponents}
          detail="Components matching QR Engine & CBOM"
        />
        <MetricCard
          index={3}
          icon={Zap}
          tone="orange"
          label="Critical Findings"
          value={summary.criticalFindings}
          detail={`of ${numberFmt(gradedFindings)} graded scanner findings`}
        />
        <MetricCard
          index={4}
          icon={ShieldCheck}
          tone="green"
          label="Quantum Readiness (QR)"
          value={qrHasData ? `${qrScores.quantumReadiness}/100` : '—'}
          detail={qrHasData ? `${qrScores.quantumReadinessLevel} - risk ${qrScores.quantumRisk}/100` : readinessLevel}
        />
      </section>

      {/* Quantum Readiness Engine reconciliation — the headline readiness/risk are
          read from the QR Engine snapshot and the component counts are checked
          against it, so this register can never silently diverge from QR. */}
      <section className={`${panelClass} p-4 md:p-5`}>
        <div className="grid gap-5 lg:grid-cols-[1.1fr_1.5fr_1.05fr]">
          <div>
            <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.22em] text-[var(--qg-cyan)]">
              <Sparkles className="h-3.5 w-3.5" /> Quantum Readiness Engine
            </div>
            <div className="mt-2 flex items-end gap-2">
              {qrHasData ? (
                <>
                  <span className="text-4xl font-black" style={{ color: readinessTone(qrScores.quantumReadiness) }}>{Math.round(qrScores.quantumReadiness)}</span>
                  <span className="mb-1 text-xs text-[var(--qg-text-muted)]">/100 · {readinessLevel}</span>
                </>
              ) : (
                <>
                  <span className="text-4xl font-black text-[var(--qg-text-muted)]">—</span>
                  <span className="mb-1 text-xs text-[var(--qg-text-muted)]">{readinessLevel}</span>
                </>
              )}
            </div>
            <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-[var(--qg-muted-panel)]">
              {qrHasData && (
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${Math.max(0, Math.min(100, qrScores.quantumReadiness))}%`, background: readinessTone(qrScores.quantumReadiness) }}
                />
              )}
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {/* An unresolved risk score renders as "—", never as 0: on a
                  lower-is-better scale a placeholder zero reads as a perfect posture. */}
              <span className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-2 py-1 text-[10px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)]">
                Quantum Risk {qrHasData ? `${qrScores.quantumRisk}/100` : '—'}
              </span>
              <span className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-2 py-1 text-[10px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)]">
                PQC Adoption {qrHasData ? `${Math.round(qrScores.pqcAdoption)}%` : `${summary.pqcReadiness}%`}
              </span>
            </div>
            {!qrHasData && (
              <p className="mt-2 text-[10px] leading-relaxed text-[var(--qg-text-muted)]">
                {qrResolved
                  ? 'The Quantum Readiness Engine has no assessment evidence for this tenant yet. Figures below are scanner-inventory only.'
                  : 'Waiting for the Quantum Readiness Engine assessment. Readiness and risk are withheld until it responds.'}
              </p>
            )}
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">
                <GitCompareArrows className="h-3.5 w-3.5" /> Inventory Reconciliation
              </span>
              {/* A verdict is only claimed once there is something to compare. */}
              <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[9px] font-black uppercase ${
                reconciliationState === 'match' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300'
                  : reconciliationState === 'diverged' ? 'border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]'
                    : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'
              }`}>
                {reconciliationState === 'match' ? <CheckCircle2 className="h-3 w-3" /> : reconciliationState === 'diverged' ? <AlertTriangle className="h-3 w-3" /> : <CircleHelp className="h-3 w-3" />}
                {reconciliationState === 'match' ? 'In sync with QR'
                  : reconciliationState === 'diverged' ? 'Diverged from QR'
                    : reconciliationState === 'no-evidence' ? 'No QR evidence' : 'Awaiting QR'}
              </span>
            </div>
            <div className="overflow-hidden rounded-lg border border-[var(--qg-card-border)]">
              <div className="grid grid-cols-[1.4fr_1fr_1fr_auto] bg-[var(--qg-muted-panel)] px-3 py-1.5 text-[9px] font-black uppercase tracking-wider text-[var(--qg-text-muted)]">
                <span>Metric</span><span className="text-right">Register</span><span className="text-right">QR Engine</span><span className="pl-3" />
              </div>
              {reconciliation.map((row) => (
                <div key={row.label} className="grid grid-cols-[1.4fr_1fr_1fr_auto] items-center border-t border-[var(--qg-card-border)] px-3 py-2 text-xs">
                  <span className="font-bold text-[var(--qg-dashboard-text)]">{row.label}</span>
                  <span className="text-right font-black text-[var(--qg-dashboard-text)]">{numberFmt(row.local)}</span>
                  <span className="text-right font-mono text-[var(--qg-dashboard-text-soft)]">{qrHasData ? numberFmt(row.qr) : '—'}</span>
                  <span className="pl-3">
                    {row.match === null
                      ? <CircleHelp className="h-3.5 w-3.5 text-[var(--qg-text-muted)]" />
                      : row.match
                        ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                        : <AlertTriangle className="h-3.5 w-3.5 text-[var(--qg-amber)]" />}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-col justify-between gap-3">
            <div className="space-y-2">
              <div className="text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Live Telemetry</div>
              <div className="flex items-center gap-2 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-xs">
                <span className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-[var(--qg-text-muted)]'}`} />
                <span className="font-bold text-[var(--qg-dashboard-text-soft)]">Scanner asset stream</span>
                <span className={`ml-auto text-[10px] font-black uppercase ${connected ? 'text-emerald-600 dark:text-emerald-300' : 'text-[var(--qg-text-muted)]'}`}>{connected ? 'Live' : 'Idle'}</span>
              </div>
              <div className="flex items-center gap-2 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-xs">
                <span className={`h-2 w-2 rounded-full ${qrLive ? 'bg-emerald-400 animate-pulse' : 'bg-[var(--qg-text-muted)]'}`} />
                <span className="font-bold text-[var(--qg-dashboard-text-soft)]">QR assessment stream</span>
                <span className={`ml-auto text-[10px] font-black uppercase ${qrLive ? 'text-emerald-600 dark:text-emerald-300' : 'text-[var(--qg-text-muted)]'}`}>{qrLive ? 'Live' : 'Idle'}</span>
              </div>
            </div>
            <Link to="/dashboard/quantum-readiness/command-center" className="inline-flex items-center justify-center gap-2 rounded-md border border-[var(--qg-cyan)]/35 bg-[var(--qg-cyan)]/10 px-3 py-2 text-[11px] font-black uppercase tracking-wider text-[var(--qg-cyan)] transition hover:border-[var(--qg-cyan)]/70">
              <ExternalLink className="h-3.5 w-3.5" /> Open QR Command Center
            </Link>
          </div>
        </div>
      </section>

      {/* Estate posture — canonical tenant-wide crypto posture straight from the
          shared scanner-intelligence snapshot. These are the exact figures the
          Quantum Readiness & Assessment Engine renders, so the Assets page can be
          reconciled against QR at a glance. */}
      <section className={`${panelClass} p-4 md:p-5`}>
        <div className="grid gap-5 lg:grid-cols-[1.1fr_1.3fr_1.3fr]">
          <div>
            <div className="text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">PQC Component Coverage</div>
            <div className="mt-2 flex items-end gap-2">
              <span className="text-4xl font-black text-emerald-600 dark:text-emerald-300">{summary.pqcReadiness}%</span>
              <span className="mb-1 text-[10px] font-mono text-[var(--qg-text-muted)]">of {numberFmt(summary.totalComponents)} components</span>
            </div>
            <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-[var(--qg-muted-panel)]">
              <div className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-emerald-400" style={{ width: `${Math.min(100, summary.pqcReadiness)}%` }} />
            </div>
            <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-[var(--qg-text-muted)]">
              <span>{numberFmt(summary.pqcReadyComponents)} PQC-ready</span>
              <span className="text-red-600 dark:text-red-300">{numberFmt(summary.vulnerableComponents)} vulnerable</span>
            </div>
          </div>

          <div>
            <div className="text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Risk Posture</div>
            <div className="mt-3 grid grid-cols-2 gap-3">
              {[
                { label: 'Risk Score', value: `${summary.riskScore}/100`, color: riskColor(summary.riskScore) },
                { label: 'Q-Score', value: `${summary.qScore}/100`, color: 'text-cyan-600 dark:text-cyan-300' },
                { label: 'Vulnerable Assets', value: `${numberFmt(summary.vulnerableAssets)}/${numberFmt(summary.totalAssets || assets.length)}`, color: 'text-red-600 dark:text-red-300' },
                { label: 'Critical Findings', value: numberFmt(summary.criticalFindings), color: 'text-orange-600 dark:text-orange-300' },
              ].map((metric) => (
                <div key={metric.label} className={`${subtlePanelClass} p-3`}>
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
                {numberFmt(gradedFindings)} graded
              </span>
            </div>
            <div className="mt-3 space-y-2">
              {([
                ['critical', 'Critical', 'bg-red-500', 'text-red-600 dark:text-red-300'],
                ['high', 'High', 'bg-orange-500', 'text-orange-600 dark:text-orange-300'],
                ['medium', 'Medium', 'bg-amber-500', 'text-amber-700 dark:text-amber-300'],
                ['low', 'Low', 'bg-emerald-500', 'text-emerald-600 dark:text-emerald-300'],
              ] as const).map(([key, label, bar, text]) => {
                const count = severityCounts[key] || 0;
                const max = Math.max(1, gradedFindings);
                return (
                  <div key={key} className="flex items-center gap-3">
                    <span className="w-14 shrink-0 text-[10px] font-black uppercase tracking-widest text-[var(--qg-text-muted)]">{label}</span>
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-[var(--qg-muted-panel)]">
                      <div className={`h-full rounded-full ${bar}`} style={{ width: `${(count / max) * 100}%` }} />
                    </div>
                    <span className={`w-7 shrink-0 text-right text-[11px] font-black ${text}`}>{numberFmt(count)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      <section className={`${panelClass} p-4 md:p-5`}>
        <div className="mb-5 flex flex-col gap-3 border-b border-[var(--qg-card-border)] pb-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-[var(--qg-amber)]">{activeView}</div>
            <h2 className="mt-1 text-xl font-black text-[var(--qg-dashboard-text)]">{VIEW_COPY[activeView].title}</h2>
            <p className="mt-1 max-w-3xl text-xs leading-relaxed text-[var(--qg-dashboard-text-soft)]">{VIEW_COPY[activeView].description}</p>
            <p className="mt-1 text-[10px] font-bold uppercase tracking-wider text-[var(--qg-text-muted)]">{VIEW_COPY[activeView].criterion}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className={`${subtlePanelClass} px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)]`}>
              {numberFmt(filteredAssets.length)} shown of {numberFmt(assets.length)}
            </span>
            {selectedAssets.length > 0 && (
              <span className="rounded-md border border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[var(--qg-amber)]">
                {numberFmt(selectedAssets.length)} selected
              </span>
            )}
            <button
              type="button"
              onClick={refresh}
              className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-3 py-2 text-xs font-bold text-[var(--qg-dashboard-text-soft)]"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              Sync Now
            </button>
          </div>
        </div>

        <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--qg-text-muted)]" />
            <input
              type="text"
              placeholder="Search assets, algorithms, domains, IP addresses..."
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              className="w-full rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] py-2.5 pl-10 pr-4 text-sm text-[var(--qg-dashboard-text)] outline-none transition placeholder:text-[var(--qg-text-muted)] focus:border-[var(--qg-amber)]/50"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            {riskLevels.map((level) => (
              <button
                key={level}
                type="button"
                onClick={() => setRiskFilter(riskFilter === level ? null : level)}
                className={`inline-flex items-center gap-2 rounded-md border px-3 py-2 text-[10px] font-black uppercase tracking-widest transition ${
                  riskFilter === level
                    ? 'border-[var(--qg-amber)]/60 bg-[var(--qg-amber)]/15 text-[var(--qg-amber)]'
                    : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)] hover:border-[var(--qg-amber)]/40 hover:text-[var(--qg-dashboard-text)]'
                }`}
              >
                <Filter className="h-3.5 w-3.5" /> {level}
                <span className="font-mono text-[var(--qg-text-muted)]">{numberFmt(riskSummary[level])}</span>
              </button>
            ))}
            {filtersActive && (
              <button
                type="button"
                onClick={() => { setSearchQuery(''); setRiskFilter(null); setActiveView('All Assets'); }}
                className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-[10px] font-black uppercase tracking-widest text-[var(--qg-dashboard-text-soft)] transition hover:border-[var(--qg-amber)]/40"
              >
                Reset
              </button>
            )}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[1040px] border-separate border-spacing-y-2 text-left">
            <thead>
              <tr>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">
                  <div className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={allVisibleSelected}
                      onChange={toggleVisibleSelection}
                      disabled={filteredAssets.length === 0}
                      aria-label="Select all visible assets"
                      className="h-4 w-4 rounded border-[var(--qg-card-border)] accent-[var(--qg-amber)]"
                    />
                    Asset Name
                  </div>
                </th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Type</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Domain / URL / IP</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Findings</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Risk Score</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Compliance</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Lifecycle</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Last Scanned</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading && assets.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-12 text-center text-xs font-black uppercase tracking-widest text-[var(--qg-amber)]">
                    <Loader2 className="mr-2 inline h-5 w-5 animate-spin" /> Loading Asset Inventory
                  </td>
                </tr>
              ) : assets.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-14 text-center">
                    <div className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-full border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]">
                      <ShieldAlert className="h-5 w-5" />
                    </div>
                    <div className="mb-4 text-xs font-black uppercase tracking-widest text-[var(--qg-text-muted)]">
                      No authorized assets scanned yet. Start a scan to build your cryptographic asset inventory.
                    </div>
                    <Link to="/dashboard/scanner" className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-[var(--qg-amber)]">
                      <ExternalLink className="h-3.5 w-3.5" /> Start Authorized Scan
                    </Link>
                  </td>
                </tr>
              ) : filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-12 text-center text-xs font-black uppercase tracking-widest text-[var(--qg-text-muted)]">
                    No assets match the current view, search or filter.
                  </td>
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
                      className={`group cursor-pointer bg-[var(--qg-card-bg)] outline-none transition-all hover:bg-[var(--qg-card-bg-strong)] focus-visible:ring-2 focus-visible:ring-[var(--qg-focus-ring)] ${isExpanded ? 'bg-[var(--qg-card-bg-strong)]' : ''}`}
                    >
                      <td className={`rounded-l-lg border-y border-l p-4 ${isExpanded ? 'border-[var(--qg-amber)]/40' : 'border-[var(--qg-card-border)]'}`}>
                        <div className="flex items-center gap-3">
                          <input
                            type="checkbox"
                            checked={selectedAssetIds.has(asset.id)}
                            onClick={(event) => event.stopPropagation()}
                            onChange={() => toggleAssetSelection(asset.id)}
                            aria-label={`Select ${asset.name} for export`}
                            className="h-4 w-4 shrink-0 rounded border-[var(--qg-card-border)] accent-[var(--qg-amber)]"
                          />
                          <div className="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]">
                            <Icon className="h-4 w-4" />
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <div className="truncate text-sm font-black text-[var(--qg-dashboard-text)] transition-colors group-hover:text-[var(--qg-amber)]">{asset.name}</div>
                              <ChevronDown className={`h-3.5 w-3.5 shrink-0 text-[var(--qg-amber)] transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                            </div>
                            <div className="mt-1 flex items-center gap-2 text-[10px] font-mono text-[var(--qg-text-muted)]">
                              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/80" />
                              {asset.status || 'active'}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className={`border-y p-4 ${isExpanded ? 'border-[var(--qg-amber)]/40' : 'border-[var(--qg-card-border)]'}`}>
                        <span className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-2 py-1 text-[10px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)]">
                          {labelize(asset.type)}
                        </span>
                      </td>
                      <td className={`border-y p-4 text-xs font-mono text-[var(--qg-dashboard-text-soft)] ${isExpanded ? 'border-[var(--qg-amber)]/40' : 'border-[var(--qg-card-border)]'}`}>
                        <div className="max-w-[260px] truncate">{assetTarget(asset)}</div>
                      </td>
                      <td className={`border-y p-4 ${isExpanded ? 'border-[var(--qg-amber)]/40' : 'border-[var(--qg-card-border)]'}`}>
                        <div className="flex items-center gap-3">
                          <span className={`inline-flex min-w-10 justify-center rounded-md border px-2 py-1 text-[10px] font-black ${vulnerable.length ? 'border-red-500/30 bg-red-500/12 text-red-600 dark:text-red-300' : 'border-emerald-500/30 bg-emerald-500/12 text-emerald-600 dark:text-emerald-300'}`}>
                            {vulnerable.length}
                          </span>
                          <div className="min-w-0">
                            <div className="text-[10px] font-black uppercase tracking-widest text-[var(--qg-dashboard-text-soft)]">
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
                                  ['critical', 'C', 'border-red-500/25 bg-red-500/15 text-red-600 dark:text-red-300'],
                                  ['high', 'H', 'border-orange-500/25 bg-orange-500/15 text-orange-600 dark:text-orange-300'],
                                  ['medium', 'M', 'border-amber-500/25 bg-amber-500/15 text-amber-700 dark:text-amber-300'],
                                  ['low', 'L', 'border-emerald-500/25 bg-emerald-500/15 text-emerald-600 dark:text-emerald-300'],
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
                      <td className={`border-y p-4 ${isExpanded ? 'border-[var(--qg-amber)]/40' : 'border-[var(--qg-card-border)]'}`}>
                        <div className="flex items-center gap-2">
                          <div className={`text-xs font-black ${riskColor(asset.riskScore)}`}>{asset.riskScore}/100</div>
                          <div className="h-1.5 w-20 overflow-hidden rounded-full bg-[var(--qg-muted-panel)]">
                            <div className={`h-full ${riskBar(asset.riskScore)}`} style={{ width: `${asset.riskScore}%` }} />
                          </div>
                        </div>
                        <div className="mt-1 text-[9px] text-[var(--qg-text-muted)]">Q-Score {asset.qScore}/100</div>
                      </td>
                      <td className={`border-y p-4 ${isExpanded ? 'border-[var(--qg-amber)]/40' : 'border-[var(--qg-card-border)]'}`}>
                        <span className={`rounded-md border px-2 py-1 text-[9px] font-black uppercase tracking-widest ${vulnerable.length > 0 ? 'border-red-500/25 bg-red-500/12 text-red-600 dark:text-red-300' : 'border-emerald-500/25 bg-emerald-500/12 text-emerald-600 dark:text-emerald-300'}`}>
                          {asset.complianceStatus}
                        </span>
                      </td>
                      <td className={`border-y p-4 ${isExpanded ? 'border-[var(--qg-amber)]/40' : 'border-[var(--qg-card-border)]'}`}>
                        {(() => {
                          const lifecycle = lifecycleByAsset.get(String(asset.name || '').toLowerCase());
                          if (!lifecycle) return <span className="text-[10px] text-[var(--qg-text-muted)]">—</span>;
                          const stageTone =
                            lifecycle.stageId === 'monitoring'
                              ? 'border-emerald-500/25 bg-emerald-500/12 text-emerald-600 dark:text-emerald-300'
                              : lifecycle.stageId === 'execution'
                                ? 'border-cyan-500/25 bg-cyan-500/12 text-cyan-600 dark:text-cyan-300'
                                : lifecycle.stageId === 'validation'
                                  ? 'border-blue-500/25 bg-blue-500/12 text-blue-600 dark:text-blue-300'
                                  : 'border-amber-500/25 bg-amber-500/12 text-amber-700 dark:text-amber-300';
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
                      <td className={`border-y p-4 text-[10px] font-mono text-[var(--qg-text-muted)] ${isExpanded ? 'border-[var(--qg-amber)]/40' : 'border-[var(--qg-card-border)]'}`}>{formatDate(asset.lastScanned)}</td>
                      <td className={`rounded-r-lg border-y border-r p-4 ${isExpanded ? 'border-[var(--qg-amber)]/40' : 'border-[var(--qg-card-border)]'}`}>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            aria-expanded={isExpanded}
                            onClick={(event) => {
                              event.stopPropagation();
                              setExpandedAssetId(isExpanded ? null : asset.id);
                            }}
                            className="inline-flex items-center gap-1 rounded-md border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 px-2 py-1 text-[10px] font-black uppercase text-[var(--qg-amber)] transition hover:border-[var(--qg-amber)]/60"
                          >
                            <Eye className="h-3 w-3" /> {isExpanded ? 'Hide' : 'Details'}
                          </button>
                          <Link onClick={(event) => event.stopPropagation()} to="/dashboard/cbom" className="text-[10px] font-black uppercase text-[var(--qg-amber)] hover:underline">CBOM</Link>
                          <Link onClick={(event) => event.stopPropagation()} to="/dashboard/scanner" className="text-[10px] font-black uppercase text-[var(--qg-text-muted)] transition hover:text-[var(--qg-amber)]">Rescan</Link>
                        </div>
                      </td>
                    </motion.tr>

                    {isExpanded && (
                      <motion.tr initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
                        <td colSpan={9} className="p-0">
                          <div className="mx-1 mb-3 rounded-lg border border-[var(--qg-amber)]/25 bg-[var(--qg-muted-panel)] p-5">
                            <div className="grid gap-5 xl:grid-cols-[0.9fr_2.1fr]">
                              <div className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] p-4">
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
                                    <div key={label} className="flex items-start justify-between gap-4 border-t border-[var(--qg-card-border)] pt-3">
                                      <span className="font-black uppercase tracking-widest text-[var(--qg-text-muted)]">{label}</span>
                                      <span className="max-w-[220px] text-right font-mono text-[var(--qg-dashboard-text-soft)]">{value}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>

                              <div>
                                <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                                  <div>
                                    <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text)]">Vulnerable Cryptographic Components</h3>
                                    <p className="mt-1 text-xs text-[var(--qg-dashboard-text-soft)]">
                                      Counted at the component level — the same unit the CBOM Explorer and Quantum Readiness Engine use.
                                      {signalCount > 0 ? ` Backed by ${signalCount} raw detection signal${signalCount === 1 ? '' : 's'}.` : ''}
                                    </p>
                                  </div>
                                  <div className="flex flex-wrap gap-2">
                                    <span className="rounded-md border border-red-500/25 bg-red-500/12 px-2 py-1 text-[10px] font-black uppercase text-red-600 dark:text-red-300">{vulnerable.length} vulnerable</span>
                                    <span className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-2 py-1 text-[10px] font-black uppercase text-[var(--qg-text-muted)]">{cryptoInventory.length} total</span>
                                    {pqcReadyCount > 0 && (
                                      <span className="rounded-md border border-emerald-500/25 bg-emerald-500/12 px-2 py-1 text-[10px] font-black uppercase text-emerald-600 dark:text-emerald-300">{pqcReadyCount} PQC-ready</span>
                                    )}
                                    {signalCount > 0 && (
                                      <span className="rounded-md border border-[var(--qg-cyan)]/25 bg-[var(--qg-cyan)]/10 px-2 py-1 text-[10px] font-black uppercase text-[var(--qg-cyan)]">{signalCount} signals</span>
                                    )}
                                  </div>
                                </div>

                                {vulnerable.length === 0 ? (
                                  <div className="rounded-md border border-emerald-500/25 bg-emerald-500/10 p-4 text-sm font-semibold text-emerald-700 dark:text-emerald-200">
                                    No vulnerable cryptographic components are currently detected for this asset. Continue monitoring and rescan after configuration changes.
                                  </div>
                                ) : (
                                  <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
                                    {vulnerable.slice(0, 12).map((item, index) => {
                                      const componentSignals = signalsForComponent(asset, item);
                                      return (
                                      <div key={item.id || `${asset.id}-vuln-${index}`} className="rounded-md border border-red-500/25 bg-red-500/[0.07] p-4">
                                        <div className="mb-3 flex items-start justify-between gap-3">
                                          <div className="min-w-0">
                                            <div className="truncate text-sm font-black text-[var(--qg-dashboard-text)]">{cryptoLabel(item)}</div>
                                            <div className="mt-1 text-[10px] font-bold uppercase tracking-widest text-[var(--qg-text-muted)]">{labelize(item.item_type || item.protocol || 'cryptography')}</div>
                                          </div>
                                          <div className="flex shrink-0 flex-wrap justify-end gap-2">
                                            <span className={`rounded border px-2 py-0.5 text-[9px] font-black uppercase ${severityClasses(item.exposure_level, item.is_vulnerable)}`}>
                                              {labelize(item.exposure_level || 'vulnerable')}
                                            </span>
                                            <Link
                                              to={remediationHref(asset, item)}
                                              onClick={(event) => event.stopPropagation()}
                                              className="inline-flex items-center gap-1 rounded border border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 px-2 py-0.5 text-[9px] font-black uppercase tracking-wider text-[var(--qg-amber)] transition hover:border-[var(--qg-amber)]/70"
                                            >
                                              <ExternalLink className="h-3 w-3" /> Remediate
                                            </Link>
                                          </div>
                                        </div>
                                        <p className="line-clamp-2 text-xs leading-relaxed text-[var(--qg-dashboard-text-soft)]">
                                          {metadataText(item, 'evidence', 'Scanner marked this cryptographic component as vulnerable or migration-sensitive.')}
                                        </p>
                                        <div className="mt-3 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] p-3">
                                          <div className="text-[9px] font-black uppercase tracking-widest text-[var(--qg-amber)]">Recommended action</div>
                                          <div className="mt-1 text-xs font-semibold leading-relaxed text-[var(--qg-dashboard-text-soft)]">
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

                            <div className="mt-5 border-t border-[var(--qg-card-border)] pt-4">
                              <div className="mb-3 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Observed Cryptography</div>
                              <div className="flex flex-wrap gap-2">
                                {cryptoInventory.length === 0 ? (
                                  <span className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-1.5 text-[10px] font-bold text-[var(--qg-text-muted)]">Manual review required</span>
                                ) : visibleCryptoInventory.map((item, index) => (
                                  <span key={item.id || `${asset.id}-crypto-${index}`} className={`rounded-md border px-3 py-1.5 text-[10px] font-bold ${item.is_vulnerable ? 'border-red-500/25 bg-red-500/12 text-red-600 dark:text-red-300' : 'border-emerald-500/25 bg-emerald-500/12 text-emerald-600 dark:text-emerald-300'}`}>
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
                                    className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)] transition hover:border-[var(--qg-amber)]/45 hover:text-[var(--qg-amber)]"
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
      </section>
    </div>
  );
}
