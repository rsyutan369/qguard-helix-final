import { Fragment, useMemo, useState } from 'react';
import { Search, Filter, Shield, AlertTriangle, ChevronRight, ChevronDown, Globe, Server, Loader2, RefreshCw, ExternalLink, Eye, Download } from 'lucide-react';
import { motion } from 'framer-motion';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { useMigrationWorkflow } from '@/hooks/use-migration-workflow';

type RiskLevel = 'critical' | 'high' | 'medium' | 'low';
type ExportFormat = 'csv' | 'json' | 'pdf';

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

const GLASS_PANEL_CLASSES = 'group relative overflow-hidden rounded-xl border border-slate-200/80 bg-white/72 text-slate-950 shadow-[inset_0_1px_0_rgba(255,255,255,0.92),0_18px_45px_rgba(15,23,42,0.08)] backdrop-blur-xl transition-all duration-500 hover:-translate-y-1 hover:border-cyan-300/80 hover:bg-white/88 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.95),0_22px_55px_rgba(15,23,42,0.12),0_0_42px_rgba(0,197,235,0.18)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-cyan-300/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(0,197,235,0.55)] group-hover:before:via-cyan-300 after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-cyan-300/12 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-cyan-300/20 group-hover:after:blur-[36px] dark:border-[#FFD36B]/20 dark:bg-[#0f1428]/45 dark:text-white dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] dark:hover:border-[#FFD36B]/70 dark:hover:bg-[#0f1428]/65 dark:hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] dark:before:via-[#FFF4C0]/70 dark:group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] dark:group-hover:before:via-[#FFF4C0] dark:after:bg-[#FFD36B]/10 dark:group-hover:after:bg-[#FFD36B]/25';

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
  if (inventory.length > 0) return mergeVulnerabilityItems(inventory);
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

function assetRiskLevel(asset: AssetRecord): RiskLevel {
  const inventory = Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory : [];
  const hasVulnerableComponent = inventory.some((item) => Boolean(item.is_vulnerable && !item.is_quantum_safe));
  const levels = [
    riskLevelFromScore(Number(asset.riskScore || 0)),
    normalizeRiskLevel(asset.riskLevel),
    hasVulnerableComponent ? 'medium' as RiskLevel : null,
    ...inventory.map((item) => (
      normalizeRiskLevel(item.exposure_level) ||
      normalizeRiskLevel(item.metadata?.severity) ||
      normalizeRiskLevel(item.metadata?.threatLevel) ||
      normalizeRiskLevel(item.metadata?.riskSeverity) ||
      (item.is_vulnerable ? 'medium' : null)
    )),
  ];
  return highestRiskLevel(levels);
}

function exportFileName(format: ExportFormat) {
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  return `qguard-assets-findings-${stamp}.${format}`;
}

function csvCell(value: unknown) {
  const text = String(value ?? '').replace(/\r?\n/g, ' ');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function exportRows(selectedAssets: AssetRecord[]) {
  return selectedAssets.flatMap((asset) => {
    const inventory = Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory : [];
    const rows = inventory.length ? inventory : [null];
    return rows.map((item) => ({
      assetId: asset.id,
      assetName: asset.name,
      type: labelize(asset.type),
      target: assetTarget(asset),
      riskLevel: assetRiskLevel(asset).toUpperCase(),
      riskScore: asset.riskScore,
      qScore: asset.qScore,
      compliance: asset.complianceStatus,
      status: asset.status,
      lastScanned: formatDate(asset.lastScanned),
      findingId: item?.id || '',
      algorithm: item ? cryptoLabel(item) : '',
      category: item ? labelize(item.item_type || item.protocol || 'cryptography') : '',
      exposureLevel: item ? labelize(item.exposure_level || (item.is_vulnerable ? 'vulnerable' : 'safe')) : '',
      vulnerable: item ? Boolean(item.is_vulnerable) : false,
      quantumSafe: item ? Boolean(item.is_quantum_safe) : false,
      evidence: item ? metadataText(item, 'evidence', '') : '',
      recommendation: item ? metadataText(item, 'recommendation', '') : '',
    }));
  });
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function exportCsv(selectedAssets: AssetRecord[]) {
  const rows = exportRows(selectedAssets);
  const headers = [
    'assetId',
    'assetName',
    'type',
    'target',
    'riskLevel',
    'riskScore',
    'qScore',
    'compliance',
    'status',
    'lastScanned',
    'findingId',
    'algorithm',
    'category',
    'exposureLevel',
    'vulnerable',
    'quantumSafe',
    'evidence',
    'recommendation',
  ];
  const csv = [
    headers.join(','),
    ...rows.map((row) => headers.map((header) => csvCell(row[header as keyof typeof row])).join(',')),
  ].join('\n');
  downloadBlob(new Blob([csv], { type: 'text/csv;charset=utf-8' }), exportFileName('csv'));
}

function exportJson(selectedAssets: AssetRecord[]) {
  const payload = {
    generatedAt: new Date().toISOString(),
    assetCount: selectedAssets.length,
    findingRows: exportRows(selectedAssets).length,
    assets: selectedAssets.map((asset) => ({
      ...asset,
      computedRiskLevel: assetRiskLevel(asset),
      target: assetTarget(asset),
      vulnerableComponents: vulnerableComponents(asset),
      detectionSignals: detectionSignals(asset),
    })),
  };
  downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' }), exportFileName('json'));
}

function pdfSafe(value: unknown) {
  return String(value ?? '')
    .normalize('NFKD')
    .replace(/[^\x20-\x7E]/g, '')
    .replace(/[\\()]/g, '\\$&');
}

function wrapPdfLine(value: string, maxLength = 92) {
  const words = value.split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    const next = current ? `${current} ${word}` : word;
    if (next.length > maxLength && current) {
      lines.push(current);
      current = word;
    } else {
      current = next;
    }
  }
  if (current) lines.push(current);
  return lines.length ? lines : [''];
}

function buildPdf(selectedAssets: AssetRecord[]) {
  const lines: string[] = [
    'QGuard Asset Inventory and Findings Report',
    `Generated: ${new Date().toLocaleString()}`,
    `Assets: ${selectedAssets.length}`,
    '',
  ];
  for (const asset of selectedAssets) {
    const components = vulnerableComponents(asset);
    const signals = detectionSignals(asset);
    const totalComponents = Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory.length : 0;
    lines.push(`${asset.name} | ${assetRiskLevel(asset).toUpperCase()} | Risk ${asset.riskScore}/100 | ${assetTarget(asset)}`);
    lines.push(`Compliance: ${asset.complianceStatus} | Components: ${totalComponents} | Vulnerable components: ${components.length} | Detection signals: ${signals.length}`);
    if (components.length === 0) {
      lines.push('No vulnerable cryptographic components currently detected.');
    } else {
      for (const item of components.slice(0, 8)) {
        const evidenceCount = signalsForComponent(asset, item).length;
        lines.push(`- ${cryptoLabel(item)} | ${labelize(item.exposure_level || 'vulnerable')}${evidenceCount > 0 ? ` | ${evidenceCount} detection signal(s)` : ''}`);
        lines.push(`  Recommendation: ${metadataText(item, 'recommendation', 'Review against NIST PQC migration policy.')}`);
      }
      if (components.length > 8) lines.push(`  +${components.length - 8} additional vulnerable component(s).`);
    }
    lines.push('');
  }

  const pageLines: string[][] = [];
  let currentPage: string[] = [];
  for (const line of lines.flatMap((line) => wrapPdfLine(line))) {
    if (currentPage.length >= 50) {
      pageLines.push(currentPage);
      currentPage = [];
    }
    currentPage.push(line);
  }
  if (currentPage.length) pageLines.push(currentPage);

  const objects: string[] = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  const pageIds: number[] = [];
  for (const [pageIndex, page] of pageLines.entries()) {
    const content = [
      'q',
      'BT',
      '/F1 16 Tf',
      `42 752 Td (${pdfSafe(pageIndex === 0 ? page[0] : 'QGuard Asset Inventory and Findings Report')}) Tj`,
      'ET',
      ...page.slice(pageIndex === 0 ? 1 : 0).map((line, index) => `BT /F1 ${line.startsWith('- ') || line.startsWith('  ') ? 9 : 10} Tf 42 ${724 - index * 13} Td (${pdfSafe(line)}) Tj ET`),
      'Q',
    ].join('\n');
    const pageId = objects.length + 1;
    const contentId = pageId + 1;
    pageIds.push(pageId);
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`);
    objects.push(`<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
  }
  objects[1] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageIds.length} >>`;

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets[index + 1] = pdf.length;
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  pdf += offsets.slice(1).map((offset) => `${String(offset).padStart(10, '0')} 00000 n \n`).join('');
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return new Blob([pdf], { type: 'application/pdf' });
}

function exportPdf(selectedAssets: AssetRecord[]) {
  downloadBlob(buildPdf(selectedAssets), exportFileName('pdf'));
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
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | null>(null);
  const [expandedAssetId, setExpandedAssetId] = useState<string | null>(null);
  const [expandedCryptoAssetIds, setExpandedCryptoAssetIds] = useState<Set<string>>(() => new Set());
  const [exportOpen, setExportOpen] = useState(false);
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

  const handleExport = (format: ExportFormat) => {
    if (exportAssets.length === 0) return;
    if (format === 'csv') exportCsv(exportAssets);
    if (format === 'json') exportJson(exportAssets);
    if (format === 'pdf') exportPdf(exportAssets);
    setExportOpen(false);
  };

  return (
    <div className="p-6 lg:p-8 space-y-6 min-h-screen">
      <WorkflowRail activeStage="discovery" tone="adaptive" />
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black uppercase tracking-tight text-slate-950 dark:text-white">Asset <span className="text-gold">Inventory</span></h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-white/50">Authorized cryptographic assets discovered from real scanner results.</p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] font-black uppercase tracking-widest">
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${connected ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:border-emerald-400/30 dark:text-emerald-300' : 'border-slate-300/60 bg-slate-100/60 text-slate-500 dark:border-white/12 dark:bg-white/[0.03] dark:text-white/40'}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-slate-400'}`} />
              {connected ? 'Live Telemetry' : 'Cached'}
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-500/25 bg-cyan-500/8 px-2 py-0.5 text-cyan-600 dark:border-cyan-400/25 dark:text-cyan-300">
              <Shield className="h-3 w-3" /> Reconciled with Quantum Readiness Engine
            </span>
          </div>
        </div>
        <div className="flex flex-wrap justify-end gap-2">
          <div className="relative">
            <button
              type="button"
              onClick={() => setExportOpen((value) => !value)}
              disabled={exportAssets.length === 0}
              className="flex items-center gap-2 rounded-lg border border-gold/25 bg-gold/10 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-gold transition hover:border-gold/60 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Download className="h-3.5 w-3.5" />
              Export {selectedAssets.length > 0 ? `${selectedAssets.length} selected` : `${filteredAssets.length} shown`}
            </button>
            {exportOpen && (
              <div className="absolute right-0 top-full z-40 mt-2 w-56 overflow-hidden rounded-lg border border-slate-200 bg-white shadow-2xl dark:border-gold/20 dark:bg-[#070b18]">
                {[
                  ['csv', 'CSV spreadsheet'],
                  ['json', 'JSON evidence bundle'],
                  ['pdf', 'Professional PDF'],
                ].map(([format, label]) => (
                  <button
                    key={format}
                    type="button"
                    onClick={() => handleExport(format as ExportFormat)}
                    className="block w-full px-4 py-3 text-left text-[11px] font-black uppercase tracking-wider text-slate-600 transition hover:bg-gold/10 hover:text-gold dark:text-white/65"
                  >
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
          <button onClick={refresh} className="flex items-center gap-2 rounded-lg border border-gold/20 bg-gold/10 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-gold">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </header>

      {error && <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm text-red-600 dark:text-red-300">{error}</div>}

      <div className="flex flex-col lg:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-white/30" />
          <input
            type="text"
            placeholder="Search assets, algorithms, domains, IP addresses..."
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white/78 py-2.5 pl-10 pr-4 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-gold/50 dark:border-gold/20 dark:bg-[#0f1428]/35 dark:text-white dark:placeholder:text-white/25"
          />
        </div>
        <div className="flex gap-2 flex-wrap text-gold">
          {riskLevels.map((level) => (
            <button key={level} onClick={() => setRiskFilter(riskFilter === level ? null : level)} className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-[10px] font-black uppercase tracking-widest transition-colors ${riskFilter === level ? 'border-gold/60 bg-gold/15 text-gold' : 'border-slate-200 bg-white/70 text-slate-600 hover:border-cyan-300 hover:text-slate-950 dark:border-white/10 dark:bg-[#0f1428]/35 dark:text-white/45 dark:hover:text-white/70'}`}>
              <Filter className="h-3.5 w-3.5" /> {level} <span className="font-mono text-slate-400 dark:text-white/35">{riskSummary[level]}</span>
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
            color: 'text-slate-950 dark:text-white',
            icon: Server,
          },
          {
            label: 'Quantum-Vulnerable Components',
            value: summary.vulnerableComponents,
            sub: 'Matches QR Engine & CBOM',
            color: 'text-red-600 dark:text-red-400',
            icon: AlertTriangle,
          },
          {
            label: 'Cryptographic Components',
            value: summary.totalComponents,
            sub: `${summary.pqcReadyComponents} PQC-ready`,
            color: 'text-gold',
            icon: Shield,
          },
          {
            label: 'PQC Readiness',
            value: `${summary.pqcReadiness}%`,
            sub: `Q-Score ${summary.qScore}/100`,
            color: 'text-emerald-600 dark:text-green-400',
            icon: Shield,
          },
        ].map((item) => (
          <div key={item.label} className={GLASS_PANEL_CLASSES + " p-4"}>
            <div className="flex items-center gap-2 mb-2 relative z-10">
              <item.icon className="h-3.5 w-3.5 text-gold/60 dark:text-gold/50" />
              <span className="text-[10px] font-black uppercase tracking-[0.15em] text-slate-500 dark:text-white/40">{item.label}</span>
            </div>
            <div className={`text-2xl font-black relative z-10 ${item.color}`}>{item.value}</div>
            <div className="mt-1 text-[10px] font-mono text-slate-500 dark:text-white/32 relative z-10">{item.sub}</div>
          </div>
        ))}
      </div>

      {/* Platform Posture — canonical tenant-wide crypto posture straight from the
          shared scanner-intelligence snapshot. These are the exact figures the
          Quantum Readiness & Assessment Engine renders, so the Assets page can be
          reconciled against QR at a glance. */}
      <div className={GLASS_PANEL_CLASSES + ' p-5'}>
        <div className="relative z-10 grid gap-6 lg:grid-cols-[1.1fr_1.3fr_1.3fr]">
          <div>
            <div className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500 dark:text-white/40">Quantum Readiness</div>
            <div className="mt-2 flex items-end gap-2">
              <span className="text-4xl font-black text-emerald-600 dark:text-green-400">{summary.pqcReadiness}%</span>
              <span className="mb-1 text-[10px] font-mono text-slate-500 dark:text-white/35">of {summary.totalComponents} components</span>
            </div>
            <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-white/10">
              <div className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-green-400" style={{ width: `${Math.min(100, summary.pqcReadiness)}%` }} />
            </div>
            <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-white/32">
              <span>{summary.pqcReadyComponents} PQC-ready</span>
              <span className="text-red-600 dark:text-red-400">{summary.vulnerableComponents} vulnerable</span>
            </div>
          </div>

          <div>
            <div className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500 dark:text-white/40">Risk Posture</div>
            <div className="mt-3 grid grid-cols-2 gap-3">
              {[
                { label: 'Risk Score', value: `${summary.riskScore}/100`, color: riskColor(summary.riskScore) },
                { label: 'Q-Score', value: `${summary.qScore}/100`, color: 'text-cyan-600 dark:text-cyan-300' },
                { label: 'Vulnerable Assets', value: `${summary.vulnerableAssets}/${summary.totalAssets || assets.length}`, color: 'text-red-600 dark:text-red-400' },
                { label: 'Critical Findings', value: summary.criticalFindings, color: 'text-orange-600 dark:text-orange-400' },
              ].map((metric) => (
                <div key={metric.label} className="rounded-lg border border-slate-200/80 bg-white/70 p-3 dark:border-white/8 dark:bg-white/[0.02]">
                  <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">{metric.label}</div>
                  <div className={`mt-1 text-lg font-black ${metric.color}`}>{metric.value}</div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between">
              <div className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500 dark:text-white/40">Detection Severity</div>
              <span className="text-[10px] font-mono text-slate-500 dark:text-white/32">{summary.totalFindings} signals</span>
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
                    <span className="w-14 shrink-0 text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-white/40">{label}</span>
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-200 dark:bg-white/10">
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
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/50">
                  <div className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={allVisibleSelected}
                      onChange={toggleVisibleSelection}
                      disabled={filteredAssets.length === 0}
                      aria-label="Select all visible assets"
                      className="h-4 w-4 rounded border-slate-300 bg-white accent-[#FFD36B] dark:border-gold/35 dark:bg-[#050816]"
                    />
                    Asset Name
                  </div>
                </th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/50">Type</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/50">Domain / URL / IP</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/50">Findings</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/50">Risk Score</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/50">Compliance</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/50">Lifecycle</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/50">Last Scanned</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/50">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={9} className="p-12 text-center text-gold/50 font-black uppercase tracking-widest">
                    <Loader2 className="h-5 w-5 animate-spin inline mr-2" /> Loading Asset Inventory
                  </td>
                </tr>
              ) : assets.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-14 text-center">
                    <div className="mb-4 text-xs font-black uppercase tracking-widest text-slate-500 dark:text-white/30">
                      No authorized assets scanned yet. Start a scan to build your cryptographic asset inventory.
                    </div>
                    <a href="/dashboard/scanner" className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-gold/30 bg-gold/10 text-gold text-[10px] font-black uppercase tracking-wider">
                      <ExternalLink className="h-3.5 w-3.5" /> Start Authorized Scan
                    </a>
                  </td>
                </tr>
              ) : filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-12 text-center uppercase tracking-widest text-slate-500 dark:text-white/30">No assets match the current search or filter.</td>
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
                      <td className="rounded-l-xl border-y border-l border-slate-200/80 p-4 dark:border-white/8">
                        <div className="flex items-center gap-3">
                          <input
                            type="checkbox"
                            checked={selectedAssetIds.has(asset.id)}
                            onClick={(event) => event.stopPropagation()}
                            onChange={() => toggleAssetSelection(asset.id)}
                            aria-label={`Select ${asset.name} for export`}
                            className="h-4 w-4 shrink-0 rounded border-slate-300 bg-white accent-[#FFD36B] dark:border-gold/35 dark:bg-[#050816]"
                          />
                          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-gold/25 bg-gold/10 text-gold shadow-[0_0_20px_rgba(255,211,107,0.10)]">
                            <Icon className="h-4 w-4" />
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <div className="truncate text-sm font-black text-slate-950 transition-colors group-hover:text-gold dark:text-white">{asset.name}</div>
                              <ChevronDown className={`h-3.5 w-3.5 shrink-0 text-gold/70 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                            </div>
                            <div className="mt-1 flex items-center gap-2 text-[10px] font-mono text-slate-500 dark:text-white/32">
                              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/80" />
                              {asset.status || 'active'}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="border-y border-slate-200/80 p-4 dark:border-white/8">
                        <span className="rounded-md border border-slate-200 bg-slate-50/80 px-2 py-1 text-[10px] font-black uppercase tracking-wider text-slate-700 dark:border-white/10 dark:bg-white/[0.03] dark:text-white/62">
                          {labelize(asset.type)}
                        </span>
                      </td>
                      <td className="border-y border-slate-200/80 p-4 text-xs font-mono text-slate-600 dark:border-white/8 dark:text-white/50">
                        <div className="max-w-[260px] truncate">{assetTarget(asset)}</div>
                      </td>
                      <td className="border-y border-slate-200/80 p-4 dark:border-white/8">
                        <div className="flex items-center gap-3">
                          <span className={`inline-flex min-w-10 justify-center rounded-md border px-2 py-1 text-[10px] font-black ${vulnerable.length ? 'border-red-500/30 bg-red-500/10 text-red-600 dark:border-red-400/35 dark:text-red-300' : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:border-emerald-400/30 dark:text-emerald-300'}`}>
                            {vulnerable.length}
                          </span>
                          <div className="min-w-0">
                            <div className="text-[10px] font-black uppercase tracking-widest text-slate-600 dark:text-white/58">
                              vulnerable of {cryptoInventory.length}
                            </div>
                            <div className="mt-1 truncate text-[10px] font-mono text-slate-500 dark:text-white/32">
                              {signalCount > 0
                                ? `${signalCount} detection signal${signalCount === 1 ? '' : 's'}`
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
                      <td className="border-y border-slate-200/80 p-4 dark:border-white/8">
                        <div className="flex items-center gap-2">
                          <div className={`text-xs font-black ${riskColor(asset.riskScore)}`}>{asset.riskScore}/100</div>
                          <div className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-200 dark:bg-white/10">
                            <div className={`h-full ${riskBar(asset.riskScore)}`} style={{ width: `${asset.riskScore}%` }} />
                          </div>
                        </div>
                        <div className="mt-1 text-[9px] text-slate-400 dark:text-white/25">Q-Score {asset.qScore}/100</div>
                      </td>
                      <td className="border-y border-slate-200/80 p-4 dark:border-white/8">
                        <span className={`rounded-md border px-2 py-1 text-[9px] font-black uppercase tracking-widest ${vulnerable.length > 0 ? 'border-red-500/25 bg-red-500/8 text-red-600 dark:border-red-400/25 dark:text-red-300' : 'border-emerald-500/25 bg-emerald-500/8 text-emerald-600 dark:border-emerald-400/25 dark:text-emerald-300'}`}>
                          {asset.complianceStatus}
                        </span>
                      </td>
                      <td className="border-y border-slate-200/80 p-4 dark:border-white/8">
                        {(() => {
                          const lifecycle = lifecycleByAsset.get(String(asset.name || '').toLowerCase());
                          if (!lifecycle) return <span className="text-[10px] text-slate-400 dark:text-white/25">—</span>;
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
                              <div className="text-[9px] text-slate-500 dark:text-white/35">
                                {lifecycle.openActions > 0 ? `${lifecycle.openActions} action${lifecycle.openActions === 1 ? '' : 's'}` : lifecycle.validationStatus}
                                {lifecycle.certificationImpactPct > 0 ? ` · +${lifecycle.certificationImpactPct}% cert` : ''}
                              </div>
                            </div>
                          );
                        })()}
                      </td>
                      <td className="border-y border-slate-200/80 p-4 text-[10px] font-mono text-slate-500 dark:border-white/8 dark:text-white/42">{formatDate(asset.lastScanned)}</td>
                      <td className="rounded-r-xl border-y border-r border-slate-200/80 p-4 dark:border-white/8">
                        <div className="flex items-center gap-2">
                          <button type="button" className="inline-flex items-center gap-1 rounded-md border border-gold/25 bg-gold/10 px-2 py-1 text-[10px] font-black uppercase text-gold transition hover:border-gold/60">
                            <Eye className="h-3 w-3" /> Details
                          </button>
                          <a onClick={(event) => event.stopPropagation()} href="/dashboard/cbom" className="text-[10px] font-black uppercase text-gold hover:underline">CBOM</a>
                          <a onClick={(event) => event.stopPropagation()} href="/dashboard/scanner" className="text-[10px] font-black uppercase text-slate-500 hover:text-gold dark:text-white/40">Rescan</a>
                        </div>
                      </td>
                    </motion.tr>

                    {isExpanded && (
                      <motion.tr initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
                        <td colSpan={9} className="p-0">
                          <div className="mx-2 mb-3 rounded-xl border border-slate-200/80 bg-slate-50/95 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.95),0_20px_45px_rgba(15,23,42,0.10)] dark:border-gold/18 dark:bg-[#070b18]/92 dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.06),0_20px_60px_rgba(0,0,0,0.32)]">
                            <div className="grid gap-5 xl:grid-cols-[0.9fr_2.1fr]">
                              <div className="rounded-lg border border-slate-200 bg-white/80 p-4 dark:border-white/8 dark:bg-white/[0.025]">
                                <div className="mb-4 flex items-center justify-between gap-3">
                                  <div>
                                    <div className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500 dark:text-white/35">Asset Profile</div>
                                    <div className="mt-1 text-lg font-black text-slate-950 dark:text-white">{asset.name}</div>
                                  </div>
                                  <span className={`rounded-md border px-2 py-1 text-[10px] font-black uppercase ${severityClasses(assetRiskLevel(asset), vulnerable.length > 0)}`}>
                                    {labelize(assetRiskLevel(asset))}
                                  </span>
                                </div>
                                <div className="grid gap-3 text-xs">
                                  {[
                                    ['Target', assetTarget(asset)],
                                    ['Type', labelize(asset.type)],
                                    ['Status', asset.status || 'active'],
                                    ['Last scanned', formatDate(asset.lastScanned)],
                                  ].map(([label, value]) => (
                                    <div key={label} className="flex items-start justify-between gap-4 border-t border-slate-200/80 pt-3 dark:border-white/6">
                                      <span className="font-black uppercase tracking-widest text-slate-500 dark:text-white/35">{label}</span>
                                      <span className="max-w-[220px] text-right font-mono text-slate-700 dark:text-white/68">{value}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>

                              <div>
                                <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                                  <div>
                                    <h3 className="text-xs font-black uppercase tracking-[0.2em] text-slate-950 dark:text-white">Vulnerable Cryptographic Components</h3>
                                    <p className="mt-1 text-xs text-slate-500 dark:text-white/45">
                                      Counted at the component level — the same unit the CBOM Explorer and Quantum Readiness Engine use.
                                      {signalCount > 0 ? ` Backed by ${signalCount} raw detection signal${signalCount === 1 ? '' : 's'}.` : ''}
                                    </p>
                                  </div>
                                  <div className="flex flex-wrap gap-2">
                                    <span className="rounded-md border border-red-500/25 bg-red-500/8 px-2 py-1 text-[10px] font-black uppercase text-red-600 dark:border-red-400/25 dark:text-red-300">{vulnerable.length} vulnerable</span>
                                    <span className="rounded-md border border-slate-200 bg-white/70 px-2 py-1 text-[10px] font-black uppercase text-slate-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-white/42">{cryptoInventory.length} total</span>
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
                                            <div className="truncate text-sm font-black text-slate-950 dark:text-white">{cryptoLabel(item)}</div>
                                            <div className="mt-1 text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-white/35">{labelize(item.item_type || item.protocol || 'cryptography')}</div>
                                          </div>
                                          <div className="flex shrink-0 flex-wrap justify-end gap-2">
                                            <span className={`rounded border px-2 py-0.5 text-[9px] font-black uppercase ${severityClasses(item.exposure_level, item.is_vulnerable)}`}>
                                              {labelize(item.exposure_level || 'vulnerable')}
                                            </span>
                                            <a
                                              href={remediationHref(asset, item)}
                                              onClick={(event) => event.stopPropagation()}
                                              className="inline-flex items-center gap-1 rounded border border-gold/35 bg-gold/10 px-2 py-0.5 text-[9px] font-black uppercase tracking-wider text-gold transition hover:border-gold/70 hover:bg-gold/15"
                                            >
                                              <ExternalLink className="h-3 w-3" /> Remediate
                                            </a>
                                          </div>
                                        </div>
                                        <p className="line-clamp-2 text-xs leading-relaxed text-slate-600 dark:text-white/58">
                                          {metadataText(item, 'evidence', 'Scanner marked this cryptographic component as vulnerable or migration-sensitive.')}
                                        </p>
                                        <div className="mt-3 rounded-md border border-slate-200 bg-white/80 p-3 dark:border-white/8 dark:bg-black/18">
                                          <div className="text-[9px] font-black uppercase tracking-widest text-gold/70">Recommended action</div>
                                          <div className="mt-1 text-xs font-semibold leading-relaxed text-slate-700 dark:text-white/68">
                                            {metadataText(item, 'recommendation', 'Review against the NIST PQC migration policy and assign remediation ownership.')}
                                          </div>
                                        </div>
                                        {componentSignals.length > 0 && (
                                          <div className="mt-2 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-slate-400 dark:text-white/30">
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
                                  <div className="mt-3 text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">
                                    +{vulnerable.length - 12} additional vulnerable component{vulnerable.length - 12 === 1 ? '' : 's'} available in CBOM.
                                  </div>
                                )}
                              </div>
                            </div>

                            <div className="mt-5 border-t border-slate-200/80 pt-4 dark:border-white/8">
                              <div className="mb-3 text-[10px] font-black uppercase tracking-[0.2em] text-slate-500 dark:text-white/35">Observed Cryptography</div>
                              <div className="flex flex-wrap gap-2">
                                {cryptoInventory.length === 0 ? (
                                  <span className="rounded-md border border-slate-200 bg-white/70 px-3 py-1.5 text-[10px] font-bold text-slate-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-white/40">Manual review required</span>
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
                                    className="rounded-md border border-slate-300 bg-white/80 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-slate-600 transition hover:border-gold/45 hover:text-gold dark:border-white/10 dark:bg-white/[0.03] dark:text-white/45 dark:hover:border-gold/45 dark:hover:text-gold"
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
    </div>
  );
}
