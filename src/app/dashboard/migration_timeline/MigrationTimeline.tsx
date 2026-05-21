'use client';

import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Circle,
  Clock,
  Database,
  Download,
  FileText,
  Gauge,
  Globe2,
  KeyRound,
  Layers,
  ListChecks,
  Network,
  Play,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  ShieldX,
  Target,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';

type TimelineStatus = 'completed' | 'in-progress' | 'scheduled' | 'pending' | 'failed';
type TimelinePhase = 'discovery' | 'assessment' | 'migration' | 'validation' | 'compliance';

type TimelineItem = {
  id: string;
  title: string;
  description: string;
  status: TimelineStatus;
  phase: TimelinePhase;
  date: string;
  time: string;
  assets: number;
  progress: number;
};

type TelemetryJob = {
  id: string;
  asset: string;
  type: string;
  progress: number;
  status: TimelineStatus;
};

type DependencyTone = 'strong' | 'weak' | 'at-risk' | 'blocked';

type DependencyNode = {
  id: string;
  label: string;
  detail: string;
  x: number;
  y: number;
  tone: DependencyTone;
  icon: LucideIcon;
};

type DependencyLink = {
  from: string;
  to: string;
  tone: DependencyTone;
};

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

const FILTERS: Array<{ label: string; value: TimelineStatus | 'all' }> = [
  { label: 'All Phases', value: 'all' },
  { label: 'Completed', value: 'completed' },
  { label: 'In Progress', value: 'in-progress' },
  { label: 'Scheduled', value: 'scheduled' },
  { label: 'Pending', value: 'pending' },
  { label: 'Failed', value: 'failed' },
];

function numberFmt(value: number) {
  return new Intl.NumberFormat().format(Math.max(0, Number(value) || 0));
}

function pct(value: number) {
  return `${Math.max(0, Math.min(100, Math.round(Number(value) || 0)))}%`;
}

function compactDate(value?: string) {
  if (!value) return 'No scan';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString([], { month: 'short', day: '2-digit', year: 'numeric' });
}

function compactTime(value?: string) {
  if (!value) return '--:--';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '--:--';
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function addDays(base: string | undefined, days: number) {
  const date = base ? new Date(base) : new Date();
  if (Number.isNaN(date.getTime())) return new Date().toISOString();
  date.setDate(date.getDate() + days);
  return date.toISOString();
}

function statusStyles(status: TimelineStatus) {
  switch (status) {
    case 'completed':
      return { color: 'text-emerald-400', border: 'border-emerald-400/35', bg: 'bg-emerald-500/10', icon: CheckCircle2, label: 'Completed' };
    case 'in-progress':
      return { color: 'text-sky-400', border: 'border-sky-400/35', bg: 'bg-sky-500/10', icon: RefreshCw, label: 'In Progress' };
    case 'scheduled':
      return { color: 'text-gold', border: 'border-gold/35', bg: 'bg-gold/10', icon: KeyRound, label: 'Scheduled' };
    case 'failed':
      return { color: 'text-red-400', border: 'border-red-400/35', bg: 'bg-red-500/10', icon: ShieldX, label: 'Failed' };
    default:
      return { color: 'text-white/55', border: 'border-white/20', bg: 'bg-white/5', icon: Circle, label: 'Pending' };
  }
}

function phaseColor(phase: TimelinePhase) {
  switch (phase) {
    case 'discovery':
      return 'text-emerald-300';
    case 'assessment':
      return 'text-gold';
    case 'migration':
      return 'text-sky-300';
    case 'validation':
      return 'text-white/70';
    default:
      return 'text-emerald-300';
  }
}

function threatWeight(level?: string) {
  const normalized = String(level || '').toUpperCase();
  if (normalized === 'CRITICAL') return 100;
  if (normalized === 'HIGH') return 78;
  if (normalized === 'MEDIUM') return 55;
  if (normalized === 'LOW') return 28;
  return 8;
}

function sparkPath(values: number[], width = 104, height = 28) {
  const safe = values.length > 1 ? values : [0, values[0] || 0];
  const max = Math.max(1, ...safe);
  return safe.map((value, index) => {
    const x = (index / Math.max(1, safe.length - 1)) * width;
    const y = height - (Number(value || 0) / max) * height;
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
}

function downloadTextFile(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function buildTimelineItems(data: ReturnType<typeof useScannerIntelligence>['data']): TimelineItem[] {
  const latest = data.history.history[0];
  const baseDate = latest?.startedAt || data.generatedAt;
  const entries = data.cbom.entries || [];
  const tlsEntries = entries.filter((entry: any) => /tls|ssl|protocol/i.test(`${entry.type || ''} ${entry.algorithm || ''}`));
  const sshEntries = entries.filter((entry: any) => /ssh|dh|key/i.test(`${entry.type || ''} ${entry.algorithm || ''}`));
  const certEntries = entries.filter((entry: any) => /cert/i.test(String(entry.type || entry.component || '')));
  const vulnerableEntries = entries.filter((entry: any) => entry.isVulnerable);
  const failedSessions = data.history.history.filter((entry: any) => entry.status === 'failed');

  return [
    {
      id: 'cbom-discovery',
      title: 'CBOM Discovery Completed',
      description: data.summary.totalComponents > 0
        ? 'Cryptographic inventory synchronized from authenticated scanner records.'
        : 'Awaiting the first authorized scanner inventory.',
      status: data.summary.totalComponents > 0 ? 'completed' : 'pending',
      phase: 'discovery',
      date: compactDate(baseDate),
      time: compactTime(baseDate),
      assets: data.summary.totalAssets,
      progress: data.summary.totalComponents > 0 ? 100 : 0,
    },
    {
      id: 'risk-assessment',
      title: 'Quantum Risk Assessment',
      description: `${numberFmt(data.summary.vulnerableComponents)} vulnerable cryptographic component(s) currently require migration review.`,
      status: data.summary.totalFindings > 0 ? 'completed' : 'pending',
      phase: 'assessment',
      date: compactDate(baseDate),
      time: compactTime(baseDate),
      assets: data.summary.vulnerableAssets,
      progress: data.summary.totalFindings > 0 ? 100 : 0,
    },
    {
      id: 'tls-migration',
      title: 'TLS/SSL Migration (Hybrid Mode)',
      description: tlsEntries.length > 0
        ? 'TLS and protocol findings are being mapped to hybrid ML-KEM migration paths.'
        : 'No TLS protocol findings are currently present in the scanner feed.',
      status: tlsEntries.some((entry: any) => entry.isVulnerable) ? 'in-progress' : tlsEntries.length > 0 ? 'completed' : 'pending',
      phase: 'migration',
      date: compactDate(addDays(baseDate, 7)),
      time: compactTime(addDays(baseDate, 7)),
      assets: tlsEntries.length,
      progress: tlsEntries.length > 0 ? Math.round((tlsEntries.filter((entry: any) => entry.isQuantumSafe).length / tlsEntries.length) * 100) : 0,
    },
    {
      id: 'ssh-migration',
      title: 'SSH Key Migration (ML-DSA)',
      description: sshEntries.length > 0
        ? 'SSH and key exchange findings are queued for PQC-safe signing and KEM migration.'
        : 'No SSH or key exchange findings are currently present in the scanner feed.',
      status: sshEntries.some((entry: any) => entry.isVulnerable) ? 'scheduled' : sshEntries.length > 0 ? 'completed' : 'pending',
      phase: 'migration',
      date: compactDate(addDays(baseDate, 14)),
      time: compactTime(addDays(baseDate, 14)),
      assets: sshEntries.length,
      progress: sshEntries.length > 0 ? Math.round((sshEntries.filter((entry: any) => entry.isQuantumSafe).length / sshEntries.length) * 100) : 0,
    },
    {
      id: 'cert-reissue',
      title: 'Certificate Re-Issuance (PQC)',
      description: certEntries.length > 0
        ? 'Certificate inventory is aligned to PQC-ready trust chain replacement planning.'
        : 'No certificate findings are currently present in the scanner feed.',
      status: certEntries.some((entry: any) => entry.isVulnerable) ? 'pending' : certEntries.length > 0 ? 'completed' : 'pending',
      phase: 'validation',
      date: compactDate(addDays(baseDate, 21)),
      time: compactTime(addDays(baseDate, 21)),
      assets: certEntries.length,
      progress: certEntries.length > 0 ? Math.round((certEntries.filter((entry: any) => entry.isQuantumSafe).length / certEntries.length) * 100) : 0,
    },
    {
      id: 'legacy-decommission',
      title: 'Legacy Crypto Decommissioning',
      description: 'Disable RSA, ECDSA, DH, weak hashes, and deprecated protocol findings that remain vulnerable.',
      status: vulnerableEntries.length > 0 ? 'scheduled' : data.summary.totalComponents > 0 ? 'completed' : 'pending',
      phase: 'migration',
      date: compactDate(addDays(baseDate, 28)),
      time: compactTime(addDays(baseDate, 28)),
      assets: vulnerableEntries.length,
      progress: data.summary.totalComponents > 0 ? data.summary.pqcReadiness : 0,
    },
    {
      id: 'validation',
      title: 'Validation & Compliance Verification',
      description: 'Final validation uses scanner history, telemetry, and PQC readiness evidence.',
      status: failedSessions.length > 0 ? 'failed' : data.summary.totalComponents > 0 && data.summary.vulnerableComponents === 0 ? 'completed' : 'pending',
      phase: 'compliance',
      date: compactDate(addDays(baseDate, 35)),
      time: compactTime(addDays(baseDate, 35)),
      assets: data.summary.totalAssets,
      progress: data.summary.pqcReadiness,
    },
  ];
}

function buildTelemetryJobs(data: ReturnType<typeof useScannerIntelligence>['data']): TelemetryJob[] {
  const jobs = data.cbom.entries.slice(0, 7).map((entry: any, index: number) => {
    const progress = entry.isQuantumSafe ? 100 : entry.isVulnerable ? Math.max(20, 75 - index * 9) : 10;
    return {
      id: String(entry.id || `job-${index + 1}`).slice(0, 14).toUpperCase(),
      asset: String(entry.sourceAsset || entry.component || 'Unknown asset'),
      type: String(entry.type || 'Crypto').toUpperCase().slice(0, 8),
      progress,
      status: entry.isQuantumSafe ? 'completed' : entry.isVulnerable ? 'in-progress' : 'pending',
    } as TelemetryJob;
  });

  if (jobs.length > 0) return jobs;

  return data.history.history.slice(0, 5).map((entry: any, index: number) => ({
    id: String(entry.scanId || `scan-${index + 1}`).slice(0, 14).toUpperCase(),
    asset: String(entry.target || 'Scanner target'),
    type: String(entry.scanType || 'SCAN').slice(0, 8).toUpperCase(),
    progress: entry.status === 'completed' ? 100 : entry.status === 'failed' ? 0 : 45,
    status: entry.status === 'completed' ? 'completed' : entry.status === 'failed' ? 'failed' : 'in-progress',
  }));
}

function dependencyToneMeta(tone: DependencyTone) {
  switch (tone) {
    case 'strong':
      return {
        label: 'Strong',
        color: '#22c55e',
        node: 'border-emerald-400/60 bg-emerald-500/15 text-emerald-300 shadow-[0_0_24px_rgba(34,197,94,0.35)]',
        text: 'text-emerald-300',
      };
    case 'weak':
      return {
        label: 'Weak',
        color: '#FFD36B',
        node: 'border-gold/65 bg-gold/15 text-gold shadow-[0_0_24px_rgba(255,211,107,0.35)]',
        text: 'text-gold',
      };
    case 'at-risk':
      return {
        label: 'At Risk',
        color: '#fb923c',
        node: 'border-orange-400/65 bg-orange-500/15 text-orange-300 shadow-[0_0_24px_rgba(251,146,60,0.35)]',
        text: 'text-orange-300',
      };
    default:
      return {
        label: 'Blocked',
        color: '#ff4d57',
        node: 'border-red-400/65 bg-red-500/15 text-red-300 shadow-[0_0_24px_rgba(255,77,87,0.35)]',
        text: 'text-red-300',
      };
  }
}

function classifyDependencyTone(risk: number, vulnerable: number, critical = false): DependencyTone {
  if (critical || risk >= 85) return 'blocked';
  if (risk >= 65 || vulnerable > 1) return 'at-risk';
  if (risk >= 35 || vulnerable > 0) return 'weak';
  return 'strong';
}

function pluralCount(count: number, label: string) {
  return `${numberFmt(count)} ${label}${count === 1 ? '' : 's'}`;
}

function buildDependencyGraph(data: ReturnType<typeof useScannerIntelligence>['data']): { nodes: DependencyNode[]; links: DependencyLink[] } {
  const assets = data.assets.assets || [];
  const entries = data.cbom.entries || [];
  const textFromAsset = (asset: any) => [
    asset.name,
    asset.type,
    asset.url,
    asset.host,
    asset.provider,
    asset.metadata?.assetType,
    asset.metadata?.environment,
  ].filter(Boolean).join(' ');
  const textFromEntry = (entry: any) => [
    entry.type,
    entry.component,
    entry.algorithm,
    entry.category,
    entry.sourceAsset,
    entry.location,
    entry.evidence,
  ].filter(Boolean).join(' ');
  const assetGroup = (regex: RegExp) => assets.filter((asset: any) => regex.test(textFromAsset(asset)));
  const entryGroup = (regex: RegExp) => entries.filter((entry: any) => regex.test(textFromEntry(entry)));
  const assetRisk = (items: any[]) => items.reduce((max, asset) => Math.max(max, Number(asset.riskScore || threatWeight(asset.riskLevel))), 0);
  const assetVuln = (items: any[]) => items.reduce((sum, asset) => sum + Number(asset.vulnerableCount || (Number(asset.riskScore || 0) >= 40 ? 1 : 0)), 0);
  const entryRisk = (items: any[]) => items.reduce((max, entry) => {
    const score = entry.isQuantumSafe
      ? 8
      : entry.isVulnerable
        ? Math.max(55, threatWeight(entry.riskSeverity || entry.threatLevel || entry.severity || entry.status))
        : threatWeight(entry.riskSeverity || entry.threatLevel || entry.severity || entry.status);
    return Math.max(max, score);
  }, 0);
  const entryVuln = (items: any[]) => items.filter((entry) => {
    const level = String(entry.riskSeverity || entry.threatLevel || entry.severity || entry.status || '').toUpperCase();
    return entry.isVulnerable || ['CRITICAL', 'HIGH', 'MEDIUM'].includes(level);
  }).length;
  const groupTone = (assetItems: any[], entryItems: any[], critical = false) => classifyDependencyTone(
    Math.max(assetRisk(assetItems), entryRisk(entryItems)),
    assetVuln(assetItems) + entryVuln(entryItems),
    critical,
  );

  const certificateEntries = entryGroup(/cert|x509|certificate|pki|trust|ca\b/i);
  const tlsEntries = entryGroup(/tls|ssl|cipher|protocol|https/i);
  const keyEntries = entryGroup(/ssh|key|rsa|ecdsa|dsa|dh|kem|ml-kem|ml-dsa/i);
  const webAssets = assetGroup(/web|portal|frontend|site|https|tls|gateway/i);
  const apiAssets = assetGroup(/\bapi\b|gateway|service endpoint/i);
  const databaseAssets = assetGroup(/database|\bdb\b|sql|postgres|mysql|oracle|mongo/i);
  const vpnAssets = assetGroup(/vpn|ssh|bastion|remote access|network/i);
  const serviceAssets = assetGroup(/service|worker|queue|lambda|function|microservice|internal/i);
  const unclassifiedAssets = assets.filter((asset: any) => ![
    ...webAssets,
    ...apiAssets,
    ...databaseAssets,
    ...vpnAssets,
    ...serviceAssets,
  ].some((known: any) => (
    (known.id && asset.id && known.id === asset.id) ||
    (known.name && asset.name && known.name === asset.name)
  )));

  const rootTone = classifyDependencyTone(data.summary.riskScore, data.summary.vulnerableComponents, data.severityCounts.critical > 0 && data.summary.riskScore >= 80);
  const ca1Tone = groupTone([], certificateEntries.concat(tlsEntries.slice(0, Math.ceil(tlsEntries.length / 2))));
  const ca2Tone = groupTone([], certificateEntries.concat(keyEntries));
  const webTone = groupTone(webAssets, tlsEntries);
  const apiTone = groupTone(apiAssets, entries.filter((entry: any) => /api|jwt|token|sign/i.test(textFromEntry(entry))));
  const databaseTone = groupTone(databaseAssets, entries.filter((entry: any) => /database|db|storage|aes|rsa|ecdsa/i.test(textFromEntry(entry))));
  const vpnTone = groupTone(vpnAssets, entries.filter((entry: any) => /vpn|ssh|dh|key exchange/i.test(textFromEntry(entry))));
  const serviceTone = groupTone(serviceAssets.concat(unclassifiedAssets), entries.filter((entry: any) => /service|internal|queue|worker|unknown/i.test(textFromEntry(entry))));
  const bridgeTone = classifyDependencyTone(
    Math.max(data.summary.riskScore, entryRisk(keyEntries)),
    entryVuln(keyEntries),
    data.severityCounts.critical > 1,
  );

  const nodes: DependencyNode[] = [
    { id: 'root', label: 'PKI Root CA', detail: pluralCount(data.summary.totalComponents, 'component'), x: 43, y: 16, tone: rootTone, icon: ShieldCheck },
    { id: 'ca-1', label: 'Intermediate CA 1', detail: pluralCount(Math.max(0, Math.ceil(certificateEntries.length / 2)), 'certificate'), x: 17, y: 39, tone: ca1Tone, icon: FileText },
    { id: 'ca-2', label: 'Intermediate CA 2', detail: pluralCount(Math.max(0, certificateEntries.length - Math.ceil(certificateEntries.length / 2)), 'certificate'), x: 47, y: 39, tone: ca2Tone, icon: FileText },
    { id: 'trust-bridge', label: 'Trust Bridge', detail: pluralCount(keyEntries.length, 'key path'), x: 76, y: 39, tone: bridgeTone, icon: KeyRound },
    { id: 'web', label: 'Web Apps', detail: pluralCount(webAssets.length, 'asset'), x: 9, y: 67, tone: webTone, icon: Globe2 },
    { id: 'api', label: 'APIs', detail: pluralCount(apiAssets.length, 'asset'), x: 29, y: 67, tone: apiTone, icon: Activity },
    { id: 'database', label: 'Databases', detail: pluralCount(databaseAssets.length, 'asset'), x: 47, y: 67, tone: databaseTone, icon: Database },
    { id: 'vpn', label: 'VPN Gateways', detail: pluralCount(vpnAssets.length, 'asset'), x: 68, y: 67, tone: vpnTone, icon: Network },
    { id: 'services', label: 'Services', detail: pluralCount(serviceAssets.length + unclassifiedAssets.length, 'asset'), x: 90, y: 67, tone: serviceTone, icon: Server },
  ];

  const links: DependencyLink[] = [
    { from: 'root', to: 'ca-1', tone: ca1Tone },
    { from: 'root', to: 'ca-2', tone: ca2Tone },
    { from: 'root', to: 'trust-bridge', tone: bridgeTone },
    { from: 'ca-1', to: 'web', tone: webTone },
    { from: 'ca-1', to: 'api', tone: apiTone },
    { from: 'ca-2', to: 'api', tone: apiTone },
    { from: 'ca-2', to: 'database', tone: databaseTone },
    { from: 'ca-2', to: 'vpn', tone: vpnTone },
    { from: 'trust-bridge', to: 'services', tone: serviceTone },
    { from: 'vpn', to: 'services', tone: serviceTone },
  ];

  return { nodes, links };
}

function DependencyGraphCanvas({ nodes, links }: { nodes: DependencyNode[]; links: DependencyLink[] }) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const pathFor = (from: DependencyNode, to: DependencyNode) => {
    const midY = (from.y + to.y) / 2;
    return `M ${from.x} ${from.y} C ${from.x} ${midY}, ${to.x} ${midY}, ${to.x} ${to.y}`;
  };

  return (
    <div className="relative z-10 mt-5 overflow-x-auto">
      <div className="relative h-[330px] min-w-[860px] rounded-xl border border-white/10 bg-[#070b18]/35">
        <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          <defs>
            {(['strong', 'weak', 'at-risk', 'blocked'] as DependencyTone[]).map((tone) => (
              <marker key={tone} id={`dependency-arrow-${tone}`} markerWidth="6" markerHeight="6" refX="5.4" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" fill={dependencyToneMeta(tone).color} />
              </marker>
            ))}
          </defs>
          {links.map((link) => {
            const from = nodeMap.get(link.from);
            const to = nodeMap.get(link.to);
            if (!from || !to) return null;
            return (
              <path
                key={`${link.from}-${link.to}`}
                d={pathFor(from, to)}
                fill="none"
                stroke={dependencyToneMeta(link.tone).color}
                strokeWidth="0.7"
                strokeLinecap="round"
                strokeLinejoin="round"
                markerEnd={`url(#dependency-arrow-${link.tone})`}
                vectorEffect="non-scaling-stroke"
                opacity="0.86"
              />
            );
          })}
        </svg>

        {nodes.map((node) => {
          const Icon = node.icon;
          const tone = dependencyToneMeta(node.tone);
          return (
            <div
              key={node.id}
              className="absolute flex -translate-x-1/2 -translate-y-1/2 items-center gap-3"
              style={{ left: `${node.x}%`, top: `${node.y}%` }}
            >
              <div className={`flex h-11 w-11 items-center justify-center rounded-full border ${tone.node}`}>
                <Icon className="h-5 w-5" />
              </div>
              <div className="min-w-max">
                <div className="text-xs font-black text-white/80">{node.label}</div>
                <div className={`mt-0.5 text-[9px] font-bold uppercase tracking-wider ${tone.text}`}>{node.detail}</div>
              </div>
            </div>
          );
        })}

        <div className="absolute inset-x-0 bottom-0 flex flex-wrap justify-center gap-10 border-t border-gold/10 bg-black/10 px-4 py-4">
          {(['strong', 'weak', 'at-risk', 'blocked'] as DependencyTone[]).map((tone) => {
            const meta = dependencyToneMeta(tone);
            return (
              <span key={tone} className="flex items-center gap-3 text-[10px] font-black uppercase tracking-wider text-white/55">
                <span className="h-1.5 w-12 rounded-full" style={{ backgroundColor: meta.color, boxShadow: `0 0 12px ${meta.color}` }} />
                {meta.label}
              </span>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function DependencyGraphList({ nodes, links }: { nodes: DependencyNode[]; links: DependencyLink[] }) {
  return (
    <div className="relative z-10 mt-5 overflow-x-auto">
      <table className="w-full min-w-[760px] text-left">
        <thead className="border-b border-gold/15 text-[9px] uppercase tracking-[0.18em] text-gold">
          <tr>
            <th className="py-3 pr-4">Dependency</th>
            <th className="py-3 pr-4">Evidence</th>
            <th className="py-3 pr-4">Status</th>
            <th className="py-3 pr-4">Upstream</th>
            <th className="py-3">Downstream</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/5 text-xs font-semibold text-white/65">
          {nodes.map((node) => {
            const meta = dependencyToneMeta(node.tone);
            const upstream = links.filter((link) => link.to === node.id).length;
            const downstream = links.filter((link) => link.from === node.id).length;
            return (
              <tr key={node.id} className="transition hover:bg-gold/[0.04]">
                <td className="py-3 pr-4 text-white/85">{node.label}</td>
                <td className="py-3 pr-4">{node.detail}</td>
                <td className={`py-3 pr-4 font-black ${meta.text}`}>{meta.label}</td>
                <td className="py-3 pr-4">{upstream}</td>
                <td className="py-3">{downstream}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ProgressDonut({ value }: { value: number }) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div
      className="relative flex h-20 w-20 shrink-0 items-center justify-center rounded-full"
      style={{ background: `conic-gradient(#FFD36B ${clamped * 3.6}deg, rgba(255,255,255,0.08) 0deg)` }}
    >
      <div className="absolute inset-2 rounded-full bg-[#0f1428]" />
      <span className="relative z-10 text-xl font-black text-white">{clamped}%</span>
    </div>
  );
}

function Sparkline({ values, tone = '#FFD36B' }: { values: number[]; tone?: string }) {
  return (
    <svg viewBox="0 0 104 28" className="h-8 w-28">
      <path d={sparkPath(values)} fill="none" stroke={tone} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.9" />
    </svg>
  );
}

function RiskChart({ history, summary }: { history: any[]; summary: ReturnType<typeof useScannerIntelligence>['data']['summary'] }) {
  const points = history.slice(0, 10).reverse();
  const exposure = points.length > 0 ? points.map((entry: any) => Number(entry.summary?.riskScore || entry.riskScore || summary.riskScore)) : [summary.riskScore];
  const vulnerable = points.length > 0 ? points.map((entry: any) => Number(entry.summary?.vulnerable || entry.vulnerableFindings || summary.vulnerableComponents)) : [summary.vulnerableComponents];
  const adoption = points.length > 0 ? points.map((entry: any) => Number(entry.summary?.pqcReady || entry.pqcReadyFindings || summary.pqcReadyComponents)) : [summary.pqcReadyComponents];
  const max = Math.max(1, ...exposure, ...vulnerable, ...adoption);
  const path = (values: number[]) => values.map((value, index) => {
    const x = (index / Math.max(1, values.length - 1)) * 100;
    const y = 100 - (value / max) * 90;
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
  }).join(' ');

  return (
    <div className="relative z-10">
      <div className="mb-5 flex flex-wrap items-center gap-4 text-[10px] font-bold uppercase tracking-wider text-white/45">
        <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-gold" /> Quantum Exposure</span>
        <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-red-400" /> Vulnerable Assets</span>
        <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-emerald-400" /> PQC Adoption</span>
      </div>
      <svg viewBox="0 0 100 100" className="h-52 w-full overflow-visible">
        {[0, 25, 50, 75, 100].map((line) => (
          <line key={line} x1="0" x2="100" y1={line} y2={line} stroke="rgba(255,255,255,0.08)" strokeDasharray="1 2" />
        ))}
        <path d={path(exposure)} fill="none" stroke="#FFD36B" strokeWidth="1.8" vectorEffect="non-scaling-stroke" />
        <path d={path(vulnerable)} fill="none" stroke="#ff4d57" strokeWidth="1.8" vectorEffect="non-scaling-stroke" />
        <path d={path(adoption)} fill="none" stroke="#22c55e" strokeWidth="1.8" vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="mt-2 flex justify-between text-[10px] font-bold text-white/35">
        <span>Oldest</span>
        <span>Latest</span>
      </div>
    </div>
  );
}

function SectionTitle({ children }: { children: string }) {
  return <h2 className="relative z-10 text-xs font-black uppercase tracking-[0.22em] text-gold">{children}</h2>;
}

export default function MigrationTimeline() {
  const { data, loading, error, connected, refresh } = useScannerIntelligence();
  const [filter, setFilter] = useState<TimelineStatus | 'all'>('all');
  const [dependencyView, setDependencyView] = useState<'graph' | 'list'>('graph');

  const timeline = useMemo(() => buildTimelineItems(data), [data]);
  const filteredTimeline = useMemo(() => timeline.filter((item) => filter === 'all' || item.status === filter), [filter, timeline]);
  const telemetryJobs = useMemo(() => buildTelemetryJobs(data), [data]);
  const dependencyGraph = useMemo(() => buildDependencyGraph(data), [data]);
  const statusCounts = useMemo(() => timeline.reduce(
    (counts, item) => ({ ...counts, [item.status]: counts[item.status] + 1 }),
    { completed: 0, 'in-progress': 0, scheduled: 0, pending: 0, failed: 0 } as Record<TimelineStatus, number>,
  ), [timeline]);

  const completed = statusCounts.completed;
  const total = Math.max(1, timeline.length);
  const overallProgress = Math.round((completed / total) * 100);
  const migratedAssets = data.cbom.stats.pqcReadyComponents;
  const totalAssetsForMigration = Math.max(data.cbom.stats.totalComponents, migratedAssets);
  const failedJobs = statusCounts.failed + data.history.history.filter((entry: any) => entry.status === 'failed').length;
  const sparkBase = data.history.history.slice(0, 8).reverse();
  const assetSpark = sparkBase.map((entry: any) => Number(entry.summary?.totalFindings || entry.detectedComponents || 0));
  const adoptionSpark = sparkBase.map((entry: any) => Number(entry.summary?.pqcReady || entry.pqcReadyFindings || 0));
  const vulnerableSpark = sparkBase.map((entry: any) => Number(entry.summary?.vulnerable || entry.vulnerableFindings || 0));
  const heatmap = data.assets.assets.slice(0, 70);
  const assetMigrationRows = useMemo(() => data.assets.assets.slice(0, 12).map((asset: any) => {
    const inventory = Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory : [];
    const vulnerable = inventory.find((entry: any) => entry.is_vulnerable) || inventory[0];
    const currentAlgorithm = String(vulnerable?.algorithm || asset.cryptography?.[0] || 'Manual review');
    const targetAlgorithm = String(vulnerable?.metadata?.pqcReplacement || vulnerable?.metadata?.recommendation || 'ML-KEM-768 / ML-DSA-65');
    const riskScore = Number(asset.riskScore || 0);
    const status: TimelineStatus = asset.vulnerableCount > 0
      ? 'in-progress'
      : inventory.length > 0
        ? 'completed'
        : 'pending';
    return {
      id: String(asset.id || asset.name),
      name: String(asset.name || 'Unknown asset'),
      type: String(asset.type || 'Asset'),
      currentAlgorithm,
      targetAlgorithm,
      status,
      riskLabel: riskScore >= 80 ? 'Critical' : riskScore >= 60 ? 'High' : riskScore >= 40 ? 'Medium' : 'Low',
      riskScore,
      environment: String(asset.metadata?.environment || (asset.metadata?.authorized_target ? 'Production' : 'Tenant Scope')),
      owner: String(asset.metadata?.owner || asset.metadata?.businessOwner || 'Unassigned'),
      lastUpdated: compactDate(asset.lastScanned || asset.metadata?.last_scanned_at),
    };
  }), [data.assets.assets]);

  const exportTimeline = () => {
    const payload = { generatedAt: new Date().toISOString(), summary: data.summary, timeline, telemetryJobs, dependencyGraph };
    downloadTextFile(`qguard-migration-timeline-${Date.now()}.json`, JSON.stringify(payload, null, 2), 'application/json;charset=utf-8');
  };

  const exportAuditLogs = () => {
    const csv = [
      ['scan_id', 'target', 'status', 'started_at', 'completed_at', 'findings', 'risk_score'].join(','),
      ...data.history.history.map((entry: any) => [
        entry.scanId,
        entry.target,
        entry.status,
        entry.startedAt,
        entry.completedAt,
        entry.detectedComponents,
        entry.riskScore ?? entry.summary?.riskScore ?? '',
      ].map((value) => `"${String(value ?? '').replaceAll('"', '""')}"`).join(',')),
    ].join('\n');
    downloadTextFile(`qguard-migration-audit-${Date.now()}.csv`, csv, 'text/csv;charset=utf-8');
  };

  return (
    <div className="min-h-screen space-y-5 p-4 font-mono text-white lg:p-6">
      <header className="flex flex-col gap-5 border-b border-gold/15 pb-5 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex items-center gap-4">
          <div className="rounded-xl border border-gold/30 bg-gold/10 p-3 text-gold shadow-[0_0_28px_rgba(255,211,107,0.24)]">
            <ArrowRight className="h-7 w-7 -rotate-45" />
          </div>
          <div>
            <h1 className="text-3xl font-black uppercase tracking-[0.12em] text-gold drop-shadow-[0_0_16px_rgba(255,211,107,0.35)]">
              Migration Timeline
            </h1>
            <p className="mt-2 text-xs font-semibold text-white/55">
              NIST Post-Quantum Cryptography (PQC) migration strategy synchronized with scanner evidence.
            </p>
          </div>
        </div>

        <div className="flex max-w-full flex-nowrap items-center gap-3 overflow-x-auto whitespace-nowrap pb-1">
          <button onClick={refresh} className="shrink-0 rounded-lg border border-gold/25 bg-gold/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-gold transition hover:border-gold/60">
            <span className="inline-flex items-center gap-2"><span className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400' : 'bg-amber-300'}`} /> {loading ? 'Syncing' : connected ? 'Live' : 'Snapshot'}</span>
          </button>
          <a href="/dashboard/migration-planner" className="shrink-0 rounded-lg border border-gold/30 bg-gold/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-gold transition hover:border-gold/70">
            <Play className="mr-1 inline h-3.5 w-3.5" /> Start Migration
          </a>
          <button onClick={exportTimeline} className="shrink-0 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/70 transition hover:border-gold/40 hover:text-gold">
            <FileText className="mr-1 inline h-3.5 w-3.5" /> Generate Reports
          </button>
          <button onClick={exportTimeline} className="shrink-0 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/70 transition hover:border-gold/40 hover:text-gold">
            <Download className="mr-1 inline h-3.5 w-3.5" /> Export Timeline
          </button>
          <button onClick={exportAuditLogs} className="shrink-0 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/70 transition hover:border-gold/40 hover:text-gold">
            <Shield className="mr-1 inline h-3.5 w-3.5" /> Audit Logs
          </button>
          <div className="flex shrink-0 items-center gap-2 text-xs font-black text-white/75">
            <Clock className="h-4 w-4 text-gold" />
            {new Date(data.generatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </div>
        </div>
      </header>

      {error && <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm font-semibold text-red-300">{error}</div>}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-7">
        <section className={`${GLASS_PANEL_CLASSES} p-4 xl:col-span-1`}>
          <div className="relative z-10 flex items-center gap-4">
            <ProgressDonut value={overallProgress} />
            <div>
              <div className="text-[9px] font-black uppercase tracking-widest text-gold">Overall Progress</div>
              <div className="mt-2 text-xs text-emerald-400">{failedJobs > 0 ? 'Attention Required' : 'On Track'}</div>
              <div className="mt-1 text-[10px] text-white/45">Estimated Completion</div>
              <div className="text-xs font-bold text-white/75">{compactDate(addDays(data.generatedAt, Math.max(1, data.summary.vulnerableComponents) * 7))}</div>
            </div>
          </div>
        </section>

        {[
          { label: 'Assets Migrated', value: `${numberFmt(migratedAssets)} / ${numberFmt(totalAssetsForMigration)}`, detail: pct(data.summary.pqcReadiness), icon: Layers, tone: '#FFD36B', spark: assetSpark },
          { label: 'PQC Adoption', value: pct(data.summary.pqcReadiness), detail: `${numberFmt(data.summary.pqcReadyComponents)} ready`, icon: Gauge, tone: '#22c55e', spark: adoptionSpark },
          { label: 'Vulnerable Assets', value: numberFmt(data.summary.vulnerableAssets), detail: `${numberFmt(data.summary.vulnerableComponents)} components`, icon: AlertTriangle, tone: '#ff4d57', spark: vulnerableSpark },
          { label: 'Active Migrations', value: numberFmt(statusCounts['in-progress']), detail: 'In Progress', icon: Activity, tone: '#38bdf8', spark: [statusCounts['in-progress'], data.summary.activeScans] },
          { label: 'Failed Jobs', value: numberFmt(failedJobs), detail: failedJobs > 0 ? 'Review Required' : 'Clean', icon: ShieldX, tone: '#ff4d57', spark: [failedJobs, failedJobs] },
          { label: 'Compliance Readiness', value: pct(data.runtime.complianceScore), detail: data.runtime.complianceScore >= 80 ? 'Good' : 'Needs Work', icon: ShieldCheck, tone: '#22c55e', spark: [data.runtime.complianceScore] },
        ].map((card) => {
          const Icon = card.icon;
          return (
            <section key={card.label} className={`${GLASS_PANEL_CLASSES} p-4`}>
              <div className="relative z-10 flex h-full flex-col justify-between">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-[9px] font-black uppercase tracking-widest text-gold">{card.label}</div>
                    <div className="mt-3 text-2xl font-black text-white">{card.value}</div>
                    <div className="mt-1 text-[10px] font-semibold" style={{ color: card.tone }}>{card.detail}</div>
                  </div>
                  <Icon className="h-6 w-6" style={{ color: card.tone }} />
                </div>
                <div className="mt-3 flex justify-end">
                  <Sparkline values={card.spark.length ? card.spark : [0]} tone={card.tone} />
                </div>
              </div>
            </section>
          );
        })}
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[270px_minmax(0,1fr)]">
        <aside className="space-y-5">
          <section className={`${GLASS_PANEL_CLASSES} p-5`}>
            <SectionTitle>NIST Migration Strategy</SectionTitle>
            <div className="relative z-10 mt-5 space-y-4">
              {[
                ['Inventory & Discovery', statusCounts.completed >= 1],
                ['Risk Assessment', data.summary.totalFindings > 0],
                ['Planning', timeline.some((item) => item.status !== 'pending')],
                ['Pilot Migration', data.summary.pqcReadyComponents > 0],
                ['Full Migration', data.summary.vulnerableComponents === 0 && data.summary.totalComponents > 0],
                ['Validation', statusCounts.failed === 0 && data.summary.totalComponents > 0],
                ['Monitor & Govern', connected],
              ].map(([label, done], index) => (
                <div key={String(label)} className="grid grid-cols-[32px_1fr_18px] items-center gap-3">
                  <div className={`flex h-8 w-8 items-center justify-center rounded-full border ${done ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300' : index === 4 ? 'border-gold/60 bg-gold/10 text-gold' : 'border-white/20 bg-white/5 text-white/40'}`}>
                    {index + 1}
                  </div>
                  <div>
                    <div className={`text-[10px] font-black uppercase ${index === 4 ? 'text-gold' : 'text-white/70'}`}>{label}</div>
                    <div className="text-[9px] text-white/35">{done ? 'Evidence available' : 'Awaiting scanner state'}</div>
                  </div>
                  {done ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <Circle className="h-4 w-4 text-white/25" />}
                </div>
              ))}
            </div>
          </section>

          <section className={`${GLASS_PANEL_CLASSES} p-5`}>
            <SectionTitle>NIST Standards</SectionTitle>
            <div className="relative z-10 mt-5 space-y-3">
              {['SP 800-208', 'SP 800-57 Rev. 5', 'SP 800-131A Rev. 2', 'SP 800-207'].map((standard) => (
                <div key={standard} className="flex items-center gap-3 rounded-lg border border-white/5 bg-white/[0.02] p-3">
                  <ListChecks className="h-4 w-4 text-gold" />
                  <div>
                    <div className="text-[10px] font-black text-white/75">{standard}</div>
                    <div className="text-[9px] text-white/35">Referenced in audit posture</div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </aside>

        <main className={`${GLASS_PANEL_CLASSES} p-5`}>
          <div className="relative z-10 mb-5 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <SectionTitle>Migration Timeline</SectionTitle>
            <div className="flex flex-wrap gap-2">
              {FILTERS.map((item) => (
                <button
                  key={item.value}
                  type="button"
                  onClick={() => setFilter(item.value)}
                  className={`rounded-lg border px-3 py-2 text-[10px] font-black uppercase tracking-wider transition ${filter === item.value ? 'border-gold/60 bg-gold/10 text-gold' : 'border-white/10 bg-white/[0.03] text-white/45 hover:border-gold/30 hover:text-white/70'}`}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>

          <div className="relative z-10 space-y-4">
            <div className="absolute bottom-8 left-[29px] top-4 w-px bg-gradient-to-b from-emerald-400 via-gold to-white/30" />
            {filteredTimeline.map((item, index) => {
              const styles = statusStyles(item.status);
              const Icon = styles.icon;
              return (
                <motion.div
                  key={item.id}
                  initial={{ opacity: 0, x: -16 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.04 }}
                  className="grid grid-cols-[60px_1fr] gap-4"
                >
                  <div className="relative flex justify-center pt-3">
                    <div className={`z-10 flex h-11 w-11 items-center justify-center rounded-full border ${styles.border} ${styles.bg} ${styles.color} shadow-[0_0_18px_rgba(255,211,107,0.18)]`}>
                      <Icon className={`h-5 w-5 ${item.status === 'in-progress' ? 'animate-spin' : ''}`} />
                    </div>
                  </div>
                  <div className={`relative rounded-xl border p-4 ${styles.border} ${styles.bg}`}>
                    <div className="absolute -left-2 top-6 h-4 w-4 rotate-45 border-b border-l border-current bg-[#111827]" />
                    <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                      <div>
                        <div className={`text-[9px] font-black uppercase tracking-widest ${phaseColor(item.phase)}`}>{styles.label}</div>
                        <h3 className="mt-1 text-sm font-black text-white">{item.title}</h3>
                        <p className="mt-1 max-w-2xl text-xs font-semibold leading-relaxed text-white/45">{item.description}</p>
                      </div>
                      <div className="text-right text-[10px] font-bold text-white/45">
                        <div>{item.date}</div>
                        <div>{item.time}</div>
                        <div>{numberFmt(item.assets)} assets</div>
                      </div>
                    </div>
                    {item.status === 'in-progress' ? (
                      <div className="mt-4 flex items-center gap-3">
                        <div className="h-2 flex-1 overflow-hidden rounded-full bg-white/10">
                          <div className="h-full rounded-full bg-sky-400 shadow-[0_0_12px_rgba(56,189,248,0.65)]" style={{ width: `${item.progress}%` }} />
                        </div>
                        <span className="text-xs font-black text-white">{pct(item.progress)}</span>
                      </div>
                    ) : null}
                  </div>
                </motion.div>
              );
            })}
          </div>
        </main>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
          <section className={`${GLASS_PANEL_CLASSES} p-5`}>
            <div className="relative z-10 flex items-center justify-between">
              <SectionTitle>Real-Time Migration Telemetry</SectionTitle>
              <span className="rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-1 text-[9px] font-black uppercase text-emerald-300">Live</span>
            </div>
            <div className="relative z-10 mt-4 overflow-x-auto">
              <table className="w-full min-w-[520px] text-left">
                <thead className="border-b border-gold/15 text-[9px] uppercase tracking-widest text-gold">
                  <tr>
                    <th className="py-2">Job</th>
                    <th>Asset</th>
                    <th>Type</th>
                    <th>Progress</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-[10px] font-semibold text-white/55">
                  {telemetryJobs.length === 0 ? (
                    <tr><td colSpan={5} className="py-8 text-center text-white/30">No telemetry jobs yet.</td></tr>
                  ) : telemetryJobs.map((job) => {
                    const styles = statusStyles(job.status);
                    return (
                      <tr key={`${job.id}-${job.asset}`}>
                        <td className="py-2 text-white/75">{job.id}</td>
                        <td className="max-w-[150px] truncate">{job.asset}</td>
                        <td>{job.type}</td>
                        <td>
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-20 overflow-hidden rounded-full bg-white/10">
                              <div className={`h-full rounded-full ${job.status === 'completed' ? 'bg-emerald-400' : 'bg-gold'}`} style={{ width: `${job.progress}%` }} />
                            </div>
                            <span>{pct(job.progress)}</span>
                          </div>
                        </td>
                        <td className={styles.color}>{styles.label}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>

          <section className={`${GLASS_PANEL_CLASSES} p-5`}>
            <div className="relative z-10 flex items-center justify-between">
              <SectionTitle>Quantum Risk Reduction</SectionTitle>
              <span className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-[9px] font-bold text-white/45">Last {Math.max(1, data.history.history.length)} scans</span>
            </div>
            <RiskChart history={data.history.history} summary={data.summary} />
          </section>

          <section className={`${GLASS_PANEL_CLASSES} p-5`}>
            <SectionTitle>Migration Health</SectionTitle>
            <div className="relative z-10 mt-5 flex items-center gap-5">
              <ProgressDonut value={data.summary.qScore} />
              <div className="space-y-2 text-xs font-semibold text-white/55">
                <div className="flex justify-between gap-8"><span className="text-emerald-400">On Track</span><b className="text-white">{statusCounts.completed}</b></div>
                <div className="flex justify-between gap-8"><span className="text-gold">At Risk</span><b className="text-white">{statusCounts.scheduled + statusCounts.pending}</b></div>
                <div className="flex justify-between gap-8"><span className="text-sky-400">In Progress</span><b className="text-white">{statusCounts['in-progress']}</b></div>
                <div className="flex justify-between gap-8"><span className="text-red-400">Failed</span><b className="text-white">{failedJobs}</b></div>
              </div>
            </div>
          </section>

          <section className={`${GLASS_PANEL_CLASSES} p-5`}>
            <SectionTitle>Risk Heatmap</SectionTitle>
            <div className="relative z-10 mt-5">
              {heatmap.length === 0 ? (
                <div className="rounded-lg border border-white/5 bg-white/[0.02] p-8 text-center text-xs font-black uppercase tracking-widest text-white/30">
                  No asset heatmap data yet.
                </div>
              ) : (
                <div className="grid grid-cols-10 gap-1">
                  {heatmap.map((asset: any, index: number) => {
                    const risk = Number(asset.riskScore || threatWeight(asset.riskLevel));
                    const color = risk >= 80 ? 'bg-red-500' : risk >= 60 ? 'bg-orange-500' : risk >= 40 ? 'bg-yellow-500' : 'bg-emerald-500';
                    return <span key={`${asset.id || asset.name}-${index}`} title={`${asset.name}: ${risk}/100`} className={`h-3 rounded-sm ${color} opacity-80 shadow-[0_0_8px_rgba(255,211,107,0.16)]`} />;
                  })}
                </div>
              )}
              <div className="mt-3 flex justify-between text-[9px] font-bold text-white/35">
                <span>Low Risk</span>
                <span>High Risk</span>
              </div>
            </div>
          </section>
      </div>

      <section className={`${GLASS_PANEL_CLASSES} p-5`}>
        <SectionTitle>Asset Migration Overview</SectionTitle>
        <div className="relative z-10 mt-5 overflow-x-auto">
          <table className="w-full min-w-[1060px] border-collapse text-left">
            <thead>
              <tr className="border-b border-gold/15 text-[9px] font-black uppercase tracking-[0.18em] text-gold">
                <th className="py-3 pr-4">Asset Name</th>
                <th className="py-3 pr-4">Type</th>
                <th className="py-3 pr-4">Current Algorithm</th>
                <th className="py-3 pr-4">Target Algorithm</th>
                <th className="py-3 pr-4">Status</th>
                <th className="py-3 pr-4">Risk Score</th>
                <th className="py-3 pr-4">Environment</th>
                <th className="py-3 pr-4">Owner</th>
                <th className="py-3 pr-4">Last Updated</th>
                <th className="py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-xs font-semibold text-white/65">
              {assetMigrationRows.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-10 text-center text-[10px] font-black uppercase tracking-widest text-white/30">
                    No asset migration records yet. Run an authorized scan to populate this overview.
                  </td>
                </tr>
              ) : assetMigrationRows.map((asset) => {
                const styles = statusStyles(asset.status);
                const riskClass = asset.riskScore >= 80
                  ? 'text-red-300'
                  : asset.riskScore >= 60
                    ? 'text-orange-300'
                    : asset.riskScore >= 40
                      ? 'text-gold'
                      : 'text-emerald-300';
                return (
                  <tr key={asset.id} className="transition hover:bg-gold/[0.04]">
                    <td className="py-3 pr-4 text-white/85">{asset.name}</td>
                    <td className="py-3 pr-4">{asset.type}</td>
                    <td className="py-3 pr-4 font-mono text-white/70">{asset.currentAlgorithm}</td>
                    <td className="py-3 pr-4 font-mono text-white/70">{asset.targetAlgorithm}</td>
                    <td className={`py-3 pr-4 font-black ${styles.color}`}>{styles.label}</td>
                    <td className={`py-3 pr-4 font-black ${riskClass}`}>{asset.riskLabel}</td>
                    <td className="py-3 pr-4">{asset.environment}</td>
                    <td className="py-3 pr-4">{asset.owner}</td>
                    <td className="py-3 pr-4">{asset.lastUpdated}</td>
                    <td className="py-3 text-right">
                      <div className="inline-flex gap-2">
                        <a href="/dashboard/assets" className="rounded-md border border-gold/20 bg-gold/10 p-1.5 text-gold transition hover:border-gold/60" title="View asset">
                          <Target className="h-3.5 w-3.5" />
                        </a>
                        <a href="/dashboard/scanner" className="rounded-md border border-gold/20 bg-gold/10 p-1.5 text-gold transition hover:border-gold/60" title="Rescan asset">
                          <RefreshCw className="h-3.5 w-3.5" />
                        </a>
                        <a href="/dashboard/migration-planner" className="rounded-md border border-gold/20 bg-gold/10 p-1.5 text-gold transition hover:border-gold/60" title="Open migration planner">
                          <ArrowRight className="h-3.5 w-3.5" />
                        </a>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className={`${GLASS_PANEL_CLASSES} p-5`}>
        <div className="relative z-10 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <SectionTitle>Migration Dependency Graph</SectionTitle>
            <div className="mt-2 text-[10px] font-bold uppercase tracking-wider text-white/35">
              {numberFmt(data.summary.totalAssets)} assets / {numberFmt(data.summary.totalComponents)} crypto components / {numberFmt(data.summary.vulnerableComponents)} vulnerable paths
            </div>
          </div>
          <div className="inline-flex w-fit rounded-lg border border-gold/20 bg-black/20 p-1">
            {(['graph', 'list'] as const).map((view) => (
              <button
                key={view}
                type="button"
                onClick={() => setDependencyView(view)}
                className={`rounded-md px-4 py-2 text-[10px] font-black uppercase tracking-wider transition ${dependencyView === view ? 'bg-gold/15 text-gold shadow-[0_0_16px_rgba(255,211,107,0.22)]' : 'text-white/45 hover:text-white/70'}`}
              >
                {view === 'graph' ? 'Graph View' : 'List View'}
              </button>
            ))}
          </div>
        </div>

        {dependencyView === 'graph' ? (
          <DependencyGraphCanvas nodes={dependencyGraph.nodes} links={dependencyGraph.links} />
        ) : (
          <DependencyGraphList nodes={dependencyGraph.nodes} links={dependencyGraph.links} />
        )}
      </section>
    </div>
  );
}
