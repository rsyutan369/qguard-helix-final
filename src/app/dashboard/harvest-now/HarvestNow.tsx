'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Crosshair,
  Database,
  Expand,
  Fingerprint,
  Flame,
  Gauge,
  LockKeyhole,
  Network,
  RefreshCw,
  Settings,
  ShieldCheck,
  Siren,
  Skull,
  UserCog,
  Zap,
} from 'lucide-react';
import { useScannerIntelligence, type ScannerFinding } from '@/lib/scanner/use-scanner-intelligence';

type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
type Tone = 'red' | 'gold' | 'green' | 'blue' | 'muted';

type ThreatRow = {
  id: string;
  anchorKey: string;
  name: string;
  location: string;
  impact: string;
  severity: Severity;
  recommendation: string;
  timestamp: string;
  riskScore: number;
};

type MapNode = {
  id: string;
  name: string;
  location: string;
  impact: Severity;
  x: number;
  y: number;
};

type MissionEvent = {
  id: string;
  time: string;
  label: string;
  detail: string;
  tone: Tone;
};

type ActionItem = {
  label: string;
  detail: string;
  icon: LucideIcon;
  count: number;
};

type TimerAnchor = {
  firstSeenMs: number;
  source: 'telemetry' | 'session';
};

const RESPONSE_WINDOW_MS = 60 * 60 * 1000;

const PANEL =
  'hndl-panel group relative overflow-hidden rounded-lg border border-[#26394a]/80 bg-[#05080d]/70 shadow-[inset_0_1px_0_rgba(255,255,255,0.08),0_0_22px_rgba(255,33,33,0.12)] backdrop-blur-xl transition-all duration-300 hover:-translate-y-0.5 hover:border-gold/70 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.14),0_0_32px_rgba(255,211,107,0.24),0_0_70px_rgba(255,211,107,0.12)]';

const RED_PANEL =
  'hndl-panel group relative overflow-hidden rounded-lg border border-red-500/45 bg-[#120606]/75 shadow-[inset_0_1px_0_rgba(255,255,255,0.08),0_0_34px_rgba(239,68,68,0.2)] backdrop-blur-xl transition-all duration-300 hover:-translate-y-0.5 hover:border-gold/70 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.16),0_0_40px_rgba(255,211,107,0.28),0_0_90px_rgba(239,68,68,0.22)]';

const GREEN_PANEL =
  'hndl-panel group relative overflow-hidden rounded-lg border border-emerald-400/45 bg-[#06120d]/75 shadow-[inset_0_1px_0_rgba(255,255,255,0.08),0_0_34px_rgba(52,211,153,0.2)] backdrop-blur-xl transition-all duration-300 hover:-translate-y-0.5 hover:border-gold/70 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.16),0_0_40px_rgba(255,211,107,0.25),0_0_90px_rgba(52,211,153,0.22)]';

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(Math.max(0, Number(value) || 0));
}

function formatPercent(value: number) {
  return `${Math.max(0, Math.min(100, Math.round(Number(value) || 0)))}%`;
}

function formatBytesFromCount(value: number) {
  const safe = Math.max(0, Number(value) || 0);
  if (safe >= 1000) return `${(safe / 1000).toFixed(2)} PB`;
  if (safe >= 1) return `${safe.toFixed(2)} TB`;
  return '0 TB';
}

function percentOf(value: number, total: number) {
  if (!total) return 0;
  return Math.max(0, Math.min(100, Math.round((value / total) * 100)));
}

function normalizeSeverity(value: unknown): Severity {
  const level = String(value || '').toUpperCase();
  if (level === 'CRITICAL') return 'Critical';
  if (level === 'HIGH') return 'High';
  if (level === 'MEDIUM' || level === 'MODERATE') return 'Medium';
  if (level === 'SAFE' || level === 'INFO') return 'Info';
  return 'Low';
}

function severityRank(severity: Severity) {
  if (severity === 'Critical') return 5;
  if (severity === 'High') return 4;
  if (severity === 'Medium') return 3;
  if (severity === 'Low') return 2;
  return 1;
}

function severityClasses(severity: Severity) {
  if (severity === 'Critical') return 'border-red-500/60 bg-red-500/15 text-red-300 shadow-[0_0_18px_rgba(239,68,68,0.25)]';
  if (severity === 'High') return 'border-orange-400/55 bg-orange-500/15 text-orange-300';
  if (severity === 'Medium') return 'border-gold/45 bg-gold/10 text-gold';
  if (severity === 'Info') return 'border-sky-400/35 bg-sky-500/10 text-sky-300';
  return 'border-white/15 bg-white/[0.04] text-white/50';
}

function toneDot(tone: Tone) {
  if (tone === 'red') return 'bg-red-400 shadow-[0_0_12px_rgba(248,113,113,0.9)]';
  if (tone === 'gold') return 'bg-gold shadow-[0_0_12px_rgba(255,211,107,0.85)]';
  if (tone === 'green') return 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.8)]';
  if (tone === 'blue') return 'bg-sky-400 shadow-[0_0_12px_rgba(56,189,248,0.8)]';
  return 'bg-white/35';
}

function threatName(finding: ScannerFinding, index: number) {
  const raw = String(finding.algorithm || finding.category || finding.source || `HNDL-${index + 1}`);
  return `${raw.replace(/[^a-z0-9]+/gi, '.').replace(/(^\.|\.$)/g, '').toUpperCase()}.HNDL`;
}

function findingLocation(finding: ScannerFinding) {
  return String(finding.location || finding.asset || finding.target || finding.source || 'Unmapped asset');
}

function findingRecommendation(finding: ScannerFinding) {
  return String(finding.recommendation || 'Prioritize PQC remediation for this exposure.');
}

function isHndlRelevant(finding: ScannerFinding) {
  const text = [
    finding.algorithm,
    finding.category,
    finding.status,
    finding.evidence,
    finding.recommendation,
    finding.source,
  ].join(' ').toLowerCase();
  const severity = normalizeSeverity(finding.threatLevel || finding.severity || finding.status);
  return severityRank(severity) >= 3 || /rsa|ecc|ecdsa|dh|dsa|legacy|vulnerable|hndl|harvest|decrypt|quantum/.test(text);
}

function eventTime(value: unknown) {
  const date = value ? new Date(String(value)) : null;
  if (!date || Number.isNaN(date.getTime())) return '--:--:--';
  return date.toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function utcTime(value: unknown) {
  const date = value ? new Date(String(value)) : new Date();
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'UTC',
    timeZoneName: 'short',
  });
}

function recordOf(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function timestampMs(value: unknown) {
  if (!value) return null;
  const parsed = Date.parse(String(value));
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
}

function findingDetectedMs(finding: ScannerFinding) {
  const raw = recordOf(finding.raw);
  const metadata = recordOf(finding.metadata);
  const candidates = [
    finding.timestamp,
    finding.detectedAt,
    finding.detected_at,
    finding.created_at,
    finding.observed_at,
    metadata.detectedAt,
    metadata.detected_at,
    metadata.timestamp,
    metadata.created_at,
    raw.detectedAt,
    raw.detected_at,
    raw.timestamp,
    raw.created_at,
  ];

  for (const candidate of candidates) {
    const parsed = timestampMs(candidate);
    if (parsed) return parsed;
  }

  return null;
}

function threatAnchorKey(finding: ScannerFinding, index: number) {
  const severity = normalizeSeverity(finding.threatLevel || finding.severity || finding.status);
  const parts = [
    finding.id,
    finding.algorithm,
    finding.category,
    findingLocation(finding),
    severity,
    finding.evidence,
  ].filter(Boolean);
  return parts.length > 0 ? parts.join('|') : `hndl-finding-${index}`;
}

function stableThreatTimestamp(finding: ScannerFinding, anchorKey: string, anchors: Map<string, TimerAnchor>) {
  const telemetryMs = findingDetectedMs(finding);
  const existing = anchors.get(anchorKey);

  if (telemetryMs) {
    const firstSeenMs = existing?.source === 'telemetry'
      ? Math.min(existing.firstSeenMs, telemetryMs)
      : telemetryMs;
    anchors.set(anchorKey, { firstSeenMs, source: 'telemetry' });
    return new Date(firstSeenMs).toISOString();
  }

  if (existing) return new Date(existing.firstSeenMs).toISOString();

  const firstSeenMs = Date.now();
  anchors.set(anchorKey, { firstSeenMs, source: 'session' });
  return new Date(firstSeenMs).toISOString();
}

function formatCountdownMs(value: number) {
  const totalSeconds = Math.max(0, Math.ceil(value / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return [hours, minutes, seconds].map((part) => String(part).padStart(2, '0')).join(':');
}

function responseWindowState(timestamp: string, now = Date.now()) {
  const source = timestampMs(timestamp);
  if (!source) {
    return {
      remainingMs: 0,
      completedCycles: 0,
      activeCycle: 1,
      overdue: false,
    };
  }

  const elapsed = Math.max(0, now - source);
  const completedCycles = Math.floor(elapsed / RESPONSE_WINDOW_MS);
  const elapsedInCycle = elapsed % RESPONSE_WINDOW_MS;
  const remainingMs = completedCycles > 0
    ? RESPONSE_WINDOW_MS - elapsedInCycle
    : Math.max(0, RESPONSE_WINDOW_MS - elapsed);

  return {
    remainingMs: Math.min(RESPONSE_WINDOW_MS, Math.max(0, remainingMs)),
    completedCycles,
    activeCycle: completedCycles + 1,
    overdue: completedCycles > 0,
  };
}

function buildRemediationHref(threat: ThreatRow | undefined, active: boolean) {
  if (!active || !threat) {
    return '/dashboard/audit-vault?source=harvest-now&status=mitigated';
  }

  const params = new URLSearchParams({
    source: 'harvest-now',
    workflow: 'hndl-remediation',
    threatId: threat.id,
    threat: threat.name,
    asset: threat.location,
    severity: threat.severity,
    action: 'remediate',
  });

  return `/dashboard/pqc-orchestration?${params.toString()}`;
}

function hashText(value: string) {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }
  return hash;
}

function deterministicPoint(seed: string, axis: 'x' | 'y') {
  const hash = hashText(`${axis}:${seed}`);
  const min = axis === 'x' ? 10 : 24;
  const max = axis === 'x' ? 90 : 72;
  return min + (hash % (max - min));
}

function sparklinePath(values: number[], width = 156, height = 58) {
  const points = values.length > 1 ? values : [0, values[0] || 0, 0];
  const max = Math.max(1, ...points);
  return points.map((value, index) => {
    const x = (index / Math.max(1, points.length - 1)) * width;
    const y = height - (Math.max(0, value) / max) * height;
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
}

function SectionHeader({ children, action }: { children: string; action?: string }) {
  return (
    <div className="relative z-10 mb-2 flex items-center justify-between gap-3 border-b border-white/10 pb-1.5">
      <h2 className="text-[11px] font-black uppercase tracking-[0.12em] text-white/72">{children}</h2>
      {action && <span className="text-[9px] font-black uppercase tracking-[0.16em] text-red-400">{action}</span>}
    </div>
  );
}

export default function HarvestNow() {
  const { data, loading, error, connected, refresh } = useScannerIntelligence();
  const [now, setNow] = useState(() => Date.now());
  const [dismissedReminderId, setDismissedReminderId] = useState<string | null>(null);
  const threatTimerAnchorsRef = useRef<Map<string, TimerAnchor>>(new Map());

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const threats = useMemo<ThreatRow[]>(() => (
    data.findings
      .filter(isHndlRelevant)
      .map((finding, index) => {
        const severity = normalizeSeverity(finding.threatLevel || finding.severity || finding.status);
        const anchorKey = threatAnchorKey(finding, index);
        return {
          id: String(finding.id || `${finding.algorithm || finding.category || 'finding'}-${index}`),
          anchorKey,
          name: threatName(finding, index),
          location: findingLocation(finding),
          impact: severity === 'Info' ? 'Low' : severity,
          severity,
          recommendation: findingRecommendation(finding),
          timestamp: stableThreatTimestamp(finding, anchorKey, threatTimerAnchorsRef.current),
          riskScore: severityRank(severity) * 20,
        };
      })
      .sort((a, b) => (severityRank(b.severity) * 100 + b.riskScore) - (severityRank(a.severity) * 100 + a.riskScore))
  ), [data.findings]);

  useEffect(() => {
    const activeKeys = new Set(threats.map((threat) => threat.anchorKey));
    for (const key of threatTimerAnchorsRef.current.keys()) {
      if (!activeKeys.has(key)) threatTimerAnchorsRef.current.delete(key);
    }
  }, [threats]);

  const activeThreatCount = threats.filter((threat) => severityRank(threat.severity) >= 3).length;
  const criticalThreatCount = data.severityCounts.critical;
  const highThreatCount = data.severityCounts.high;
  const mediumThreatCount = data.severityCounts.medium;
  const lowThreatCount = data.severityCounts.low;
  const infoThreatCount = data.severityCounts.safe;
  const primaryThreat = threats[0];
  const primaryThreatTimestamp = primaryThreat?.timestamp || '';
  const responseWindow = responseWindowState(primaryThreatTimestamp, now);
  const responseCountdown = formatCountdownMs(responseWindow.remainingMs);
  const hndlAlertActive = activeThreatCount > 0;
  const responseWindowExpired = hndlAlertActive && responseWindow.overdue;
  const reminderId = primaryThreat ? `${primaryThreat.id}:${primaryThreat.timestamp}:cycle-${responseWindow.completedCycles}` : 'hndl-reminder';
  const showOverdueReminder = responseWindowExpired && dismissedReminderId !== reminderId;
  const remediationHref = buildRemediationHref(primaryThreat, hndlAlertActive);
  const hndlHeroPanel = hndlAlertActive ? RED_PANEL : GREEN_PANEL;
  const hndlTone = {
    badge: hndlAlertActive
      ? 'border-red-500/70 bg-red-500/15 text-red-200 shadow-[0_0_26px_rgba(239,68,68,0.35)]'
      : 'border-emerald-400/70 bg-emerald-500/15 text-emerald-200 shadow-[0_0_26px_rgba(52,211,153,0.32)]',
    icon: hndlAlertActive ? 'text-red-300' : 'text-emerald-300',
    text: hndlAlertActive ? 'text-red-300' : 'text-emerald-300',
    textStrong: hndlAlertActive ? 'text-red-400' : 'text-emerald-300',
    borderStrong: hndlAlertActive ? 'border-red-500/45' : 'border-emerald-400/45',
    borderMid: hndlAlertActive ? 'border-red-400/45' : 'border-emerald-400/40',
    borderSoft: hndlAlertActive ? 'border-red-300/30' : 'border-emerald-300/25',
    ringShadow: hndlAlertActive ? 'shadow-[0_0_26px_rgba(239,68,68,0.3)]' : 'shadow-[0_0_26px_rgba(52,211,153,0.28)]',
    iconShadow: hndlAlertActive ? 'drop-shadow-[0_0_18px_rgba(248,113,113,0.9)]' : 'drop-shadow-[0_0_18px_rgba(52,211,153,0.75)]',
    textMuted: hndlAlertActive ? 'text-red-300/65' : 'text-emerald-300/65',
    action: hndlAlertActive
      ? 'border-red-400/70 bg-red-500/20 text-red-100 shadow-[0_0_28px_rgba(239,68,68,0.38)]'
      : 'border-emerald-400/70 bg-emerald-500/15 text-emerald-100 shadow-[0_0_28px_rgba(52,211,153,0.28)]',
    meter: hndlAlertActive
      ? 'border-red-500/35 shadow-[0_0_22px_rgba(239,68,68,0.18)]'
      : 'border-emerald-400/35 shadow-[0_0_22px_rgba(52,211,153,0.16)]',
    flow: hndlAlertActive ? 'rgba(239,68,68,0.92)' : 'rgba(52,211,153,0.92)',
    flowSoft: hndlAlertActive ? 'rgba(239,68,68,0.32)' : 'rgba(52,211,153,0.30)',
  };

  useEffect(() => {
    setDismissedReminderId(null);
  }, [reminderId]);

  const assetTotals = useMemo(() => {
    const unknown = data.assets.assets.filter((asset: any) => !asset.riskScore && !asset.vulnerableCount).length;
    const compromised = data.summary.vulnerableAssets;
    const atRisk = data.assets.assets.filter((asset: any) => Number(asset.riskScore || 0) > 0 && Number(asset.vulnerableCount || 0) === 0).length;
    const secure = Math.max(0, data.summary.totalAssets - compromised - atRisk - unknown);
    return {
      total: data.summary.totalAssets,
      secure,
      atRisk,
      compromised,
      unknown,
    };
  }, [data.assets.assets, data.summary.totalAssets, data.summary.vulnerableAssets]);

  const mapNodes = useMemo<MapNode[]>(() => {
    const sourceNodes = data.exposure.nodes.length > 0
      ? data.exposure.nodes
      : data.assets.assets.map((asset: any) => ({
        id: asset.id,
        label: asset.name || asset.domain || asset.url,
        name: asset.name || asset.domain || asset.url,
        region: asset.region || asset.metadata?.region || asset.environment || asset.metadata?.environment,
        riskScore: asset.riskScore,
        vulnerableCount: asset.vulnerableCount,
      }));

    return sourceNodes
      .map((node: any, index: number) => {
        const id = String(node.id || node.name || node.label || `node-${index}`);
        const risk = Number(node.riskScore || node.risk || 0);
        const vulnerable = Number(node.vulnerableCount || node.vulnerableComponents || 0);
        const impact: Severity = risk >= 80 ? 'Critical' : risk >= 55 || vulnerable > 0 ? 'High' : risk >= 25 ? 'Medium' : 'Low';
        return {
          id,
          name: String(node.name || node.label || `Asset ${index + 1}`),
          location: String(node.region || node.location || node.environment || 'Tenant scope'),
          impact,
          x: Number(node.x) || deterministicPoint(id, 'x'),
          y: Number(node.y) || deterministicPoint(id, 'y'),
        };
      })
      .filter((node) => severityRank(node.impact) >= 2)
      .slice(0, 16);
  }, [data.assets.assets, data.exposure.nodes]);

  const missionFeed = useMemo<MissionEvent[]>(() => {
    const telemetryEvents = data.telemetry.map((event: any, index: number) => {
      const message = String(event.message || event.status || event.type || event.event || 'Scanner telemetry update');
      const finding = event.finding || {};
      const severity = normalizeSeverity(finding.threatLevel || event.severity || event.level);
      return {
        id: String(event.id || event.timestamp || `telemetry-${index}`),
        time: eventTime(event.timestamp || event.observedAt || event.created_at),
        label: severityRank(severity) >= 4 ? 'HNDL threat detected' : message,
        detail: String(event.target || event.asset || finding.location || finding.algorithm || message),
        tone: severityRank(severity) >= 4 ? 'red' as Tone : severityRank(severity) >= 3 ? 'gold' as Tone : 'blue' as Tone,
      };
    });

    const historyEvents = data.history.history.slice(0, 6).map((entry: any, index: number) => ({
      id: String(entry.scanId || `history-${index}`),
      time: eventTime(entry.startedAt || entry.completedAt),
      label: String(entry.status || 'Scan activity').replace(/[-_]/g, ' '),
      detail: String(entry.target || `${entry.detectedComponents || 0} detections`),
      tone: Number(entry.vulnerableFindings || 0) > 0 ? 'red' as Tone : 'green' as Tone,
    }));

    return telemetryEvents.concat(historyEvents).slice(0, 8);
  }, [data.history.history, data.telemetry]);

  const defenseActions = useMemo<ActionItem[]>(() => [
    { label: 'Isolate Asset', detail: 'Block threat propagation', icon: Network, count: assetTotals.compromised },
    { label: 'Kill Process', detail: 'Terminate malicious process', icon: Zap, count: data.runtime.alerts },
    { label: 'Revoke Credentials', detail: 'Invalidate exposed keys', icon: Fingerprint, count: data.runtime.keyRotations },
    { label: 'Patch & Harden', detail: 'Apply security hardening', icon: Settings, count: data.summary.vulnerableComponents },
    { label: 'Backup & Restore', detail: 'Recover from clean backup', icon: Database, count: data.summary.completedScans },
    { label: 'Deploy Honeypot', detail: 'Trap and analyze attacker', icon: Crosshair, count: activeThreatCount },
  ], [activeThreatCount, assetTotals.compromised, data.runtime.alerts, data.runtime.keyRotations, data.summary.completedScans, data.summary.vulnerableComponents]);

  const sparkValues = useMemo(() => {
    const riskHistory = data.history.history
      .slice(0, 12)
      .map((entry: any) => Number(entry.riskScore || entry.summary?.riskScore || entry.vulnerableFindings || 0))
      .reverse();
    return riskHistory.length > 0 ? riskHistory : [criticalThreatCount, highThreatCount, mediumThreatCount, lowThreatCount, infoThreatCount];
  }, [criticalThreatCount, data.history.history, highThreatCount, infoThreatCount, lowThreatCount, mediumThreatCount]);

  const dataAtRisk = formatBytesFromCount(data.summary.vulnerableComponents / 10);
  const attackSurfaceChange = percentOf(data.summary.totalFindings, Math.max(1, data.summary.totalComponents + data.summary.totalFindings));
  const pqcReadyChange = data.summary.pqcReadiness;

  return (
    <div className="hndl-shell min-h-full bg-[#02050a] p-3 text-white md:p-4">
      <style>{`
        .hndl-shell {
          background:
            radial-gradient(circle at 18% 10%, rgba(239, 68, 68, 0.18), transparent 28%),
            radial-gradient(circle at 76% 8%, rgba(255, 211, 107, 0.12), transparent 26%),
            linear-gradient(180deg, #02050a 0%, #05070c 48%, #020409 100%);
        }
        .hndl-panel::before,
        .hndl-hero::before {
          content: "";
          position: absolute;
          inset: 0;
          pointer-events: none;
          background:
            linear-gradient(135deg, rgba(255,255,255,0.08), transparent 18%, transparent 82%, rgba(255,33,33,0.08)),
            repeating-linear-gradient(90deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 42px);
          opacity: 0.72;
        }
        .hndl-panel::after,
        .hndl-hero::after {
          content: "";
          position: absolute;
          inset: 0;
          pointer-events: none;
          border-radius: inherit;
          background: linear-gradient(90deg, transparent, rgba(255,211,107,0.28), transparent);
          height: 1px;
          top: 0;
          opacity: 0;
          transition: opacity 300ms ease;
        }
        .hndl-panel:hover::after,
        .hndl-hero:hover::after {
          opacity: 1;
        }
        .hndl-grid {
          background-size: 28px 28px;
        }
        .hndl-grid-alert {
          background-image:
            linear-gradient(rgba(239,68,68,0.08) 1px, transparent 1px),
            linear-gradient(90deg, rgba(239,68,68,0.08) 1px, transparent 1px);
        }
        .hndl-grid-clear {
          background-image:
            linear-gradient(rgba(52,211,153,0.08) 1px, transparent 1px),
            linear-gradient(90deg, rgba(52,211,153,0.08) 1px, transparent 1px);
        }
        .hndl-hero-alert {
          animation: hndlRedPulse 2.35s ease-in-out infinite;
        }
        .hndl-hero-clear {
          animation: hndlGreenPulse 3s ease-in-out infinite;
        }
        .hndl-hero-clear::before {
          background:
            linear-gradient(135deg, rgba(255,255,255,0.08), transparent 18%, transparent 82%, rgba(52,211,153,0.09)),
            repeating-linear-gradient(90deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 42px);
        }
        .hndl-rune {
          animation: hndlRunePulse 2.2s ease-in-out infinite;
        }
        .hndl-map {
          background:
            radial-gradient(circle at 25% 45%, rgba(239,68,68,0.22), transparent 13%),
            radial-gradient(circle at 54% 38%, rgba(239,68,68,0.18), transparent 16%),
            radial-gradient(circle at 78% 52%, rgba(239,68,68,0.24), transparent 13%),
            radial-gradient(circle at 40% 60%, rgba(255,211,107,0.08), transparent 18%),
            linear-gradient(180deg, rgba(4, 9, 16, 0.2), rgba(2, 5, 10, 0.85));
        }
        .hndl-map-clear {
          background:
            radial-gradient(circle at 25% 45%, rgba(52,211,153,0.18), transparent 13%),
            radial-gradient(circle at 54% 38%, rgba(52,211,153,0.14), transparent 16%),
            radial-gradient(circle at 78% 52%, rgba(52,211,153,0.2), transparent 13%),
            radial-gradient(circle at 40% 60%, rgba(255,211,107,0.08), transparent 18%),
            linear-gradient(180deg, rgba(4, 16, 11, 0.25), rgba(2, 8, 6, 0.85));
        }
        .hndl-map::before {
          content: "";
          position: absolute;
          inset: 18px;
          opacity: 0.68;
          background-image:
            radial-gradient(circle, rgba(248,113,113,0.72) 0 1px, transparent 1.5px),
            linear-gradient(rgba(56,189,248,0.08) 1px, transparent 1px),
            linear-gradient(90deg, rgba(56,189,248,0.08) 1px, transparent 1px);
          background-size: 16px 10px, 48px 48px, 48px 48px;
          mask-image: radial-gradient(ellipse at 25% 45%, black 0 20%, transparent 35%),
            radial-gradient(ellipse at 50% 40%, black 0 24%, transparent 38%),
            radial-gradient(ellipse at 78% 52%, black 0 22%, transparent 35%);
          mask-composite: add;
        }
        .hndl-map-clear::before {
          background-image:
            radial-gradient(circle, rgba(52,211,153,0.62) 0 1px, transparent 1.5px),
            linear-gradient(rgba(52,211,153,0.08) 1px, transparent 1px),
            linear-gradient(90deg, rgba(52,211,153,0.08) 1px, transparent 1px);
        }
        .hndl-flow-line {
          stroke-dasharray: 7 9;
          animation: hndlFlow 1.6s linear infinite;
        }
        .hndl-flow-glow {
          stroke-dasharray: 10 16;
          animation: hndlFlow 2.6s linear infinite reverse;
        }
        .hndl-scanline {
          background: linear-gradient(180deg, transparent, rgba(255,255,255,0.08), transparent);
          animation: hndlScan 4s linear infinite;
        }
        .hndl-scanline-clear {
          background: linear-gradient(180deg, transparent, rgba(52,211,153,0.12), transparent);
        }
        @keyframes hndlScan {
          from { transform: translateY(-100%); }
          to { transform: translateY(100%); }
        }
        @keyframes hndlFlow {
          from { stroke-dashoffset: 0; }
          to { stroke-dashoffset: -48; }
        }
        @keyframes hndlRedPulse {
          0%, 100% { box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 0 28px rgba(239,68,68,0.22), 0 0 70px rgba(239,68,68,0.08); }
          50% { box-shadow: inset 0 1px 0 rgba(255,255,255,0.14), 0 0 42px rgba(239,68,68,0.42), 0 0 110px rgba(239,68,68,0.18); }
        }
        @keyframes hndlGreenPulse {
          0%, 100% { box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 0 26px rgba(52,211,153,0.18), 0 0 70px rgba(52,211,153,0.07); }
          50% { box-shadow: inset 0 1px 0 rgba(255,255,255,0.14), 0 0 38px rgba(52,211,153,0.34), 0 0 100px rgba(52,211,153,0.14); }
        }
        @keyframes hndlRunePulse {
          0%, 100% { transform: scale(1); opacity: 0.86; }
          50% { transform: scale(1.035); opacity: 1; }
        }
      `}</style>

      <div className="mx-auto grid max-w-[1600px] gap-3">
        <header className="grid gap-2 sm:grid-cols-2 xl:grid-cols-[minmax(340px,1fr)_160px_150px_48px_48px_230px]">
          <div className={`${PANEL} sm:col-span-2 xl:col-span-1`}>
            <div className="relative z-10 flex min-h-[56px] flex-col justify-center px-3 py-2">
              <h1 className="text-lg font-black uppercase leading-none tracking-[0.07em] text-white md:text-xl xl:whitespace-nowrap">
                Harvest Now, Decrypt Later
              </h1>
              <p className="mt-1 text-[10px] font-black uppercase tracking-[0.16em] text-white/48">
                Quantum threat command center
              </p>
            </div>
          </div>

          <div className={PANEL}>
            <div className="relative z-10 flex min-h-[56px] flex-col justify-center px-3 py-2">
              <p className="text-[9px] font-black uppercase tracking-[0.16em] text-white/35">System Time</p>
              <p className="mt-1 font-mono text-xs font-black text-white">{utcTime(data.generatedAt)}</p>
            </div>
          </div>
          <div className={`${PANEL} border-emerald-400/35`}>
            <div className="relative z-10 flex min-h-[56px] flex-col justify-center px-3 py-2">
              <p className="text-[9px] font-black uppercase tracking-[0.16em] text-emerald-300/70">Defense Mode</p>
              <p className="mt-1 text-xs font-black uppercase text-emerald-300">{connected ? 'Active' : 'Syncing'}</p>
            </div>
          </div>
          <button type="button" className={`${PANEL} relative z-10 grid min-h-[56px] place-items-center text-white/65 hover:text-gold`} aria-label="Expand harvest dashboard">
            <Expand className="h-4 w-4" />
          </button>
          <button type="button" onClick={refresh} className={`${PANEL} relative z-10 grid min-h-[56px] place-items-center text-white/65 hover:text-gold`} aria-label="Refresh harvest dashboard">
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <div className={PANEL}>
            <div className="relative z-10 flex min-h-[56px] items-center gap-2 px-2.5 py-2">
              <div className="grid h-9 w-9 shrink-0 place-items-center rounded-md border border-red-400/40 bg-red-500/15 text-red-300">
                <UserCog className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <p className="truncate text-[10px] font-black uppercase tracking-[0.1em] text-white">QGuard Commander</p>
                <p className="text-[9px] font-bold text-white/45">Authenticated</p>
              </div>
            </div>
          </div>
        </header>

        {error && (
          <div className="rounded-lg border border-red-400/30 bg-red-500/10 px-4 py-3 text-sm font-semibold text-red-200">
            {error}
          </div>
        )}

        {showOverdueReminder && (
          <div className="fixed bottom-5 right-5 z-[70] w-[min(360px,calc(100vw-32px))] overflow-hidden rounded-lg border border-red-400/55 bg-[#140606]/95 p-4 text-white shadow-[0_0_34px_rgba(239,68,68,0.35)] backdrop-blur-xl">
            <div className="flex gap-3">
              <div className="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-red-400/50 bg-red-500/15 text-red-300">
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-black uppercase tracking-[0.14em] text-red-300">1HR remediation overdue</p>
                <p className="mt-1 text-xs font-medium leading-5 text-white/62">
                  {primaryThreat ? `${primaryThreat.name} on ${primaryThreat.location} is still active in live scanner telemetry.` : 'An active HNDL exposure is still unresolved in live scanner telemetry.'}
                  {' '}Escalation cycle {responseWindow.activeCycle} is now running and will repeat hourly until remediation clears the finding.
                </p>
              </div>
            </div>
            <div className="mt-3 flex gap-2">
              <a href={remediationHref} className="inline-flex h-8 flex-1 items-center justify-center rounded border border-red-400/70 bg-red-500/15 text-[10px] font-black uppercase tracking-[0.12em] text-red-100 transition hover:border-gold hover:bg-gold/10 hover:text-gold">
                Remediate Now
              </a>
              <button type="button" onClick={() => setDismissedReminderId(reminderId)} className="inline-flex h-8 items-center justify-center rounded border border-white/10 px-3 text-[10px] font-black uppercase tracking-[0.12em] text-white/55 transition hover:border-white/30 hover:text-white">
                Dismiss
              </button>
            </div>
          </div>
        )}

        <main className="grid gap-3">
          <div className="grid gap-3">
            <section className={`${hndlHeroPanel} hndl-hero ${hndlAlertActive ? 'hndl-hero-alert' : 'hndl-hero-clear'} min-h-[270px]`}>
              <div className={`hndl-grid ${hndlAlertActive ? 'hndl-grid-alert' : 'hndl-grid-clear'} absolute inset-0 opacity-70`} />
              <div className={`hndl-scanline ${hndlAlertActive ? '' : 'hndl-scanline-clear'} absolute inset-x-0 top-0 h-1/2 opacity-35`} />
              <div className="relative z-10 flex h-full flex-col p-3">
                <div className={`mx-auto mb-3 inline-flex items-center gap-2 rounded-md px-6 py-1.5 ${hndlTone.badge}`}>
                  {hndlAlertActive ? <AlertTriangle className="h-4 w-4 fill-red-400/20" /> : <ShieldCheck className="h-4 w-4" />}
                  <span className="text-xs font-black uppercase tracking-[0.18em]">
                    {hndlAlertActive ? 'HNDL Threat Detected' : 'HNDL Remediated / Mitigated'}
                  </span>
                </div>

                <div className="grid flex-1 items-center gap-4 lg:grid-cols-[190px_1fr]">
                  <div className="flex flex-col items-center justify-center">
                    <div className="hndl-rune relative grid h-32 w-32 place-items-center">
                      <div className={`absolute inset-0 rotate-45 border ${hndlTone.borderStrong} ${hndlTone.ringShadow}`} />
                      <div className={`absolute inset-5 rotate-45 border ${hndlTone.borderMid}`} />
                      <div className={`absolute inset-10 rotate-45 border ${hndlTone.borderSoft}`} />
                      <LockKeyhole className={`h-12 w-12 ${hndlTone.icon} ${hndlTone.iconShadow}`} />
                    </div>
                    <p className={`mt-2 text-[10px] font-black uppercase tracking-[0.18em] ${hndlTone.textMuted}`}>Threat Level</p>
                    <p className={`text-xl font-black uppercase tracking-[0.16em] ${hndlTone.textStrong}`}>
                      {criticalThreatCount > 0 ? 'Critical' : activeThreatCount > 0 ? 'Elevated' : 'Mitigated'}
                    </p>
                  </div>

                  <div className="text-center">
                    <p className={`text-sm font-black uppercase tracking-[0.16em] ${hndlTone.text}`}>
                      {hndlAlertActive ? 'Critical Threat Detected' : 'Threat Remediated / Mitigated'}
                    </p>
                    <h2 className={`mt-2 text-3xl font-black uppercase leading-tight tracking-[0.05em] text-white ${hndlTone.iconShadow} md:text-4xl`}>
                      Harvest Now, Decrypt Later
                    </h2>
                    <p className="mt-2 text-xs font-black uppercase tracking-[0.14em] text-white/65">
                      {hndlAlertActive ? 'Immediate action required' : 'Current tenant telemetry is clear'}
                    </p>

                    <div className="mt-4 flex flex-col items-center justify-center gap-3 md:flex-row">
                      <div className={`rounded-lg border bg-black/40 px-4 py-2 ${hndlTone.meter}`}>
                        <p className={`text-[9px] font-black uppercase tracking-[0.18em] ${hndlTone.textMuted}`}>{hndlAlertActive ? (responseWindowExpired ? 'Next 1HR Escalation' : '1HR Response Window') : 'Remediation State'}</p>
                        <p className={`mt-1 font-mono text-3xl font-black tracking-[0.1em] ${hndlTone.text}`}>
                          {activeThreatCount > 0 ? responseCountdown : '00:00:00'}
                        </p>
                        <p className={`mt-1 text-[9px] font-black uppercase tracking-[0.14em] ${hndlTone.textMuted}`}>
                          {hndlAlertActive ? (responseWindowExpired ? `Cycle ${responseWindow.activeCycle} active` : 'Live SLA countdown') : 'No active HNDL SLA'}
                        </p>
                      </div>
                      <a href={remediationHref} className={`inline-flex min-h-11 items-center gap-2 rounded-md px-6 text-xs font-black uppercase tracking-[0.08em] transition hover:border-gold/80 hover:bg-gold/15 hover:text-gold ${hndlTone.action}`}>
                        {hndlAlertActive ? <AlertTriangle className="h-4 w-4" /> : <ShieldCheck className="h-4 w-4" />}
                        {hndlAlertActive ? 'Attend & Remediate Now' : 'Review Mitigation Evidence'}
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            <section className={`${PANEL} min-h-[370px]`}>
              <div className="relative z-10 p-3">
                <SectionHeader>Global Threat Map</SectionHeader>
                <div className={`hndl-map ${hndlAlertActive ? '' : 'hndl-map-clear'} relative min-h-[270px] overflow-hidden rounded-lg border ${hndlAlertActive ? 'border-red-500/25' : 'border-emerald-400/25'} bg-black/40`}>
                  <svg className="absolute inset-0 h-full w-full opacity-70" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
                    <path className="hndl-flow-glow" d="M7 66 C22 42, 34 40, 47 55 S78 72, 91 39" fill="none" stroke={hndlTone.flowSoft} strokeWidth="1.15" strokeLinecap="round" />
                    <path className="hndl-flow-line" d="M7 66 C22 42, 34 40, 47 55 S78 72, 91 39" fill="none" stroke={hndlTone.flow} strokeWidth="0.45" strokeLinecap="round" />
                    <path className="hndl-flow-line" d="M23 51 C34 34, 51 30, 73 52" fill="none" stroke={hndlAlertActive ? 'rgba(255,211,107,0.55)' : 'rgba(167,243,208,0.48)'} strokeWidth="0.32" strokeLinecap="round" />
                    <path className="hndl-flow-line" d="M13 42 C31 58, 45 70, 68 61 S83 46, 94 58" fill="none" stroke={hndlTone.flowSoft} strokeWidth="0.35" strokeLinecap="round" />
                  </svg>

                  {mapNodes.map((node) => (
                    <div
                      key={node.id}
                      className="absolute z-10 -translate-x-1/2 -translate-y-1/2"
                      style={{ left: `${node.x}%`, top: `${node.y}%` }}
                    >
                      <div className={`grid h-8 w-8 place-items-center rounded-full border ${severityClasses(node.impact)} bg-black/50`}>
                        <Crosshair className="h-4 w-4" />
                      </div>
                      <div className="mt-1 hidden w-44 rounded border border-red-500/35 bg-black/80 p-2 text-[10px] font-black uppercase tracking-[0.08em] text-white/70 shadow-[0_0_22px_rgba(239,68,68,0.22)] md:block">
                        <p className="truncate text-red-300">{node.name}</p>
                        <p className="mt-1 text-white/50">Location: {node.location}</p>
                        <p className="text-gold">Impact: {node.impact}</p>
                      </div>
                    </div>
                  ))}

                  {mapNodes.length === 0 && (
                    <div className="absolute inset-0 z-10 grid place-items-center text-center">
                      <div>
                        <ShieldCheck className="mx-auto h-10 w-10 text-emerald-300" />
                        <p className="mt-3 text-sm font-black uppercase tracking-[0.12em] text-white">No mapped HNDL exposure</p>
                        <p className="mt-1 text-xs font-medium text-white/45">Run an authenticated scan to populate the tenant exposure map.</p>
                      </div>
                    </div>
                  )}
                </div>

                <div className="mt-3 grid gap-3 md:grid-cols-4">
                  {[
                    { label: 'Attack Surface', value: formatNumber(data.summary.totalAssets), delta: attackSurfaceChange },
                    { label: 'Data At Risk', value: dataAtRisk, delta: percentOf(data.summary.vulnerableComponents, Math.max(1, data.summary.totalComponents)) },
                    { label: 'Encryption Targets', value: formatNumber(data.summary.totalComponents), delta: pqcReadyChange },
                    { label: 'Compromised Assets', value: formatNumber(assetTotals.compromised), delta: percentOf(assetTotals.compromised, Math.max(1, data.summary.totalAssets)) },
                  ].map((metric) => (
                    <div key={metric.label} className="rounded-md border border-white/10 bg-black/35 p-3 transition hover:border-gold/50 hover:bg-gold/[0.06]">
                      <p className="text-[10px] font-black uppercase tracking-[0.14em] text-white/35">{metric.label}</p>
                      <div className="mt-2 flex items-end justify-between gap-2">
                        <p className="font-mono text-2xl font-black text-white">{metric.value}</p>
                        <p className="text-[10px] font-black text-emerald-300">+{formatPercent(metric.delta)}</p>
                      </div>
                      <p className="mt-1 text-[10px] font-semibold text-white/35">vs latest scan baseline</p>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          </div>

          <aside className="grid gap-3 lg:grid-cols-3">
            <section className={PANEL}>
              <div className="relative z-10 p-3">
                <SectionHeader>Threat Status</SectionHeader>
                <div className="grid gap-2">
                  <div>
                    <div className="flex items-end gap-3">
                      <p className="font-mono text-5xl font-black leading-none text-red-400 drop-shadow-[0_0_16px_rgba(248,113,113,0.8)]">{formatNumber(activeThreatCount)}</p>
                      <div className="pb-1">
                        <p className="text-[9px] font-black uppercase tracking-[0.14em] text-white/35">Active HNDL Threats</p>
                        <p className="mt-0.5 text-[10px] font-bold text-white/55">{formatNumber(data.summary.totalFindings)} total findings</p>
                      </div>
                    </div>
                    <svg className="mt-2 h-12 w-full" viewBox="0 0 156 58" preserveAspectRatio="none" aria-hidden="true">
                      <defs>
                        <linearGradient id="hndlSpark" x1="0" x2="0" y1="0" y2="1">
                          <stop offset="0%" stopColor="rgba(239,68,68,0.65)" />
                          <stop offset="100%" stopColor="rgba(239,68,68,0.02)" />
                        </linearGradient>
                      </defs>
                      <path d={`${sparklinePath(sparkValues)} L 156 58 L 0 58 Z`} fill="url(#hndlSpark)" />
                      <path d={sparklinePath(sparkValues)} fill="none" stroke="#ef4444" strokeWidth="2" />
                    </svg>
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                    {[
                      ['Critical', criticalThreatCount],
                      ['High', highThreatCount],
                      ['Medium', mediumThreatCount],
                      ['Low', lowThreatCount],
                      ['Info', infoThreatCount],
                    ].map(([label, value]) => (
                      <div key={label} className="flex items-center justify-between gap-2 text-[10px]">
                        <span className={`inline-flex items-center gap-1.5 font-black uppercase tracking-[0.08em] ${label === 'Critical' ? 'text-red-300' : label === 'High' ? 'text-orange-300' : label === 'Medium' ? 'text-gold' : label === 'Info' ? 'text-sky-300' : 'text-white/45'}`}>
                          <span className="h-1.5 w-1.5 rounded-full border border-current" />
                          {label}
                        </span>
                        <span className="font-mono font-black text-white">{formatNumber(Number(value))}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>

            <section className={PANEL}>
              <div className="relative z-10 p-3">
                <SectionHeader>Remediate & Secure</SectionHeader>
                <div className="grid gap-2">
                  <div className="rounded-lg border border-red-500/35 bg-red-500/10 p-3">
                    <div className="flex gap-2.5">
                      <div className="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-red-400/45 bg-red-500/15 text-red-300">
                        <Skull className="h-5 w-5" />
                      </div>
                      <div>
                        <p className="text-xs font-black uppercase tracking-[0.1em] text-red-300">
                          {activeThreatCount > 0 ? 'Mitigation Required' : 'No Mitigation Queue'}
                        </p>
                        <p className="mt-1 text-[10px] font-medium text-white/52">
                          {activeThreatCount > 0 ? `${formatNumber(activeThreatCount)} active HNDL threats require immediate remediation.` : 'No active HNDL threats are currently reported.'}
                        </p>
                      </div>
                    </div>
                    <a href={remediationHref} className="mt-3 inline-flex h-8 w-full items-center justify-center rounded border border-red-400/70 bg-red-500/15 text-[10px] font-black uppercase tracking-[0.12em] text-red-100 transition hover:border-gold hover:bg-gold/10 hover:text-gold">
                      Start Remediation
                    </a>
                  </div>
                  <div className="rounded-lg border border-emerald-400/35 bg-emerald-500/10 p-3">
                    <div className="flex gap-2.5">
                      <div className="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-emerald-400/45 bg-emerald-500/15 text-emerald-300">
                        <ShieldCheck className="h-5 w-5" />
                      </div>
                      <div>
                        <p className="text-xs font-black uppercase tracking-[0.1em] text-emerald-300">All Clear</p>
                        <p className="mt-1 text-[10px] font-medium text-white/52">
                          {activeThreatCount === 0 ? 'No active HNDL threats. System is secure.' : `${formatNumber(Math.max(0, data.summary.totalAssets - assetTotals.compromised))} assets remain outside the active HNDL queue.`}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            <section className={PANEL}>
              <div className="relative z-10 p-3">
                <SectionHeader action="View All">Top HNDL Threats</SectionHeader>
                <div className="space-y-1.5">
                  {threats.slice(0, 4).map((threat) => (
                    <div key={threat.id} className="grid grid-cols-[16px_1fr_auto_14px] items-center gap-2 rounded border border-white/8 bg-white/[0.025] px-2 py-1.5 text-[10px] transition hover:border-gold/45 hover:bg-gold/[0.06]">
                      <Siren className="h-3 w-3 text-red-400" />
                      <div className="min-w-0">
                        <p className="truncate font-black uppercase tracking-[0.08em] text-red-300">{threat.name}</p>
                        <p className="truncate text-[9px] font-semibold text-white/38">{threat.location}</p>
                      </div>
                      <span className={`text-[9px] font-black uppercase ${severityClasses(threat.severity).split(' ').find((part) => part.startsWith('text-')) || 'text-white/50'}`}>
                        {threat.severity}
                      </span>
                      <ChevronRight className="h-3 w-3 text-white/25" />
                    </div>
                  ))}
                  {threats.length === 0 && (
                    <div className="rounded border border-white/10 bg-white/[0.025] px-3 py-5 text-center">
                      <CheckCircle2 className="mx-auto h-6 w-6 text-emerald-300" />
                      <p className="mt-2 text-xs font-black text-white">No active HNDL threats</p>
                      <p className="mt-1 text-xs font-medium text-white/42">Findings will appear here from live scanner intelligence.</p>
                    </div>
                  )}
                </div>
              </div>
            </section>
          </aside>
        </main>

        <section className="grid gap-3 xl:grid-cols-[420px_minmax(0,1fr)]">
          <div className={PANEL}>
            <div className="relative z-10 p-4">
              <SectionHeader>Mission Feed</SectionHeader>
              <div className="space-y-3">
                {missionFeed.map((event) => (
                  <div key={event.id} className="grid grid-cols-[10px_54px_1fr] gap-3 text-xs">
                    <span className={`mt-1.5 h-2 w-2 rounded-full ${toneDot(event.tone)}`} />
                    <span className="font-mono text-[10px] font-bold text-white/48">{event.time}</span>
                    <div className="min-w-0">
                      <p className={`truncate text-[11px] font-black uppercase tracking-[0.08em] ${event.tone === 'red' ? 'text-red-300' : event.tone === 'green' ? 'text-emerald-300' : event.tone === 'gold' ? 'text-gold' : 'text-sky-300'}`}>
                        {event.label}
                      </p>
                      <p className="truncate text-[10px] font-medium text-white/44">{event.detail}</p>
                    </div>
                  </div>
                ))}
                {missionFeed.length === 0 && (
                  <div className="rounded border border-white/10 bg-white/[0.025] px-4 py-8 text-center">
                    <Activity className="mx-auto h-7 w-7 text-white/35" />
                    <p className="mt-3 text-sm font-black text-white">No mission activity yet</p>
                    <p className="mt-1 text-xs font-medium text-white/42">Live scan telemetry and activity events will stream into this feed.</p>
                  </div>
                )}
              </div>
              <a href="/dashboard/scanner" className="mt-4 flex h-8 items-center justify-center rounded border border-sky-400/25 text-[10px] font-black uppercase tracking-[0.14em] text-sky-300 transition hover:border-gold/60 hover:text-gold">
                View Full Log
              </a>
            </div>
          </div>

          <div className={PANEL}>
            <div className="relative z-10 p-4">
              <SectionHeader>Defense Actions</SectionHeader>
              <div className="grid gap-3 md:grid-cols-2">
                {defenseActions.map((action) => {
                  const Icon = action.icon;
                  return (
                    <a key={action.label} href="/dashboard/pqc-orchestration" className="grid grid-cols-[44px_1fr_18px] items-center gap-3 rounded-lg border border-white/10 bg-white/[0.025] p-3 transition hover:border-gold/50 hover:bg-gold/[0.06]">
                      <div className="grid h-11 w-11 place-items-center rounded-md border border-red-400/35 bg-red-500/10 text-red-300">
                        <Icon className="h-5 w-5" />
                      </div>
                      <div className="min-w-0">
                        <p className="truncate text-xs font-black uppercase tracking-[0.1em] text-white">{action.label}</p>
                        <p className="truncate text-[10px] font-medium text-white/42">{action.detail}</p>
                        <p className="mt-1 font-mono text-[10px] font-black text-gold">{formatNumber(action.count)} linked signals</p>
                      </div>
                      <ChevronRight className="h-4 w-4 text-white/25" />
                    </a>
                  );
                })}
              </div>
            </div>
          </div>

          <div className={`${PANEL} xl:col-span-2`}>
            <div className="relative z-10 p-4">
              <SectionHeader>Asset Status</SectionHeader>
              <div className="grid gap-4 md:grid-cols-[1fr_190px_1fr]">
                <div className="grid content-center gap-4">
                  <div className="flex items-center justify-between rounded-lg border border-emerald-400/20 bg-emerald-500/8 p-3">
                    <span className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.12em] text-emerald-300"><ShieldCheck className="h-4 w-4" /> Secure</span>
                    <span className="font-mono text-2xl font-black text-emerald-300">{formatNumber(assetTotals.secure)}</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg border border-gold/20 bg-gold/8 p-3">
                    <span className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.12em] text-gold"><AlertTriangle className="h-4 w-4" /> At Risk</span>
                    <span className="font-mono text-2xl font-black text-gold">{formatNumber(assetTotals.atRisk)}</span>
                  </div>
                </div>

                <div className="relative grid min-h-[190px] place-items-center">
                  <div className="absolute h-40 w-40 rounded-full border border-red-400/30 shadow-[0_0_28px_rgba(239,68,68,0.2)]" />
                  <div
                    className="absolute h-36 w-36 rounded-full"
                    style={{
                      background: `conic-gradient(#ef4444 0 ${percentOf(assetTotals.compromised, Math.max(1, assetTotals.total))}%, #facc15 ${percentOf(assetTotals.compromised, Math.max(1, assetTotals.total))}% ${percentOf(assetTotals.compromised + assetTotals.atRisk, Math.max(1, assetTotals.total))}%, #34d399 ${percentOf(assetTotals.compromised + assetTotals.atRisk, Math.max(1, assetTotals.total))}% 100%)`,
                    }}
                  />
                  <div className="absolute h-28 w-28 rounded-full bg-[#05080d]" />
                  <div className="relative text-center">
                    <p className="font-mono text-3xl font-black text-white">{formatNumber(assetTotals.total)}</p>
                    <p className="mt-1 text-[10px] font-black uppercase tracking-[0.14em] text-white/45">Total Assets</p>
                  </div>
                </div>

                <div className="grid content-center gap-4">
                  <div className="flex items-center justify-between rounded-lg border border-red-400/20 bg-red-500/10 p-3">
                    <span className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.12em] text-red-300"><Flame className="h-4 w-4" /> Compromised</span>
                    <span className="font-mono text-2xl font-black text-red-300">{formatNumber(assetTotals.compromised)}</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg border border-white/10 bg-white/[0.03] p-3">
                    <span className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.12em] text-white/42"><Gauge className="h-4 w-4" /> Unknown</span>
                    <span className="font-mono text-2xl font-black text-white/65">{formatNumber(assetTotals.unknown)}</span>
                  </div>
                </div>
              </div>
              <a href="/dashboard/asset-intelligence" className="mt-4 flex h-9 items-center justify-center rounded border border-sky-400/25 text-[10px] font-black uppercase tracking-[0.14em] text-sky-300 transition hover:border-gold/60 hover:text-gold">
                View All Assets
              </a>
            </div>
          </div>
        </section>

        <footer className="relative overflow-hidden rounded-lg border border-red-500/30 bg-red-500/5 px-5 py-3 text-center shadow-[0_0_24px_rgba(239,68,68,0.12)]">
          <p className="relative z-10 text-sm font-black uppercase tracking-[0.16em] text-red-300">
            Protect Today. Decrypt Never.
          </p>
        </footer>
      </div>
    </div>
  );
}
