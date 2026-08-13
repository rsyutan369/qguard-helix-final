/**
 * Runtime Cryptographic Intelligence — presentation library.
 *
 * Pure client-side helpers only: colour mapping, formatting, filtering and CSV
 * export. Every NUMBER shown on the page is served by the runtime intelligence
 * engine; nothing is computed or invented here.
 */

import type {
  QuantumStatus,
  RiskLevel,
  RuntimeCryptoIntelligence,
  RuntimeEvent,
  RuntimeIssue,
  SecurityState,
  TimeWindowKey,
} from '@/lib/runtime-crypto/runtime-intelligence';

/* ------------------------------------------------------------------ */
/* Semantic palette (§24)                                              */
/* ------------------------------------------------------------------ */

export const GREEN = '#34d399';   // Quantum Safe
export const BLUE = '#60a5fa';    // Hybrid PQC
export const AMBER = '#fbbf24';   // Attention
export const ORANGE = '#fb923c';  // High risk
export const RED = '#f87171';     // Critical
export const SLATE = '#94a3b8';   // Unknown
export const CYAN = '#22d3ee';    // Platform accent
export const VIOLET = '#a78bfa';  // Sophia / AI

export const STATUS_HEX: Record<QuantumStatus, string> = {
  safe: GREEN,
  hybrid: BLUE,
  vulnerable: RED,
  unknown: SLATE,
};

export const RISK_HEX: Record<RiskLevel, string> = {
  critical: RED,
  high: ORANGE,
  medium: AMBER,
  low: GREEN,
};

/** Risk is never communicated by colour alone (§25). */
export const RISK_GLYPH: Record<RiskLevel, string> = {
  critical: '●',
  high: '●',
  medium: '◐',
  low: '✓',
};

export const RISK_LABEL: Record<RiskLevel, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'ATTENTION',
  low: 'LOW',
};

export const STATE_HEX: Record<SecurityState, string> = {
  excellent: GREEN,
  good: GREEN,
  attention: AMBER,
  'high-risk': ORANGE,
  critical: RED,
  unknown: SLATE,
};

/* ------------------------------------------------------------------ */
/* Formatting                                                          */
/* ------------------------------------------------------------------ */

export function fmtInt(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return new Intl.NumberFormat('en-US').format(Math.round(value));
}

export function fmtCompact(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  if (Math.abs(value) >= 1000) {
    return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(value);
  }
  return fmtInt(value);
}

/** A percentage that is genuinely unmeasured renders as an em dash, never 0%. */
export function fmtPct(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return `${Math.round(value)}%`;
}

export function clockTime(iso: string | null | undefined): string {
  if (!iso) return '--:--:--';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '--:--:--';
  return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return 'never';
  const diff = Date.now() - then;
  if (diff < 5000) return 'just now';
  if (diff < 60_000) return `${Math.max(1, Math.floor(diff / 1000))} seconds ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export function fullTimestamp(iso: string | null | undefined): string {
  if (!iso) return 'Not recorded';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return 'Not recorded';
  return date.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'medium' });
}

/* ------------------------------------------------------------------ */
/* Filters (§15)                                                       */
/* ------------------------------------------------------------------ */

export interface RuntimeFilters {
  environment: string;
  risk: 'all' | RiskLevel;
  status: 'all' | QuantumStatus;
  window: TimeWindowKey;
  search: string;
}

export const EMPTY_FILTERS: RuntimeFilters = {
  environment: 'all',
  risk: 'all',
  status: 'all',
  window: '24h',
  search: '',
};

export function activeFilterCount(filters: RuntimeFilters): number {
  let count = 0;
  if (filters.environment !== 'all') count += 1;
  if (filters.risk !== 'all') count += 1;
  if (filters.status !== 'all') count += 1;
  if (filters.search.trim()) count += 1;
  return count;
}

export function filtersFromSearchParams(search: string): RuntimeFilters {
  const params = new URLSearchParams(search);
  const risk = params.get('risk');
  const status = params.get('status');
  const window = params.get('window');
  return {
    environment: params.get('environment') || 'all',
    risk: (['critical', 'high', 'medium', 'low'] as string[]).includes(risk || '') ? (risk as RiskLevel) : 'all',
    status: (['safe', 'hybrid', 'vulnerable', 'unknown'] as string[]).includes(status || '') ? (status as QuantumStatus) : 'all',
    window: (['15m', '1h', '24h', '7d', '30d'] as string[]).includes(window || '') ? (window as TimeWindowKey) : '24h',
    search: params.get('q') || '',
  };
}

export function filtersToSearchParams(filters: RuntimeFilters): string {
  const params = new URLSearchParams();
  if (filters.environment !== 'all') params.set('environment', filters.environment);
  if (filters.risk !== 'all') params.set('risk', filters.risk);
  if (filters.status !== 'all') params.set('status', filters.status);
  if (filters.window !== '24h') params.set('window', filters.window);
  if (filters.search.trim()) params.set('q', filters.search.trim());
  const query = params.toString();
  return query ? `?${query}` : '';
}

/**
 * Client-side filtering of the already-fetched page of events. The server
 * applies the same predicates for paged requests (§26) — this keeps the visible
 * table responsive between fetches without ever widening the data set.
 */
export function filterEvents(events: RuntimeEvent[], filters: RuntimeFilters): RuntimeEvent[] {
  const search = filters.search.trim().toLowerCase();
  return events.filter((event) => {
    if (filters.environment !== 'all' && event.environment !== filters.environment) return false;
    if (filters.risk !== 'all' && event.risk !== filters.risk) return false;
    if (filters.status !== 'all' && event.quantumStatus !== filters.status) return false;
    if (search) {
      const haystack = [
        event.assetName,
        event.algorithm,
        event.observedValue,
        event.operation,
        event.technical.host ?? '',
        event.technical.cipherSuite ?? '',
        event.technical.certificateFingerprint ?? '',
        event.technical.library ?? '',
      ]
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });
}

export function filterIssues(issues: RuntimeIssue[], filters: RuntimeFilters): RuntimeIssue[] {
  const search = filters.search.trim().toLowerCase();
  return issues.filter((issue) => {
    if (filters.environment !== 'all' && issue.environment !== filters.environment) return false;
    if (filters.risk !== 'all' && issue.severity !== filters.risk) return false;
    if (filters.status !== 'all' && issue.quantumStatus !== filters.status) return false;
    if (search) {
      const haystack = `${issue.assetName} ${issue.title} ${issue.recommendedAction}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });
}

/* ------------------------------------------------------------------ */
/* Export                                                             */
/* ------------------------------------------------------------------ */

function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * Exports exactly what is on screen, and says so in the header row — an export
 * that silently widens or narrows the filtered view is a reconciliation bug
 * waiting to be reported as a data error.
 */
export function eventsToCsv(events: RuntimeEvent[], filters: RuntimeFilters, windowLabel: string): string {
  const header = [
    `# QGuard Helix — Runtime Cryptographic Activity`,
    `# Window: ${windowLabel}`,
    `# Filters: environment=${filters.environment}, risk=${filters.risk}, quantum status=${filters.status}${filters.search.trim() ? `, search="${filters.search.trim()}"` : ''}`,
    `# Rows: ${events.length}`,
  ].join('\n');
  const columns = ['Observed At', 'Application', 'Environment', 'Operation', 'Algorithm', 'Observed Value', 'Quantum Status', 'Risk', 'Priority', 'Recommended Action'];
  const rows = events.map((event) =>
    [
      event.observedAt ?? '',
      event.assetName,
      event.environment,
      event.operation,
      event.algorithm,
      event.observedValue,
      event.statusLabel,
      RISK_LABEL[event.risk],
      event.riskScore,
      event.recommendedAction,
    ]
      .map(csvCell)
      .join(','),
  );
  return `${header}\n${columns.join(',')}\n${rows.join('\n')}\n`;
}

export function downloadTextFile(filename: string, content: string, mime = 'text/csv;charset=utf-8'): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

/* ------------------------------------------------------------------ */
/* Sophia grounding                                                    */
/* ------------------------------------------------------------------ */

/**
 * Compact page context handed to the copilot so its answer is grounded in the
 * same evidence the user is looking at, and never in invented telemetry.
 */
export function sophiaContextFor(data: RuntimeCryptoIntelligence | null): string {
  if (!data) return 'Runtime Cryptographic Intelligence — no data loaded.';
  const mix = data.securityStatus.mix.map((row) => `${row.label} ${row.count} (${row.percent}%)`).join(', ');
  return [
    `Page: Runtime Cryptographic Intelligence (${data.window.label}).`,
    `Runtime observations: ${data.kpis.activity}. Covered assets: ${data.telemetry.coveredAssets}.`,
    `Runtime mix — ${mix}.`,
    data.securityStatus.score === null
      ? 'Runtime security score: not published (no runtime evidence).'
      : `Runtime security score: ${data.securityStatus.score}/100 (${data.securityStatus.stateLabel}).`,
    `Open runtime issues: ${data.kpis.activeIssues} (${data.kpis.criticalIssues} critical).`,
    data.issues.length ? `Top issue: ${data.issues[0].title} on ${data.issues[0].assetName}.` : 'No open runtime issues.',
    `Estate PQC adoption (Quantum Readiness): ${data.pqcAdoption.estateAdoptionPct}%.`,
  ].join(' ');
}
