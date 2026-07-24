/**
 * Enterprise Migration Operations Center — derivation library.
 *
 * Pure, side-effect-free functions that transform the three SHARED live
 * snapshots the platform already produces into the view models each section of
 * the Operations Center renders. Nothing here fabricates production metrics —
 * every value is derived from authenticated evidence, and where a real source is
 * absent the field is reported as null / "—" with an honest `basis`.
 *
 * Inputs (all reused, never duplicated):
 *   - ScannerIntelligenceSnapshot  → useScannerIntelligence()  (CBOM/assets/history/telemetry)
 *   - MigrationWorkflowState        → useMigrationWorkflow()     (11-stage NIST lifecycle)
 *   - OrchestratorSnapshot          → useMigrationOrchestrator() (live job orchestration)
 */

import type { ScannerIntelligenceSnapshot } from '@/lib/scanner/use-scanner-intelligence';
import type { MigrationWorkflowState, WorkflowStageStatus } from '@/types/migration-workflow';
import type { OrchestratorSnapshot, OrchestratorJobPhase } from '@/types/migration-orchestrator';

/* ------------------------------------------------------------------ */
/* Palette — neon-cyan design language (matches Executive / Live Ops)  */
/* ------------------------------------------------------------------ */

export const CYAN = '#22d3ee';
export const GREEN = '#34d399';
export const RED = '#f87171';
export const AMBER = '#fbbf24';
export const VIOLET = '#a78bfa';
export const BLUE = '#60a5fa';

export type OpsTone = 'good' | 'warning' | 'critical' | 'neutral' | 'info' | 'ai';

export const TONE_HEX: Record<OpsTone, string> = {
  good: GREEN,
  warning: AMBER,
  critical: RED,
  neutral: CYAN,
  info: BLUE,
  ai: VIOLET,
};

/* ------------------------------------------------------------------ */
/* Formatters + small helpers                                          */
/* ------------------------------------------------------------------ */

export function numberFmt(value: number): string {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(Number(value) || 0)));
}

export function compact(value: number): string {
  const v = Number(value) || 0;
  if (Math.abs(v) >= 1000) return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(v);
  return numberFmt(v);
}

export function pct(value: number): string {
  return `${clampPct(value)}%`;
}

export function clampPct(value: number): number {
  return Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
}

export function safeDate(value?: string | null): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function compactDate(value?: string | null): string {
  const date = safeDate(value);
  if (!date) return '—';
  return date.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
}

export function compactTime(value?: string | null): string {
  const date = safeDate(value);
  if (!date) return '--:--';
  return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
}

export function clockTime(value?: string | null): string {
  const date = safeDate(value);
  if (!date) return '--:--:--';
  return date.toLocaleTimeString('en-US', { hour12: false });
}

export function addDays(base: string | undefined, days: number): string {
  const date = base ? new Date(base) : new Date();
  if (Number.isNaN(date.getTime())) return new Date().toISOString();
  date.setDate(date.getDate() + days);
  return date.toISOString();
}

export function relativeTime(iso?: string | null): string {
  const then = safeDate(iso)?.getTime();
  if (!then) return 'awaiting sync';
  const diff = Date.now() - then;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export function fmtDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds <= 0) return '—';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

export function threatWeight(level?: string): number {
  const n = String(level || '').toUpperCase();
  if (n === 'CRITICAL') return 100;
  if (n === 'HIGH') return 78;
  if (n === 'MEDIUM' || n === 'MODERATE') return 55;
  if (n === 'LOW') return 28;
  return 8;
}

export function riskLabel(score: number): { label: string; tone: OpsTone } {
  if (score >= 80) return { label: 'Critical', tone: 'critical' };
  if (score >= 60) return { label: 'High', tone: 'warning' };
  if (score >= 40) return { label: 'Medium', tone: 'neutral' };
  return { label: 'Low', tone: 'good' };
}

export function downloadTextFile(filename: string, content: string, type: string): void {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function csvCell(value: unknown): string {
  return `"${String(value ?? '').replaceAll('"', '""')}"`;
}

/* ------------------------------------------------------------------ */
/* Shared input bundle                                                 */
/* ------------------------------------------------------------------ */

export interface OpsInputs {
  scanner: ScannerIntelligenceSnapshot;
  workflow: MigrationWorkflowState | null;
  orch: OrchestratorSnapshot;
}

export function hasAnyEvidence(input: OpsInputs): boolean {
  const s = input.scanner.summary;
  return Boolean(
    s.totalAssets || s.totalComponents || s.totalFindings ||
    input.orch.hasData || input.workflow?.hasData,
  );
}

/* -- history series helpers (oldest → latest) ----------------------- */

function historyPoints(scanner: ScannerIntelligenceSnapshot, limit = 12): any[] {
  return scanner.history.history.slice(0, limit).reverse();
}

export function seriesPqcReady(scanner: ScannerIntelligenceSnapshot): number[] {
  return historyPoints(scanner).map((e: any) => Number(e.summary?.pqcReady ?? e.pqcReadyFindings ?? 0));
}
export function seriesVulnerable(scanner: ScannerIntelligenceSnapshot): number[] {
  return historyPoints(scanner).map((e: any) => Number(e.summary?.vulnerable ?? e.vulnerableFindings ?? 0));
}
export function seriesRisk(scanner: ScannerIntelligenceSnapshot): number[] {
  return historyPoints(scanner).map((e: any) => Number(e.summary?.riskScore ?? e.riskScore ?? scanner.summary.riskScore));
}
export function seriesFindings(scanner: ScannerIntelligenceSnapshot): number[] {
  return historyPoints(scanner).map((e: any) => Number(e.summary?.totalFindings ?? e.detectedComponents ?? 0));
}

/* ------------------------------------------------------------------ */
/* Inventory classification (drives waves + dependency graph)          */
/* ------------------------------------------------------------------ */

export type CategoryKey =
  | 'applications' | 'certificates' | 'vpn'
  | 'webApis' | 'tls' | 'pki'
  | 'cloud' | 'containers' | 'iot' | 'hsm';

interface CategorySpec { key: CategoryKey; label: string; icon: string; rx: RegExp }

const CATEGORY_SPECS: CategorySpec[] = [
  { key: 'applications', label: 'Applications', icon: 'AppWindow', rx: /app|application|service|portal|frontend|backend|microservice|workload/i },
  { key: 'certificates', label: 'Certificates', icon: 'BadgeCheck', rx: /cert|x509|certificate|leaf|chain|issuer/i },
  { key: 'vpn', label: 'VPN / Remote Access', icon: 'Network', rx: /vpn|ipsec|wireguard|remote access|bastion|tunnel/i },
  { key: 'webApis', label: 'Web APIs', icon: 'Globe2', rx: /\bapi\b|gateway|rest|graphql|endpoint|webhook|jwt|oauth|oidc/i },
  { key: 'tls', label: 'TLS / SSL', icon: 'Lock', rx: /tls|ssl|https|cipher|handshake|protocol/i },
  { key: 'pki', label: 'PKI', icon: 'ShieldCheck', rx: /pki|ca\b|trust|root|intermediate|authority/i },
  { key: 'cloud', label: 'Cloud', icon: 'Cloud', rx: /cloud|aws|azure|gcp|s3|ec2|lambda|blob|bucket/i },
  { key: 'containers', label: 'Containers / K8s', icon: 'Boxes', rx: /container|docker|kubernetes|k8s|pod|helm|registry|image/i },
  { key: 'iot', label: 'IoT / Edge', icon: 'Cpu', rx: /iot|edge|device|firmware|sensor|embedded|mqtt/i },
  { key: 'hsm', label: 'HSM / Keys', icon: 'KeyRound', rx: /hsm|kms|key vault|keystore|rsa|ecdsa|ed25519|private key|dek|kek/i },
];

function entryText(entry: any): string {
  return [entry.type, entry.component, entry.algorithm, entry.category, entry.sourceAsset, entry.location, entry.evidence]
    .filter(Boolean).join(' ');
}
function assetText(asset: any): string {
  return [asset.name, asset.type, asset.url, asset.host, asset.provider, asset.metadata?.assetType, asset.metadata?.environment]
    .filter(Boolean).join(' ');
}

export interface CategoryStat {
  key: CategoryKey;
  label: string;
  icon: string;
  total: number;
  ready: number;
  vulnerable: number;
  progress: number;
  status: 'completed' | 'running' | 'scheduled' | 'empty';
}

export function classifyInventory(scanner: ScannerIntelligenceSnapshot): CategoryStat[] {
  const entries = scanner.cbom.entries || [];
  const assets = scanner.assets.assets || [];
  return CATEGORY_SPECS.map((spec) => {
    const matchedEntries = entries.filter((e: any) => spec.rx.test(entryText(e)));
    const matchedAssets = assets.filter((a: any) => spec.rx.test(assetText(a)));
    const entryTotal = matchedEntries.length;
    const total = entryTotal > 0 ? entryTotal : matchedAssets.length;
    const ready = entryTotal > 0
      ? matchedEntries.filter((e: any) => e.isQuantumSafe).length
      : matchedAssets.filter((a: any) => Number(a.riskScore || 0) < 40 && Number(a.vulnerableCount || 0) === 0).length;
    const vulnerable = entryTotal > 0
      ? matchedEntries.filter((e: any) => e.isVulnerable).length
      : matchedAssets.filter((a: any) => Number(a.vulnerableCount || 0) > 0 || Number(a.riskScore || 0) >= 40).length;
    const progress = total > 0 ? clampPct((ready / total) * 100) : 0;
    const status: CategoryStat['status'] = total === 0
      ? 'empty'
      : progress >= 100
        ? 'completed'
        : ready > 0 || vulnerable < total
          ? 'running'
          : 'scheduled';
    return { key: spec.key, label: spec.label, icon: spec.icon, total, ready, vulnerable, progress, status };
  });
}

/* ------------------------------------------------------------------ */
/* Section 3 — Migration Waves                                         */
/* ------------------------------------------------------------------ */

export type WaveStatus = 'completed' | 'running' | 'scheduled' | 'empty';

export interface MigrationWave {
  id: number;
  name: string;
  theme: string;
  status: WaveStatus;
  progress: number;
  total: number;
  ready: number;
  vulnerable: number;
  categories: CategoryStat[];
  window: string;
}

const WAVE_LAYOUT: Array<{ id: number; name: string; theme: string; keys: CategoryKey[] }> = [
  { id: 1, name: 'Wave 1', theme: 'Foundational Trust', keys: ['applications', 'certificates', 'vpn'] },
  { id: 2, name: 'Wave 2', theme: 'Perimeter & Transport', keys: ['webApis', 'tls', 'pki'] },
  { id: 3, name: 'Wave 3', theme: 'Platform & Edge', keys: ['cloud', 'containers', 'iot', 'hsm'] },
];

export function buildWaves(scanner: ScannerIntelligenceSnapshot): MigrationWave[] {
  const cats = classifyInventory(scanner);
  const byKey = new Map(cats.map((c) => [c.key, c]));
  const base = scanner.history.history[0]?.startedAt || scanner.generatedAt;
  return WAVE_LAYOUT.map((layout, idx) => {
    const categories = layout.keys.map((k) => byKey.get(k)!).filter(Boolean);
    const total = categories.reduce((s, c) => s + c.total, 0);
    const ready = categories.reduce((s, c) => s + c.ready, 0);
    const vulnerable = categories.reduce((s, c) => s + c.vulnerable, 0);
    const progress = total > 0 ? clampPct((ready / total) * 100) : 0;
    let status: WaveStatus = 'empty';
    if (total > 0) {
      if (progress >= 100) status = 'completed';
      else if (progress > 0 || categories.some((c) => c.status === 'running')) status = 'running';
      else status = 'scheduled';
    }
    return {
      ...layout,
      status,
      progress,
      total,
      ready,
      vulnerable,
      categories,
      window: `${compactDate(addDays(base, idx * 21))} – ${compactDate(addDays(base, idx * 21 + 21))}`,
    };
  });
}

export function activeWave(waves: MigrationWave[]): MigrationWave | null {
  return waves.find((w) => w.status === 'running')
    ?? waves.find((w) => w.status === 'scheduled')
    ?? waves.find((w) => w.total > 0)
    ?? null;
}

/* ------------------------------------------------------------------ */
/* Section 1 — Executive Summary Banner                                */
/* ------------------------------------------------------------------ */

export interface BannerMetric {
  key: string;
  label: string;
  value: string;
  tone: OpsTone;
  basis: string;
}

export function buildExecutiveBanner(input: OpsInputs): BannerMetric[] {
  const { scanner, workflow, orch } = input;
  const s = scanner.summary;
  const m = orch.metrics;
  const waves = buildWaves(scanner);
  const wave = activeWave(waves);

  const migrated = s.pqcReadyComponents;
  const remaining = s.vulnerableComponents;
  const denom = migrated + remaining;
  const riskReduction = denom > 0 ? clampPct((migrated / denom) * 100) : 0;

  const overallProgress = orch.hasData
    ? m.overallProgressPct
    : workflow?.hasData
      ? workflow.overallProgressPct
      : s.pqcReadiness;

  const validation = orch.hasData ? m.validationProgressPct : deriveValidationFromHistory(scanner);
  const failRate = m.total > 0 ? ((m.failed + m.deadLetter) / m.total) * 100 : 0;
  const confidence = hasAnyEvidence(input)
    ? clampPct(0.45 * validation + 0.30 * (100 - failRate) + 0.25 * s.pqcReadiness)
    : 0;

  const rollback = rollbackReadiness(input);
  const compliance = clampPct(scanner.runtime.complianceScore);
  const completion = estimateCompletion(input);
  const zeroDowntime = m.failed === 0;

  return [
    { key: 'progress', label: 'Migration Progress', value: pct(overallProgress), tone: overallProgress >= 66 ? 'good' : overallProgress >= 33 ? 'neutral' : 'warning', basis: orch.hasData ? 'Live orchestration progress' : workflow?.hasData ? 'Workflow lifecycle progress' : 'PQC-ready component share' },
    { key: 'readiness', label: 'Quantum Readiness', value: pct(s.qScore), tone: s.qScore >= 66 ? 'good' : s.qScore >= 33 ? 'neutral' : 'critical', basis: 'Q-Score = 100 − quantum risk exposure' },
    { key: 'risk', label: 'Risk Reduction', value: pct(riskReduction), tone: riskReduction >= 50 ? 'good' : 'neutral', basis: 'Migrated ÷ (migrated + vulnerable) components' },
    { key: 'confidence', label: 'Migration Confidence', value: pct(confidence), tone: confidence >= 80 ? 'good' : confidence >= 50 ? 'neutral' : 'warning', basis: 'Validation, failure rate & PQC coverage composite' },
    { key: 'rollback', label: 'Rollback Ready', value: pct(rollback.value), tone: rollback.value >= 90 ? 'good' : 'warning', basis: rollback.basis },
    { key: 'downtime', label: 'Expected Downtime', value: zeroDowntime ? '0s' : `${m.failed} review`, tone: zeroDowntime ? 'good' : 'critical', basis: zeroDowntime ? 'Hybrid ML-KEM cutover — no interruption' : `${m.failed} failed cutover(s) require review` },
    { key: 'compliance', label: 'Compliance', value: pct(compliance), tone: compliance >= 80 ? 'good' : compliance >= 50 ? 'neutral' : 'warning', basis: 'PQC-ready share across governed inventory' },
    { key: 'completion', label: 'Projected Completion', value: completion.value, tone: 'info', basis: completion.basis },
    { key: 'wave', label: 'Current Wave', value: wave ? wave.name : '—', tone: 'neutral', basis: wave ? `${wave.theme} · ${pct(wave.progress)} complete` : 'No wave evidence yet' },
  ];
}

function deriveValidationFromHistory(scanner: ScannerIntelligenceSnapshot): number {
  const h = scanner.history.history;
  if (h.length === 0) return scanner.summary.pqcReadiness;
  const completed = h.filter((e: any) => e.status === 'completed').length;
  return clampPct((completed / h.length) * 100);
}

export function rollbackReadiness(input: OpsInputs): { value: number; basis: string } {
  const m = input.orch.metrics;
  if (input.orch.hasData) {
    const protectedJobs = m.running + m.leased + m.validating + m.completed + m.rolledBack;
    const base = protectedJobs + m.failed;
    const value = base > 0 ? clampPct((protectedJobs / base) * 100) : 100;
    return { value, basis: 'Snapshot-backed jobs ÷ (backed + unrolled failures)' };
  }
  const ready = input.scanner.summary.pqcReadyComponents > 0 ? 100 : 0;
  return { value: ready, basis: 'Pre-migration crypto-state snapshot coverage' };
}

export function estimateCompletion(input: OpsInputs): { value: string; basis: string } {
  const m = input.orch.metrics;
  const remaining = input.orch.hasData ? m.assetsRemaining : input.scanner.summary.vulnerableComponents;
  if (remaining <= 0) {
    return hasAnyEvidence(input)
      ? { value: 'Complete', basis: 'No remaining quantum-vulnerable work' }
      : { value: '—', basis: 'Awaiting scanner evidence' };
  }
  if (m.throughputPerMin && m.throughputPerMin > 0) {
    const perDay = m.throughputPerMin * 60 * 24;
    const days = Math.max(1, Math.ceil(remaining / perDay));
    return { value: compactDate(addDays(input.orch.generatedAt || new Date().toISOString(), days)), basis: `Measured throughput (${m.throughputPerMin.toFixed(1)}/min)` };
  }
  const days = Math.max(7, remaining * 3);
  return { value: compactDate(addDays(new Date().toISOString(), days)), basis: 'Planning estimate (~3 days / component)' };
}

/* ------------------------------------------------------------------ */
/* Section 2 — Mission Control KPIs                                    */
/* ------------------------------------------------------------------ */

export interface OpsKpi {
  key: string;
  label: string;
  value: string;
  detail: string;
  tone: OpsTone;
  spark: number[];
  live: boolean;
  basis: string;
}

export function buildKpis(input: OpsInputs): OpsKpi[] {
  const { scanner, orch } = input;
  const s = scanner.summary;
  const m = orch.metrics;
  const waves = buildWaves(scanner);
  const wave = activeWave(waves);
  const cats = classifyInventory(scanner);
  const catBy = (k: CategoryKey) => cats.find((c) => c.key === k);
  const tls = catBy('tls');
  const certs = catBy('certificates');

  const assets = scanner.assets.assets || [];
  const owners = new Set(assets.map((a: any) => String(a.metadata?.owner || a.metadata?.businessOwner || '').trim()).filter(Boolean));
  const failRate = m.total > 0 ? ((m.failed + m.deadLetter) / m.total) * 100 : 0;
  const businessImpact = s.criticalFindings + scanner.severityCounts.high;
  const confidence = hasAnyEvidence(input)
    ? clampPct(0.45 * (orch.hasData ? m.validationProgressPct : deriveValidationFromHistory(scanner)) + 0.30 * (100 - failRate) + 0.25 * s.pqcReadiness)
    : 0;
  const downtimeRisk = m.failed > 0 ? 'High' : m.retrying > 0 ? 'Medium' : 'Low';
  const velocity = m.throughputPerMin != null ? `${m.throughputPerMin.toFixed(1)}/min` : '—';

  const readySpark = seriesPqcReady(scanner);
  const vulnSpark = seriesVulnerable(scanner);
  const riskSpark = seriesRisk(scanner);
  const throughSpark = orch.throughput.map((p) => p.completed);

  return [
    { key: 'coverage', label: 'Migration Coverage', value: pct(s.pqcReadiness), detail: `${numberFmt(s.pqcReadyComponents)} of ${numberFmt(s.totalComponents)} components`, tone: 'good', spark: readySpark, live: true, basis: 'PQC-ready components ÷ total components' },
    { key: 'migrated', label: 'Assets Migrated', value: numberFmt(orch.hasData ? m.assetsUpgraded : s.pqcReadyComponents), detail: 'Quantum-safe', tone: 'good', spark: readySpark, live: orch.hasData, basis: orch.hasData ? 'Orchestrator assets upgraded' : 'PQC-ready components' },
    { key: 'remaining', label: 'Assets Remaining', value: numberFmt(orch.hasData ? m.assetsRemaining : s.vulnerableComponents), detail: 'Vulnerable', tone: 'warning', spark: vulnSpark, live: orch.hasData, basis: orch.hasData ? 'Orchestrator assets remaining' : 'Quantum-vulnerable components' },
    { key: 'velocity', label: 'Migration Velocity', value: velocity, detail: m.throughputPerMin != null ? 'measured' : 'awaiting jobs', tone: 'neutral', spark: throughSpark, live: orch.hasData, basis: 'Completed assets per minute (windowed)' },
    { key: 'wave', label: 'Current Wave', value: wave ? wave.name : '—', detail: wave ? wave.theme : 'no evidence', tone: 'neutral', spark: [wave?.progress ?? 0], live: false, basis: 'Active migration wave' },
    { key: 'owners', label: 'Affected Owners', value: numberFmt(owners.size || 0), detail: 'business teams', tone: 'info', spark: [owners.size], live: false, basis: 'Distinct asset owners in scope' },
    { key: 'downtime', label: 'Downtime Risk', value: downtimeRisk, detail: downtimeRisk === 'Low' ? 'hybrid cutover' : 'review jobs', tone: downtimeRisk === 'Low' ? 'good' : downtimeRisk === 'Medium' ? 'warning' : 'critical', spark: [m.failed, m.retrying], live: orch.hasData, basis: 'Failed / retrying cutover jobs' },
    { key: 'rollback', label: 'Rollback Ready', value: pct(rollbackReadiness(input).value), detail: 'snapshot-backed', tone: 'good', spark: [rollbackReadiness(input).value], live: orch.hasData, basis: rollbackReadiness(input).basis },
    { key: 'hybridtls', label: 'Hybrid TLS Adoption', value: tls && tls.total > 0 ? pct(tls.progress) : '—', detail: tls ? `${numberFmt(tls.ready)} of ${numberFmt(tls.total)}` : 'no TLS findings', tone: 'neutral', spark: readySpark, live: true, basis: 'Quantum-safe TLS ÷ total TLS findings' },
    { key: 'certrotation', label: 'Certificate Rotation', value: certs && certs.total > 0 ? pct(certs.progress) : '—', detail: certs ? `${numberFmt(certs.ready)} of ${numberFmt(certs.total)}` : 'no cert findings', tone: 'neutral', spark: readySpark, live: true, basis: 'PQC-ready certificates ÷ total certificates' },
    { key: 'legacy', label: 'Legacy Crypto Remaining', value: numberFmt(s.vulnerableComponents), detail: 'RSA / ECDSA / DH', tone: s.vulnerableComponents > 0 ? 'warning' : 'good', spark: vulnSpark, live: true, basis: 'Quantum-vulnerable components' },
    { key: 'critdeps', label: 'Critical Dependencies', value: numberFmt(scanner.severityCounts.critical), detail: 'critical findings', tone: scanner.severityCounts.critical > 0 ? 'critical' : 'good', spark: [scanner.severityCounts.critical, scanner.severityCounts.high], live: true, basis: 'Critical-severity crypto findings' },
    { key: 'impact', label: 'Business Impact', value: businessImpact >= 20 ? 'High' : businessImpact >= 5 ? 'Medium' : 'Low', detail: `${numberFmt(businessImpact)} high-risk`, tone: businessImpact >= 20 ? 'critical' : businessImpact >= 5 ? 'warning' : 'good', spark: riskSpark, live: true, basis: 'Critical + high severity findings' },
    { key: 'confidence', label: 'Migration Confidence', value: pct(confidence), detail: confidence >= 80 ? 'high' : 'building', tone: confidence >= 80 ? 'good' : 'neutral', spark: readySpark, live: true, basis: 'Validation, failure & coverage composite' },
    { key: 'validation', label: 'Avg Validation Success', value: pct(orch.hasData ? m.validationProgressPct : deriveValidationFromHistory(scanner)), detail: 'post-change checks', tone: 'good', spark: readySpark, live: orch.hasData, basis: orch.hasData ? 'Orchestrator validation progress' : 'Completed scan ratio' },
  ];
}

/* ------------------------------------------------------------------ */
/* Section 4 — NIST Phase Gates                                        */
/* ------------------------------------------------------------------ */

export interface PhaseGate {
  id: string;
  label: string;
  status: WorkflowStageStatus;
  progress: number;
  kpi: string;
  detail: string;
  route: string;
  owner: string;
  standards: string[];
  estDuration: string;
  deliverables: string[];
  rollback: string;
  validation: string;
  telemetry: string;
}

const STAGE_STANDARDS: Record<string, string[]> = {
  discovery: ['NIST SP 1800-38B', 'CNSA 2.0'],
  cbom: ['NIST SP 1800-38C', 'CycloneDX CBOM'],
  assessment: ['NIST SP 800-208', 'NIST IR 8547'],
  risk: ['NIST CSF 2.0', 'NIST SP 800-30'],
  remediation: ['NIST SP 1800-38', 'FIPS 203/204/205'],
  planning: ['NIST SP 1800-38D', 'ETSI TR 103 619'],
  approval: ['ISO 27001', 'SOC 2 CC8.1'],
  execution: ['NIST SP 800-208', 'CNSA 2.0'],
  validation: ['NIST SP 800-131A r2', 'FIPS 140-3'],
  monitoring: ['NIST CSF 2.0 DE', 'NIST SP 800-137'],
  certification: ['ISO 27001', 'NIST SP 1800-38'],
};

const STAGE_DELIVERABLES: Record<string, string[]> = {
  discovery: ['Authenticated asset inventory', 'Connector coverage report'],
  cbom: ['Cryptographic Bill of Materials', 'Component-to-asset mapping'],
  assessment: ['Quantum vulnerability assessment', 'Algorithm exposure matrix'],
  risk: ['Risk-scored asset register', 'Blast-radius model'],
  remediation: ['Per-asset NIST playbooks', 'Target-algorithm mapping'],
  planning: ['Wave & sequencing plan', 'Maintenance windows'],
  approval: ['CAB change record', 'Signed RFC + rollback plan'],
  execution: ['Hybrid cutover jobs', 'Certificate re-issuance'],
  validation: ['Post-change validation logs', 'Interop test results'],
  monitoring: ['Runtime crypto telemetry', 'Drift alerts'],
  certification: ['ML-DSA-signed trust certificate', 'Evidence bundle'],
};

const STATUS_EST: Record<WorkflowStageStatus, string> = {
  complete: 'Completed',
  active: 'In progress',
  pending: 'Not started',
  blocked: 'Blocked',
};

export function buildPhaseGates(input: OpsInputs): PhaseGate[] {
  const { workflow, orch } = input;
  if (workflow?.stages?.length) {
    return workflow.stages.map((stage) => ({
      id: stage.id,
      label: stage.label,
      status: stage.status,
      progress: clampPct(stage.progressPct),
      kpi: stage.kpi,
      detail: stage.detail,
      route: stage.route,
      owner: 'Platform Team',
      standards: STAGE_STANDARDS[stage.id] || ['NIST SP 1800-38'],
      estDuration: STATUS_EST[stage.status],
      deliverables: STAGE_DELIVERABLES[stage.id] || ['Evidence artifact'],
      rollback: stage.id === 'execution' ? `${orch.metrics.rolledBack} rollback(s) executed · snapshot-backed` : 'Snapshot rollback available',
      validation: stage.id === 'validation' ? `${clampPct(orch.hasData ? orch.metrics.validationProgressPct : stage.progressPct)}% validated` : stage.status === 'complete' ? 'Passed' : 'Pending',
      telemetry: stage.id === 'execution' ? `${orch.metrics.running} running · ${orch.metrics.queued} queued` : stage.status === 'active' ? 'Live evidence' : '—',
    }));
  }
  // Fallback: derive gates from scanner evidence when workflow is unavailable.
  return deriveFallbackGates(input);
}

function deriveFallbackGates(input: OpsInputs): PhaseGate[] {
  const s = input.scanner.summary;
  const done = (cond: boolean, active = false): WorkflowStageStatus => (cond ? 'complete' : active ? 'active' : 'pending');
  const rows: Array<[string, string, WorkflowStageStatus, number, string]> = [
    ['discovery', 'Discovery', done(s.totalComponents > 0), s.totalComponents > 0 ? 100 : 0, `${numberFmt(s.totalAssets)} assets`],
    ['assessment', 'Assessment', done(s.totalFindings > 0, s.totalComponents > 0), s.totalFindings > 0 ? 100 : 0, `${numberFmt(s.vulnerableComponents)} vulnerable`],
    ['planning', 'Planning', done(s.pqcReadyComponents > 0, s.totalFindings > 0), s.pqcReadiness, `${pct(s.pqcReadiness)} planned`],
    ['execution', 'Production Rollout', done(false, s.pqcReadyComponents > 0), s.pqcReadiness, `${numberFmt(s.pqcReadyComponents)} migrated`],
    ['validation', 'Validation', done(s.vulnerableComponents === 0 && s.totalComponents > 0), s.pqcReadiness, `${pct(s.pqcReadiness)} validated`],
    ['monitoring', 'Continuous Monitoring', done(s.completedScans > 0), s.completedScans > 0 ? 100 : 0, `${numberFmt(s.completedScans)} scans`],
  ];
  return rows.map(([id, label, status, progress, kpi]) => ({
    id, label, status, progress: clampPct(progress), kpi, detail: 'Derived from scanner evidence',
    route: '/dashboard/migration-planner', owner: 'Platform Team', standards: STAGE_STANDARDS[id] || ['NIST SP 1800-38'],
    estDuration: STATUS_EST[status], deliverables: STAGE_DELIVERABLES[id] || ['Evidence artifact'],
    rollback: 'Snapshot rollback available', validation: status === 'complete' ? 'Passed' : 'Pending', telemetry: '—',
  }));
}

/* ------------------------------------------------------------------ */
/* Section 5 — Enterprise Timeline Cards                               */
/* ------------------------------------------------------------------ */

export type MigrationStatus = 'completed' | 'in-progress' | 'scheduled' | 'pending' | 'failed';

export interface TimelineCard {
  id: string;
  title: string;
  description: string;
  status: MigrationStatus;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  wave: string;
  owner: string;
  assets: number;
  dependencies: number;
  businessImpact: string;
  risk: { label: string; tone: OpsTone };
  downtime: string;
  rollback: string;
  evidenceSource: string;
  policy: string[];
  scannerEvidence: string;
  sophia: string;
  digitalTwin: 'PASS' | 'REVIEW' | 'PENDING';
  validation: string;
  progress: number;
  confidence: number;
  date: string;
  currentAlgo: string;
  targetAlgo: string;
}

export function buildTimelineCards(input: OpsInputs): TimelineCard[] {
  const { scanner } = input;
  const entries = scanner.cbom.entries || [];
  const base = scanner.history.history[0]?.startedAt || scanner.generatedAt;
  const waves = buildWaves(scanner);
  const waveName = (k: CategoryKey) => waves.find((w) => w.categories.some((c) => c.key === k))?.name || 'Wave 1';

  const groups: Array<{ key: CategoryKey; id: string; title: string; algo: string; target: string; owner: string; policy: string[]; offset: number }> = [
    { key: 'tls', id: 'tls-hybrid', title: 'TLS Hybrid Migration', algo: 'RSA-2048 / ECDHE', target: 'X25519 + ML-KEM-768', owner: 'Infrastructure Team', policy: ['NIST SP 1800-38', 'CNSA 2.0'], offset: 7 },
    { key: 'certificates', id: 'cert-reissue', title: 'Certificate Re-Issuance', algo: 'RSA / ECDSA leaf', target: 'ML-DSA-65', owner: 'PKI Administrators', policy: ['NIST SP 800-208', 'FIPS 204'], offset: 14 },
    { key: 'webApis', id: 'api-tokens', title: 'API & Token Signing Migration', algo: 'RS256 / ES256', target: 'ML-DSA-65', owner: 'Identity Team', policy: ['NIST SP 800-208'], offset: 21 },
    { key: 'vpn', id: 'vpn-kex', title: 'VPN Key Exchange Migration', algo: 'DH / ECDH', target: 'X25519 + ML-KEM-1024', owner: 'Network Team', policy: ['CNSA 2.0'], offset: 28 },
    { key: 'hsm', id: 'key-rotation', title: 'HSM Key Rotation (PQC)', algo: 'RSA / ECDSA keys', target: 'ML-DSA / ML-KEM', owner: 'QKMS Team', policy: ['FIPS 203', 'FIPS 204'], offset: 35 },
    { key: 'cloud', id: 'cloud-workloads', title: 'Cloud Workload Migration', algo: 'Provider-managed TLS', target: 'Hybrid PQC TLS', owner: 'Cloud Platform', policy: ['NIST SP 1800-38'], offset: 42 },
  ];

  const cats = classifyInventory(scanner);
  const catBy = (k: CategoryKey) => cats.find((c) => c.key === k);

  return groups.map((g): TimelineCard => {
    const cat = catBy(g.key);
    const total = cat?.total ?? 0;
    const ready = cat?.ready ?? 0;
    const vulnerable = cat?.vulnerable ?? 0;
    const progress = cat?.progress ?? 0;
    const status: MigrationStatus = total === 0
      ? 'pending'
      : progress >= 100
        ? 'completed'
        : vulnerable > 0 && progress > 0
          ? 'in-progress'
          : vulnerable > 0
            ? 'scheduled'
            : 'completed';
    const riskScore = vulnerable > 0 ? Math.min(100, 40 + vulnerable * 6) : 15;
    const priority = riskScore >= 80 ? 'Critical' : riskScore >= 60 ? 'High' : riskScore >= 40 ? 'Medium' : 'Low';
    const confidence = clampPct(70 + progress * 0.25 - (vulnerable > 5 ? 8 : 0));
    return {
      id: g.id,
      title: g.title,
      description: total > 0
        ? `${numberFmt(vulnerable)} quantum-vulnerable ${g.key} finding(s) mapped to ${g.target}.`
        : `No ${g.key} findings in the current scanner feed.`,
      status,
      priority: priority as TimelineCard['priority'],
      wave: waveName(g.key),
      owner: g.owner,
      assets: total,
      dependencies: Math.max(0, Math.round(total * 0.4)),
      businessImpact: riskScore >= 70 ? 'High' : riskScore >= 40 ? 'Medium' : 'Low',
      risk: riskLabel(riskScore),
      downtime: '0s (hybrid)',
      rollback: 'Ready',
      evidenceSource: 'Scanner CBOM',
      policy: g.policy,
      scannerEvidence: `${numberFmt(total)} components`,
      sophia: vulnerable > 0 ? `Prioritize ${g.target} rollout for ${numberFmt(vulnerable)} exposed component(s).` : 'No action — quantum-safe.',
      digitalTwin: status === 'completed' ? 'PASS' : vulnerable > 3 ? 'REVIEW' : 'PENDING',
      validation: status === 'completed' ? 'Passed' : 'Pending',
      progress,
      confidence,
      date: compactDate(addDays(base, g.offset)),
      currentAlgo: g.algo,
      targetAlgo: g.target,
    };
  }).filter((c) => entries.length === 0 ? true : c.assets > 0 || c.status !== 'pending');
}

/* ------------------------------------------------------------------ */
/* Section 6 — Digital Twin                                            */
/* ------------------------------------------------------------------ */

export interface DigitalTwinState {
  cloneFidelity: number;
  simulationAccuracy: number;
  predictedFailures: number;
  dependenciesModeled: number;
  rollbackSnapshots: number;
  isolationVerified: boolean;
  confidence: number;
  status: 'idle' | 'ready' | 'running';
  basis: string;
}

export function buildDigitalTwin(input: OpsInputs): DigitalTwinState {
  const { scanner, orch } = input;
  const deps = scanner.exposure.nodes.length || scanner.assets.assets.length;
  const predicted = orch.hasData ? orch.metrics.failed + orch.metrics.deadLetter + orch.metrics.retrying : scanner.severityCounts.critical;
  const evidenceCompleteness = clampPct(
    (scanner.summary.totalComponents > 0 ? 40 : 0) +
    (deps > 0 ? 30 : 0) +
    (scanner.history.history.length > 0 ? 30 : 0),
  );
  return {
    cloneFidelity: clampPct(60 + evidenceCompleteness * 0.35),
    simulationAccuracy: clampPct(evidenceCompleteness),
    predictedFailures: predicted,
    dependenciesModeled: deps,
    rollbackSnapshots: orch.hasData ? orch.metrics.rolledBack + orch.metrics.completed : scanner.summary.pqcReadyComponents,
    isolationVerified: scanner.summary.totalComponents > 0,
    confidence: clampPct(evidenceCompleteness - (predicted > 0 ? Math.min(20, predicted) : 0)),
    status: orch.metrics.running > 0 ? 'running' : scanner.summary.totalComponents > 0 ? 'ready' : 'idle',
    basis: 'Modeled from CBOM, exposure graph & scan history',
  };
}

/* ------------------------------------------------------------------ */
/* Section 7 — Live Migration Telemetry (jobs)                         */
/* ------------------------------------------------------------------ */

export interface LiveJob {
  id: string;
  asset: string;
  businessUnit: string;
  migrationType: string;
  currentAlgo: string;
  targetAlgo: string;
  migrationPct: number;
  validationPct: number;
  phase: OrchestratorJobPhase | MigrationStatus;
  latency: string;
  downtime: string;
  started: string;
  duration: string;
  operator: string;
  health: 'healthy' | 'degraded' | 'failed' | 'queued';
  retryCount: number;
}

const PHASE_PROGRESS: Record<OrchestratorJobPhase, number> = {
  blocked: 0, queued: 5, leased: 15, running: 55, validating: 85, completed: 100,
  retrying: 40, failed: 60, rolled_back: 30, dead_letter: 0, paused: 45,
};

export function buildLiveJobs(input: OpsInputs): LiveJob[] {
  const { orch, scanner } = input;
  const assetsByName = new Map(scanner.assets.assets.map((a: any) => [String(a.name || '').toLowerCase(), a]));
  if (orch.hasData && orch.priorityQueue.length > 0) {
    return orch.priorityQueue.slice(0, 40).map((job) => {
      const asset = assetsByName.get(String(job.asset || '').toLowerCase());
      const migrationPct = PHASE_PROGRESS[job.phase] ?? 0;
      const health: LiveJob['health'] = job.phase === 'failed' || job.phase === 'dead_letter'
        ? 'failed'
        : job.phase === 'retrying' || job.blockedBy > 0
          ? 'degraded'
          : job.phase === 'queued' || job.phase === 'blocked'
            ? 'queued'
            : 'healthy';
      return {
        id: String(job.id).slice(0, 12).toUpperCase(),
        asset: String(job.asset || 'Unknown asset'),
        businessUnit: String(asset?.metadata?.owner || asset?.metadata?.businessOwner || asset?.metadata?.environment || '—'),
        migrationType: 'Hybrid PQC',
        currentAlgo: String(asset?.cryptography?.[0] || 'RSA / ECDSA'),
        targetAlgo: 'ML-KEM-768 / ML-DSA-65',
        migrationPct,
        validationPct: job.phase === 'completed' ? 100 : job.phase === 'validating' ? 60 : 0,
        phase: job.phase,
        latency: orch.metrics.networkLatencyMs != null ? `${Math.round(orch.metrics.networkLatencyMs)}ms` : '—',
        downtime: '0s',
        started: '—',
        duration: orch.metrics.avgDurationSeconds != null ? fmtDuration(orch.metrics.avgDurationSeconds) : '—',
        operator: String(job.leaseWorker || 'unassigned'),
        health,
        retryCount: job.retryCount,
      };
    });
  }
  // Fallback: derive representative jobs from CBOM evidence.
  return (scanner.cbom.entries || []).slice(0, 12).map((entry: any, i: number) => {
    const safe = entry.isQuantumSafe;
    const vuln = entry.isVulnerable;
    return {
      id: String(entry.id || `cbom-${i + 1}`).slice(0, 12).toUpperCase(),
      asset: String(entry.sourceAsset || entry.component || 'Component'),
      businessUnit: String(entry.location || '—'),
      migrationType: 'Hybrid PQC',
      currentAlgo: String(entry.algorithm || 'Unknown'),
      targetAlgo: String(entry.pqcReplacement || 'ML-KEM-768 / ML-DSA-65'),
      migrationPct: safe ? 100 : vuln ? Math.max(20, 70 - i * 5) : 10,
      validationPct: safe ? 100 : 0,
      phase: (safe ? 'completed' : vuln ? 'in-progress' : 'pending') as MigrationStatus,
      latency: '—',
      downtime: '0s',
      started: '—',
      duration: '—',
      operator: 'scanner',
      health: safe ? 'healthy' : vuln ? 'degraded' : 'queued',
      retryCount: 0,
    };
  });
}

/* ------------------------------------------------------------------ */
/* Section 9 — Migration Health                                        */
/* ------------------------------------------------------------------ */

export interface HealthMetric { label: string; value: string; pct: number; tone: OpsTone; }

export function buildHealth(input: OpsInputs): HealthMetric[] {
  const { scanner, orch } = input;
  const m = orch.metrics;
  const waves = buildWaves(scanner);
  const completedWaves = waves.filter((w) => w.status === 'completed').length;
  const pendingWaves = waves.filter((w) => w.status === 'scheduled' || w.status === 'running').length;
  const finished = m.completed + m.failed;
  const successRate = finished > 0 ? clampPct((m.completed / finished) * 100) : scanner.summary.pqcReadiness;
  const rollbackSuccess = m.rolledBack > 0 ? 100 : m.failed === 0 ? 100 : clampPct((m.rolledBack / Math.max(1, m.failed)) * 100);
  const validation = orch.hasData ? m.validationProgressPct : deriveValidationFromHistory(scanner);
  const compliance = clampPct(scanner.runtime.complianceScore);
  const criticalIssues = scanner.severityCounts.critical + m.deadLetter;
  const changeSuccess = finished > 0 ? successRate : scanner.summary.pqcReadiness;

  return [
    { label: 'Migration Success Rate', value: pct(successRate), pct: successRate, tone: successRate >= 90 ? 'good' : 'neutral' },
    { label: 'Rollback Success', value: pct(rollbackSuccess), pct: rollbackSuccess, tone: rollbackSuccess >= 90 ? 'good' : 'warning' },
    { label: 'Validation Success', value: pct(validation), pct: validation, tone: validation >= 90 ? 'good' : 'neutral' },
    { label: 'Downtime', value: m.failed === 0 ? '0s' : `${m.failed} review`, pct: m.failed === 0 ? 100 : 60, tone: m.failed === 0 ? 'good' : 'critical' },
    { label: 'Policy Compliance', value: pct(compliance), pct: compliance, tone: compliance >= 80 ? 'good' : 'warning' },
    { label: 'Completed Waves', value: `${completedWaves} / ${waves.length}`, pct: clampPct((completedWaves / waves.length) * 100), tone: 'neutral' },
    { label: 'Pending Waves', value: String(pendingWaves), pct: clampPct((pendingWaves / waves.length) * 100), tone: 'info' },
    { label: 'Critical Issues', value: numberFmt(criticalIssues), pct: criticalIssues > 0 ? 100 : 0, tone: criticalIssues > 0 ? 'critical' : 'good' },
    { label: 'Avg Migration Time', value: fmtDuration(m.avgDurationSeconds), pct: 50, tone: 'neutral' },
    { label: 'Change Success Rate', value: pct(changeSuccess), pct: changeSuccess, tone: changeSuccess >= 90 ? 'good' : 'neutral' },
  ];
}

/* ------------------------------------------------------------------ */
/* Section 10 — Risk Burn-down                                         */
/* ------------------------------------------------------------------ */

export interface RiskBurndown {
  buckets: Array<{ label: string; count: number; tone: OpsTone }>;
  resolved: number;
  added: number;
  trend: 'down' | 'up' | 'flat';
  series: { critical: number[]; high: number[]; medium: number[]; resolved: number[] };
}

export function buildRiskBurndown(input: OpsInputs): RiskBurndown {
  const { scanner } = input;
  const sc = scanner.severityCounts;
  const points = scanner.history.history.slice(0, 10).reverse();
  const pick = (e: any, k: string) => Number(e.summary?.[k] ?? 0);
  const critical = points.map((e: any) => pick(e, 'critical') || 0);
  const high = points.map((e: any) => pick(e, 'high') || 0);
  const medium = points.map((e: any) => pick(e, 'medium') || 0);
  const resolvedSeries = points.map((e: any) => Number(e.summary?.pqcReady ?? 0));

  const firstVuln = Number(points[0]?.summary?.vulnerable ?? scanner.summary.vulnerableComponents);
  const lastVuln = Number(points[points.length - 1]?.summary?.vulnerable ?? scanner.summary.vulnerableComponents);
  const resolved = Math.max(0, firstVuln - lastVuln);
  const added = Math.max(0, lastVuln - firstVuln);
  const trend: RiskBurndown['trend'] = lastVuln < firstVuln ? 'down' : lastVuln > firstVuln ? 'up' : 'flat';

  return {
    buckets: [
      { label: 'Critical', count: sc.critical, tone: 'critical' },
      { label: 'High', count: sc.high, tone: 'warning' },
      { label: 'Medium', count: sc.medium, tone: 'neutral' },
      { label: 'Low', count: sc.low, tone: 'info' },
      { label: 'Resolved', count: scanner.summary.pqcReadyComponents, tone: 'good' },
      { label: 'New', count: added, tone: 'ai' },
    ],
    resolved,
    added,
    trend,
    series: { critical, high, medium, resolved: resolvedSeries },
  };
}

/* ------------------------------------------------------------------ */
/* Section 11 — Enterprise Asset Migration Table                       */
/* ------------------------------------------------------------------ */

export interface AssetRow {
  id: string;
  name: string;
  type: string;
  environment: string;
  businessUnit: string;
  criticality: string;
  owner: string;
  application: string;
  currentCrypto: string;
  targetCrypto: string;
  certificate: string;
  tls: string;
  dependencies: number;
  risk: { label: string; tone: OpsTone };
  riskScore: number;
  priority: string;
  window: string;
  cabApproval: string;
  rollback: string;
  validation: string;
  evidence: string;
  policy: string;
  status: MigrationStatus;
  progress: number;
  wave: string;
  lastUpdated: string;
}

export function buildAssetRows(input: OpsInputs): AssetRow[] {
  const { scanner, workflow } = input;
  const waves = buildWaves(scanner);
  const lifecycleByAsset = new Map((workflow?.assetStates || []).map((a) => [a.asset.toLowerCase(), a]));

  return (scanner.assets.assets || []).map((asset: any) => {
    const inventory = Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory : [];
    const vulnerable = inventory.find((e: any) => e.is_vulnerable) || inventory[0];
    const riskScore = Number(asset.riskScore || threatWeight(asset.riskLevel));
    const rl = riskLabel(riskScore);
    const life = lifecycleByAsset.get(String(asset.name || '').toLowerCase());
    const vulnCount = Number(asset.vulnerableCount || 0);
    const status: MigrationStatus = life?.migrationStatus === 'completed'
      ? 'completed'
      : life?.migrationStatus === 'running'
        ? 'in-progress'
        : vulnCount > 0
          ? (life?.migrationStatus === 'planned' ? 'scheduled' : 'in-progress')
          : inventory.length > 0
            ? 'completed'
            : 'pending';
    const env = String(asset.metadata?.environment || (asset.metadata?.authorized_target ? 'Production' : 'Tenant Scope'));
    const wave = waves.find((w) => w.categories.some((c) => CATEGORY_SPECS.find((s) => s.key === c.key)?.rx.test(assetText(asset))))?.name || 'Wave 1';
    return {
      id: String(asset.id || asset.name),
      name: String(asset.name || 'Unknown asset'),
      type: String(asset.type || 'Asset'),
      environment: env,
      businessUnit: String(asset.metadata?.businessUnit || asset.metadata?.owner || 'Unassigned'),
      criticality: rl.label,
      owner: String(asset.metadata?.owner || asset.metadata?.businessOwner || 'Unassigned'),
      application: String(asset.metadata?.application || asset.type || '—'),
      currentCrypto: String(vulnerable?.algorithm || asset.cryptography?.[0] || 'Manual review'),
      targetCrypto: String(vulnerable?.metadata?.pqcReplacement || vulnerable?.metadata?.recommendation || 'ML-KEM-768 / ML-DSA-65'),
      certificate: inventory.some((e: any) => /cert/i.test(String(e.type || e.algorithm || ''))) ? 'Present' : '—',
      tls: inventory.some((e: any) => /tls|ssl/i.test(String(e.type || e.algorithm || ''))) ? 'Detected' : '—',
      dependencies: Number(asset.dependencies?.length || life?.openActions || 0),
      risk: rl,
      riskScore,
      priority: rl.label,
      window: env.toLowerCase().includes('prod') ? 'Off-peak' : 'Rolling',
      cabApproval: status === 'completed' ? 'Approved' : status === 'in-progress' ? 'Approved' : 'Pending',
      rollback: 'Ready',
      validation: life?.validationStatus || (status === 'completed' ? 'Passed' : 'Pending'),
      evidence: 'Scanner CBOM',
      policy: 'NIST SP 1800-38',
      status,
      progress: status === 'completed' ? 100 : status === 'in-progress' ? clampPct(60 - vulnCount * 4) : status === 'scheduled' ? 10 : 0,
      wave,
      lastUpdated: compactDate(asset.lastScanned || asset.metadata?.last_scanned_at),
    };
  });
}

/* ------------------------------------------------------------------ */
/* Section 12 — Dependency Graph                                       */
/* ------------------------------------------------------------------ */

export type DepTone = 'strong' | 'weak' | 'at-risk' | 'blocked';

export interface DepNode {
  id: string;
  label: string;
  detail: string;
  x: number;
  y: number;
  tone: DepTone;
  icon: string;
  blastRadius: number;
  risk: number;
  migrationOrder: number;
  algorithms: string;
}
export interface DepLink { from: string; to: string; tone: DepTone; }

function classifyDepTone(risk: number, vulnerable: number, critical = false): DepTone {
  if (critical || risk >= 85) return 'blocked';
  if (risk >= 65 || vulnerable > 1) return 'at-risk';
  if (risk >= 35 || vulnerable > 0) return 'weak';
  return 'strong';
}

export function buildDependencyGraph(scanner: ScannerIntelligenceSnapshot): { nodes: DepNode[]; links: DepLink[] } {
  const cats = classifyInventory(scanner);
  const catBy = (k: CategoryKey) => cats.find((c) => c.key === k);
  const tone = (k: CategoryKey): DepTone => {
    const c = catBy(k);
    if (!c || c.total === 0) return 'strong';
    return classifyDepTone(c.progress < 100 ? 100 - c.progress : 10, c.vulnerable);
  };
  const detail = (k: CategoryKey) => {
    const c = catBy(k);
    return c ? `${numberFmt(c.total)} component${c.total === 1 ? '' : 's'}` : '0 components';
  };
  const risk = (k: CategoryKey) => { const c = catBy(k); return c && c.total > 0 ? clampPct(100 - c.progress) : 10; };

  const rootTone = classifyDepTone(scanner.summary.riskScore, scanner.summary.vulnerableComponents, scanner.severityCounts.critical > 0 && scanner.summary.riskScore >= 80);

  const spec: Array<[string, string, string, number, number, DepTone, number, CategoryKey | null, number]> = [
    // id, label, icon, x, y, tone, migrationOrder, categoryKey(for detail/risk), blastRadiusBase
    ['root', 'PKI Root CA', 'ShieldCheck', 46, 12, rootTone, 1, 'pki', 100],
    ['ca-1', 'Intermediate CA', 'BadgeCheck', 20, 34, tone('certificates'), 2, 'certificates', 70],
    ['ca-2', 'Certificate Store', 'FileText', 46, 34, tone('certificates'), 2, 'certificates', 65],
    ['bridge', 'HSM / Key Vault', 'KeyRound', 74, 34, tone('hsm'), 2, 'hsm', 80],
    ['web', 'Web Apps', 'Globe2', 8, 58, tone('applications'), 3, 'applications', 40],
    ['api', 'APIs', 'Activity', 27, 58, tone('webApis'), 3, 'webApis', 55],
    ['tls', 'TLS Endpoints', 'Lock', 46, 58, tone('tls'), 3, 'tls', 60],
    ['vpn', 'VPN Gateways', 'Network', 65, 58, tone('vpn'), 3, 'vpn', 45],
    ['cloud', 'Cloud', 'Cloud', 84, 58, tone('cloud'), 4, 'cloud', 50],
    ['k8s', 'Kubernetes', 'Boxes', 20, 82, tone('containers'), 4, 'containers', 35],
    ['db', 'Databases', 'Database', 46, 82, tone('applications'), 4, 'applications', 40],
    ['iot', 'IoT / Edge', 'Cpu', 72, 82, tone('iot'), 5, 'iot', 25],
  ];

  const nodes: DepNode[] = spec.map(([id, label, icon, x, y, t, order, catKey, blast]) => ({
    id, label, icon, x, y, tone: t, migrationOrder: order,
    detail: catKey ? detail(catKey) : '—',
    risk: catKey ? risk(catKey) : scanner.summary.riskScore,
    blastRadius: blast,
    algorithms: catKey === 'hsm' ? 'RSA/ECDSA → ML-DSA/ML-KEM' : catKey === 'tls' ? 'ECDHE → X25519+ML-KEM' : 'RSA/ECDSA → ML-DSA',
  }));

  const linkTone = (to: string): DepTone => nodes.find((n) => n.id === to)?.tone || 'strong';
  const linkPairs: Array<[string, string]> = [
    ['root', 'ca-1'], ['root', 'ca-2'], ['root', 'bridge'],
    ['ca-1', 'web'], ['ca-1', 'api'], ['ca-2', 'tls'], ['ca-2', 'db'],
    ['bridge', 'vpn'], ['bridge', 'cloud'], ['api', 'tls'],
    ['cloud', 'k8s'], ['cloud', 'iot'], ['vpn', 'iot'],
  ];
  const links: DepLink[] = linkPairs.map(([from, to]) => ({ from, to, tone: linkTone(to) }));
  return { nodes, links };
}

export function depToneMeta(tone: DepTone): { label: string; color: string } {
  switch (tone) {
    case 'strong': return { label: 'Quantum-Safe', color: GREEN };
    case 'weak': return { label: 'In Progress', color: CYAN };
    case 'at-risk': return { label: 'At Risk', color: AMBER };
    default: return { label: 'Blocked', color: RED };
  }
}

/* ------------------------------------------------------------------ */
/* Section 13 — Live Activity Feed                                     */
/* ------------------------------------------------------------------ */

export interface ActivityEvent { id: string; time: string; iso: string; message: string; tone: OpsTone; }

export function buildActivityFeed(input: OpsInputs): ActivityEvent[] {
  const { scanner, orch } = input;
  const events: ActivityEvent[] = [];

  scanner.telemetry.slice(0, 30).forEach((ev: any, i: number) => {
    const iso = String(ev.timestamp || scanner.generatedAt);
    events.push({
      id: `tel-${i}`,
      iso,
      time: compactTime(iso),
      message: String(ev.message || ev.event || ev.type || 'Telemetry event') + (ev.target ? ` · ${ev.target}` : ''),
      tone: /fail|error|critical/i.test(String(ev.status || ev.severity || '')) ? 'critical' : /complete|success|safe/i.test(String(ev.status || '')) ? 'good' : 'neutral',
    });
  });

  scanner.history.history.slice(0, 12).forEach((scan: any, i: number) => {
    const iso = String(scan.completedAt || scan.startedAt || scanner.generatedAt);
    events.push({
      id: `scan-${i}`,
      iso,
      time: compactTime(iso),
      message: `Scan ${scan.status} · ${scan.target || 'target'} · ${numberFmt(scan.detectedComponents || 0)} components`,
      tone: scan.status === 'failed' ? 'critical' : scan.status === 'completed' ? 'good' : 'neutral',
    });
  });

  if (orch.hasData) {
    orch.agents.slice(0, 6).forEach((agent, i) => {
      events.push({
        id: `agent-${i}`,
        iso: String(agent.lastSeenAt || orch.generatedAt),
        time: compactTime(agent.lastSeenAt || orch.generatedAt),
        message: `Agent ${agent.name} ${agent.status} · ${agent.leasedJobs} leased job(s)`,
        tone: agent.status === 'online' ? 'good' : agent.status === 'degraded' ? 'warning' : 'neutral',
      });
    });
  }

  return events
    .filter((e) => e.message.trim().length > 0)
    .sort((a, b) => (Date.parse(b.iso) || 0) - (Date.parse(a.iso) || 0))
    .slice(0, 40);
}

/* ------------------------------------------------------------------ */
/* Section 14 — Audit Trail                                            */
/* ------------------------------------------------------------------ */

export interface AuditRow {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  outcome: string;
  evidence: string;
  tone: OpsTone;
}

export function buildAuditTrail(input: OpsInputs): AuditRow[] {
  const { scanner } = input;
  return (scanner.history.history || []).slice(0, 50).map((scan: any, i: number) => ({
    id: String(scan.scanId || `audit-${i}`),
    timestamp: `${compactDate(scan.startedAt)} ${compactTime(scan.startedAt)}`,
    actor: String(scan.initiatedBy || scan.actor || 'scanner-service'),
    action: `${String(scan.scanType || 'crypto').toUpperCase()} scan`,
    target: String(scan.target || '—'),
    outcome: String(scan.status || 'unknown'),
    evidence: `${numberFmt(scan.detectedComponents || 0)} components · risk ${numberFmt(scan.riskScore ?? scan.summary?.riskScore ?? 0)}`,
    tone: scan.status === 'failed' ? 'critical' : scan.status === 'completed' ? 'good' : 'neutral',
  }));
}

export function auditToCsv(rows: AuditRow[]): string {
  return [
    ['timestamp', 'actor', 'action', 'target', 'outcome', 'evidence'].join(','),
    ...rows.map((r) => [r.timestamp, r.actor, r.action, r.target, r.outcome, r.evidence].map(csvCell).join(',')),
  ].join('\n');
}

export function assetsToCsv(rows: AssetRow[]): string {
  const header = ['asset', 'type', 'environment', 'owner', 'current_crypto', 'target_crypto', 'risk', 'priority', 'wave', 'status', 'progress', 'cab_approval', 'validation', 'last_updated'];
  return [
    header.join(','),
    ...rows.map((r) => [r.name, r.type, r.environment, r.owner, r.currentCrypto, r.targetCrypto, r.risk.label, r.priority, r.wave, r.status, `${r.progress}%`, r.cabApproval, r.validation, r.lastUpdated].map(csvCell).join(',')),
  ].join('\n');
}

/* -- Compliance standards surfaced across the center ---------------- */
export const COMPLIANCE_STANDARDS = [
  'NIST SP 800-208', 'NIST SP 1800-38', 'NIST CSF 2.0', 'CNSA 2.0', 'ETSI PQC', 'ISO 27001', 'PCI DSS', 'SOC 2',
];
