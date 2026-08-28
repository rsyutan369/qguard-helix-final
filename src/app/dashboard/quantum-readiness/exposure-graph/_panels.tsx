'use client';

import { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Crosshair,
  FileKey2,
  Gauge,
  Network,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  X,
} from 'lucide-react';
import type {
  BlastRadiusResult,
  ExposureGraphEdge,
  ExposureGraphNode,
  ExposureIntelligence,
  MigrationImpactAnalysis,
  PriorityLabel,
} from '@/types/exposure-graph';
import { Badge, EmptyState, Ring, SectionTitle, integerFmt, CYAN, ORANGE, RED, EMERALD } from '../_shared';
import { CATEGORY_ICON, POSTURE_COLOR, POSTURE_LABEL, PRIORITY_COLOR, TRUST_CLASS_COLOR, TRUST_CLASS_LABEL } from './_common';

/* ------------------------------------------------------------------ */
/* Shared bits                                                         */
/* ------------------------------------------------------------------ */

function Stat({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="rounded-md border border-white/8 bg-black/20 p-2.5">
      <div className="text-base font-semibold leading-tight" style={{ color }}>{value}</div>
      <div className="mt-0.5 text-[9px] font-bold uppercase tracking-wide text-white/45">{label}</div>
    </div>
  );
}

function SeverityDot({ severity }: { severity: PriorityLabel }) {
  return <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: PRIORITY_COLOR[severity] }} />;
}

function NodeChipList({
  ids,
  nodes,
  onSelectNode,
  max = 8,
}: {
  ids: string[];
  nodes: ExposureGraphNode[];
  onSelectNode: (id: string) => void;
  max?: number;
}) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const resolved = ids.map((id) => byId.get(id)).filter((n): n is ExposureGraphNode => Boolean(n));
  if (!resolved.length) return <div className="text-[11px] text-white/35">None recorded.</div>;
  return (
    <div className="space-y-1">
      {resolved.slice(0, max).map((node) => (
        <button
          key={node.id}
          type="button"
          onClick={() => onSelectNode(node.id)}
          className="flex w-full items-center justify-between gap-2 rounded px-2 py-1 text-left text-[11px] transition hover:bg-white/5"
        >
          <span className="inline-flex min-w-0 items-center gap-1.5 text-white/70">
            <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: POSTURE_COLOR[node.posture] }} />
            <span className="truncate">{node.label}</span>
          </span>
          <span className="shrink-0 font-mono text-white/40">{integerFmt(node.riskScore)}</span>
        </button>
      ))}
      {resolved.length > max ? <div className="px-2 text-[10px] text-white/30">+{resolved.length - max} more affected asset(s)</div> : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Default rail — exposure summary                                     */
/* ------------------------------------------------------------------ */

export function RailSummary({
  data,
  onSelectNode,
}: {
  data: ExposureIntelligence;
  onSelectNode: (id: string) => void;
}) {
  const { summary } = data;
  const total = Math.max(1, summary.quantumVulnerable + summary.hybridAssets + summary.pqcReadyAssets + summary.migrationInProgress + summary.unknownPosture);
  const rows = [
    { key: 'vulnerable' as const, value: summary.quantumVulnerable, icon: ShieldAlert },
    { key: 'hybrid' as const, value: summary.hybridAssets, icon: Activity },
    { key: 'migrating' as const, value: summary.migrationInProgress, icon: Radar },
    { key: 'pqc' as const, value: summary.pqcReadyAssets, icon: ShieldCheck },
    { key: 'unknown' as const, value: summary.unknownPosture, icon: Crosshair },
  ];
  const topBlast = [...data.graph.nodes].sort((a, b) => b.blastRadius - a.blastRadius).slice(0, 5);
  return (
    <div>
      <SectionTitle>Cryptographic Posture</SectionTitle>
      <div className="space-y-2">
        {rows.map((row) => {
          const Icon = row.icon;
          const color = POSTURE_COLOR[row.key];
          const pct = Math.round((row.value / total) * 100);
          return (
            <div key={row.key} className="rounded-md border border-white/8 bg-white/[0.025] p-2.5">
              <div className="flex items-center justify-between">
                <span className="inline-flex items-center gap-2 text-[11px] font-bold text-white/75">
                  <Icon className="h-3.5 w-3.5" style={{ color }} />
                  {POSTURE_LABEL[row.key]}
                </span>
                <span className="font-mono text-xs" style={{ color }}>{integerFmt(row.value)}</span>
              </div>
              <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-white/5">
                <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: color }} />
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-5">
        <SectionTitle>Largest Blast Radius</SectionTitle>
        {topBlast.length ? (
          <div className="space-y-1">
            {topBlast.map((node) => (
              <button
                key={node.id}
                type="button"
                onClick={() => onSelectNode(node.id)}
                className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-[11px] transition hover:bg-white/5"
              >
                <span className="inline-flex min-w-0 items-center gap-1.5 text-white/70">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: POSTURE_COLOR[node.posture] }} />
                  <span className="truncate">{node.label}</span>
                </span>
                <span className="shrink-0 font-mono text-cyan-300/80">{integerFmt(node.blastRadius)} affected</span>
              </button>
            ))}
            {data.graph.nodes.length > 5 ? (
              <div className="pt-1 text-[10px] text-white/35">
                Showing the 5 largest of {integerFmt(data.graph.nodes.length)} graph assets.
              </div>
            ) : null}
          </div>
        ) : (
          <EmptyState label="No dependency data yet." hint="Record asset relationships to compute blast radius." />
        )}
      </div>

      <p className="mt-4 text-[11px] leading-relaxed text-white/45">
        Select any node to run Migration Impact Analysis™ and Blast Radius Analysis™. Select a connection to inspect the trust
        relationship securing it.
      </p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Node rail — Overview / Impact / Blast tabs                          */
/* ------------------------------------------------------------------ */

type NodeTab = 'overview' | 'impact' | 'blast';

export function NodeRail({
  node,
  nodes,
  blast,
  impact,
  onSelectNode,
  onClose,
}: {
  node: ExposureGraphNode;
  nodes: ExposureGraphNode[];
  blast: BlastRadiusResult | null;
  impact: MigrationImpactAnalysis | null;
  onSelectNode: (id: string) => void;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<NodeTab>('overview');
  const Icon = CATEGORY_ICON[node.category] || Network;
  return (
    <div>
      <div className="mb-3 flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md border" style={{ borderColor: `${POSTURE_COLOR[node.posture]}45`, color: POSTURE_COLOR[node.posture], backgroundColor: `${POSTURE_COLOR[node.posture]}14` }}>
            <Icon className="h-4.5 w-4.5" />
          </span>
          <div className="min-w-0">
            <div className="truncate text-sm font-bold text-white">{node.label}</div>
            <div className="truncate text-[10px] text-white/45">{node.tierLabel} · {node.environment}{node.kind === 'external' ? ' · Third-Party' : ''}</div>
          </div>
        </div>
        <button type="button" onClick={onClose} className="rounded p-1 text-white/40 transition hover:text-white" aria-label="Close details">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        <Badge color={POSTURE_COLOR[node.posture]}>{POSTURE_LABEL[node.posture]}</Badge>
        <Badge color={PRIORITY_COLOR[node.priority]}>{node.priority} Priority</Badge>
        {node.internetFacing ? <Badge color={ORANGE}>Internet-Facing</Badge> : null}
      </div>

      <div className="mb-4 grid grid-cols-3 gap-1 rounded-md border border-white/8 bg-black/25 p-1">
        {([
          { key: 'overview', label: 'Overview' },
          { key: 'impact', label: 'Impact' },
          { key: 'blast', label: 'Blast Radius' },
        ] as Array<{ key: NodeTab; label: string }>).map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={`rounded px-2 py-1.5 text-[10px] font-black uppercase tracking-wide transition ${
              tab === t.key ? 'bg-blue-500/20 text-blue-100' : 'text-white/45 hover:text-white/75'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'overview' ? <NodeOverview node={node} nodes={nodes} blast={blast} onSelectNode={onSelectNode} /> : null}
      {tab === 'impact' ? <ImpactPanel node={node} impact={impact} /> : null}
      {tab === 'blast' ? <BlastPanel blast={blast} nodes={nodes} onSelectNode={onSelectNode} /> : null}
    </div>
  );
}

function NodeOverview({
  node,
  nodes,
  blast,
  onSelectNode,
}: {
  node: ExposureGraphNode;
  nodes: ExposureGraphNode[];
  blast: BlastRadiusResult | null;
  onSelectNode: (id: string) => void;
}) {
  return (
    <div className="space-y-3.5">
      <div className="grid grid-cols-2 gap-2">
        <Stat label="Risk Score" value={integerFmt(node.riskScore)} color={node.riskScore >= 60 ? RED : node.riskScore >= 30 ? ORANGE : EMERALD} />
        <Stat label="Priority Score" value={integerFmt(node.priorityScore)} color={PRIORITY_COLOR[node.priority]} />
        <Stat label="Blast Radius" value={integerFmt(node.blastRadius)} color={CYAN} />
        <Stat label="Trust Links" value={integerFmt(node.dependencies + node.dependents)} color={CYAN} />
      </div>

      <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 rounded-md border border-white/8 bg-black/20 p-3 text-[11px]">
        <span className="text-white/40">Owner</span><span className="truncate text-right text-white/75">{node.owner}</span>
        <span className="text-white/40">Region</span><span className="truncate text-right text-white/75">{node.region}</span>
        <span className="text-white/40">Business Criticality</span><span className="text-right font-bold" style={{ color: PRIORITY_COLOR[node.businessCriticality] }}>{node.businessCriticality}</span>
        <span className="text-white/40">Migration Wave Order</span><span className="text-right text-white/75">{node.migrationTier}</span>
        {node.findingsCount ? (<><span className="text-white/40">Scan Findings</span><span className="text-right font-mono text-red-300">{integerFmt(node.findingsCount)}</span></>) : null}
      </div>

      {node.priorityDrivers.length ? (
        <div className="rounded-md border border-white/8 bg-black/20 p-3">
          <div className="mb-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">Priority Drivers</div>
          <ul className="space-y-1">
            {node.priorityDrivers.map((driver) => (
              <li key={driver} className="flex items-start gap-1.5 text-[11px] text-white/65">
                <SeverityDot severity={node.priority} /> {driver}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="rounded-md border border-white/8 bg-black/20 p-3">
        <div className="mb-1.5 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">
          <Gauge className="h-3.5 w-3.5" /> Observed Cryptography
        </div>
        {node.algorithms.length ? (
          <div className="flex flex-wrap gap-1">
            {node.algorithms.map((algorithm) => (
              <span key={algorithm} className="rounded border border-white/10 bg-white/[0.03] px-1.5 py-0.5 font-mono text-[10px] text-white/65">
                {algorithm}
              </span>
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-white/35">No algorithms observed — posture unverified.</div>
        )}
        {node.protocols.length ? (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {node.protocols.map((protocol) => (
              <span key={protocol} className="rounded border border-cyan-400/20 bg-cyan-400/[0.05] px-1.5 py-0.5 font-mono text-[10px] text-cyan-200/70">
                {protocol}
              </span>
            ))}
          </div>
        ) : null}
      </div>

      {node.certificates.length ? (
        <div className="rounded-md border border-white/8 bg-black/20 p-3">
          <div className="mb-1.5 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">
            <FileKey2 className="h-3.5 w-3.5" /> Certificates
          </div>
          <div className="space-y-1.5">
            {node.certificates.map((cert, index) => (
              <div key={`${cert.name}-${index}`} className="flex items-center justify-between gap-2 text-[11px]">
                <span className="min-w-0">
                  <span className="block truncate text-white/70">{cert.name}</span>
                  <span className="block truncate text-[10px] text-white/35">{cert.algorithm} · {cert.issuer || 'Unknown issuer'}</span>
                </span>
                <span className="shrink-0">
                  {cert.quantumSafe ? <Badge color={EMERALD}>PQC</Badge> : cert.expiringSoon ? <Badge color={ORANGE}>Expiring</Badge> : <Badge color={RED}>Classical</Badge>}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      <div className="rounded-md border border-white/8 bg-black/20 p-3">
        <div className="mb-1.5 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">
          <Crosshair className="h-3.5 w-3.5" /> Directly Connected Assets
        </div>
        <NodeChipList ids={blast?.direct || []} nodes={nodes} onSelectNode={onSelectNode} />
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Migration Impact Analysis™                                          */
/* ------------------------------------------------------------------ */

function ImpactPanel({ node, impact }: { node: ExposureGraphNode; impact: MigrationImpactAnalysis | null }) {
  if (!impact) return <EmptyState label="Impact analysis unavailable for this node." />;
  return (
    <div className="space-y-3.5">
      <div className="grid grid-cols-2 gap-2">
        <Stat label="Estimated Risk" value={impact.estimatedRisk} color={PRIORITY_COLOR[impact.estimatedRisk]} />
        <Stat
          label="Est. Downtime (hrs)"
          value={impact.estimatedDowntimeHours.max === 0 ? '0' : `${impact.estimatedDowntimeHours.min}–${impact.estimatedDowntimeHours.max}`}
          color={impact.estimatedDowntimeHours.max >= 6 ? RED : impact.estimatedDowntimeHours.max > 1 ? ORANGE : EMERALD}
        />
      </div>
      <div className="flex items-center justify-around rounded-md border border-white/8 bg-black/20 p-3">
        <div className="flex flex-col items-center gap-1">
          <Ring value={impact.compatibilityScorePct} color={impact.compatibilityScorePct >= 70 ? EMERALD : impact.compatibilityScorePct >= 40 ? ORANGE : RED} size={62} stroke={7}>
            <span className="text-xs font-bold text-white">{impact.compatibilityScorePct}%</span>
          </Ring>
          <span className="text-[9px] font-black uppercase tracking-wide text-white/45">Compatibility</span>
        </div>
        <div className="flex flex-col items-center gap-1">
          <Ring value={impact.confidencePct} color={CYAN} size={62} stroke={7}>
            <span className="text-xs font-bold text-white">{impact.confidencePct}%</span>
          </Ring>
          <span className="text-[9px] font-black uppercase tracking-wide text-white/45">Confidence</span>
        </div>
      </div>

      <div className="rounded-md border border-white/8 bg-black/20 p-3">
        <div className="mb-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">Current State</div>
        <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
          <span className="text-white/40">Algorithms</span><span className="text-right font-mono text-white/75">{impact.currentState.algorithms.length}</span>
          <span className="text-white/40">Certificates</span><span className="text-right font-mono text-white/75">{impact.currentState.certificates}</span>
          <span className="text-white/40">Vulnerable Certs</span><span className="text-right font-mono text-red-300">{impact.currentState.vulnerableCertificates}</span>
          <span className="text-white/40">Trust Relationships</span><span className="text-right font-mono text-white/75">{impact.currentState.trustRelationships}</span>
          <span className="text-white/40">Communication Paths</span><span className="text-right font-mono text-white/75">{impact.currentState.communicationPaths}</span>
        </div>
      </div>

      <div className="rounded-md border border-white/8 bg-black/20 p-3">
        <div className="mb-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">Proposed PQC Migration</div>
        {impact.proposedMigration.length ? (
          <div className="space-y-1.5">
            {impact.proposedMigration.map((change) => (
              <div key={`${change.from}-${change.to}`} className="text-[11px]">
                <div className="flex items-center gap-1.5">
                  <span className="max-w-[45%] truncate font-mono text-red-300/85">{change.from}</span>
                  <ArrowRight className="h-3 w-3 shrink-0 text-white/35" />
                  <span className="min-w-0 truncate font-mono text-emerald-300/90">{change.to}</span>
                </div>
                <div className="text-[9px] uppercase tracking-wide text-white/30">{change.kind}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-emerald-300/80">
            {node.posture === 'pqc' ? 'Asset already runs quantum-safe cryptography.' : 'No classical algorithms observed to replace.'}
          </div>
        )}
      </div>

      <div className="rounded-md border border-red-400/15 bg-red-400/[0.04] p-3">
        <div className="mb-1.5 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-red-200/75">
          <AlertTriangle className="h-3.5 w-3.5" /> What Will Break?
        </div>
        {impact.potentialInterruptions.length ? (
          <ul className="space-y-1.5">
            {impact.potentialInterruptions.map((item) => (
              <li key={item.label} className="flex items-start gap-1.5 text-[11px]">
                <SeverityDot severity={item.severity} />
                <span className="min-w-0">
                  <span className="block font-bold text-white/80">{item.label}</span>
                  <span className="block text-white/45">{item.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-[11px] text-white/40">No dependent services recorded — isolated migration.</div>
        )}
      </div>

      <div className="rounded-md border border-white/8 bg-black/20 p-3">
        <div className="mb-1.5 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">
          <Wrench className="h-3.5 w-3.5" /> Required Remediation
        </div>
        {impact.requiredRemediation.length ? (
          <ul className="space-y-1.5">
            {impact.requiredRemediation.map((item) => (
              <li key={item.label} className="flex items-start gap-1.5 text-[11px]">
                <SeverityDot severity={item.severity} />
                <span className="min-w-0">
                  <span className="block font-bold text-white/80">{item.label}</span>
                  <span className="block text-white/45">{item.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-[11px] text-white/40">No remediation steps required.</div>
        )}
      </div>

      <p className="text-[10px] leading-relaxed text-white/35">{impact.evidenceNote}</p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Blast Radius Analysis™                                              */
/* ------------------------------------------------------------------ */

function BlastPanel({
  blast,
  nodes,
  onSelectNode,
}: {
  blast: BlastRadiusResult | null;
  nodes: ExposureGraphNode[];
  onSelectNode: (id: string) => void;
}) {
  if (!blast) return <EmptyState label="Select a node to compute its blast radius." />;
  return (
    <div className="space-y-3.5">
      <div className="grid grid-cols-2 gap-2">
        <Stat label="Total Affected" value={integerFmt(blast.totalAffected)} color={CYAN} />
        <Stat label="Direct Dependencies" value={integerFmt(blast.direct.length)} color={CYAN} />
        <Stat label="Indirect Dependencies" value={integerFmt(blast.indirect.length)} color={ORANGE} />
        <Stat label="Trust-Chain Impact" value={integerFmt(blast.trustChain.length)} color={PRIORITY_COLOR.High} />
        <Stat label="Internet-Facing" value={integerFmt(blast.internetFacing)} color={ORANGE} />
        <Stat label="Business-Critical" value={integerFmt(blast.businessCritical)} color={RED} />
      </div>

      {blast.environments.length ? (
        <div className="rounded-md border border-white/8 bg-black/20 p-3">
          <div className="mb-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">Environments In Radius</div>
          <div className="flex flex-wrap gap-1">
            {blast.environments.map((env) => (
              <span key={env} className="rounded border border-white/10 bg-white/[0.03] px-1.5 py-0.5 text-[10px] text-white/65">{env}</span>
            ))}
          </div>
        </div>
      ) : null}

      {blast.affectedByTier.length ? (
        <div className="rounded-md border border-white/8 bg-black/20 p-3">
          <div className="mb-2 text-[10px] font-black uppercase tracking-wide text-white/45">Affected By Migration Layer</div>
          <div className="space-y-1.5">
            {blast.affectedByTier.map((row) => {
              const max = Math.max(1, blast.affectedByTier[0]?.count || 1);
              return (
                <div key={row.tierLabel} className="text-[11px]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-white/65">{row.tierLabel}</span>
                    <span className="font-mono text-white/55">{row.count}</span>
                  </div>
                  <div className="mt-0.5 h-1 overflow-hidden rounded-full bg-white/5">
                    <div className="h-full rounded-full" style={{ width: `${(row.count / max) * 100}%`, backgroundColor: CYAN }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : null}

      <div className="rounded-md border border-white/8 bg-black/20 p-3">
        <div className="mb-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">Impacted Assets</div>
        <NodeChipList ids={[...blast.direct, ...blast.indirect]} nodes={nodes} onSelectNode={onSelectNode} max={10} />
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Edge rail — trust relationship metadata                             */
/* ------------------------------------------------------------------ */

export function EdgeRail({
  edge,
  nodes,
  onSelectNode,
  onClose,
}: {
  edge: ExposureGraphEdge;
  nodes: ExposureGraphNode[];
  onSelectNode: (id: string) => void;
  onClose: () => void;
}) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const source = byId.get(edge.source);
  const target = byId.get(edge.target);
  const color = TRUST_CLASS_COLOR[edge.trustClass];
  return (
    <div>
      <div className="mb-3 flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4" style={{ color }} />
          <h2 className="text-xs font-black uppercase tracking-[0.10em] text-white">Trust Relationship</h2>
        </div>
        <button type="button" onClick={onClose} className="rounded p-1 text-white/40 transition hover:text-white" aria-label="Close details">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        <Badge color={color}>{TRUST_CLASS_LABEL[edge.trustClass]}</Badge>
        {edge.critical ? <Badge color={RED}>Critical Link</Badge> : null}
        {edge.posture !== 'unknown' ? <Badge color={POSTURE_COLOR[edge.posture]}>{POSTURE_LABEL[edge.posture]}</Badge> : null}
      </div>

      <div className="space-y-2">
        {[source, target].map((endpoint, index) =>
          endpoint ? (
            <button
              key={endpoint.id}
              type="button"
              onClick={() => onSelectNode(endpoint.id)}
              className="flex w-full items-center justify-between gap-2 rounded-md border border-white/8 bg-black/20 p-2.5 text-left transition hover:border-blue-400/35"
            >
              <span className="min-w-0">
                <span className="block text-[9px] font-black uppercase tracking-wide text-white/35">{index === 0 ? 'Source' : 'Target'}</span>
                <span className="block truncate text-xs font-bold text-white/85">{endpoint.label}</span>
                <span className="block truncate text-[10px] text-white/40">{endpoint.tierLabel}</span>
              </span>
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: POSTURE_COLOR[endpoint.posture] }} />
            </button>
          ) : null,
        )}
      </div>

      <div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1.5 rounded-md border border-white/8 bg-black/20 p-3 text-[11px]">
        <span className="text-white/40">Relationship</span><span className="truncate text-right text-white/75">{edge.type}</span>
        <span className="text-white/40">Securing Algorithm</span>
        <span className="truncate text-right font-mono text-white/75">{edge.algorithm || 'Not observed'}</span>
      </div>

      {edge.posture === 'vulnerable' ? (
        <div className="mt-3 rounded-md border border-red-400/20 bg-red-400/[0.05] p-3 text-[11px] text-red-100/80">
          This connection is secured with quantum-vulnerable cryptography. Traffic on this path is exposed to
          harvest-now-decrypt-later capture — prioritise hybrid key establishment on both endpoints.
        </div>
      ) : null}
    </div>
  );
}
