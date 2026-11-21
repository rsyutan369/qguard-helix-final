'use client';
import { useState } from 'react';
import { AlertTriangle, ArrowRight, ShieldAlert, Wrench } from 'lucide-react';
import type { BlastRadiusResult, ExposureGraphNode, MigrationImpactAnalysis, PriorityLabel } from '@/types/exposure-graph';
import { DetailFacts, DetailLink, DetailSection } from '@/components/trust-workflow/VendorTrustWorkflowCanvas';
import { useExposureFindings } from '@/hooks/use-exposure-graph';
import { EXPOSURE_STATUS } from '@/lib/exposure-graph-workflow';
import { EmptyState, Ring, integerFmt, CYAN, ORANGE, RED, EMERALD } from '../_shared';
import { POSTURE_COLOR, PRIORITY_COLOR } from './_common';

const readable = (value?: string | null) => value?.replace(/[_-]+/g, ' ') || 'Not recorded';
const date = (value?: string | null) => value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString() : 'Not recorded';
const FINDING_SOURCES: Record<string, string> = {
  pqc_scan_results: 'PQC scanner',
  crypto_exposures: 'Crypto exposure',
  crypto_inventory: 'Crypto inventory',
  vulnerabilities: 'Vulnerability register',
};

function AssetFindings({ node }: { node: ExposureGraphNode }) {
  const [offset, setOffset] = useState(0);
  const { data, error, retry } = useExposureFindings(node.id, node.findingsRevision, offset);
  return (
    <DetailSection title={`Findings & vulnerabilities · ${integerFmt(data?.total ?? node.findingsCount)}`}>
      {error && <p className="qg-wf__text" role="alert">{error} <button type="button" className="underline" onClick={retry}>Retry</button></p>}
      {!data && !error && <p className="qg-wf__text-muted" role="status">Loading this asset’s recorded findings…</p>}
      {data?.total === 0 && <p className="qg-wf__text-muted">No findings for this asset in the loaded evidence.</p>}
      {data && data.revision !== node.findingsRevision && <p className="qg-wf__text-muted">The finding list has a newer snapshot. The graph will refresh on its next update.</p>}
      {data?.findings.map((finding, index) => (
        <details key={`${finding.id}:${index}`} className="mt-2 rounded-md border border-white/15 px-2 py-1.5">
          <summary className="qg-wf__text cursor-pointer break-words">
            <strong className="capitalize">{finding.severity}</strong> · {finding.title}
          </summary>
          <div className="mt-2 space-y-1 break-words">
            <p className="qg-wf__text-muted">{finding.category} · {date(finding.detectedAt)}</p>
            <p className="qg-wf__text">{finding.description}</p>
            {finding.recommendation && <p className="qg-wf__text"><strong>Recommended action</strong> {finding.recommendation}</p>}
            {finding.sources.length > 0 && <p className="qg-wf__text-muted">Sources · {finding.sources.map((source) => FINDING_SOURCES[source] ?? source).join(', ')}</p>}
          </div>
        </details>
      ))}
      {data && data.total > data.limit && (
        <div className="mt-2 flex flex-wrap items-center gap-2" aria-label="Finding pages">
          <button type="button" disabled={data.offset === 0} onClick={() => setOffset(Math.max(0, data.offset - data.limit))} className="rounded border border-white/20 px-2 py-1 disabled:opacity-40">Previous</button>
          <span className="qg-wf__text-muted">{data.offset + 1}–{data.offset + data.findings.length} of {data.total}</span>
          <button type="button" disabled={data.offset + data.limit >= data.total} onClick={() => setOffset(data.offset + data.limit)} className="rounded border border-white/20 px-2 py-1 disabled:opacity-40">Next</button>
        </div>
      )}
      <DetailLink primary href={`/dashboard/assets?asset=${encodeURIComponent(node.id)}`}>Open asset in Assets &amp; CBOM</DetailLink>
    </DetailSection>
  );
}

export function ExposureNodeDetail({
  node, nodes, blast, impact, onSelectNode,
}: {
  node: ExposureGraphNode;
  nodes: ExposureGraphNode[];
  blast: BlastRadiusResult | null;
  impact: MigrationImpactAnalysis | null;
  onSelectNode: (id: string) => void;
}) {
  const [tab, setTab] = useState<'evidence' | 'blast' | 'impact'>('evidence');
  return (
    <>
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Exposure details">
        {([['evidence', 'Evidence'], ['blast', 'Blast radius'], ['impact', 'Migration impact']] as const).map(([key, label]) => (
          <button key={key} type="button" aria-pressed={tab === key} onClick={() => setTab(key)} className="rounded-md border border-white/15 px-2 py-1.5 text-xs font-semibold aria-pressed:border-cyan-400/60 aria-pressed:bg-cyan-500/10">{label}</button>
        ))}
      </div>
      {tab === 'evidence' ? (
        <>
          <DetailFacts items={[
            ['Type', node.type], ['Owner', node.owner], ['Environment', node.environment], ['Region', node.region],
            ['Criticality', node.businessCriticality],
            ['Risk score', node.riskMeasured ? integerFmt(node.riskScore) : 'Unavailable', true],
            ['Recorded dependencies', integerFmt(node.dependencies), true], ['Recorded dependents', integerFmt(node.dependents), true],
            ...(node.kind === 'asset' ? [
            ['Asset status', readable(node.assetStatus)], ['Latest migration job', readable(node.migrationStatus)],
            ['Crypto posture', EXPOSURE_STATUS[node.cryptoPosture ?? node.posture].label],
              ['Latest evidence', date(node.lastEvidenceAt)],
            ] as Array<[string, string]> : []),
          ]} />
          <DetailSection title="Observed cryptography">
            <p className="qg-wf__text break-words">{node.algorithms.join(', ') || 'No algorithm evidence recorded here.'}</p>
            {node.protocols.length > 0 && <p className="qg-wf__text-muted">{node.protocols.join(', ')}</p>}
            {(node.algorithmCount ?? 0) > node.algorithms.length && <p className="qg-wf__text-muted">Showing {node.algorithms.length} of {node.algorithmCount} recorded algorithms.</p>}
            {node.certificates.length > 0 && (
              <ul className="qg-wf__list">
                {node.certificates.map((cert, index) => (
                  <li key={`${cert.name}:${index}`} className="qg-wf__text break-words">
                    <strong>{cert.name}</strong> · {cert.algorithm} · {cert.issuer || 'Issuer unavailable'}
                    {cert.notAfter && ` · Expires ${date(cert.notAfter)}`}
                  </li>
                ))}
              </ul>
            )}
            {(node.certificateCount ?? 0) > node.certificates.length && <p className="qg-wf__text-muted">Showing {node.certificates.length} of {node.certificateCount} certificate records. Open Assets &amp; CBOM for the full inventory.</p>}
          </DetailSection>
          {node.kind === 'asset' && <AssetFindings node={node} />}
        </>
      ) : tab === 'blast' ? (
        <>
          <p className="qg-wf__text-muted">Up to six hops across stored and observed links, in both directions.</p>
          <BlastPanel blast={blast} nodes={nodes} onSelectNode={onSelectNode} />
        </>
      ) : (
        <ImpactPanel impact={impact} />
      )}
    </>
  );
}

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
          <span className="shrink-0 font-mono text-white/40">{node.riskMeasured ? integerFmt(node.riskScore) : '—'}</span>
        </button>
      ))}
      {resolved.length > max ? <div className="px-2 text-[10px] text-white/30">+{resolved.length - max} more affected asset(s)</div> : null}
    </div>
  );
}


function ImpactPanel({ impact }: { impact: MigrationImpactAnalysis | null }) {
  if (!impact) return <EmptyState label="Impact analysis unavailable for this node." />;
  return (
    <div className="space-y-3.5">
      <p className="qg-wf__text-muted">Planning estimates based on this asset’s recorded evidence and mapped dependencies.</p>
      <div className="grid grid-cols-2 gap-2">
        <Stat label="Estimated Risk" value={impact.estimatedRisk} color={PRIORITY_COLOR[impact.estimatedRisk]} />
        <Stat
          label="Est. Downtime (hrs)"
          value={impact.estimatedDowntimeHours.max === 0 ? '0' : `${impact.estimatedDowntimeHours.min}–${impact.estimatedDowntimeHours.max}`}
          color={impact.estimatedDowntimeHours.max >= 6 ? RED : impact.estimatedDowntimeHours.max > 1 ? ORANGE : EMERALD}
        />
      </div>
      {impact.affected.direct > 0 && <div className="flex items-center justify-around rounded-md border border-white/8 bg-black/20 p-3">
        <div className="flex flex-col items-center gap-1">
          <Ring value={impact.compatibilityScorePct} color={impact.compatibilityScorePct >= 70 ? EMERALD : impact.compatibilityScorePct >= 40 ? ORANGE : RED} size={62} stroke={7}>
            <span className="text-xs font-bold text-white">{impact.compatibilityScorePct}%</span>
          </Ring>
          <span className="text-[9px] font-black uppercase tracking-wide text-white/45">Estimated compatibility</span>
        </div>
      </div>}

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
          <div className="text-[11px] text-white/40">No replacement recommendation for the loaded algorithms.</div>
        )}
      </div>

      <div className="rounded-md border border-red-400/15 bg-red-400/[0.04] p-3">
        <div className="mb-1.5 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-red-200/75">
          <AlertTriangle className="h-3.5 w-3.5" /> Potential Interruptions
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
          <div className="text-[11px] text-white/40">No potential interruptions identified from the mapped dependencies.</div>
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
          <div className="text-[11px] text-white/40">No remediation steps derived from the loaded evidence.</div>
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
        <Stat label="Direct Neighbors" value={integerFmt(blast.direct.length)} color={CYAN} />
        <Stat label="Indirect Neighbors" value={integerFmt(blast.indirect.length)} color={ORANGE} />
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
        <div className="mb-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">Impacted Nodes</div>
        <NodeChipList ids={[...blast.direct, ...blast.indirect]} nodes={nodes} onSelectNode={onSelectNode} max={10} />
      </div>
    </div>
  );
}
