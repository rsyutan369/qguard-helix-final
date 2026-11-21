'use client';

/* ==================================================================== */
/* Governance drill-down drawers — shared by all four pages.            */
/*                                                                      */
/* §15 requires every important metric to be actionable: clicking        */
/* "Critical gaps: 27" must show the actual 27 records, and the user     */
/* must be able to walk                                                 */
/*   Framework → Requirement → Control → Asset → Finding → Evidence      */
/* without losing context. These drawers are that walk. Each one loads   */
/* lazily from the API rather than shipping every relationship in the    */
/* dashboard payload, and each one carries the TraceChain so the user    */
/* always knows where they are in the graph.                            */
/* ==================================================================== */

import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, ArrowRight, CheckCircle2, FileCheck2, Fingerprint, ShieldCheck } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Drawer, Pager, TableShell, Td, Th } from '../observability/primitives';
import {
  Basis,
  CONTROL_DOMAIN_LABEL,
  CopyValue,
  FreshnessChip,
  GovernanceSkeleton,
  IntegrityBadge,
  NoMatches,
  Panel,
  PanelEmpty,
  Pill,
  RetentionBadge,
  SeverityBadge,
  StatusBadge,
  TONE,
  TraceChain,
  absoluteTime,
  fmtNumber,
  relativeTime,
  scoreCell,
  type ChainStep,
} from './primitives';
import {
  useGovernanceActions,
  useGovernanceDetail,
  useGovernancePagedResource,
  type AssetComplianceDetail,
  type AuditEventDetail,
  type ControlDetail,
  type ControlSummary,
  type EvidenceDetail,
  type FrameworkDetail,
  type GovernanceView,
  type RequirementDetail,
} from '@/hooks/use-governance';
import type { ControlSubject, EvidenceRecord } from '@/lib/governance/types';

/* ------------------------------------------------------------------ */
/* Selection model — one open drawer at a time, addressable by kind     */
/* ------------------------------------------------------------------ */

export type DrawerTarget =
  | { kind: 'control'; id: string }
  | { kind: 'framework'; id: string }
  | { kind: 'requirement'; id: string }
  | { kind: 'evidence'; id: string }
  | { kind: 'audit'; id: string }
  | { kind: 'asset'; id: string }
  | { kind: 'reconciliation' }
  | null;

/* ------------------------------------------------------------------ */
/* Shared building blocks                                              */
/* ------------------------------------------------------------------ */

function Section({ title, children, meta }: { title: string; children: React.ReactNode; meta?: React.ReactNode }) {
  return (
    <section>
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="text-[10px] font-black uppercase tracking-[0.14em] text-white/55">{title}</h3>
        {meta ? <span className="text-[9.5px] font-bold uppercase tracking-wider text-white/30">{meta}</span> : null}
      </div>
      {children}
    </section>
  );
}

function Fact({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <dt className="text-[9px] font-black uppercase tracking-wider text-white/35">{label}</dt>
      <dd className={cn('mt-0.5 text-[11px] text-white/75', mono && 'font-mono tabular-nums')}>{value}</dd>
    </div>
  );
}

function ControlLinkRow({ control, onOpen }: { control: ControlSummary; onOpen: (id: string) => void }) {
  return (
    <button
      type="button"
      onClick={() => onOpen(control.id)}
      className="flex w-full items-center justify-between gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2 text-left transition hover:border-white/20 hover:bg-white/[0.05]"
    >
      <span className="min-w-0">
        <span className="font-mono text-[9.5px] text-cyan-300/70">{control.code}</span>
        <span className="ml-1.5 text-[11px] font-semibold text-white/80">{control.title}</span>
      </span>
      <span className="flex shrink-0 items-center gap-2">
        {scoreCell(control.score, control.measured)}
        <StatusBadge status={control.status} size="sm" />
      </span>
    </button>
  );
}

function EvidenceRow({ record, onOpen }: { record: EvidenceRecord; onOpen?: (id: string) => void }) {
  const body = (
    <>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[11px] font-semibold text-white/80">{record.title}</span>
        <span className="mt-0.5 block truncate font-mono text-[9.5px] text-white/35">
          {record.source.table} · {record.source.collector} · {relativeTime(record.occurredAt)}
        </span>
      </span>
      <span className="flex shrink-0 items-center gap-1.5">
        <Pill tone={record.outcome === 'contradicting' ? 'critical' : record.outcome === 'supporting' ? 'good' : 'neutral'}>
          {record.outcome === 'contradicting' ? 'Contradicts' : record.outcome === 'supporting' ? 'Supports' : 'Info'}
        </Pill>
        <IntegrityBadge state={record.integrity.state} assurance={record.integrity.assurance} />
      </span>
    </>
  );
  if (!onOpen) {
    return <div className="flex items-center gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2">{body}</div>;
  }
  return (
    <button
      type="button"
      onClick={() => onOpen(record.id)}
      className="flex w-full items-center gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2 text-left transition hover:border-white/20 hover:bg-white/[0.05]"
    >
      {body}
    </button>
  );
}

/* ------------------------------------------------------------------ */
/* Control drawer                                                      */
/* ------------------------------------------------------------------ */

/**
 * The control drawer answers the five questions every governance page owes the
 * user: what is affected, why it is risky, how urgent, what to do next, and
 * whether it has been verified. The failing-subject table is SERVER paged, so a
 * control failing on 4,000 components does not ship 4,000 rows to the browser.
 */
function ControlDrawer({
  view,
  id,
  onClose,
  onNavigate,
  revision,
}: {
  view: GovernanceView;
  id: string;
  onClose: () => void;
  onNavigate: (target: DrawerTarget) => void;
  revision: number;
}) {
  const { loadControl, loading, detailError } = useGovernanceDetail(view);
  const { updateControlAssessment, pending } = useGovernanceActions(view);
  const [detail, setDetail] = useState<ControlDetail | null>(null);
  const [offset, setOffset] = useState(0);
  const [severity, setSeverity] = useState('all');
  const [ownerInput, setOwnerDraft] = useState<string | null>(null);
  const ownerDraft = ownerInput ?? detail?.control.owner ?? '';
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    void loadControl(id).then((result) => {
      if (cancelled) return;
      setDetail(result);
    });
    return () => {
      cancelled = true;
    };
  }, [id, revision, loadControl, reloadKey]);

  const subjects = useGovernancePagedResource<ControlSubject>(
    view,
    `/controls/${encodeURIComponent(id)}/subjects`,
    'subjects',
    { limit: 25, offset, severity },
    revision + reloadKey,
  );

  const saveOwner = useCallback(async () => {
    const result = await updateControlAssessment(id, { owner: ownerDraft });
    setActionMessage(result.ok ? 'Owner recorded.' : result.message);
    if (result.ok) setReloadKey((value) => value + 1);
  }, [id, ownerDraft, updateControlAssessment]);

  const control = detail?.control;
  const chain: ChainStep[] = control
    ? [
        {
          label: 'Framework',
          value: detail?.frameworks[0]?.shortName || `${control.frameworkIds.length} frameworks`,
          onClick: detail?.frameworks[0] ? () => onNavigate({ kind: 'framework', id: detail.frameworks[0].id }) : undefined,
          muted: !detail?.frameworks.length,
        },
        {
          label: 'Requirement',
          value: detail?.requirements[0]?.code || `${control.requirementIds.length} requirements`,
          onClick: detail?.requirements[0] ? () => onNavigate({ kind: 'requirement', id: detail.requirements[0].id }) : undefined,
          muted: !detail?.requirements.length,
        },
        { label: 'Control', value: control.code },
        {
          label: 'Assets',
          value: control.affectedAssetCount ? `${control.affectedAssetCount} affected` : 'none affected',
          muted: !control.affectedAssetCount,
        },
        { label: 'Evidence', value: `${control.evidenceIds.length} records`, muted: !control.evidenceIds.length },
      ]
    : [];

  return (
    <Drawer open title={control ? control.title : 'Control'} subtitle={control ? `${control.code} · ${CONTROL_DOMAIN_LABEL[control.domain]}` : id} onClose={onClose}>
      {loading && !detail ? <GovernanceSkeleton rows={5} /> : null}
      {detailError ? <PanelEmpty>{detailError}</PanelEmpty> : null}

      {control ? (
        <div className="space-y-5">
          <TraceChain steps={chain} />

          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={control.status} />
            <SeverityBadge severity={control.severity} />
            <FreshnessChip state={control.evidenceFreshness} ageDays={control.evidenceAgeDays} />
            {control.exception ? (
              <Pill tone={control.exception.expired ? 'critical' : 'info'}>
                {control.exception.expired ? 'Exception expired' : 'Exception active'}
              </Pill>
            ) : null}
          </div>

          <Section title="What this control requires">
            <p className="text-[11.5px] leading-relaxed text-white/60">{control.objective}</p>
            <p className="mt-2 rounded-lg border border-white/8 bg-white/[0.02] p-2.5 text-[11px] leading-relaxed text-white/50">
              <span className="font-black uppercase tracking-wider text-white/40">Pass criterion — </span>
              {control.criterion}
            </p>
          </Section>

          <Section title="How this status was produced">
            <p className="text-[11.5px] leading-relaxed text-white/60">{control.basis}</p>
            <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2.5 sm:grid-cols-4">
              <Fact label="Score" value={scoreCell(control.score, control.measured)} />
              <Fact label="In scope" value={fmtNumber(control.population)} mono />
              <Fact label="Satisfied" value={fmtNumber(control.satisfied)} mono />
              <Fact label="Failing" value={fmtNumber(control.failing)} mono />
              <Fact label="Weight" value={`${control.weight} / 5`} mono />
              <Fact label="Last validated" value={control.lastValidatedAt ? absoluteTime(control.lastValidatedAt) : 'Never'} />
              <Fact label="Affected assets" value={fmtNumber(control.affectedAssetCount)} mono />
              <Fact label="Evidence sources" value={control.evidenceSources.join(', ') || '—'} />
            </dl>
          </Section>

          {control.exception ? (
            <Section title="Exception">
              <div className="rounded-lg border border-amber-400/25 bg-amber-500/[0.06] p-3">
                <p className="text-[11px] leading-relaxed text-amber-100/85">{control.exception.reason}</p>
                <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2">
                  <Fact label="Approved by" value={control.exception.approvedBy} />
                  <Fact label="Expires" value={control.exception.expiresAt ? absoluteTime(control.exception.expiresAt) : 'No expiry recorded'} />
                </dl>
                {control.exception.expired ? (
                  <p className="mt-2 flex items-center gap-1.5 text-[10.5px] font-semibold text-amber-200">
                    <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                    Expired — the control is back in scope and is being scored again.
                  </p>
                ) : null}
              </div>
            </Section>
          ) : null}

          <Section title="Ownership" meta={control.ownerSource}>
            <div className="flex flex-wrap items-center gap-2">
              <input
                value={ownerDraft}
                onChange={(event) => setOwnerDraft(event.target.value)}
                placeholder="Assign an accountable owner"
                className="h-8 min-w-[220px] flex-1 rounded-md border border-white/12 bg-black/30 px-3 text-[11px] text-white outline-none placeholder:text-white/30 focus-visible:ring-2 focus-visible:ring-cyan-300/70"
              />
              <button
                type="button"
                onClick={saveOwner}
                disabled={Boolean(pending) || ownerDraft === (control.owner || '')}
                className="rounded-md border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Save
              </button>
            </div>
            {actionMessage ? <p className="mt-1.5 text-[10.5px] text-white/45">{actionMessage}</p> : null}
          </Section>

          <Section
            title="Failing subjects"
            meta={subjects.total ? `${fmtNumber(subjects.total)} total` : control.measured ? 'none' : 'not measured'}
          >
            <div className="mb-2 flex flex-wrap gap-1.5">
              {['all', 'critical', 'high', 'medium', 'low'].map((option) => (
                <button
                  key={option}
                  type="button"
                  onClick={() => {
                    setSeverity(option);
                    setOffset(0);
                  }}
                  className={cn(
                    'rounded-md border px-2 py-1 text-[9px] font-black uppercase tracking-wider transition',
                    severity === option
                      ? 'border-cyan-400/40 bg-cyan-500/15 text-cyan-200'
                      : 'border-white/10 bg-white/[0.03] text-white/45 hover:bg-white/[0.07]',
                  )}
                >
                  {option}
                </button>
              ))}
            </div>
            {subjects.loading ? (
              <GovernanceSkeleton rows={3} height={36} />
            ) : subjects.rows.length ? (
              <>
                <TableShell minWidth={520}>
                  <thead>
                    <tr>
                      <Th>Subject</Th>
                      <Th>Why it fails</Th>
                      <Th align="right">Severity</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {subjects.rows.map((subject) => (
                      <tr key={subject.id}>
                        <Td>
                          <div className="truncate font-semibold text-white/80" title={subject.label}>
                            {subject.href ? (
                              <Link to={subject.href} className="text-cyan-200 no-underline hover:text-cyan-100">
                                {subject.label}
                              </Link>
                            ) : (
                              subject.label
                            )}
                          </div>
                          <div className="font-mono text-[9.5px] text-white/30">
                            {subject.type} · {subject.source.table}
                          </div>
                        </Td>
                        <Td className="text-white/55">{subject.reason}</Td>
                        <Td align="right">
                          <SeverityBadge severity={subject.severity} />
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </TableShell>
                <Pager offset={offset} limit={25} total={subjects.total} onChange={setOffset} />
              </>
            ) : control.measured ? (
              <div className="flex items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-500/[0.05] px-3 py-2.5">
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-300" aria-hidden="true" />
                <p className="text-[11px] text-emerald-100/85">Every in-scope subject satisfies this control.</p>
              </div>
            ) : (
              <PanelEmpty>
                This control has no evidence to evaluate, so there are no failing subjects — and no passing ones either.
              </PanelEmpty>
            )}
          </Section>

          {detail?.policies.length ? (
            <Section title="Governing policy rules">
              <div className="space-y-1.5">
                {detail.policies.map((policy) => (
                  <div key={policy.id} className="rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-[11px] font-semibold text-white/80">{policy.title}</span>
                      <span className="font-mono text-[10px] text-white/45">
                        {policy.violations} violation{policy.violations === 1 ? '' : 's'} / {fmtNumber(policy.evaluated)} evaluated
                      </span>
                    </div>
                    <p className="mt-1 text-[10px] text-white/35">{policy.basis}</p>
                  </div>
                ))}
              </div>
            </Section>
          ) : null}

          {detail?.requirements.length ? (
            <Section title="Requirements linked to this control" meta={`${detail.requirements.length}`}>
              <div className="space-y-1.5">
                {detail.requirements.map((requirement) => (
                  <button
                    key={requirement.id}
                    type="button"
                    onClick={() => onNavigate({ kind: 'requirement', id: requirement.id })}
                    className="flex w-full items-center justify-between gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2 text-left transition hover:border-white/20 hover:bg-white/[0.05]"
                  >
                    <span className="min-w-0">
                      <span className="font-mono text-[9.5px] text-cyan-300/70">{requirement.code}</span>
                      <span className="ml-1.5 text-[11px] font-semibold text-white/80">{requirement.title}</span>
                    </span>
                    <StatusBadge status={requirement.status} size="sm" />
                  </button>
                ))}
              </div>
            </Section>
          ) : null}

          {detail?.evidence.length ? (
            <Section title="Evidence cited" meta={`${detail.evidence.length}`}>
              <div className="space-y-1.5">
                {detail.evidence.slice(0, 12).map((record) => (
                  <EvidenceRow key={record.id} record={record} onOpen={(evidenceId) => onNavigate({ kind: 'evidence', id: evidenceId })} />
                ))}
              </div>
            </Section>
          ) : null}

          <div className="flex flex-wrap gap-2 border-t border-white/[0.06] pt-3">
            <Link
              to={control.remediationRoute}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/35 bg-cyan-500/12 px-3 py-1.5 text-[10.5px] font-black uppercase tracking-wider text-cyan-100 no-underline transition hover:bg-cyan-500/20"
            >
              Remediate <ArrowRight className="h-3 w-3" aria-hidden="true" />
            </Link>
          </div>
        </div>
      ) : null}
    </Drawer>
  );
}

/* ------------------------------------------------------------------ */
/* Framework drawer                                                    */
/* ------------------------------------------------------------------ */

function FrameworkDrawer({
  view,
  id,
  revision,
  onClose,
  onNavigate,
}: {
  view: GovernanceView;
  id: string;
  revision: number;
  onClose: () => void;
  onNavigate: (target: DrawerTarget) => void;
}) {
  const { loadFramework, loading, detailError } = useGovernanceDetail(view);
  const [detail, setDetail] = useState<FrameworkDetail | null>(null);

  useEffect(() => {
    let cancelled = false;
    void loadFramework(id).then((result) => {
      if (!cancelled) setDetail(result);
    });
    return () => {
      cancelled = true;
    };
  }, [id, revision, loadFramework]);

  const framework = detail?.framework;

  return (
    <Drawer open title={framework ? framework.name : 'Framework'} subtitle={framework ? `${framework.authority} · ${framework.version}` : id} onClose={onClose}>
      {loading && !detail ? <GovernanceSkeleton rows={5} /> : null}
      {detailError ? <PanelEmpty>{detailError}</PanelEmpty> : null}

      {framework ? (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={framework.status} />
            {scoreCell(framework.score, framework.measured)}
            <FreshnessChip state={framework.evidenceFreshness} />
          </div>

          <p className="text-[11.5px] leading-relaxed text-white/55">{framework.scope}</p>

          <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5 sm:grid-cols-3">
            <Fact label="Requirements" value={fmtNumber(framework.requirementsTotal)} mono />
            <Fact label="Assessed" value={fmtNumber(framework.requirementsMeasured)} mono />
            <Fact label="Coverage" value={`${framework.coverage}%`} mono />
            <Fact label="Compliant" value={fmtNumber(framework.requirementsCompliant)} mono />
            <Fact label="Partial" value={fmtNumber(framework.requirementsPartial)} mono />
            <Fact label="Failing" value={fmtNumber(framework.requirementsFailing)} mono />
            <Fact label="Not assessed" value={fmtNumber(framework.requirementsUnassessed)} mono />
            <Fact label="Evidence records" value={fmtNumber(framework.evidenceCount)} mono />
            <Fact label="Stored attestations" value={fmtNumber(framework.attestedEvidenceCount)} mono />
          </dl>

          {framework.referenceOnly ? (
            <p className="rounded-lg border border-white/10 bg-white/[0.02] p-2.5 text-xs leading-relaxed text-white/60">
              Reference mapping. Related controls can help you gather evidence, but Qguard Helix does not assess applicability, conformance or compliance for this source.
            </p>
          ) : framework.attestedEvidenceCount === 0 ? (
            <p className="rounded-lg border border-white/10 bg-white/[0.02] p-2.5 text-[10.5px] leading-relaxed text-white/45">
              No stored attestation names this framework. Its status rests entirely on derived platform signals — real
              measurements, but not an auditor-facing attestation. Record evidence against its controls to strengthen it.
            </p>
          ) : null}

          <Section title="Requirements" meta={`${detail?.requirements.length ?? 0}`}>
            {detail?.requirements.length ? (
              <div className="space-y-1.5">
                {detail.requirements.map((requirement) => (
                  <button
                    key={requirement.id}
                    type="button"
                    onClick={() => onNavigate({ kind: 'requirement', id: requirement.id })}
                    className="flex w-full items-start justify-between gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2 text-left transition hover:border-white/20 hover:bg-white/[0.05]"
                  >
                    <span className="min-w-0">
                      <span className="font-mono text-[9.5px] text-cyan-300/70">{requirement.code}</span>
                      <span className="ml-1.5 text-[11px] font-semibold text-white/80">{requirement.title}</span>
                      <span className="mt-0.5 block text-[10px] leading-snug text-white/35">{requirement.summary}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2">
                      {scoreCell(requirement.score, requirement.measured)}
                      <StatusBadge status={requirement.status} size="sm" />
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <PanelEmpty>No requirements mapped.</PanelEmpty>
            )}
          </Section>

          <Section title={framework.referenceOnly ? "Related controls" : "Controls"} meta={`${detail?.controls.length ?? 0}`}>
            {detail?.controls.length ? (
              <div className="space-y-1.5">
                {detail.controls.map((control) => (
                  <ControlLinkRow key={control.id} control={control} onOpen={(controlId) => onNavigate({ kind: 'control', id: controlId })} />
                ))}
              </div>
            ) : (
              <PanelEmpty>No controls mapped.</PanelEmpty>
            )}
          </Section>

          <Basis>
            Requirement text is paraphrased for this platform. Read the authoritative wording at{' '}
            <a href={framework.reference} target="_blank" rel="noreferrer" className="text-cyan-300 hover:text-cyan-200">
              {framework.reference}
            </a>
            .
          </Basis>
        </div>
      ) : null}
    </Drawer>
  );
}

/* ------------------------------------------------------------------ */
/* Requirement drawer                                                  */
/* ------------------------------------------------------------------ */

function RequirementDrawer({
  view,
  id,
  revision,
  onClose,
  onNavigate,
}: {
  view: GovernanceView;
  id: string;
  revision: number;
  onClose: () => void;
  onNavigate: (target: DrawerTarget) => void;
}) {
  const { loadRequirement, loading, detailError } = useGovernanceDetail(view);
  const [detail, setDetail] = useState<RequirementDetail | null>(null);

  useEffect(() => {
    let cancelled = false;
    void loadRequirement(id).then((result) => {
      if (!cancelled) setDetail(result);
    });
    return () => {
      cancelled = true;
    };
  }, [id, revision, loadRequirement]);

  const requirement = detail?.requirement;

  return (
    <Drawer
      open
      title={requirement ? requirement.title : 'Requirement'}
      subtitle={requirement ? `${detail?.framework?.shortName || ''} ${requirement.code}`.trim() : id}
      onClose={onClose}
    >
      {loading && !detail ? <GovernanceSkeleton rows={4} /> : null}
      {detailError ? <PanelEmpty>{detailError}</PanelEmpty> : null}

      {requirement ? (
        <div className="space-y-5">
          <TraceChain
            steps={[
              {
                label: 'Framework',
                value: detail?.framework?.shortName || requirement.frameworkId,
                onClick: detail?.framework ? () => onNavigate({ kind: 'framework', id: detail.framework!.id }) : undefined,
              },
              { label: 'Requirement', value: requirement.code },
              { label: 'Controls', value: `${requirement.controlsTotal}`, muted: !requirement.controlsTotal },
            ]}
          />

          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={requirement.status} />
            {scoreCell(requirement.score, requirement.measured)}
            <FreshnessChip state={requirement.evidenceFreshness} />
          </div>

          <Section title="Obligation">
            <p className="text-[11.5px] leading-relaxed text-white/60">{requirement.summary}</p>
          </Section>

          <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5 sm:grid-cols-4">
            <Fact label="Controls" value={fmtNumber(requirement.controlsTotal)} mono />
            <Fact label="Assessed" value={fmtNumber(requirement.controlsMeasured)} mono />
            <Fact label="Compliant" value={fmtNumber(requirement.controlsCompliant)} mono />
            <Fact label="Failing" value={fmtNumber(requirement.controlsFailing)} mono />
            <Fact label="Evidence" value={fmtNumber(requirement.evidenceCount)} mono />
            <Fact label="Last validated" value={requirement.lastValidatedAt ? absoluteTime(requirement.lastValidatedAt) : 'Never'} />
          </dl>

          {requirement.referenceOnly ? (
            <p className="rounded-lg border border-white/10 bg-white/[0.02] p-2.5 text-xs leading-relaxed text-white/60">
              This is a reference mapping. The related controls provide evidence to review; they do not establish whether the requirement applies or has been met.
            </p>
          ) : requirement.unmeasuredControlIds.length ? (
            <p className="rounded-lg border border-white/10 bg-white/[0.02] p-2.5 text-[10.5px] leading-relaxed text-white/45">
              {requirement.unmeasuredControlIds.length} of its controls have no evidence yet, so this requirement is scored
              only over the controls that could be assessed. Connecting those sources changes the score.
            </p>
          ) : null}

          <Section title={requirement.referenceOnly ? "Related controls" : "Controls"} meta={`${detail?.controls.length ?? 0}`}>
            {detail?.controls.length ? (
              <div className="space-y-1.5">
                {detail.controls.map((control) => (
                  <ControlLinkRow key={control.id} control={control} onOpen={(controlId) => onNavigate({ kind: 'control', id: controlId })} />
                ))}
              </div>
            ) : (
              <PanelEmpty>No controls mapped to this requirement.</PanelEmpty>
            )}
          </Section>

          {detail?.evidence.length ? (
            <Section title="Evidence" meta={`${detail.evidence.length}`}>
              <div className="space-y-1.5">
                {detail.evidence.slice(0, 12).map((record) => (
                  <EvidenceRow key={record.id} record={record} onOpen={(evidenceId) => onNavigate({ kind: 'evidence', id: evidenceId })} />
                ))}
              </div>
            </Section>
          ) : null}
        </div>
      ) : null}
    </Drawer>
  );
}

/* ------------------------------------------------------------------ */
/* Evidence drawer                                                     */
/* ------------------------------------------------------------------ */

function EvidenceDrawer({
  view,
  id,
  revision,
  onClose,
  onNavigate,
}: {
  view: GovernanceView;
  id: string;
  revision: number;
  onClose: () => void;
  onNavigate: (target: DrawerTarget) => void;
}) {
  const { loadEvidence, loading, detailError } = useGovernanceDetail(view);
  const { anchorEvidence, verifyEvidence, pending } = useGovernanceActions(view);
  const [detail, setDetail] = useState<EvidenceDetail | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    void loadEvidence(id).then((result) => {
      if (!cancelled) setDetail(result);
    });
    return () => {
      cancelled = true;
    };
  }, [id, revision, loadEvidence, reloadKey]);

  const record = detail?.evidence;

  return (
    <Drawer open title={record ? record.title : 'Evidence'} subtitle={record ? `${record.kind} · ${record.source.table}` : id} onClose={onClose}>
      {loading && !detail ? <GovernanceSkeleton rows={4} /> : null}
      {detailError ? <PanelEmpty>{detailError}</PanelEmpty> : null}

      {record ? (
        <div className="space-y-5">
          <TraceChain
            steps={[
              {
                label: 'Framework',
                value: detail?.frameworks[0]?.shortName || `${record.frameworkIds.length}`,
                onClick: detail?.frameworks[0] ? () => onNavigate({ kind: 'framework', id: detail.frameworks[0].id }) : undefined,
                muted: !detail?.frameworks.length,
              },
              {
                label: 'Control',
                value: detail?.controls[0]?.code || `${record.controlIds.length}`,
                onClick: detail?.controls[0] ? () => onNavigate({ kind: 'control', id: detail.controls[0].id }) : undefined,
                muted: !detail?.controls.length,
              },
              {
                label: 'Asset',
                value: record.assetName || 'not asset-scoped',
                onClick: record.assetId ? () => onNavigate({ kind: 'asset', id: record.assetId! }) : undefined,
                muted: !record.assetId,
              },
              { label: 'Evidence', value: record.source.recordId.slice(0, 8) || record.kind },
            ]}
          />

          <div className="flex flex-wrap items-center gap-2">
            <Pill tone={record.outcome === 'contradicting' ? 'critical' : record.outcome === 'supporting' ? 'good' : 'neutral'}>
              {record.outcome === 'contradicting' ? 'Contradicts control' : record.outcome === 'supporting' ? 'Supports control' : 'Informational'}
            </Pill>
            <IntegrityBadge state={record.integrity.state} assurance={record.integrity.assurance} />
            <RetentionBadge state={record.retention.state} expiresAt={record.retention.expiresAt} periodDays={record.retention.periodDays} />
            <FreshnessChip state={record.freshness} ageDays={record.ageDays} />
            <SeverityBadge severity={record.severity} />
          </div>

          <p className="text-[11.5px] leading-relaxed text-white/60">{record.description}</p>

          <Section title="Provenance">
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5 sm:grid-cols-3">
              <Fact label="Source table" value={record.source.table} mono />
              <Fact label="Record id" value={<CopyValue value={record.source.recordId} label="record id" />} />
              <Fact label="Collector" value={record.source.collector} />
              <Fact label="Actor" value={`${record.actor} (${record.actorType})`} />
              <Fact label="Occurred" value={record.occurredAt ? absoluteTime(record.occurredAt) : 'Undated'} />
              <Fact label="Recorded" value={record.recordedAt ? absoluteTime(record.recordedAt) : 'Undated'} />
              <Fact label="Asset" value={record.assetName || 'Not asset-scoped'} />
              <Fact label="Status on source" value={record.statusLabel || '—'} />
            </dl>
          </Section>

          <Section title="Integrity">
            <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
              <div className="flex flex-wrap items-center gap-2">
                <Fingerprint className="h-3.5 w-3.5 shrink-0 text-cyan-300" aria-hidden="true" />
                <span className="text-[10px] font-black uppercase tracking-wider text-white/45">SHA3-256 content digest</span>
              </div>
              <div className="mt-1.5">
                <CopyValue value={record.integrity.digest} label="digest" />
              </div>
              <p className="mt-2 text-[10.5px] leading-relaxed text-white/45">{record.integrity.assurance}</p>
              <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2">
                <Fact label="Computed" value={absoluteTime(record.integrity.computedAt)} />
                <Fact label="Anchored" value={record.integrity.anchoredAt ? absoluteTime(record.integrity.anchoredAt) : 'Never'} />
              </dl>
              <div className="mt-2.5 flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={Boolean(pending)}
                  onClick={async () => {
                    const result = await anchorEvidence({ evidenceIds: [record.id] });
                    setMessage(result.message);
                    if (result.ok) setReloadKey((value) => value + 1);
                  }}
                  className="rounded-md border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-1 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/20 disabled:opacity-40"
                >
                  {record.integrity.state === 'unanchored' ? 'Anchor' : 'Re-anchor'}
                </button>
                <button
                  type="button"
                  disabled={Boolean(pending)}
                  onClick={async () => {
                    const result = await verifyEvidence(record.id);
                    setMessage(result.ok ? result.data?.assurance || 'Verified.' : result.message);
                    if (result.ok) setReloadKey((value) => value + 1);
                  }}
                  className="rounded-md border border-white/12 bg-white/[0.04] px-2.5 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08] disabled:opacity-40"
                >
                  Verify now
                </button>
              </div>
              {message ? <p className="mt-2 text-[10.5px] leading-relaxed text-white/50">{message}</p> : null}
            </div>
          </Section>

          {record.custody.length ? (
            <Section title="Chain of custody" meta={`${record.custody.length} entr${record.custody.length === 1 ? 'y' : 'ies'}`}>
              <ol className="space-y-1.5">
                {record.custody.map((entry, index) => (
                  <li key={`${entry.action}-${index}`} className="flex items-start gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2">
                    <span className="mt-[3px] h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400/70" aria-hidden="true" />
                    <span className="min-w-0 flex-1">
                      <span className="block text-[11px] font-semibold capitalize text-white/80">{entry.action}</span>
                      <span className="block font-mono text-[9.5px] text-white/35">
                        {entry.actor} · {entry.source} · {entry.at ? absoluteTime(entry.at) : 'undated'}
                      </span>
                    </span>
                  </li>
                ))}
              </ol>
            </Section>
          ) : null}

          {detail?.controls.length ? (
            <Section title="Controls this supports" meta={`${detail.controls.length}`}>
              <div className="space-y-1.5">
                {detail.controls.map((control) => (
                  <ControlLinkRow key={control.id} control={control} onOpen={(controlId) => onNavigate({ kind: 'control', id: controlId })} />
                ))}
              </div>
            </Section>
          ) : null}

          {record.href ? (
            <Link
              to={record.href}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/35 bg-cyan-500/12 px-3 py-1.5 text-[10.5px] font-black uppercase tracking-wider text-cyan-100 no-underline transition hover:bg-cyan-500/20"
            >
              Open source record <ArrowRight className="h-3 w-3" aria-hidden="true" />
            </Link>
          ) : null}
        </div>
      ) : null}
    </Drawer>
  );
}

/* ------------------------------------------------------------------ */
/* Audit event drawer                                                  */
/* ------------------------------------------------------------------ */

function AuditEventDrawer({
  view,
  id,
  revision,
  onClose,
  onNavigate,
}: {
  view: GovernanceView;
  id: string;
  revision: number;
  onClose: () => void;
  onNavigate: (target: DrawerTarget) => void;
}) {
  const { loadAuditEvent, loading, detailError } = useGovernanceDetail(view);
  const [detail, setDetail] = useState<AuditEventDetail | null>(null);

  useEffect(() => {
    let cancelled = false;
    void loadAuditEvent(id).then((result) => {
      if (!cancelled) setDetail(result);
    });
    return () => {
      cancelled = true;
    };
  }, [id, revision, loadAuditEvent]);

  const event = detail?.event;

  return (
    <Drawer open title={event ? event.action : 'Audit event'} subtitle={event ? `${event.category} · ${event.source.table}` : id} onClose={onClose}>
      {loading && !detail ? <GovernanceSkeleton rows={4} /> : null}
      {detailError ? <PanelEmpty>{detailError}</PanelEmpty> : null}

      {event ? (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <Pill tone={event.outcome === 'failure' || event.outcome === 'denied' ? 'critical' : event.outcome === 'success' ? 'good' : 'neutral'}>
              {event.outcome}
            </Pill>
            <SeverityBadge severity={event.severity} />
            <Pill tone={event.appendOnlySource ? 'good' : 'neutral'} title={
              event.appendOnlySource
                ? 'This source has no update path in the platform: rows are inserted once and never rewritten.'
                : 'This source can be updated in place, so the record is not append-only. Anchor its evidence to make changes detectable.'
            }>
              {event.appendOnlySource ? 'Append-only source' : 'Mutable source'}
            </Pill>
          </div>

          <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5 sm:grid-cols-3">
            <Fact label="When" value={event.at ? absoluteTime(event.at) : 'Undated'} />
            <Fact label="Actor" value={`${event.actor} (${event.actorType})`} />
            <Fact label="Subject" value={event.subject} />
            <Fact label="Subject type" value={event.subjectType} mono />
            <Fact label="Source table" value={event.source.table} mono />
            <Fact label="Record id" value={<CopyValue value={event.source.recordId} label="record id" />} />
            <Fact label="IP address" value={event.ipAddress || '—'} mono />
          </dl>

          {event.detail ? (
            <Section title="Detail">
              <p className="rounded-lg border border-white/8 bg-white/[0.02] p-2.5 text-[11px] leading-relaxed text-white/55">{event.detail}</p>
            </Section>
          ) : null}

          {detail?.evidence ? (
            <Section title="Evidence record">
              <EvidenceRow record={detail.evidence} onOpen={(evidenceId) => onNavigate({ kind: 'evidence', id: evidenceId })} />
            </Section>
          ) : null}

          {detail?.controls.length ? (
            <Section title="Controls this event feeds" meta={`${detail.controls.length}`}>
              <div className="space-y-1.5">
                {detail.controls.map((control) => (
                  <ControlLinkRow key={control.id} control={control} onOpen={(controlId) => onNavigate({ kind: 'control', id: controlId })} />
                ))}
              </div>
            </Section>
          ) : null}

          {detail?.related.length ? (
            <Section title="Related activity" meta={`${detail.related.length}`}>
              <div className="space-y-1">
                {detail.related.map((related) => (
                  <button
                    key={related.id}
                    type="button"
                    onClick={() => onNavigate({ kind: 'audit', id: related.id })}
                    className="flex w-full items-center justify-between gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-1.5 text-left transition hover:border-white/20"
                  >
                    <span className="truncate text-[10.5px] text-white/70">{related.action}</span>
                    <span className="shrink-0 font-mono text-[9.5px] text-white/30">{relativeTime(related.at)}</span>
                  </button>
                ))}
              </div>
            </Section>
          ) : null}
        </div>
      ) : null}
    </Drawer>
  );
}

/* ------------------------------------------------------------------ */
/* Asset compliance drawer                                             */
/* ------------------------------------------------------------------ */

function AssetDrawer({
  view,
  id,
  revision,
  onClose,
  onNavigate,
}: {
  view: GovernanceView;
  id: string;
  revision: number;
  onClose: () => void;
  onNavigate: (target: DrawerTarget) => void;
}) {
  const { loadAsset, loading, detailError } = useGovernanceDetail(view);
  const [detail, setDetail] = useState<AssetComplianceDetail | null>(null);

  useEffect(() => {
    let cancelled = false;
    void loadAsset(id).then((result) => {
      if (!cancelled) setDetail(result);
    });
    return () => {
      cancelled = true;
    };
  }, [id, revision, loadAsset]);

  const asset = detail?.asset;

  return (
    <Drawer open title={asset ? asset.name : 'Asset'} subtitle={asset ? `${asset.type} · ${asset.environment}` : id} onClose={onClose}>
      {loading && !detail ? <GovernanceSkeleton rows={4} /> : null}
      {detailError ? <PanelEmpty>{detailError}</PanelEmpty> : null}

      {asset ? (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={asset.status} />
            <Pill tone="neutral">{asset.postureLabel}</Pill>
            {asset.internetFacing ? <Pill tone="warning">Internet-facing</Pill> : null}
            <FreshnessChip state={asset.evidenceFreshness} />
          </div>

          <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5 sm:grid-cols-3">
            <Fact label="Owner" value={asset.owner} />
            <Fact label="Criticality" value={asset.criticality} />
            <Fact label="Risk score" value={asset.posture === 'unknown' || asset.posture === 'not-assessed' ? 'Not assessed' : fmtNumber(asset.riskScore)} mono />
            <Fact label="Readiness" value={`${asset.readinessScore}%`} mono />
            <Fact label="Failing controls" value={fmtNumber(asset.controlsFailing)} mono />
            <Fact label="Open findings" value={fmtNumber(asset.openFindings)} mono />
            <Fact label="Critical findings" value={fmtNumber(asset.criticalFindings)} mono />
            <Fact label="Policy violations" value={fmtNumber(asset.policyViolations)} mono />
            <Fact label="Evidence records" value={fmtNumber(asset.evidenceCount)} mono />
          </dl>

          {asset.attestedFrameworks.length ? (
            <Section title="Attested frameworks">
              <div className="flex flex-wrap gap-1.5">
                {asset.attestedFrameworks.map((framework) => (
                  <Pill key={framework} tone="info">
                    {framework}
                  </Pill>
                ))}
              </div>
            </Section>
          ) : null}

          <Section title="Failing controls" meta={`${detail?.failingControls.length ?? 0}`}>
            {detail?.failingControls.length ? (
              <div className="space-y-1.5">
                {detail.failingControls.map((control) => (
                  <ControlLinkRow key={control.id} control={control} onOpen={(controlId) => onNavigate({ kind: 'control', id: controlId })} />
                ))}
              </div>
            ) : asset.status === 'not-assessed' ? (
              <PanelEmpty>No cryptographic evidence is bound to this asset, so no control could be evaluated for it.</PanelEmpty>
            ) : (
              <div className="flex items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-500/[0.05] px-3 py-2.5">
                <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-emerald-300" aria-hidden="true" />
                <p className="text-[11px] text-emerald-100/85">This asset satisfies every control it is in scope for.</p>
              </div>
            )}
          </Section>

          {detail?.evidence.length ? (
            <Section title="Evidence" meta={`${detail.evidence.length}`}>
              <div className="space-y-1.5">
                {detail.evidence.slice(0, 12).map((record) => (
                  <EvidenceRow key={record.id} record={record} onOpen={(evidenceId) => onNavigate({ kind: 'evidence', id: evidenceId })} />
                ))}
              </div>
            </Section>
          ) : null}

          <Link
            to={asset.href}
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/35 bg-cyan-500/12 px-3 py-1.5 text-[10.5px] font-black uppercase tracking-wider text-cyan-100 no-underline transition hover:bg-cyan-500/20"
          >
            Open asset dossier <ArrowRight className="h-3 w-3" aria-hidden="true" />
          </Link>
        </div>
      ) : null}
    </Drawer>
  );
}

/* ------------------------------------------------------------------ */
/* Host                                                                */
/* ------------------------------------------------------------------ */

/**
 * Renders whichever drawer the current target names, and lets a drawer navigate
 * to another one without closing first — so the user can follow the chain from a
 * gap to its control to its requirement to its framework in one motion.
 */
export function GovernanceDrawers({
  view,
  target,
  onTarget,
  revision,
  reconciliation,
}: {
  view: GovernanceView;
  target: DrawerTarget;
  onTarget: (target: DrawerTarget) => void;
  revision: number;
  reconciliation?: React.ReactNode;
}) {
  const close = useCallback(() => onTarget(null), [onTarget]);
  if (!target) return null;

  switch (target.kind) {
    case 'control':
      return <ControlDrawer key={target.id} view={view} id={target.id} onClose={close} onNavigate={onTarget} revision={revision} />;
    case 'framework':
      return <FrameworkDrawer key={target.id} revision={revision} view={view} id={target.id} onClose={close} onNavigate={onTarget} />;
    case 'requirement':
      return <RequirementDrawer key={target.id} revision={revision} view={view} id={target.id} onClose={close} onNavigate={onTarget} />;
    case 'evidence':
      return <EvidenceDrawer key={target.id} revision={revision} view={view} id={target.id} onClose={close} onNavigate={onTarget} />;
    case 'audit':
      return <AuditEventDrawer key={target.id} revision={revision} view={view} id={target.id} onClose={close} onNavigate={onTarget} />;
    case 'asset':
      return <AssetDrawer key={target.id} revision={revision} view={view} id={target.id} onClose={close} onNavigate={onTarget} />;
    case 'reconciliation':
      return (
        <Drawer open title="Data reconciliation" subtitle="Where every number on this page comes from" onClose={close}>
          {reconciliation ?? <PanelEmpty>Reconciliation report unavailable.</PanelEmpty>}
        </Drawer>
      );
    default:
      return null;
  }
}

export { Section as DrawerSection, Fact as DrawerFact, ControlLinkRow, EvidenceRow };
