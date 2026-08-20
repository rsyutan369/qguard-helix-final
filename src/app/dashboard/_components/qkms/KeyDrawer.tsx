'use client';

/**
 * Key inspection drawer — the complete, evidence-driven profile of one key.
 *
 * Opened from any of the seven pages, and identical on all of them. It is the
 * only place a key's full record is rendered, which is what stops Inventory,
 * Lifecycle and Risk Analysis from each showing a different partial view of the
 * same key.
 *
 * Everything here is fetched lazily from `/keys/:id`: the dashboard payloads
 * deliberately do not carry every version, violation and audit event for every
 * key, because for a large estate that is the difference between a page that
 * renders and one that does not.
 */

import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  BadgeCheck,
  Boxes,
  FileClock,
  Fingerprint,
  GitBranch,
  History,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useKeyDetail, useQkmsActions } from '@/hooks/use-qkms';
import {
  ActionButton,
  CustodyBadge,
  Drawer,
  EvidenceList,
  ExplainBox,
  Field,
  JobStatusBadge,
  LifecycleBadge,
  Notice,
  OwnerPrompt,
  Panel,
  PanelEmpty,
  Pill,
  PostureBadge,
  RequirementBadge,
  RiskBadge,
  RotationBadge,
  SectionLabel,
  SeverityBadge,
  TONE,
  absoluteTime,
  fmtNumber,
  keySubtitle,
  relativeTime,
  riskTone,
  useNotice,
} from './shell';

export function KeyDrawer({
  keyId,
  onClose,
  onChanged,
}: {
  keyId: string | null;
  onClose: () => void;
  onChanged?: () => void;
}) {
  const { detail, loading, error, load } = useKeyDetail();
  const { notice, show, dismiss } = useNotice();
  const [editingOwner, setEditingOwner] = useState(false);

  const reload = useCallback(() => {
    void load(keyId);
    onChanged?.();
  }, [keyId, load, onChanged]);

  const actions = useQkmsActions(reload);

  useEffect(() => {
    void load(keyId);
    setEditingOwner(false);
  }, [keyId, load]);

  const key = detail?.key ?? null;

  const runAction = useCallback(
    async (promise: Promise<{ ok: boolean; message: string }>) => {
      const result = await promise;
      show(result.ok, result.message);
    },
    [show],
  );

  return (
    <Drawer
      open={Boolean(keyId)}
      title={key ? key.label : loading ? 'Loading key…' : 'Key'}
      subtitle={key ? keySubtitle(key) : keyId || undefined}
      onClose={onClose}
    >
      <Notice notice={notice} onDismiss={dismiss} />

      {error ? (
        <div className="rounded-lg border border-red-500/25 bg-red-500/10 p-3 text-[11.5px] text-red-200">{error}</div>
      ) : null}

      {loading && !key ? (
        <div className="space-y-3" aria-busy="true">
          {Array.from({ length: 4 }).map((_, index) => (
            <div key={index} className="h-24 animate-pulse rounded-lg bg-white/[0.04]" />
          ))}
        </div>
      ) : null}

      {key ? (
        <>
          {/* ---- Risk headline: score, decomposition, action ---------- */}
          <Panel>
            <SectionLabel
              icon={ShieldAlert}
              hint="One weighted model produces this score. The same number appears on Inventory, Lifecycle, Rotation, Risk Analysis and in every export."
              meta={<span>Confidence {key.risk.confidence}%</span>}
            >
              Risk assessment
            </SectionLabel>

            <div className="flex flex-wrap items-center gap-3">
              <div className={cn('grid h-16 w-16 shrink-0 place-items-center rounded-xl border text-2xl font-black tabular-nums', TONE[riskTone(key.risk.level)].border, TONE[riskTone(key.risk.level)].soft, TONE[riskTone(key.risk.level)].text)}>
                {key.risk.score}
              </div>
              <div className="min-w-0 flex-1">
                <RiskBadge level={key.risk.level} />
                <p className="mt-1.5 text-[11.5px] leading-relaxed text-white/65">{key.risk.drivers[0]}</p>
              </div>
            </div>

            {/* Contributing factors — the score is never a bare number. */}
            <div className="mt-3 space-y-1.5">
              {key.risk.factors.map((factor) => (
                <div key={factor.key} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-[10px] font-black uppercase tracking-wider text-white/60">
                      {factor.label}
                      {!factor.measured ? <span className="ml-1.5 font-semibold normal-case tracking-normal text-amber-300/80">not measured</span> : null}
                    </span>
                    <span className="font-mono text-[10px] tabular-nums text-white/45">
                      {factor.score}/100 × {factor.weight}% = <span className="text-cyan-300">{factor.contribution.toFixed(1)}</span>
                    </span>
                  </div>
                  <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-white/10">
                    <span
                      className="block h-full rounded-full"
                      style={{ width: `${Math.max(2, factor.score)}%`, backgroundColor: TONE[factor.score >= 70 ? 'critical' : factor.score >= 40 ? 'warning' : 'good'].hex }}
                    />
                  </div>
                  <p className="mt-1.5 text-[10.5px] leading-snug text-white/50">{factor.reason}</p>
                </div>
              ))}
            </div>

            <ExplainBox tone="info" title="Recommended action">
              {key.risk.recommendedAction}
            </ExplainBox>
          </Panel>

          {/* ---- Governed operations ---------------------------------- */}
          <Panel>
            <SectionLabel icon={BadgeCheck} hint="Only operations this platform can actually perform are offered. A control that cannot be honoured is disabled and states why.">
              Governed operations
            </SectionLabel>

            {editingOwner ? (
              <OwnerPrompt
                current={key.owner}
                busy={actions.pending === `owner:${key.id}`}
                onCancel={() => setEditingOwner(false)}
                onSubmit={(owner) => {
                  setEditingOwner(false);
                  void runAction(actions.assignOwner(key.id, owner));
                }}
              />
            ) : (
              <div className="flex flex-wrap gap-1.5">
                <ActionButton
                  label={key.owner ? 'Change owner' : 'Assign owner'}
                  icon={BadgeCheck}
                  tone={key.owner ? 'neutral' : 'warning'}
                  disabled={!key.capabilities.assignOwner}
                  disabledReason={key.capabilities.reason}
                  onClick={() => setEditingOwner(true)}
                />
                <ActionButton
                  label="Raise rotation order"
                  icon={RefreshCw}
                  tone="info"
                  busy={actions.pending === `rotate:${key.id}`}
                  disabled={!key.capabilities.requestRotation}
                  disabledReason={key.capabilities.reason}
                  onClick={() => void runAction(actions.requestRotation(key.id))}
                />
                <ActionButton
                  label="Revoke"
                  icon={ShieldAlert}
                  tone="critical"
                  busy={actions.pending === `revoke:${key.id}`}
                  disabled={!key.capabilities.revoke}
                  disabledReason={key.capabilities.reason}
                  onClick={() => {
                    if (window.confirm(`Revoke "${key.label}"? This is a governed, audited action.`)) {
                      void runAction(actions.revokeKey(key.id));
                    }
                  }}
                />
                <ActionButton
                  label="Decommission"
                  icon={Trash2}
                  tone="critical"
                  busy={actions.pending === `decommission:${key.id}`}
                  disabled={!key.capabilities.decommission}
                  disabledReason={key.capabilities.reason}
                  onClick={() => {
                    if (window.confirm(`Decommission "${key.label}"? The key is recorded as permanently out of service.`)) {
                      void runAction(actions.decommissionKey(key.id));
                    }
                  }}
                />
              </div>
            )}
            <p className="mt-2 text-[10.5px] leading-relaxed text-white/40">{key.capabilities.reason}</p>
            <p className="mt-1.5 text-[10.5px] leading-relaxed text-white/40">
              A rotation order governs the operation — request, approve, execute, validate — and holds its evidence. QKMS does not
              hold this key&rsquo;s private material and never reports a rotation it did not observe.
            </p>
          </Panel>

          {/* ---- Identity & cryptography ------------------------------ */}
          <Panel>
            <SectionLabel icon={Fingerprint}>Identity and cryptography</SectionLabel>
            <div className="grid gap-2 sm:grid-cols-2">
              <Field label="Key ID" hint="Stable across re-scans: derived from key material or the registry, never from a scan row id.">
                <span className="font-mono text-[10px]">{key.id}</span>
              </Field>
              <Field label="Version">v{key.version}</Field>
              <Field label="Algorithm">{key.algorithm}</Field>
              <Field label="Family">{key.family}</Field>
              <Field label="Key size">{key.keySize ? `${key.keySize} bits` : <span className="text-white/35">Not observed</span>}</Field>
              <Field label="Type">{key.keyType}</Field>
              <Field label="Purpose">{key.purpose}</Field>
              <Field label="Fingerprint">
                {key.fingerprint ? <span className="font-mono text-[10px]">{key.fingerprint.slice(0, 40)}</span> : <span className="text-white/35">Not observed</span>}
              </Field>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <PostureBadge posture={key.posture} />
              <RequirementBadge requirement={key.migrationRequirement} />
            </div>
            <ExplainBox tone="neutral" title="Why this posture">{key.postureReason}</ExplainBox>
          </Panel>

          {/* ---- Lifecycle ------------------------------------------- */}
          <Panel>
            <SectionLabel icon={GitBranch}>Lifecycle</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              <LifecycleBadge state={key.lifecycle} />
              <RotationBadge state={key.rotation} />
            </div>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              <Field label="Created">{key.createdAt ? absoluteTime(key.createdAt) : <span className="text-white/35">Not observed</span>}</Field>
              <Field label="Activated">{key.activatedAt ? absoluteTime(key.activatedAt) : <span className="text-white/35">Not observed</span>}</Field>
              <Field label="Last used" hint="From runtime telemetry attributed to this key's asset and algorithm family.">
                {key.lastUsedAt ? relativeTime(key.lastUsedAt) : <span className="text-white/35">Not observed</span>}
              </Field>
              <Field label="Last rotated">{key.lastRotatedAt ? relativeTime(key.lastRotatedAt) : <span className="text-white/35">Never</span>}</Field>
              <Field label="Next rotation due">{key.nextRotationDueAt ? absoluteTime(key.nextRotationDueAt) : <span className="text-white/35">No interval established</span>}</Field>
              <Field label="Expires">{key.expiresAt ? absoluteTime(key.expiresAt) : <span className="text-white/35">No expiry recorded</span>}</Field>
              <Field label="Age">{key.ageDays === null ? <span className="text-white/35">Unknown</span> : `${fmtNumber(key.ageDays)} days`}</Field>
              <Field label="Runtime usage" hint="Null means usage was never measured for this key — which is not the same as unused.">
                {key.runtimeUsage === null ? <span className="text-white/35">Not measured</span> : `${fmtNumber(key.runtimeUsage)} operation(s)`}
              </Field>
            </div>
            <ExplainBox tone="neutral" title="Lifecycle verdict">{key.lifecycleReason}</ExplainBox>
            <ExplainBox tone="neutral" title="Rotation verdict">{key.rotationReason}</ExplainBox>
          </Panel>

          {/* ---- Version chain --------------------------------------- */}
          {key.versions.length > 1 ? (
            <Panel>
              <SectionLabel icon={History}>Version chain</SectionLabel>
              <ol className="space-y-1.5">
                {[...key.versions].reverse().map((version) => (
                  <li key={version.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono text-[11px] font-bold text-white">v{version.version}</span>
                      <Pill tone={version.status === 'active' ? 'good' : 'neutral'}>{version.status}</Pill>
                    </div>
                    <p className="mt-1 font-mono text-[10px] text-white/45">{version.algorithm}</p>
                    <p className="mt-1 text-[10px] text-white/35">
                      Created {relativeTime(version.createdAt)}
                      {version.supersededAt ? ` · superseded ${relativeTime(version.supersededAt)}` : ''}
                    </p>
                  </li>
                ))}
              </ol>
            </Panel>
          ) : null}

          {/* ---- Custody --------------------------------------------- */}
          <Panel>
            <SectionLabel icon={Lock}>Custody</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              <CustodyBadge custody={key.custody} backend={key.backend} />
              {key.hsmBacked ? <Pill tone="good">HSM-backed</Pill> : null}
              {key.exportable === true ? <Pill tone="critical">Exportable</Pill> : key.exportable === false ? <Pill tone="good">Non-exportable</Pill> : <Pill tone="neutral">Export unknown</Pill>}
            </div>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              <Field label="Backend">{key.backend}</Field>
              <Field label="Storage reference">{key.storageReference || <span className="text-white/35">Not recorded</span>}</Field>
              <Field label="Entropy source">{key.entropySource || <span className="text-white/35">Not attributed</span>}</Field>
              <Field label="Environment">{key.environment}</Field>
            </div>
          </Panel>

          {/* ---- Relationships --------------------------------------- */}
          <Panel>
            <SectionLabel icon={Boxes} hint="Key → certificate → service → asset. This is the blast radius a rotation has to account for.">
              Relationships
            </SectionLabel>
            <div className="grid gap-2 sm:grid-cols-2">
              <Field label="Owner">
                {key.owner || <span className="font-semibold text-amber-300/80">Unassigned</span>}
              </Field>
              <Field label="Asset">
                {key.assetId ? (
                  <Link to={`/dashboard/assets?asset=${encodeURIComponent(key.assetId)}`} className="text-cyan-300 hover:text-cyan-200">
                    {key.assetName || key.assetId}
                  </Link>
                ) : <span className="text-white/35">Unmapped</span>}
              </Field>
              <Field label="Service">{key.serviceName || <span className="text-white/35">Not recorded</span>}</Field>
              <Field label="Application">{key.applicationName || <span className="text-white/35">Not recorded</span>}</Field>
              <Field label="Blast radius">{fmtNumber(key.blastRadius)} dependent record(s)</Field>
              <Field label="Certificates">{fmtNumber(key.linkedCertificates.length)}</Field>
            </div>

            {key.linkedCertificates.length ? (
              <ul className="mt-2 space-y-1.5">
                {key.linkedCertificates.map((cert) => (
                  <li key={cert.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Link to={`/dashboard/pki-visibility?certificate=${encodeURIComponent(cert.id)}`} className="truncate text-[11px] font-semibold text-cyan-300 hover:text-cyan-200">
                        {cert.subject}
                      </Link>
                      <span className="font-mono text-[9.5px] text-white/35">{cert.algorithm}</span>
                    </div>
                    <p className="mt-1 text-[10px] text-white/35">
                      {cert.expiresAt ? `Expires ${relativeTime(cert.expiresAt)}` : 'No expiry recorded'} · {cert.status}
                    </p>
                  </li>
                ))}
              </ul>
            ) : null}

            {detail.relatedKeys.length ? (
              <>
                <h3 className="mt-3 text-[9px] font-black uppercase tracking-wider text-white/35">Other keys on this asset</h3>
                <ul className="mt-1.5 space-y-1">
                  {detail.relatedKeys.map((related) => (
                    <li key={related.id} className="flex items-center justify-between gap-2 rounded-md border border-white/10 bg-black/20 px-2.5 py-1.5">
                      <span className="truncate text-[10.5px] text-white/65">{related.label}</span>
                      <RiskBadge level={related.riskLevel} score={related.riskScore} />
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </Panel>

          {/* ---- Governance violations ------------------------------- */}
          <Panel>
            <SectionLabel icon={ShieldCheck} meta={<span>{fmtNumber(detail.violations.length)}</span>}>
              Governance violations
            </SectionLabel>
            {detail.violations.length ? (
              <ul className="space-y-1.5">
                {detail.violations.map((violation) => (
                  <li key={violation.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <SeverityBadge severity={violation.severity} />
                      <span className="font-mono text-[9.5px] text-white/35">{violation.policyName}</span>
                    </div>
                    <p className="mt-1.5 text-[11px] leading-snug text-white/70">{violation.detail}</p>
                    <p className="mt-1 text-[10.5px] leading-snug text-cyan-300/80">{violation.remediation}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <PanelEmpty>No policy in force is violated by this key.</PanelEmpty>
            )}
          </Panel>

          {/* ---- Rotation work orders -------------------------------- */}
          <Panel>
            <SectionLabel icon={RefreshCw} meta={<span>{fmtNumber(detail.rotationJobs.length)}</span>}>
              Rotation work orders
            </SectionLabel>
            {detail.rotationJobs.length ? (
              <ul className="space-y-1.5">
                {detail.rotationJobs.map((job) => (
                  <li key={job.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <JobStatusBadge status={job.status} />
                      <span className="font-mono text-[9.5px] text-white/35">{relativeTime(job.requestedAt)}</span>
                    </div>
                    <p className="mt-1.5 text-[11px] leading-snug text-white/70">{job.reason}</p>
                    <p className="mt-1 text-[10px] text-white/40">{job.validationDetail}</p>
                    {job.allowedTransitions.length ? (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {job.allowedTransitions.map((target) => (
                          <ActionButton
                            key={target}
                            label={target.replace(/-/g, ' ')}
                            tone={target === 'failed' || target === 'cancelled' ? 'critical' : 'info'}
                            busy={actions.pending === `job:${job.id}`}
                            onClick={() => void runAction(actions.transitionJob(job.id, target))}
                          />
                        ))}
                      </div>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : (
              <PanelEmpty>No rotation work order has been raised against this key.</PanelEmpty>
            )}
          </Panel>

          {/* ---- Evidence -------------------------------------------- */}
          <Panel>
            <SectionLabel icon={Activity} hint="Every statement on this page traces to one of these rows.">
              Evidence
            </SectionLabel>
            <EvidenceList evidence={key.evidence} limit={8} />
          </Panel>

          {/* ---- Audit trail ----------------------------------------- */}
          <Panel>
            <SectionLabel icon={FileClock} meta={<span>{fmtNumber(key.auditTrail.length)}</span>}>
              Audit trail
            </SectionLabel>
            {key.auditTrail.length ? (
              <ol className="space-y-1.5">
                {key.auditTrail.map((entry) => (
                  <li key={entry.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono text-[10px] text-cyan-300">{entry.eventType}</span>
                      <span className="font-mono text-[9.5px] text-white/35" title={absoluteTime(entry.at)}>{relativeTime(entry.at)}</span>
                    </div>
                    <p className="mt-1 text-[11px] leading-snug text-white/70">{entry.summary}</p>
                    <p className="mt-0.5 text-[9.5px] text-white/30">Actor: {entry.actor}</p>
                  </li>
                ))}
              </ol>
            ) : (
              <PanelEmpty>
                No audit record exists for this key yet. Operations performed through QKMS are recorded here automatically.
              </PanelEmpty>
            )}
          </Panel>

          <Field label="Data freshness">
            Last observed {relativeTime(key.lastObservedAt)} · policy evaluated {relativeTime(key.lastPolicyEvaluationAt)}
          </Field>
        </>
      ) : null}
    </Drawer>
  );
}
