import { type ReactNode, useEffect, useState } from 'react'
import { BadgeCheck, CheckCircle2, CircleDashed, Copy, Download, FileCheck2, FileWarning, Fingerprint, Gavel, MoreHorizontal, Pencil, Plus, Power, RefreshCw, ScrollText, ShieldCheck, Trash2, XCircle } from 'lucide-react'
import type { AdminDashboard } from '@/hooks/use-admin-dashboard'
import type { GovernancePolicy, VerificationState } from '@/lib/admin/governance'
import { ActionMenu, Chip, Dialog, Field, SelectField, formatCount, formatDate, formatDateTime, timeAgo, useNow, type MenuEntry, type Tone } from '../_shared/primitives'
import { ConfirmDialog, ConsoleHeader, EmptyState, ErrorBanner, IntegrityStrip, Kpi, KpiGrid, Panel, ProvenanceNote } from '../_shared/console'

const ICON = 'h-4 w-4'

const VERIFICATION_META: Record<VerificationState, { label: string; tone: Tone; icon: ReactNode }> = {
  met: { label: 'Met', tone: 'ok', icon: <CheckCircle2 className="h-3.5 w-3.5" /> },
  not_met: { label: 'Not met', tone: 'bad', icon: <XCircle className="h-3.5 w-3.5" /> },
  enforced_by_platform: { label: 'Enforced by platform', tone: 'ok', icon: <ShieldCheck className="h-3.5 w-3.5" /> },
  attested: { label: 'Attested', tone: 'neutral', icon: <ScrollText className="h-3.5 w-3.5" /> },
  disabled: { label: 'Disabled', tone: 'neutral', icon: <Power className="h-3.5 w-3.5" /> },
  unknown: { label: 'Not measured', tone: 'warn', icon: <CircleDashed className="h-3.5 w-3.5" /> },
}

const CATEGORIES = ['access', 'identity', 'data', 'retention', 'billing', 'operations']

type GovernanceDialog =
  | { kind: 'create' }
  | { kind: 'edit'; policy: GovernancePolicy }
  | { kind: 'toggle'; policy: GovernancePolicy }
  | { kind: 'delete'; policy: GovernancePolicy }
  | { kind: 'evidence' }

function PolicyDialog({ admin, policy, onClose }: { admin: AdminDashboard; policy?: GovernancePolicy; onClose: () => void }) {
  const editing = Boolean(policy)
  const [form, setForm] = useState({
    name: policy?.name || '',
    key: policy?.key || '',
    category: policy?.category || 'operations',
    enforcementLevel: policy?.enforcementLevel || 'monitor',
    description: policy?.description || '',
  })
  const [error, setError] = useState<string | null>(null)
  const busy = admin.mutating === (policy ? `policy:${policy.id}` : 'create-policy')
  const autoKey = form.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64)
  const submit = async () => {
    setError(null)
    const outcome = policy
      ? await admin.updatePolicy(policy.id, { name: form.name, category: form.category, enforcementLevel: form.enforcementLevel, description: form.description })
      : await admin.createPolicy({ name: form.name, key: form.key || autoKey, category: form.category, enforcementLevel: form.enforcementLevel, description: form.description, status: 'enabled' })
    if (outcome.ok) onClose()
    else setError(outcome.error)
  }
  return (
    <Dialog
      title={editing ? `Edit policy — ${policy!.name}` : 'Add policy'}
      subtitle={editing ? `Key ${policy!.key}` : 'A governance statement. Without an automated check it is recorded as an attestation.'}
      icon={<Gavel className="h-5 w-5 qgu-tone-violet" />}
      onClose={onClose}
      busy={busy}
      width={600}
      footer={(
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="qgu-btn qgu-btn--primary" onClick={() => void submit()} disabled={busy || !form.name.trim()}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            {editing ? 'Save policy' : 'Add policy'}
          </button>
        </>
      )}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" htmlFor="qgu-policy-name">
          <input id="qgu-policy-name" className="qgu-field" maxLength={120} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
        </Field>
        <Field label="Key" htmlFor="qgu-policy-key" hint={editing ? 'Keys are permanent.' : 'Lowercase letters, digits and hyphens.'}>
          <input id="qgu-policy-key" className="qgu-field font-mono" disabled={editing} value={editing ? policy!.key : form.key || autoKey} onChange={(event) => setForm({ ...form, key: event.target.value.toLowerCase() })} />
        </Field>
        <Field label="Category" htmlFor="qgu-policy-category">
          <SelectField id="qgu-policy-category" label="Category" value={form.category} onChange={(value) => setForm({ ...form, category: value })}>
            {CATEGORIES.map((category) => <option key={category} value={category}>{category}</option>)}
          </SelectField>
        </Field>
        <Field label="Enforcement level" htmlFor="qgu-policy-level" hint="What the policy intends — verification (below) reports what is actually true.">
          <SelectField id="qgu-policy-level" label="Enforcement level" value={form.enforcementLevel} onChange={(value) => setForm({ ...form, enforcementLevel: value })}>
            <option value="enforce">Enforce</option>
            <option value="monitor">Monitor</option>
            <option value="advisory">Advisory</option>
          </SelectField>
        </Field>
      </div>
      <Field label="Description" htmlFor="qgu-policy-description">
        <textarea id="qgu-policy-description" className="qgu-field" maxLength={1000} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} />
      </Field>
      {error && <ErrorBanner message={error} />}
    </Dialog>
  )
}

function EvidenceDialog({ admin, onClose }: { admin: AdminDashboard; onClose: () => void }) {
  const [title, setTitle] = useState(`Administration evidence — ${new Date().toISOString().slice(0, 10)}`)
  return (
    <ConfirmDialog
      title="Generate evidence package"
      icon={<FileCheck2 className="h-5 w-5 qgu-tone-ok" />}
      effects={[
        'The server captures the measured state now: users (auth parity, status, MFA, sessions), roles, tenants, billing, the 30-day security controls, every policy’s verification and the audit-trail extent.',
        'The snapshot is fingerprinted with SHA3-256 over canonical JSON and stored with its fingerprint.',
        'Anyone can re-verify it later: the download includes the snapshot and a freshly recomputed hash.',
      ]}
      extra={(
        <Field label="Title" htmlFor="qgu-evidence-title">
          <input id="qgu-evidence-title" className="qgu-field" maxLength={160} value={title} onChange={(event) => setTitle(event.target.value)} />
        </Field>
      )}
      confirmLabel="Generate"
      busy={admin.mutating === 'generate-evidence'}
      onClose={onClose}
      onConfirm={() => admin.generateEvidence(title)}
    />
  )
}

export function GovernanceTab({ admin }: { admin: AdminDashboard }) {
  const resource = admin.governance
  const { data } = resource
  const [dialog, setDialog] = useState<GovernanceDialog | null>(null)
  const now = useNow()
  const { ensureLoaded } = resource
  useEffect(() => { ensureLoaded() }, [ensureLoaded])
  const stats = data?.stats

  const menuFor = (policy: GovernancePolicy): MenuEntry[] => [
    { kind: 'item', label: 'Edit…', icon: <Pencil className={ICON} />, onSelect: () => setDialog({ kind: 'edit', policy }) },
    { kind: 'item', label: policy.status === 'enabled' ? 'Disable…' : 'Enable…', icon: <Power className={ICON} />, onSelect: () => setDialog({ kind: 'toggle', policy }) },
    { kind: 'separator' },
    { kind: 'item', label: 'Delete policy…', danger: true, icon: <Trash2 className={ICON} />, disabled: policy.builtin, disabledReason: 'Platform-verified policies can be disabled, not deleted', onSelect: () => setDialog({ kind: 'delete', policy }) },
  ]

  return (
    <div className="qgu space-y-5">
      <ConsoleHeader
        title="Governance"
        description="Policies checked against measured evidence, and evidence packages you can independently verify."
        admin={admin}
        updatedAt={data?.generatedAt}
        actions={(
          <>
            <button type="button" className="qgu-btn" onClick={() => void resource.refresh()} disabled={resource.loading}>
              <RefreshCw className={`h-4 w-4 ${resource.loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button type="button" className="qgu-btn" onClick={() => setDialog({ kind: 'create' })}>
              <Plus className="h-4 w-4" />
              Add policy
            </button>
            <button type="button" className="qgu-btn qgu-btn--primary" onClick={() => setDialog({ kind: 'evidence' })}>
              <FileCheck2 className="h-4 w-4" />
              Generate evidence
            </button>
          </>
        )}
      />

      {resource.error && <ErrorBanner message={`Governance could not be loaded: ${resource.error}`} onRetry={() => void resource.refresh()} />}

      <KpiGrid loading={!stats}>
        {stats && (
          <>
            <Kpi icon={<Gavel className="h-4 w-4" />} label="Policies" value={formatCount(stats.policies)} sub={`${stats.enabled} enabled`} />
            <Kpi icon={<BadgeCheck className="h-4 w-4" />} label="Met / enforced" value={formatCount(stats.met + stats.enforcedByPlatform)} sub={`${stats.met} measured met · ${stats.enforcedByPlatform} platform-enforced`} subTone="ok" />
            <Kpi icon={<XCircle className="h-4 w-4" />} label="Not met" value={formatCount(stats.notMet)} sub="evidence contradicts the policy" subTone={stats.notMet ? 'bad' : undefined} />
            <Kpi icon={<ScrollText className="h-4 w-4" />} label="Attested" value={formatCount(stats.attested)} sub="no automated check exists" />
            <Kpi icon={<Fingerprint className="h-4 w-4" />} label="Evidence packages" value={formatCount(stats.evidence)} sub={stats.latestEvidenceAt ? `latest ${timeAgo(stats.latestEvidenceAt, now)} · ${stats.evidenceIntact} verified` : 'none generated yet'} />
            <Kpi icon={<ScrollText className="h-4 w-4" />} label="Audit records" value={formatCount(stats.auditRecords)} sub={stats.oldestAuditAt ? `retained since ${formatDate(stats.oldestAuditAt)}` : 'none'} />
          </>
        )}
      </KpiGrid>

      <IntegrityStrip checks={data?.integrity} />

      <Panel title="Policies">
        {!data ? <div className="qgu-skeleton h-40" /> : data.policies.length === 0 ? (
          <EmptyState icon={<Gavel className="h-6 w-6" />} title="No policies" action={<button type="button" className="qgu-btn" onClick={() => setDialog({ kind: 'create' })}><Plus className="h-4 w-4" />Add policy</button>} />
        ) : (
          <div className="overflow-auto">
            <table className="qgu-table min-w-[980px]">
              <thead><tr><th>Policy</th><th>Intent</th><th>Verification</th><th>Updated</th><th className="text-right"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {data.policies.map((policy) => {
                  const meta = VERIFICATION_META[policy.verification.state]
                  return (
                    <tr key={policy.id}>
                      <td>
                        <div className="max-w-[300px]">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-bold qgu-strong">{policy.name}</span>
                            {policy.builtin && <Chip tone="info">Platform-verified</Chip>}
                          </div>
                          <div className="font-mono text-[11px] qgu-muted">{policy.key} · {policy.category}</div>
                          {policy.description && <div className="mt-1 text-xs qgu-soft">{policy.description}</div>}
                        </div>
                      </td>
                      <td className="text-xs">
                        <Chip tone={policy.status === 'enabled' ? 'ok' : 'neutral'}>{policy.status}</Chip>
                        <div className="mt-1 qgu-muted">level: {policy.enforcementLevel}</div>
                      </td>
                      <td>
                        <div className="max-w-[420px]">
                          <Chip tone={meta.tone} icon={meta.icon}>{meta.label}</Chip>
                          <div className="mt-1 text-xs qgu-soft">{policy.verification.detail}</div>
                          {policy.verification.mechanism && <div className="mt-0.5 text-[11px] qgu-muted">How: {policy.verification.mechanism}</div>}
                        </div>
                      </td>
                      <td className="text-xs qgu-muted">{policy.updatedAt ? timeAgo(policy.updatedAt, now) : '—'}{policy.updatedBy ? <div>{policy.updatedBy}</div> : null}</td>
                      <td className="text-right">
                        {admin.mutating === `policy:${policy.id}` ? <RefreshCw className="ml-auto h-4 w-4 animate-spin qgu-tone-info" /> : <ActionMenu label={`Actions for policy ${policy.name}`} trigger={<MoreHorizontal className="h-4 w-4" />} entries={menuFor(policy)} />}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Evidence packages">
        {!data ? <div className="qgu-skeleton h-24" /> : data.evidence.length === 0 ? (
          <EmptyState icon={<Fingerprint className="h-6 w-6" />} title="No evidence packages yet" body="Generate one to capture the measured state of the platform with a verifiable SHA3-256 fingerprint — for auditors, customers or your own records." action={<button type="button" className="qgu-btn qgu-btn--primary" onClick={() => setDialog({ kind: 'evidence' })}><FileCheck2 className="h-4 w-4" />Generate evidence</button>} />
        ) : (
          <ul className="space-y-2">
            {data.evidence.map((item) => (
              <li key={item.id} className="qgu-inset grid gap-3 p-3 text-sm md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-bold qgu-strong">{item.title}</span>
                    {item.intact === true && <Chip tone="ok" icon={<Fingerprint className="h-3.5 w-3.5" />}>Fingerprint verified</Chip>}
                    {item.intact === false && <Chip tone="bad" icon={<FileWarning className="h-3.5 w-3.5" />}>Does not match its fingerprint</Chip>}
                    {item.intact === null && <Chip tone="neutral">No fingerprint (legacy)</Chip>}
                  </div>
                  <div className="mt-0.5 text-xs qgu-muted" title={formatDateTime(item.createdAt)}>{formatDate(item.createdAt)} · {item.generatedBy || 'unknown'} · {item.framework}</div>
                  {item.hash && (
                    <button type="button" className="mt-1 inline-flex max-w-full items-center gap-1.5 font-mono text-[11px] qgu-soft hover:underline" title="Copy fingerprint" onClick={() => void navigator.clipboard?.writeText(item.hash!.value).catch(() => undefined)}>
                      <span className="truncate">{item.hash.algorithm} {item.hash.value}</span>
                      <Copy className="h-3 w-3 shrink-0" />
                    </button>
                  )}
                  {item.summary && (
                    <div className="mt-1 text-xs qgu-soft">
                      {String(item.summary.users ?? '—')} users · controls {String(item.summary.controlsPassing ?? '—')}/{String(item.summary.controlsMeasured ?? '—')} passing · {String(item.summary.policiesNotMet ?? '—')} policy(ies) not met · {String(item.summary.auditRecords ?? '—')} audit records
                    </div>
                  )}
                </div>
                <button type="button" className="qgu-btn" onClick={() => void admin.downloadEvidence(item.id)} disabled={admin.mutating === `evidence:${item.id}`}>
                  <Download className="h-4 w-4" />
                  Download JSON
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <ProvenanceNote>
        Verification states come from measurements (Supabase Auth MFA factors, the admin audit trail, the owner-only API guard). A policy with no automated check is shown as Attested — never as compliant. No certification (ISO 27001, SOC 2, PCI DSS) is asserted by this console.
      </ProvenanceNote>

      {dialog?.kind === 'create' && <PolicyDialog admin={admin} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'edit' && <PolicyDialog admin={admin} policy={dialog.policy} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'evidence' && <EvidenceDialog admin={admin} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'toggle' && (
        <ConfirmDialog
          title={`${dialog.policy.status === 'enabled' ? 'Disable' : 'Enable'} policy — ${dialog.policy.name}`}
          icon={<Power className="h-5 w-5 qgu-tone-warn" />}
          effects={dialog.policy.status === 'enabled'
            ? ['The policy is no longer evaluated and shows as Disabled.', 'Recorded in the admin audit trail.']
            : ['The policy is evaluated again (verification appears immediately).']}
          confirmLabel={dialog.policy.status === 'enabled' ? 'Disable' : 'Enable'}
          busy={admin.mutating === `policy:${dialog.policy.id}`}
          onClose={() => setDialog(null)}
          onConfirm={() => admin.updatePolicy(dialog.policy.id, { status: dialog.policy.status === 'enabled' ? 'disabled' : 'enabled' })}
        />
      )}
      {dialog?.kind === 'delete' && (
        <ConfirmDialog
          title={`Delete policy — ${dialog.policy.name}`}
          icon={<Trash2 className="h-5 w-5 qgu-tone-bad" />}
          effects={['Removes the policy permanently.', 'Existing evidence packages keep the policy as it was when they were generated.']}
          confirmLabel="Delete policy"
          danger
          typeToConfirm={dialog.policy.key}
          busy={admin.mutating === `policy:${dialog.policy.id}`}
          onClose={() => setDialog(null)}
          onConfirm={({ typed }) => admin.deletePolicy(dialog.policy.id, typed)}
        />
      )}
    </div>
  )
}
