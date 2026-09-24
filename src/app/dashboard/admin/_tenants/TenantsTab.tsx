import { useEffect, useState } from 'react'
import { AlertTriangle, Building2, CheckCircle2, Eye, Gauge, MoreHorizontal, PauseCircle, Pencil, Plus, RefreshCw, Search, ShieldCheck, Trash2, UserX, Users, X } from 'lucide-react'
import type { AdminDashboard } from '@/hooks/use-admin-dashboard'
import type { CatalogTenant } from '@/lib/admin/tenant-directory'
import { ActionMenu, Chip, Dialog, Field, SelectField, formatCount, formatDate, timeAgo, useNow, type MenuEntry, type Tone } from '../_shared/primitives'
import { ConfirmDialog, ConsoleHeader, EmptyState, ErrorBanner, IntegrityStrip, Kpi, KpiGrid, Pager, ProvenanceNote } from '../_shared/console'

const ICON = 'h-4 w-4'
const STATUS_TONE: Record<CatalogTenant['status'], Tone> = { active: 'ok', suspended: 'warn', disabled: 'bad' }

type TenantDialog =
  | { kind: 'create' }
  | { kind: 'edit'; tenant: CatalogTenant }
  | { kind: 'suspend'; tenant: CatalogTenant }
  | { kind: 'restore'; tenant: CatalogTenant }
  | { kind: 'delete'; tenant: CatalogTenant }

function TenantFormDialog({ admin, tenant, onClose }: { admin: AdminDashboard; tenant?: CatalogTenant; onClose: () => void }) {
  const editing = Boolean(tenant)
  const [form, setForm] = useState({
    name: tenant?.name || '',
    slug: tenant?.slug || '',
    ownerUserId: tenant?.owner?.id || '',
    quotaUsers: tenant?.quotaUsers ? String(tenant.quotaUsers) : '',
    quotaStorageGb: tenant?.quotaStorageGb ? String(tenant.quotaStorageGb) : '',
    domain: tenant?.domain || '',
    region: tenant?.region || '',
  })
  const [users, setUsers] = useState<Array<{ id: string; email: string; name: string }>>([])
  const [error, setError] = useState<string | null>(null)
  const busy = admin.mutating === (tenant ? `tenant:${tenant.id}` : 'create-tenant')
  const autoSlug = form.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64)

  useEffect(() => {
    let active = true
    admin.loadUserOptions().then((rows) => active && setUsers(rows)).catch(() => undefined)
    return () => {
      active = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const submit = async () => {
    setError(null)
    // Quotas are NOT NULL in the schema: blank on create = the database default; an existing quota can change but not be cleared.
    if (editing && (!form.quotaUsers || !form.quotaStorageGb)) {
      setError('Both quotas are required — a tenant cannot be set to unlimited.')
      return
    }
    const payload: Record<string, unknown> = {
      name: form.name,
      slug: form.slug || autoSlug,
      ownerUserId: form.ownerUserId || null,
      quotaUsers: form.quotaUsers || undefined,
      quotaStorageGb: form.quotaStorageGb || undefined,
      domain: form.domain,
      region: form.region,
    }
    if (tenant) {
      // PATCH only what changed, so the audit trail names the fields actually edited.
      const before: Record<string, unknown> = {
        name: tenant.name, slug: tenant.slug || '', ownerUserId: tenant.owner?.id || null,
        quotaUsers: tenant.quotaUsers ? String(tenant.quotaUsers) : undefined, quotaStorageGb: tenant.quotaStorageGb ? String(tenant.quotaStorageGb) : undefined,
        domain: tenant.domain || '', region: tenant.region || '',
      }
      for (const key of Object.keys(payload)) if (payload[key] === before[key]) delete payload[key]
      if (!Object.keys(payload).length) {
        onClose()
        return
      }
    }
    const outcome = tenant ? await admin.updateTenant(tenant.id, payload) : await admin.createTenant(payload)
    if (outcome.ok) onClose()
    else setError(outcome.error)
  }

  return (
    <Dialog
      title={editing ? `Edit tenant — ${tenant!.name}` : 'Add tenant'}
      subtitle={editing ? `${formatCount(tenant!.members)} member(s)` : 'An organization that groups accounts. Assign members from the Users tab.'}
      icon={<Building2 className="h-5 w-5 qgu-tone-info" />}
      onClose={onClose}
      busy={busy}
      width={620}
      footer={(
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="qgu-btn qgu-btn--primary" onClick={() => void submit()} disabled={busy || !form.name.trim()}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            {editing ? 'Save tenant' : 'Create tenant'}
          </button>
        </>
      )}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Organization name" htmlFor="qgu-tenant-name">
          <input id="qgu-tenant-name" className="qgu-field" maxLength={120} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Acme Corporation" />
        </Field>
        <Field label="Slug" htmlFor="qgu-tenant-slug" hint="Unique; lowercase letters, digits and hyphens.">
          <input id="qgu-tenant-slug" className="qgu-field font-mono" value={form.slug || (editing ? '' : autoSlug)} onChange={(event) => setForm({ ...form, slug: event.target.value.toLowerCase() })} />
        </Field>
      </div>
      <Field label="Owner account" htmlFor="qgu-tenant-owner" hint="The accountable contact for this organization (optional).">
        <SelectField id="qgu-tenant-owner" label="Owner account" value={form.ownerUserId} onChange={(value) => setForm({ ...form, ownerUserId: value })}>
          <option value="">No owner</option>
          {users.map((user) => <option key={user.id} value={user.id}>{user.name ? `${user.name} — ${user.email}` : user.email}</option>)}
        </SelectField>
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="User quota" htmlFor="qgu-tenant-quota" hint={editing ? 'Enforced: Users refuses to add a member beyond it. Cannot go below the current member count.' : 'Enforced: Users refuses to add a member beyond it. Blank = the database default.'}>
          <input id="qgu-tenant-quota" className="qgu-field" type="number" min={1} value={form.quotaUsers} onChange={(event) => setForm({ ...form, quotaUsers: event.target.value })} />
        </Field>
        <Field label="Storage quota (GB)" htmlFor="qgu-tenant-storage" hint={editing ? 'Recorded only — storage use is not metered per tenant yet.' : 'Recorded only — storage use is not metered per tenant yet. Blank = the database default.'}>
          <input id="qgu-tenant-storage" className="qgu-field" type="number" min={1} value={form.quotaStorageGb} onChange={(event) => setForm({ ...form, quotaStorageGb: event.target.value })} />
        </Field>
        <Field label="Primary domain" htmlFor="qgu-tenant-domain">
          <input id="qgu-tenant-domain" className="qgu-field" value={form.domain} onChange={(event) => setForm({ ...form, domain: event.target.value })} placeholder="optional, e.g. acme.com" />
        </Field>
        <Field label="Region" htmlFor="qgu-tenant-region">
          <input id="qgu-tenant-region" className="qgu-field" value={form.region} onChange={(event) => setForm({ ...form, region: event.target.value })} placeholder="optional, e.g. eu-west-2" />
        </Field>
      </div>
      {error && <ErrorBanner message={error} />}
    </Dialog>
  )
}

export function TenantsTab({ admin, onViewMembers }: { admin: AdminDashboard; onViewMembers: (tenantId: string) => void }) {
  const resource = admin.tenants
  const { data, query } = resource
  const [dialog, setDialog] = useState<TenantDialog | null>(null)
  const [applyToMembers, setApplyToMembers] = useState(false)
  const now = useNow()
  const { ensureLoaded } = resource
  useEffect(() => { ensureLoaded() }, [ensureLoaded])
  const stats = data?.stats
  const activeFilters = (['status', 'quota'] as const).filter((key) => query[key] !== 'all').length + (query.search ? 1 : 0)

  const menuFor = (tenant: CatalogTenant): MenuEntry[] => [
    { kind: 'item', label: 'View members in Users', description: `${formatCount(tenant.members)} member(s)`, icon: <Eye className={ICON} />, disabled: tenant.members === 0, disabledReason: 'No members yet', onSelect: () => onViewMembers(tenant.id) },
    { kind: 'item', label: 'Edit…', icon: <Pencil className={ICON} />, onSelect: () => setDialog({ kind: 'edit', tenant }) },
    tenant.status === 'active'
      ? { kind: 'item', label: 'Suspend…', description: 'Optionally block its members', icon: <PauseCircle className={ICON} />, onSelect: () => { setApplyToMembers(false); setDialog({ kind: 'suspend', tenant }) } }
      : { kind: 'item', label: 'Restore…', icon: <CheckCircle2 className={ICON} />, onSelect: () => { setApplyToMembers(tenant.suspendedMemberIds.length > 0); setDialog({ kind: 'restore', tenant }) } },
    { kind: 'separator' },
    { kind: 'item', label: 'Delete tenant…', danger: true, icon: <Trash2 className={ICON} />, disabled: tenant.members > 0, disabledReason: `Has ${tenant.members} member(s) — move them first`, onSelect: () => setDialog({ kind: 'delete', tenant }) },
  ]

  return (
    <div className="qgu space-y-5">
      <ConsoleHeader
        title="Tenants"
        description="Organizations that group accounts. Members, plan access, MFA and sessions are read from the Users directory."
        admin={admin}
        updatedAt={data?.generatedAt}
        actions={(
          <>
            <button type="button" className="qgu-btn" onClick={() => void resource.refresh()} disabled={resource.loading}>
              <RefreshCw className={`h-4 w-4 ${resource.loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button type="button" className="qgu-btn qgu-btn--primary" onClick={() => setDialog({ kind: 'create' })}>
              <Plus className="h-4 w-4" />
              Add tenant
            </button>
          </>
        )}
      />

      <KpiGrid loading={!stats}>
        {stats && (
          <>
            <Kpi icon={<Building2 className="h-4 w-4" />} label="Tenants" value={formatCount(stats.total)} sub={`${stats.byStatus.active} active · ${stats.byStatus.suspended + stats.byStatus.disabled} suspended`} onClick={resource.resetQuery} active={activeFilters === 0} />
            <Kpi icon={<Users className="h-4 w-4" />} label="Members" value={formatCount(stats.members)} sub="accounts assigned to a tenant" />
            <Kpi icon={<UserX className="h-4 w-4" />} label="Unassigned users" value={formatCount(stats.unassignedUsers)} sub="accounts in no tenant" />
            <Kpi icon={<PauseCircle className="h-4 w-4" />} label="Suspended" value={formatCount(stats.byStatus.suspended + stats.byStatus.disabled)} sub="tenant status only" onClick={() => resource.setQuery({ status: query.status === 'suspended' ? 'all' : 'suspended' })} active={query.status === 'suspended'} />
            <Kpi icon={<Gauge className="h-4 w-4" />} label="Over quota" value={formatCount(stats.overQuota)} sub="more members than allowed" subTone={stats.overQuota ? 'bad' : undefined} onClick={() => resource.setQuery({ quota: query.quota === 'over' ? 'all' : 'over' })} active={query.quota === 'over'} />
            <Kpi icon={<ShieldCheck className="h-4 w-4" />} label="Without owner" value={formatCount(stats.withoutOwner)} sub="no accountable contact" subTone={stats.withoutOwner ? 'warn' : undefined} onClick={() => resource.setQuery({ quota: query.quota === 'no_owner' ? 'all' : 'no_owner' })} active={query.quota === 'no_owner'} />
          </>
        )}
      </KpiGrid>

      <IntegrityStrip checks={data?.integrity} />

      <div className="qgu-panel space-y-3 p-4">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_repeat(2,minmax(0,200px))]">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 qgu-muted" aria-hidden />
            <input className="qgu-field pl-9 pr-9" aria-label="Search tenants" placeholder="Search name, slug, domain, owner or ID" value={query.search} onChange={(event) => resource.setQuery({ search: event.target.value })} />
            {query.search && <button type="button" className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 qgu-muted" aria-label="Clear search" onClick={() => resource.setQuery({ search: '' })}><X className="h-4 w-4" /></button>}
          </div>
          <SelectField label="Status filter" value={query.status} onChange={(value) => resource.setQuery({ status: value })}>
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="suspended">Suspended</option>
            <option value="disabled">Disabled</option>
          </SelectField>
          <SelectField label="Attention filter" value={query.quota} onChange={(value) => resource.setQuery({ quota: value })}>
            <option value="all">Any</option>
            <option value="over">Over user quota</option>
            <option value="no_owner">Without owner</option>
          </SelectField>
        </div>
      </div>

      <div className="qgu-panel overflow-hidden">
        {resource.error && <div className="m-4"><ErrorBanner message={`Tenants could not be loaded: ${resource.error}`} onRetry={() => void resource.refresh()} /></div>}
        <div className="max-h-[70vh] overflow-auto">
          <table className="qgu-table min-w-[1100px]">
            <thead>
              <tr>
                <th scope="col">Tenant</th>
                <th scope="col">Owner</th>
                <th scope="col">Members / quota</th>
                <th scope="col">Access &amp; MFA</th>
                <th scope="col" className="text-right">Live sessions</th>
                <th scope="col">Status</th>
                <th scope="col">Last member activity</th>
                <th scope="col" className="text-right"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody aria-busy={resource.loading}>
              {!data && !resource.error ? (
                Array.from({ length: 3 }, (_, index) => <tr key={index}><td colSpan={8}><div className="qgu-skeleton h-10" /></td></tr>)
              ) : data && data.tenants.length === 0 ? (
                <tr>
                  <td colSpan={8}>
                    {activeFilters ? (
                      <EmptyState icon={<Building2 className="h-6 w-6" />} title="No tenants match" body="Widen or clear the filters." action={<button type="button" className="qgu-btn" onClick={resource.resetQuery}>Clear filters</button>} />
                    ) : (
                      <EmptyState icon={<Building2 className="h-6 w-6" />} title="No tenants yet" body="Create an organization, then assign accounts to it from the Users tab (Assign tenant). Every account is currently unassigned." action={<button type="button" className="qgu-btn qgu-btn--primary" onClick={() => setDialog({ kind: 'create' })}><Plus className="h-4 w-4" />Add tenant</button>} />
                    )}
                  </td>
                </tr>
              ) : data?.tenants.map((tenant) => (
                <tr key={tenant.id}>
                  <td>
                    <div className="max-w-[280px]">
                      <div className="font-bold qgu-strong">{tenant.name}</div>
                      <div className="font-mono text-[11px] qgu-muted">{tenant.slug}</div>
                      {(tenant.domain || tenant.region) && <div className="mt-0.5 text-[11px] qgu-soft">{[tenant.domain, tenant.region].filter(Boolean).join(' · ')}</div>}
                    </div>
                  </td>
                  <td className="text-xs">
                    {tenant.owner ? <span className="qgu-soft">{tenant.owner.email}</span> : tenant.ownerMissing ? <Chip tone="warn" icon={<AlertTriangle className="h-3.5 w-3.5" />}>Owner account deleted</Chip> : <span className="qgu-muted">No owner</span>}
                  </td>
                  <td>
                    <div className="font-mono font-black qgu-strong qgu-num">{formatCount(tenant.members)}{tenant.quotaUsers ? <span className="qgu-muted"> / {formatCount(tenant.quotaUsers)}</span> : ''}</div>
                    {tenant.quotaUsers ? (
                      <div className="mt-1 h-1.5 w-28 overflow-hidden rounded-full qgu-inset">
                        <div className="h-full rounded-full" style={{ width: `${Math.min(100, tenant.quotaUsedPercent || 0)}%`, background: tenant.overQuota ? 'var(--qgu-bad-text)' : 'var(--qgu-accent)' }} />
                      </div>
                    ) : <div className="text-[11px] qgu-muted">no quota</div>}
                    {tenant.membershipDrift > 0 && <div className="mt-1"><Chip tone="warn">{tenant.membershipDrift} membership drift</Chip></div>}
                  </td>
                  <td className="text-xs qgu-soft">
                    <div>{formatCount(tenant.membersWithAccess)} with plan access</div>
                    <div>{formatCount(tenant.membersMfa)} MFA enrolled</div>
                    {tenant.membersBlocked > 0 && <div className="qgu-tone-warn">{formatCount(tenant.membersBlocked)} blocked</div>}
                  </td>
                  <td className="text-right font-mono font-bold qgu-num">{tenant.liveSessions === null ? <span className="qgu-muted">—</span> : formatCount(tenant.liveSessions)}</td>
                  <td>
                    <Chip tone={STATUS_TONE[tenant.status]}>{tenant.status}</Chip>
                    {tenant.suspendedMemberIds.length > 0 && <div className="mt-1 text-[11px] qgu-muted">{tenant.suspendedMemberIds.length} member(s) suspended with it</div>}
                  </td>
                  <td className="text-xs qgu-soft">{tenant.lastActivityAt ? <span title={formatDate(tenant.lastActivityAt)}>{timeAgo(tenant.lastActivityAt, now)}</span> : <span className="qgu-muted">No member activity</span>}</td>
                  <td className="text-right">
                    {admin.mutating === `tenant:${tenant.id}` ? <RefreshCw className="ml-auto h-4 w-4 animate-spin qgu-tone-info" /> : <ActionMenu label={`Actions for tenant ${tenant.name}`} trigger={<MoreHorizontal className="h-4 w-4" />} entries={menuFor(tenant)} />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pager pagination={data?.pagination} noun="tenants" loading={resource.loading} onPage={(page) => void resource.refresh(page)} />
      </div>

      <ProvenanceNote>Members are accounts whose profile names this tenant (profiles.tenant_id); plan access, MFA and sessions are the same measurements the Users tab shows. The tenant plan label is not an entitlement — access follows each member&apos;s own subscription.</ProvenanceNote>

      {dialog?.kind === 'create' && <TenantFormDialog admin={admin} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'edit' && <TenantFormDialog admin={admin} tenant={dialog.tenant} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'suspend' && (
        <ConfirmDialog
          title={`Suspend tenant — ${dialog.tenant.name}`}
          icon={<PauseCircle className="h-5 w-5 qgu-tone-warn" />}
          effects={[
            'The tenant is marked suspended.',
            applyToMembers
              ? `${dialog.tenant.members} member account(s) (owner excluded) are suspended: sign-in blocked, every session ended. Restoring the tenant restores exactly these accounts.`
              : 'Members keep their own account status — a tenant flag alone does not block sign-in.',
          ]}
          extra={dialog.tenant.members > 0 ? (
            <label className="flex items-start gap-2 text-sm qgu-soft">
              <input type="checkbox" className="mt-1" checked={applyToMembers} onChange={(event) => setApplyToMembers(event.target.checked)} />
              <span>Also suspend its {dialog.tenant.members} member account(s)</span>
            </label>
          ) : undefined}
          reasonLabel="Reason (recorded in the audit trail)"
          confirmLabel="Suspend tenant"
          danger
          busy={admin.mutating === `tenant:${dialog.tenant.id}`}
          onClose={() => setDialog(null)}
          onConfirm={({ reason }) => admin.tenantAction(dialog.tenant.id, 'suspend', { reason, applyToMembers })}
        />
      )}
      {dialog?.kind === 'restore' && (
        <ConfirmDialog
          title={`Restore tenant — ${dialog.tenant.name}`}
          icon={<CheckCircle2 className="h-5 w-5 qgu-tone-ok" />}
          effects={[
            'The tenant is marked active.',
            dialog.tenant.suspendedMemberIds.length
              ? applyToMembers
                ? `The ${dialog.tenant.suspendedMemberIds.length} member account(s) suspended with the tenant are restored (others are untouched).`
                : 'Member accounts stay suspended until restored in Users.'
              : 'No member accounts were suspended with this tenant.',
          ]}
          extra={dialog.tenant.suspendedMemberIds.length > 0 ? (
            <label className="flex items-start gap-2 text-sm qgu-soft">
              <input type="checkbox" className="mt-1" checked={applyToMembers} onChange={(event) => setApplyToMembers(event.target.checked)} />
              <span>Restore the {dialog.tenant.suspendedMemberIds.length} member account(s) suspended with it</span>
            </label>
          ) : undefined}
          confirmLabel="Restore tenant"
          busy={admin.mutating === `tenant:${dialog.tenant.id}`}
          onClose={() => setDialog(null)}
          onConfirm={() => admin.tenantAction(dialog.tenant.id, 'restore', { applyToMembers })}
        />
      )}
      {dialog?.kind === 'delete' && (
        <ConfirmDialog
          title={`Delete tenant — ${dialog.tenant.name}`}
          icon={<Trash2 className="h-5 w-5 qgu-tone-bad" />}
          effects={['Removes the organization permanently.', 'It has no members, so no account changes.', 'The deletion is recorded in the admin audit trail.']}
          confirmLabel="Delete tenant"
          danger
          typeToConfirm={dialog.tenant.name}
          busy={admin.mutating === `tenant:${dialog.tenant.id}`}
          onClose={() => setDialog(null)}
          onConfirm={({ typed }) => admin.tenantAction(dialog.tenant.id, 'delete', { confirmName: typed })}
        />
      )}
    </div>
  )
}
