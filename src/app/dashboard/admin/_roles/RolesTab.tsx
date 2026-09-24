import { useEffect, useState } from 'react'
import { Archive, Bot, CheckCircle2, CircleSlash, Eye, Info, KeyRound, Layers, MoreHorizontal, Pencil, Plus, RefreshCw, Search, ShieldCheck, Trash2, Users, X } from 'lucide-react'
import type { AdminDashboard } from '@/hooks/use-admin-dashboard'
import type { CatalogRole } from '@/lib/admin/role-catalog'
import { ActionMenu, Chip, Dialog, Field, SelectField, formatCount, formatDate, timeAgo, useNow, type MenuEntry, type Tone } from '../_shared/primitives'
import { ConfirmDialog, ConsoleHeader, EmptyState, ErrorBanner, IntegrityStrip, Kpi, KpiGrid, Pager, ProvenanceNote } from '../_shared/console'

const ICON = 'h-4 w-4'

const TYPE_META: Record<CatalogRole['type'], { label: string; tone: Tone }> = {
  builtin: { label: 'Built-in', tone: 'violet' },
  system: { label: 'System', tone: 'info' },
  custom: { label: 'Custom', tone: 'neutral' },
  discovered: { label: 'Not in catalogue', tone: 'warn' },
}

const STATUS_TONE: Record<CatalogRole['status'], Tone> = { active: 'ok', inactive: 'warn', archived: 'neutral' }

function Capabilities({ role }: { role: CatalogRole }) {
  const caps = role.sophia.capabilities
  const items: Array<[string, boolean]> = [['Read', caps.read], ['Operate', caps.operate], ['Audit', caps.audit], ['Executive', caps.executive]]
  return (
    <div className="flex flex-col items-start gap-1.5">
      <Chip tone="info" icon={<Bot className="h-3.5 w-3.5" />} title="Sophia copilot role this maps to (api-server/copilot normalizeRole)">{role.sophia.label}</Chip>
      <div className="flex flex-wrap gap-1">
        {items.map(([label, on]) => (
          <span key={label} className={`text-[10px] font-bold ${on ? 'qgu-tone-ok' : 'qgu-muted line-through'}`} title={on ? `${label} tools allowed` : `${label} tools refused`}>{label}</span>
        ))}
      </div>
    </div>
  )
}

type RoleDialog =
  | { kind: 'create' }
  | { kind: 'edit'; role: CatalogRole }
  | { kind: 'status'; role: CatalogRole; action: 'activate' | 'deactivate' | 'archive' }
  | { kind: 'delete'; role: CatalogRole }

function RoleFormDialog({ admin, role, onClose }: { admin: AdminDashboard; role?: CatalogRole; onClose: () => void }) {
  const editing = Boolean(role)
  const [form, setForm] = useState({
    name: role?.name || '',
    key: role?.key || '',
    description: role?.description || '',
    scope: role?.scope || 'Custom',
    permissions: (role?.permissions || []).join(', '),
    tenantId: role?.tenantId || '',
    status: 'active',
  })
  const [tenants, setTenants] = useState<Array<{ id: string; name: string }>>([])
  const [error, setError] = useState<string | null>(null)
  const busy = admin.mutating === (role ? `role:${role.id}` : 'create-role')
  const derivedKey = (form.key || form.name).toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')

  useEffect(() => {
    let active = true
    admin.loadTenantOptions().then((rows) => active && setTenants(rows)).catch(() => undefined)
    return () => {
      active = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const submit = async () => {
    setError(null)
    const permissions = form.permissions.split(/[\s,]+/).filter(Boolean)
    const outcome = role && role.id
      ? await admin.updateRole(role.id, { name: form.name, description: form.description, scope: form.scope, permissions, tenantId: form.tenantId || null })
      : await admin.createRole({ name: form.name, key: derivedKey, description: form.description, scope: form.scope, permissions, tenantId: form.tenantId || null, status: form.status })
    if (outcome.ok) onClose()
    else setError(outcome.error)
  }

  return (
    <Dialog
      title={editing ? `Edit role — ${role!.name}` : 'Create role'}
      subtitle={editing ? `Key ${role!.key} · held by ${formatCount(role!.holders)} user(s)` : 'A custom access label you can assign to accounts in Users.'}
      icon={<ShieldCheck className="h-5 w-5 qgu-tone-violet" />}
      onClose={onClose}
      busy={busy}
      width={620}
      footer={(
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="qgu-btn qgu-btn--primary" onClick={() => void submit()} disabled={busy || !form.name.trim() || !derivedKey}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            {editing ? 'Save role' : 'Create role'}
          </button>
        </>
      )}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" htmlFor="qgu-role-name">
          <input id="qgu-role-name" className="qgu-field" maxLength={80} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="e.g. Security Reviewer" />
        </Field>
        <Field label="Key" htmlFor="qgu-role-key" hint={editing ? 'Keys are permanent — accounts reference them.' : 'Stored on accounts as profiles.role.'}>
          <input id="qgu-role-key" className="qgu-field font-mono" value={editing ? role!.key : derivedKey} disabled={editing} onChange={(event) => setForm({ ...form, key: event.target.value })} />
        </Field>
      </div>
      <Field label="Description" htmlFor="qgu-role-description">
        <textarea id="qgu-role-description" className="qgu-field" maxLength={500} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} />
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Scope label" htmlFor="qgu-role-scope">
          <input id="qgu-role-scope" className="qgu-field" maxLength={40} value={form.scope} onChange={(event) => setForm({ ...form, scope: event.target.value })} />
        </Field>
        <Field label="Tenant" htmlFor="qgu-role-tenant">
          <SelectField id="qgu-role-tenant" label="Tenant" value={form.tenantId} onChange={(value) => setForm({ ...form, tenantId: value })}>
            <option value="">Platform-wide</option>
            {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
          </SelectField>
        </Field>
      </div>
      <Field label="Permission patterns" htmlFor="qgu-role-perms" hint="Comma or space separated, e.g. security.read, audit.*. Recorded for governance review — per-request access is enforced by plan tier and the Sophia role mapping, not by these patterns.">
        <textarea id="qgu-role-perms" className="qgu-field font-mono text-xs" value={form.permissions} onChange={(event) => setForm({ ...form, permissions: event.target.value })} />
      </Field>
      {!editing && (
        <Field label="Initial status" htmlFor="qgu-role-status">
          <SelectField id="qgu-role-status" label="Initial status" value={form.status} onChange={(value) => setForm({ ...form, status: value })}>
            <option value="active">Active — assignable now</option>
            <option value="inactive">Inactive — draft, not assignable</option>
          </SelectField>
        </Field>
      )}
      {error && <ErrorBanner message={error} />}
    </Dialog>
  )
}

export function RolesTab({ admin, onViewHolders }: { admin: AdminDashboard; onViewHolders: (roleKey: string) => void }) {
  const resource = admin.roles
  const { data, query } = resource
  const [dialog, setDialog] = useState<RoleDialog | null>(null)
  const now = useNow()
  const { ensureLoaded } = resource
  useEffect(() => { ensureLoaded() }, [ensureLoaded])
  const stats = data?.stats
  const activeFilters = (['type', 'status', 'usage'] as const).filter((key) => query[key] !== 'all').length + (query.search ? 1 : 0)

  const menuFor = (role: CatalogRole): MenuEntry[] => {
    const protectedReason = role.type === 'builtin' ? 'Built-in roles are fixed' : role.type === 'discovered' ? 'Add it to the catalogue first (create a role with this key)' : 'System roles are protected'
    const entries: MenuEntry[] = [
      { kind: 'item', label: 'View holders in Users', description: `${formatCount(role.holders)} account(s)`, icon: <Eye className={ICON} />, disabled: role.holders === 0, disabledReason: 'Nobody holds this role', onSelect: () => onViewHolders(role.key) },
      { kind: 'separator' },
      { kind: 'item', label: 'Edit…', icon: <Pencil className={ICON} />, disabled: role.protected || !role.id, disabledReason: protectedReason, onSelect: () => setDialog({ kind: 'edit', role }) },
    ]
    if (role.status !== 'active') entries.push({ kind: 'item', label: 'Activate…', description: 'Assignable again', icon: <CheckCircle2 className={ICON} />, disabled: role.protected || !role.id, disabledReason: protectedReason, onSelect: () => setDialog({ kind: 'status', role, action: 'activate' }) })
    if (role.status === 'active') entries.push({ kind: 'item', label: 'Deactivate…', description: 'Stop new assignments', icon: <CircleSlash className={ICON} />, disabled: role.protected || !role.id, disabledReason: protectedReason, onSelect: () => setDialog({ kind: 'status', role, action: 'deactivate' }) })
    if (role.status !== 'archived') entries.push({ kind: 'item', label: 'Archive…', icon: <Archive className={ICON} />, disabled: role.protected || !role.id, disabledReason: protectedReason, onSelect: () => setDialog({ kind: 'status', role, action: 'archive' }) })
    entries.push({ kind: 'separator' }, {
      kind: 'item', label: 'Delete role…', danger: true, icon: <Trash2 className={ICON} />,
      disabled: role.protected || !role.id || role.holders > 0,
      disabledReason: role.holders > 0 ? `Held by ${role.holders} user(s) — reassign them first` : protectedReason,
      onSelect: () => setDialog({ kind: 'delete', role }),
    })
    return entries
  }

  return (
    <div className="qgu space-y-5">
      <ConsoleHeader
        title="Roles"
        description="Access roles held by accounts, who holds them, and what each one actually changes on the platform."
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
              Create role
            </button>
          </>
        )}
      />

      <KpiGrid loading={!stats} count={5}>
        {stats && (
          <>
            <Kpi icon={<Layers className="h-4 w-4" />} label="Roles" value={formatCount(stats.total)} sub={`${stats.byType.builtin} built-in · ${stats.byType.system} system · ${stats.byType.custom} custom`} onClick={resource.resetQuery} active={activeFilters === 0} />
            <Kpi icon={<Users className="h-4 w-4" />} label="Roles in use" value={formatCount(stats.inUse)} sub={`covering ${formatCount(stats.usersCovered)} of ${formatCount(stats.totalUsers)} users`} onClick={() => resource.setQuery({ usage: query.usage === 'in_use' ? 'all' : 'in_use' })} active={query.usage === 'in_use'} />
            <Kpi icon={<KeyRound className="h-4 w-4" />} label="Unassigned custom" value={formatCount(stats.unassignedCustom)} sub="custom roles nobody holds" onClick={() => resource.setQuery({ usage: query.usage === 'unassigned' ? 'all' : 'unassigned', type: 'custom' })} active={query.usage === 'unassigned'} />
            <Kpi icon={<CircleSlash className="h-4 w-4" />} label="Inactive / archived" value={formatCount(stats.byStatus.inactive + stats.byStatus.archived)} sub={stats.inactiveButAssigned ? `${stats.inactiveButAssigned} still assigned` : 'none still assigned'} subTone={stats.inactiveButAssigned ? 'warn' : undefined} onClick={() => resource.setQuery({ status: query.status === 'inactive' ? 'all' : 'inactive' })} active={query.status === 'inactive'} />
            <Kpi icon={<Info className="h-4 w-4" />} label="Not in catalogue" value={formatCount(stats.byType.discovered)} sub={stats.byType.discovered ? 'held by users, undefined here' : 'every held role is defined'} subTone={stats.byType.discovered ? 'bad' : 'ok'} />
          </>
        )}
      </KpiGrid>

      <IntegrityStrip checks={data?.integrity} />

      <div className="qgu-banner qgu-banner--info">
        <Bot className="mt-0.5 h-4 w-4 shrink-0" />
        <span>
          A role is a label on the account. Module access is decided by the account&apos;s plan (and the owner account); what a role changes today is the
          <strong> Sophia copilot capability set</strong> it maps to (Read · Operate · Audit · Executive). Permission patterns are recorded for governance and are not enforced per request.
        </span>
      </div>

      <div className="qgu-panel space-y-3 p-4">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_repeat(3,minmax(0,180px))]">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 qgu-muted" aria-hidden />
            <input className="qgu-field pl-9 pr-9" aria-label="Search roles" placeholder="Search name, key, description or permission" value={query.search} onChange={(event) => resource.setQuery({ search: event.target.value })} />
            {query.search && (
              <button type="button" className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 qgu-muted" aria-label="Clear search" onClick={() => resource.setQuery({ search: '' })}><X className="h-4 w-4" /></button>
            )}
          </div>
          <SelectField label="Type filter" value={query.type} onChange={(value) => resource.setQuery({ type: value })}>
            <option value="all">All types</option>
            <option value="builtin">Built-in</option>
            <option value="system">System</option>
            <option value="custom">Custom</option>
            <option value="discovered">Not in catalogue</option>
          </SelectField>
          <SelectField label="Status filter" value={query.status} onChange={(value) => resource.setQuery({ status: value })}>
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
            <option value="archived">Archived</option>
          </SelectField>
          <SelectField label="Usage filter" value={query.usage} onChange={(value) => resource.setQuery({ usage: value })}>
            <option value="all">Any usage</option>
            <option value="in_use">Held by someone</option>
            <option value="unassigned">Held by nobody</option>
          </SelectField>
        </div>
        {activeFilters > 0 && (
          <div className="flex items-center gap-2 text-xs qgu-soft">
            <span>{formatCount(data?.pagination.total)} of {formatCount(stats?.total)} roles match</span>
            <button type="button" className="qgu-btn qgu-btn--ghost min-h-0 px-2 py-1 text-xs" onClick={resource.resetQuery}><X className="h-3.5 w-3.5" />Clear filters</button>
          </div>
        )}
      </div>

      <div className="qgu-panel overflow-hidden">
        {resource.error && <div className="m-4"><ErrorBanner message={`Roles could not be loaded: ${resource.error}`} onRetry={() => void resource.refresh()} /></div>}
        <div className="max-h-[70vh] overflow-auto">
          <table className="qgu-table min-w-[1100px]">
            <thead>
              <tr>
                <th scope="col">Role</th>
                <th scope="col">Holders</th>
                <th scope="col">Effect today</th>
                <th scope="col">Permission patterns</th>
                <th scope="col">Status</th>
                <th scope="col">Updated</th>
                <th scope="col" className="text-right"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody aria-busy={resource.loading}>
              {!data && !resource.error ? (
                Array.from({ length: 4 }, (_, index) => <tr key={index}><td colSpan={7}><div className="qgu-skeleton h-10" /></td></tr>)
              ) : data && data.roles.length === 0 ? (
                <tr><td colSpan={7}><EmptyState icon={<Layers className="h-6 w-6" />} title="No roles match" body="Widen or clear the filters." action={<button type="button" className="qgu-btn" onClick={resource.resetQuery}>Clear filters</button>} /></td></tr>
              ) : data?.roles.map((role) => (
                <tr key={role.key}>
                  <td>
                    <div className="max-w-[320px]">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-bold qgu-strong">{role.name}</span>
                        <Chip tone={TYPE_META[role.type].tone}>{TYPE_META[role.type].label}</Chip>
                        {role.reserved && <Chip tone="violet">Reserved</Chip>}
                      </div>
                      <div className="mt-0.5 font-mono text-[11px] qgu-muted">{role.key}{role.tenantName ? ` · tenant ${role.tenantName}` : ''}</div>
                      {role.description && <div className="mt-1 text-xs qgu-soft">{role.description}</div>}
                    </div>
                  </td>
                  <td>
                    <div className="font-mono text-base font-black qgu-strong qgu-num">{formatCount(role.holders)}</div>
                    {role.holderSample.length > 0 && (
                      <div className="mt-1 max-w-[200px] truncate text-[11px] qgu-muted" title={role.holderSample.map((holder) => holder.email).join(', ')}>
                        {role.holderSample.map((holder) => holder.email).join(', ')}{role.holders > role.holderSample.length ? ` +${role.holders - role.holderSample.length}` : ''}
                      </div>
                    )}
                  </td>
                  <td><Capabilities role={role} /></td>
                  <td>
                    <div className="text-xs font-bold qgu-soft">{role.permissionSummary}</div>
                    {role.permissions.length > 0 && !role.permissions.includes('*') && (
                      <div className="mt-1 flex max-w-[260px] flex-wrap gap-1">
                        {role.permissions.slice(0, 4).map((permission) => <code key={permission} className="rounded px-1.5 py-0.5 text-[10px] qgu-inset">{permission}</code>)}
                        {role.permissions.length > 4 && <span className="text-[10px] qgu-muted">+{role.permissions.length - 4}</span>}
                      </div>
                    )}
                  </td>
                  <td><Chip tone={STATUS_TONE[role.status]}>{role.status}</Chip></td>
                  <td className="text-xs qgu-soft">{role.updatedAt ? <span title={formatDate(role.updatedAt)}>{timeAgo(role.updatedAt, now)}</span> : <span className="qgu-muted">—</span>}</td>
                  <td className="text-right">
                    {admin.mutating === `role:${role.id}` ? <RefreshCw className="ml-auto h-4 w-4 animate-spin qgu-tone-info" /> : <ActionMenu label={`Actions for role ${role.name}`} trigger={<MoreHorizontal className="h-4 w-4" />} entries={menuFor(role)} />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pager pagination={data?.pagination} noun="roles" loading={resource.loading} onPage={(page) => void resource.refresh(page)} />
      </div>

      <ProvenanceNote>Role holders come from the Users directory (profiles.role; no role = User). The effect column is the Sophia copilot mapping the platform applies at request time.</ProvenanceNote>

      {dialog?.kind === 'create' && <RoleFormDialog admin={admin} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'edit' && <RoleFormDialog admin={admin} role={dialog.role} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'status' && (
        <ConfirmDialog
          title={`${dialog.action === 'activate' ? 'Activate' : dialog.action === 'deactivate' ? 'Deactivate' : 'Archive'} role — ${dialog.role.name}`}
          icon={dialog.action === 'activate' ? <CheckCircle2 className="h-5 w-5 qgu-tone-ok" /> : <CircleSlash className="h-5 w-5 qgu-tone-warn" />}
          effects={dialog.action === 'activate'
            ? ['The role becomes assignable again in Users.']
            : [
              'The role can no longer be assigned to anyone new.',
              dialog.role.holders
                ? `${dialog.role.holders} account(s) keep it until reassigned — they are flagged in the integrity checks.`
                : 'Nobody holds it today.',
            ]}
          confirmLabel={dialog.action === 'activate' ? 'Activate' : dialog.action === 'deactivate' ? 'Deactivate' : 'Archive'}
          busy={admin.mutating === `role:${dialog.role.id}`}
          onClose={() => setDialog(null)}
          onConfirm={() => admin.roleAction(dialog.role.id!, dialog.action)}
        />
      )}
      {dialog?.kind === 'delete' && (
        <ConfirmDialog
          title={`Delete role — ${dialog.role.name}`}
          icon={<Trash2 className="h-5 w-5 qgu-tone-bad" />}
          effects={['Removes the role from the catalogue permanently.', 'Nobody holds it, so no account changes.', 'The deletion is recorded in the admin audit trail.']}
          confirmLabel="Delete role"
          danger
          typeToConfirm={dialog.role.key}
          busy={admin.mutating === `role:${dialog.role.id}`}
          onClose={() => setDialog(null)}
          onConfirm={({ typed }) => admin.roleAction(dialog.role.id!, 'delete', { confirmKey: typed })}
        />
      )}
    </div>
  )
}
