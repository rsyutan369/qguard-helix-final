import { type ReactNode, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Copy,
  CreditCard,
  KeyRound,
  LogOut,
  MailCheck,
  PauseCircle,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Trash2,
  UserCog,
  UserPlus,
  Building2,
  Wand2,
} from 'lucide-react'
import type { AdminDashboard, AdminUser } from '@/hooks/use-admin-dashboard'
import { Dialog, Field, SelectField, formatCount, formatDate } from '../_shared/primitives'

export type UserDialogState =
  | { kind: 'status'; user: AdminUser; action: 'suspend' | 'disable' | 'restore' }
  | { kind: 'force_logout'; user: AdminUser }
  | { kind: 'mfa'; user: AdminUser; action: 'mfa_require' | 'mfa_relax' }
  | { kind: 'verify_email'; user: AdminUser }
  | { kind: 'reset_password'; user: AdminUser }
  | { kind: 'role'; user: AdminUser }
  | { kind: 'tenant'; user: AdminUser }
  | { kind: 'plan'; user: AdminUser }
  | { kind: 'delete'; user: AdminUser }
  | { kind: 'create' }

type DialogProps = { admin: AdminDashboard; onClose: () => void }

function who(user: AdminUser) {
  return user.name ? `${user.name} (${user.email})` : user.email
}

function Effects({ items }: { items: ReactNode[] }) {
  return (
    <div className="qgu-inset p-3">
      <div className="qgu-label">What happens</div>
      <ul className="space-y-1.5 text-sm qgu-soft">
        {items.map((item, index) => (
          <li key={index} className="flex gap-2">
            <span className="mt-2 h-1 w-1 shrink-0 rounded-full" style={{ background: 'var(--qgu-text-muted)' }} />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function InlineError({ message }: { message: string | null }) {
  if (!message) return null
  return (
    <div className="qgu-banner qgu-banner--bad" role="alert">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{message}</span>
    </div>
  )
}

function sessionsPhrase(user: AdminUser) {
  const count = user.sessions.count
  if (count === null) return 'every live session (count not measured)'
  return `all ${formatCount(count)} live session${count === 1 ? '' : 's'}`
}

// ---------------------------------------------------------------------------
// Suspend / disable / restore / sign-out / MFA policy / verify email
// ---------------------------------------------------------------------------

const ACTION_COPY = {
  suspend: {
    title: 'Suspend user',
    confirm: 'Suspend user',
    icon: <PauseCircle className="h-5 w-5 qgu-tone-warn" />,
    danger: true,
    reason: true,
  },
  disable: {
    title: 'Disable user',
    confirm: 'Disable user',
    icon: <Ban className="h-5 w-5 qgu-tone-bad" />,
    danger: true,
    reason: true,
  },
  restore: {
    title: 'Restore access',
    confirm: 'Restore access',
    icon: <CheckCircle2 className="h-5 w-5 qgu-tone-ok" />,
    danger: false,
    reason: false,
  },
  force_logout: {
    title: 'Sign out everywhere',
    confirm: 'Sign out all sessions',
    icon: <LogOut className="h-5 w-5 qgu-tone-warn" />,
    danger: true,
    reason: true,
  },
  mfa_require: {
    title: 'Require MFA',
    confirm: 'Require MFA',
    icon: <ShieldCheck className="h-5 w-5 qgu-tone-info" />,
    danger: false,
    reason: false,
  },
  mfa_relax: {
    title: 'Remove MFA requirement',
    confirm: 'Remove requirement',
    icon: <ShieldOff className="h-5 w-5 qgu-tone-warn" />,
    danger: false,
    reason: false,
  },
  verify_email: {
    title: 'Mark email as verified',
    confirm: 'Mark verified',
    icon: <MailCheck className="h-5 w-5 qgu-tone-info" />,
    danger: false,
    reason: false,
  },
} as const

type SimpleAction = keyof typeof ACTION_COPY

function effectsFor(action: SimpleAction, user: AdminUser): ReactNode[] {
  switch (action) {
    case 'suspend':
    case 'disable':
      return [
        <>Supabase Auth <strong>refuses sign-in and token refresh</strong> for this account until it is restored.</>,
        <>Ends {sessionsPhrase(user)} now; the API rejects access tokens already issued — effective immediately.</>,
        <>Profile status becomes <strong>{action === 'suspend' ? 'Suspended' : 'Disabled'}</strong>. {action === 'disable' ? 'Use for accounts that should not return (e.g. departed staff).' : 'Use for a temporary block (e.g. investigation).'}</>,
        <>Billing is not changed — manage the plan separately if needed.</>,
      ]
    case 'restore':
      return [
        <>Lifts the Supabase Auth block — the user can sign in again.</>,
        <>Profile status becomes <strong>Active</strong>.</>,
        <>Sessions ended earlier stay ended; the user signs in afresh.</>,
      ]
    case 'force_logout':
      return [
        <>Ends {sessionsPhrase(user)} in Supabase Auth (refresh tokens revoked) — no device can renew its login.</>,
        <>The API rejects this user&apos;s access tokens issued before now — effective immediately.</>,
        <>The account stays <strong>active</strong>; the user can sign in again.</>,
      ]
    case 'mfa_require':
      return [
        <>Records an <strong>MFA-required</strong> policy on the account; the console flags it until an authenticator is enrolled (Settings → Security).</>,
        <>Sign-in is <strong>not blocked</strong> by this policy yet — MFA enforcement at sign-in is not implemented on the platform.</>,
      ]
    case 'mfa_relax':
      return [
        <>Removes the MFA-required policy flag.</>,
        <>Enrolled authenticators are not removed; the user keeps using them.</>,
      ]
    case 'verify_email':
      return [
        <>Marks the email address as confirmed in Supabase Auth without the user clicking the verification link.</>,
        <>Only do this after confirming ownership of the mailbox another way.</>,
      ]
  }
}

export function ConfirmActionDialog({ admin, onClose, user, action }: DialogProps & { user: AdminUser; action: SimpleAction }) {
  const copy = ACTION_COPY[action]
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string | null>(null)
  const busy = admin.mutating === `${action}:${user.id}`

  const submit = async () => {
    setError(null)
    const outcome = await admin.userAction(user.id, action, copy.reason && reason.trim() ? { reason: reason.trim() } : {})
    if (outcome.ok) onClose()
    else setError(outcome.error)
  }

  return (
    <Dialog
      title={copy.title}
      subtitle={who(user)}
      icon={copy.icon}
      onClose={onClose}
      busy={busy}
      footer={(
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className={`qgu-btn ${copy.danger ? 'qgu-btn--danger' : 'qgu-btn--primary'}`} onClick={() => void submit()} disabled={busy}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            {copy.confirm}
          </button>
        </>
      )}
    >
      <Effects items={effectsFor(action, user)} />
      {copy.reason && (
        <Field label="Reason (recorded in the audit trail and the user's security log)" htmlFor="qgu-reason">
          <textarea id="qgu-reason" className="qgu-field" maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="e.g. Suspicious sign-in reported by the SOC" />
        </Field>
      )}
      <InlineError message={error} />
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------------

export function ResetPasswordDialog({ admin, onClose, user }: DialogProps & { user: AdminUser }) {
  const [delivery, setDelivery] = useState<'email' | 'link'>('email')
  const [link, setLink] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const busy = admin.mutating === `reset_password:${user.id}`

  const submit = async () => {
    setError(null)
    const outcome = await admin.userAction(user.id, 'reset_password', { delivery })
    if (!outcome.ok) {
      setError(outcome.error)
      return
    }
    if (delivery === 'link' && typeof outcome.data.recoveryLink === 'string') setLink(outcome.data.recoveryLink)
    else onClose()
  }

  const copy = async () => {
    if (!link) return
    try {
      await navigator.clipboard.writeText(link)
      setCopied(true)
    } catch {
      setError('Copy failed — select the link and copy it manually.')
    }
  }

  return (
    <Dialog
      title="Reset password"
      subtitle={who(user)}
      icon={<KeyRound className="h-5 w-5 qgu-tone-info" />}
      onClose={onClose}
      busy={busy}
      footer={link ? (
        <button type="button" className="qgu-btn qgu-btn--primary" onClick={onClose}>Done</button>
      ) : (
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="qgu-btn qgu-btn--primary" onClick={() => void submit()} disabled={busy}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            {delivery === 'email' ? 'Send reset email' : 'Generate link'}
          </button>
        </>
      )}
    >
      {link ? (
        <>
          <div className="qgu-banner">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              This single-use link signs whoever opens it into <strong>{user.email}</strong>. Share it only with the account holder over a trusted channel —
              do not open it yourself (it would replace your owner session). It was not stored in any audit record.
            </span>
          </div>
          <Field label="One-time recovery link">
            <div className="flex gap-2">
              <input className="qgu-field font-mono text-xs" readOnly value={link} onFocus={(event) => event.target.select()} />
              <button type="button" className="qgu-btn" onClick={() => void copy()}>
                <Copy className="h-4 w-4" />
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          </Field>
        </>
      ) : (
        <>
          <div className="space-y-2">
            {([
              ['email', 'Email the user a reset link', `Supabase Auth emails ${user.email} a link to set a new password on the /reset-password page. Recommended.`],
              ['link', 'Generate a one-time link', 'For when email is not reaching the user. You hand the link over yourself — treat it like a password.'],
            ] as const).map(([value, title, description]) => (
              <label key={value} className="qgu-inset flex cursor-pointer gap-3 p-3" style={delivery === value ? { borderColor: 'var(--qgu-border-strong)' } : undefined}>
                <input type="radio" name="qgu-delivery" className="mt-1" checked={delivery === value} onChange={() => setDelivery(value)} />
                <span>
                  <span className="block text-sm font-bold qgu-strong">{title}</span>
                  <span className="block text-xs qgu-muted">{description}</span>
                </span>
              </label>
            ))}
          </div>
          <p className="text-xs qgu-muted">The current password keeps working until the user sets a new one. To lock the account out right away, use Sign out everywhere or Suspend as well.</p>
        </>
      )}
      <InlineError message={error} />
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

export function ChangeRoleDialog({ admin, onClose, user }: DialogProps & { user: AdminUser }) {
  const roles = admin.usersDirectory?.assignableRoles || []
  const [role, setRole] = useState(roles.some((candidate) => candidate.key === user.role) ? user.role : 'user')
  const [error, setError] = useState<string | null>(null)
  const busy = admin.mutating === `update:${user.id}`
  const selected = roles.find((candidate) => candidate.key === role)

  const submit = async () => {
    setError(null)
    const outcome = await admin.updateUser(user.id, { role })
    if (outcome.ok) onClose()
    else setError(outcome.error)
  }

  return (
    <Dialog
      title="Change role"
      subtitle={who(user)}
      icon={<UserCog className="h-5 w-5 qgu-tone-violet" />}
      onClose={onClose}
      busy={busy}
      footer={(
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="qgu-btn qgu-btn--primary" onClick={() => void submit()} disabled={busy || role === user.role}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            Save role
          </button>
        </>
      )}
    >
      <Field label="Access role" htmlFor="qgu-role" hint={selected?.description}>
        <SelectField id="qgu-role" label="Access role" value={role} onChange={setRole}>
          {roles.map((candidate) => (
            <option key={candidate.key} value={candidate.key}>{candidate.label}{candidate.type === 'custom' ? ' (custom)' : ''}</option>
          ))}
        </SelectField>
      </Field>
      <p className="text-xs qgu-muted">
        Current role: <strong>{user.roleLabel}</strong> (from {user.roleSource.replace(/_/g, ' ')}). Roles come from the active role catalogue (Roles tab);
        Super Admin is reserved for the platform owner. The change is written to the profile and Supabase Auth metadata and audited.
      </p>
      <InlineError message={error} />
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Tenant
// ---------------------------------------------------------------------------

export function AssignTenantDialog({ admin, onClose, user }: DialogProps & { user: AdminUser }) {
  const [options, setOptions] = useState<Array<{ id: string; name: string; status: string }> | null>(null)
  const [tenantId, setTenantId] = useState(user.tenantId || '')
  const [error, setError] = useState<string | null>(null)
  const busy = admin.mutating === `update:${user.id}`

  useEffect(() => {
    let active = true
    admin.loadTenantOptions()
      .then((rows) => active && setOptions(rows))
      .catch((err) => active && setError(err instanceof Error ? err.message : 'Tenants could not be loaded'))
    return () => {
      active = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const submit = async () => {
    setError(null)
    const outcome = await admin.updateUser(user.id, { tenantId: tenantId || null })
    if (outcome.ok) onClose()
    else setError(outcome.error)
  }

  return (
    <Dialog
      title="Assign tenant"
      subtitle={who(user)}
      icon={<Building2 className="h-5 w-5 qgu-tone-info" />}
      onClose={onClose}
      busy={busy}
      footer={(
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="qgu-btn qgu-btn--primary" onClick={() => void submit()} disabled={busy || options === null || tenantId === (user.tenantId || '')}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            Save tenant
          </button>
        </>
      )}
    >
      {options === null && !error ? (
        <div className="qgu-skeleton h-10" />
      ) : options && options.length === 0 ? (
        <div className="qgu-banner qgu-banner--info">
          <Building2 className="mt-0.5 h-4 w-4 shrink-0" />
          <span>No tenants exist yet. Create one in the Tenants tab, then assign users to it here.</span>
        </div>
      ) : (
        <Field label="Tenant" htmlFor="qgu-tenant" hint="Membership in the tenant is created (and removed from the previous one) with the user's role.">
          <SelectField id="qgu-tenant" label="Tenant" value={tenantId} onChange={setTenantId}>
            <option value="">No tenant</option>
            {(options || []).map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}{tenant.status && tenant.status !== 'active' ? ` (${tenant.status})` : ''}</option>)}
          </SelectField>
        </Field>
      )}
      <InlineError message={error} />
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

const PLANS = ['Starter', 'Basic', 'Pro', 'Elite'] as const

function isoDateInput(daysFromNow: number) {
  return new Date(Date.now() + daysFromNow * 86_400_000).toISOString().slice(0, 10)
}

export function ManagePlanDialog({ admin, onClose, user }: DialogProps & { user: AdminUser }) {
  const { access } = user
  const providerLocked = access.providerManaged && access.isActive
  const currentPlan = access.tier !== 'none' ? access.tier[0].toUpperCase() + access.tier.slice(1) : 'Pro'
  const [mode, setMode] = useState<'activate' | 'deactivate' | 'cancel'>('activate')
  const [plan, setPlan] = useState<string>(PLANS.includes(currentPlan as never) ? currentPlan : 'Pro')
  const [interval, setCycle] = useState<'monthly' | 'annual'>(access.billingCycle === 'annual' ? 'annual' : 'monthly')
  const [periodEnd, setPeriodEnd] = useState(() => isoDateInput(30))
  const [error, setError] = useState<string | null>(null)
  const busy = admin.mutating === `subscription:${user.id}`
  const hasSubscription = access.source === 'subscription'

  useEffect(() => {
    setPeriodEnd(isoDateInput(interval === 'annual' ? 365 : 30))
  }, [interval])

  const submit = async () => {
    setError(null)
    const payload: Record<string, unknown> = { action: mode }
    if (mode === 'activate') {
      payload.plan = plan
      payload.interval = interval
      // End of the chosen day, UTC.
      payload.expiresAt = new Date(`${periodEnd}T23:59:59Z`).toISOString()
    }
    const outcome = await admin.manageUserSubscription(user.id, payload)
    if (outcome.ok) onClose()
    else setError(outcome.error)
  }

  return (
    <Dialog
      title="Manage plan"
      subtitle={who(user)}
      icon={<CreditCard className="h-5 w-5 qgu-tone-ok" />}
      onClose={onClose}
      busy={busy}
      footer={(
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className={`qgu-btn ${mode === 'activate' ? 'qgu-btn--primary' : 'qgu-btn--danger'}`} onClick={() => void submit()} disabled={busy || providerLocked || (!hasSubscription && mode !== 'activate')}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            {mode === 'activate' ? (hasSubscription ? 'Save plan' : 'Grant plan') : mode === 'deactivate' ? 'Pause access' : 'Cancel subscription'}
          </button>
        </>
      )}
    >
      <div className="qgu-inset grid gap-3 p-3 sm:grid-cols-3">
        <div>
          <div className="qgu-label">Current plan</div>
          <div className="text-sm font-bold qgu-strong">{access.tierLabel}</div>
        </div>
        <div>
          <div className="qgu-label">Access</div>
          <div className={`text-sm font-bold ${access.isActive ? 'qgu-tone-ok' : 'qgu-tone-warn'}`}>{access.isActive ? 'Granted' : 'None'}{access.status ? ` · ${access.status.replace(/_/g, ' ')}` : ''}</div>
        </div>
        <div>
          <div className="qgu-label">Billing</div>
          <div className="text-sm font-bold qgu-strong">{access.providerLabel || (hasSubscription ? 'Manual / comp' : '—')}</div>
          {access.periodEnd && <div className="text-xs qgu-muted">Period end {formatDate(access.periodEnd)}</div>}
        </div>
      </div>

      {providerLocked ? (
        <div className="qgu-banner">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            This subscription is billed by <strong>{access.providerLabel}</strong>. Changing its plan or period here would disagree with what the provider charges.
            The customer changes plan from Settings → Billing; cancellation is done from the <strong>Plans &amp; Billing</strong> tab (it cancels at the provider).
          </span>
        </div>
      ) : (
        <>
          <div className="grid gap-2 sm:grid-cols-3" role="radiogroup" aria-label="Plan action">
            {([
              ['activate', hasSubscription ? 'Change / renew' : 'Grant plan'],
              ['deactivate', 'Pause access'],
              ['cancel', 'Cancel'],
            ] as const).map(([value, label]) => (
              <label key={value} className="qgu-inset flex cursor-pointer items-center gap-2 p-2.5 text-sm font-bold" style={mode === value ? { borderColor: 'var(--qgu-border-strong)' } : undefined}>
                <input type="radio" name="qgu-plan-mode" checked={mode === value} disabled={value !== 'activate' && !hasSubscription} onChange={() => setMode(value)} />
                {label}
              </label>
            ))}
          </div>
          {mode === 'activate' ? (
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Plan" htmlFor="qgu-plan">
                <SelectField id="qgu-plan" label="Plan" value={plan} onChange={setPlan}>
                  {PLANS.map((value) => <option key={value} value={value}>{value}</option>)}
                </SelectField>
              </Field>
              <Field label="Cycle" htmlFor="qgu-cycle">
                <SelectField id="qgu-cycle" label="Billing cycle" value={interval} onChange={(value) => setCycle(value === 'annual' ? 'annual' : 'monthly')}>
                  <option value="monthly">Monthly</option>
                  <option value="annual">Annual</option>
                </SelectField>
              </Field>
              <Field label="Access until (UTC)" htmlFor="qgu-period">
                <input id="qgu-period" type="date" className="qgu-field" min={isoDateInput(1)} value={periodEnd} onChange={(event) => setPeriodEnd(event.target.value)} />
              </Field>
            </div>
          ) : (
            <Effects items={mode === 'deactivate'
              ? ['Status becomes suspended — the user loses plan access immediately (the account itself stays active).', 'Reversible: grant the plan again at any time.']
              : ['Status becomes cancelled — plan access ends immediately.', 'The customer is notified in Settings → Billing.']}
            />
          )}
          <p className="text-xs qgu-muted">
            Plans granted here are recorded as <strong>Manual — not billed</strong>: they grant access but are excluded from MRR in Revenue Intelligence.
            The customer&apos;s billing trail and notifications record the change.
          </p>
        </>
      )}
      <InlineError message={error} />
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

export function DeleteUserDialog({ admin, onClose, user }: DialogProps & { user: AdminUser }) {
  const [typed, setTyped] = useState('')
  const [error, setError] = useState<string | null>(null)
  const busy = admin.mutating === `delete:${user.id}`
  const blocked = user.access.providerManaged && user.access.isActive
  const matches = typed.trim().toLowerCase() === user.email.toLowerCase()

  const submit = async () => {
    setError(null)
    const outcome = await admin.deleteUser(user.id, typed.trim())
    if (outcome.ok) onClose()
    else setError(outcome.error)
  }

  return (
    <Dialog
      title="Delete user permanently"
      subtitle={who(user)}
      icon={<Trash2 className="h-5 w-5 qgu-tone-bad" />}
      onClose={onClose}
      busy={busy}
      footer={(
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="qgu-btn qgu-btn--danger" onClick={() => void submit()} disabled={busy || blocked || !matches}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            Delete permanently
          </button>
        </>
      )}
    >
      {blocked ? (
        <div className="qgu-banner qgu-banner--bad">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>This user has an active <strong>{user.access.providerLabel}</strong> subscription. Cancel it in Plans &amp; Billing first — deleting the account would leave the customer being charged.</span>
        </div>
      ) : (
        <>
          <Effects items={[
            <>Ends {sessionsPhrase(user)} and deletes the Supabase Auth account — this <strong>cannot be undone</strong>.</>,
            <>Removes the profile, subscription record, tenant memberships, device and session records.</>,
            <>The admin audit trail keeps a record of the deletion. To keep the account recoverable, use <strong>Disable</strong> instead.</>,
          ]}
          />
          <Field label={`Type ${user.email} to confirm`} htmlFor="qgu-delete-confirm">
            <input id="qgu-delete-confirm" className="qgu-field" autoComplete="off" value={typed} onChange={(event) => setTyped(event.target.value)} placeholder={user.email} />
          </Field>
        </>
      )}
      <InlineError message={error} />
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

function generatePassword(length = 20) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_'
  const bytes = new Uint32Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (value) => alphabet[value % alphabet.length]).join('')
}

export function CreateUserDialog({ admin, onClose }: DialogProps) {
  const roles = admin.usersDirectory?.assignableRoles || []
  const [form, setForm] = useState({ email: '', name: '', password: '', role: 'user', tenantId: '', plan: 'none', interval: 'monthly', mfaRequired: false })
  const [tenants, setTenants] = useState<Array<{ id: string; name: string; status: string }>>([])
  const [error, setError] = useState<string | null>(null)
  const [showPassword, setShowPassword] = useState(false)
  const busy = admin.mutating === 'create-user'
  const valid = useMemo(() => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(form.email.trim()) && form.password.length >= 12 && form.password.length <= 128, [form.email, form.password])

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
    const outcome = await admin.createUser({
      email: form.email.trim(),
      name: form.name.trim(),
      password: form.password,
      role: form.role,
      tenantId: form.tenantId || null,
      plan: form.plan,
      interval: form.interval,
      mfaRequired: form.mfaRequired,
    })
    if (outcome.ok) onClose()
    else setError(outcome.error)
  }

  return (
    <Dialog
      title="Add user"
      subtitle="Creates a confirmed Supabase Auth account with a temporary password."
      icon={<UserPlus className="h-5 w-5 qgu-tone-info" />}
      onClose={onClose}
      busy={busy}
      width={620}
      footer={(
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="qgu-btn qgu-btn--primary" onClick={() => void submit()} disabled={busy || !valid}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            Create user
          </button>
        </>
      )}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Email" htmlFor="qgu-new-email">
          <input id="qgu-new-email" type="email" autoComplete="off" className="qgu-field" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} placeholder="name@company.com" />
        </Field>
        <Field label="Full name" htmlFor="qgu-new-name">
          <input id="qgu-new-name" className="qgu-field" value={form.name} maxLength={120} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Optional" />
        </Field>
      </div>
      <Field label="Temporary password" htmlFor="qgu-new-password" hint="12–128 characters. Share it with the user over a trusted channel and ask them to change it after first sign-in.">
        <div className="flex gap-2">
          <input id="qgu-new-password" type={showPassword ? 'text' : 'password'} autoComplete="new-password" className="qgu-field font-mono" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} />
          <button type="button" className="qgu-btn" onClick={() => { setForm({ ...form, password: generatePassword() }); setShowPassword(true) }}>
            <Wand2 className="h-4 w-4" />
            Generate
          </button>
        </div>
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Role" htmlFor="qgu-new-role">
          <SelectField id="qgu-new-role" label="Role" value={form.role} onChange={(value) => setForm({ ...form, role: value })}>
            {(roles.length ? roles : [{ key: 'user', label: 'User', description: '', type: 'system' }]).map((role) => <option key={role.key} value={role.key}>{role.label}</option>)}
          </SelectField>
        </Field>
        <Field label="Tenant" htmlFor="qgu-new-tenant">
          <SelectField id="qgu-new-tenant" label="Tenant" value={form.tenantId} onChange={(value) => setForm({ ...form, tenantId: value })}>
            <option value="">No tenant</option>
            {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
          </SelectField>
        </Field>
        <Field label="Plan access" htmlFor="qgu-new-plan" hint={form.plan === 'none' ? 'Without a plan the user can sign in but reaches no paid modules.' : 'Granted as Manual — not billed (excluded from MRR).'}>
          <SelectField id="qgu-new-plan" label="Plan" value={form.plan} onChange={(value) => setForm({ ...form, plan: value })}>
            <option value="none">No plan</option>
            {PLANS.map((plan) => <option key={plan} value={plan.toLowerCase()}>{plan}</option>)}
          </SelectField>
        </Field>
        <Field label="Cycle" htmlFor="qgu-new-cycle">
          <SelectField id="qgu-new-cycle" label="Billing cycle" value={form.interval} onChange={(value) => setForm({ ...form, interval: value })}>
            <option value="monthly">Monthly (30 days)</option>
            <option value="annual">Annual (365 days)</option>
          </SelectField>
        </Field>
      </div>
      <label className="flex items-start gap-2 text-sm qgu-soft">
        <input type="checkbox" className="mt-1" checked={form.mfaRequired} onChange={(event) => setForm({ ...form, mfaRequired: event.target.checked })} />
        <span>Flag the account as <strong>MFA required</strong> (policy flag; tracked here until an authenticator is enrolled).</span>
      </label>
      <InlineError message={error} />
    </Dialog>
  )
}

export function UserDialogs({ admin, dialog, onClose }: { admin: AdminDashboard; dialog: UserDialogState | null; onClose: () => void }) {
  if (!dialog) return null
  switch (dialog.kind) {
    case 'status': return <ConfirmActionDialog admin={admin} onClose={onClose} user={dialog.user} action={dialog.action} />
    case 'force_logout': return <ConfirmActionDialog admin={admin} onClose={onClose} user={dialog.user} action="force_logout" />
    case 'mfa': return <ConfirmActionDialog admin={admin} onClose={onClose} user={dialog.user} action={dialog.action} />
    case 'verify_email': return <ConfirmActionDialog admin={admin} onClose={onClose} user={dialog.user} action="verify_email" />
    case 'reset_password': return <ResetPasswordDialog admin={admin} onClose={onClose} user={dialog.user} />
    case 'role': return <ChangeRoleDialog admin={admin} onClose={onClose} user={dialog.user} />
    case 'tenant': return <AssignTenantDialog admin={admin} onClose={onClose} user={dialog.user} />
    case 'plan': return <ManagePlanDialog admin={admin} onClose={onClose} user={dialog.user} />
    case 'delete': return <DeleteUserDialog admin={admin} onClose={onClose} user={dialog.user} />
    case 'create': return <CreateUserDialog admin={admin} onClose={onClose} />
  }
}
