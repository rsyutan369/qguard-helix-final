import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Bell,
  CheckCircle2,
  ChevronDown,
  CreditCard,
  Download,
  ExternalLink,
  FileText,
  Gauge,
  KeyRound,
  Layers,
  LifeBuoy,
  LockKeyhole,
  ReceiptText,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  Trash2,
  WalletCards,
  Webhook,
  X,
  XCircle,
} from 'lucide-react'
import type {
  BillingAction,
  BillingBundle,
  BillingCycle,
  BillingInvoice,
  BillingNotificationSettings,
  BillingPaymentMethod,
  BillingPlan,
  BillingPlanDefinition,
} from '@/hooks/use-billing-settings'

const panelClass = 'rounded-lg border border-gold/15 bg-[#07101e]/70 p-5 shadow-[0_0_34px_rgba(0,0,0,0.24)] backdrop-blur-xl transition hover:border-gold/35 hover:shadow-[0_0_36px_rgba(212,175,55,0.12)]'
const subtlePanelClass = 'rounded-lg border border-white/10 bg-white/[0.025] p-4'
const primaryButtonClass = 'inline-flex items-center justify-center gap-2 rounded-lg border border-gold/40 bg-gold px-4 py-2 text-xs font-black uppercase tracking-[0.12em] text-black shadow-[0_0_20px_rgba(212,175,55,0.18)] transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50'
const ghostButtonClass = 'inline-flex items-center justify-center gap-2 rounded-lg border border-gold/20 bg-gold/[0.04] px-3 py-2 text-xs font-bold text-gold transition hover:border-gold/40 hover:bg-gold/[0.08] disabled:cursor-not-allowed disabled:opacity-50'
const dangerButtonClass = 'inline-flex items-center justify-center gap-2 rounded-lg border border-red-400/35 bg-red-500/10 px-3 py-2 text-xs font-bold text-red-100 transition hover:border-red-300/60 hover:bg-red-500/15 disabled:cursor-not-allowed disabled:opacity-50'
const inputClass = 'w-full rounded-lg border border-gold/15 bg-[#0f1428]/45 px-3 py-2.5 text-sm text-white outline-none transition focus:border-gold/50 focus:bg-[#0f1428]/65'
const labelClass = 'mb-1.5 block text-[10px] font-black uppercase tracking-[0.16em] text-white/35'

type PendingAction = {
  action: BillingAction
  plan?: BillingPlan
  billingCycle?: BillingCycle
  title: string
  description: string
  danger?: boolean
}

function money(cents: number, currency = 'USD') {
  return new Intl.NumberFormat(undefined, { style: 'currency', currency }).format((cents || 0) / 100)
}

function formatDate(value?: string | null) {
  if (!value) return 'Not scheduled'
  return new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

function formatDateTime(value?: string | null) {
  if (!value) return 'Not recorded'
  return new Date(value).toLocaleString()
}

function formatBytes(value: number) {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const index = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)))
  return `${(value / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

function formatMetricValue(value: number, unit?: string) {
  if (unit === 'bytes') return formatBytes(value)
  if (unit === 'days') return `${value} days`
  return new Intl.NumberFormat().format(value || 0)
}

function statusLabel(value: string) {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function statusTone(status: string) {
  if (['active', 'paid', 'success'].includes(status)) return 'border-green-400/30 bg-green-400/10 text-green-300'
  if (['trial', 'pending', 'pending_renewal', 'incomplete'].includes(status)) return 'border-yellow-400/30 bg-yellow-400/10 text-yellow-200'
  if (['failed', 'expired', 'suspended', 'cancelled', 'past_due', 'critical'].includes(status)) return 'border-red-400/30 bg-red-500/10 text-red-200'
  return 'border-cyan-400/30 bg-cyan-400/10 text-cyan-200'
}

function planOrder(plan: BillingPlan) {
  return plan === 'Elite' ? 4 : plan === 'Pro' ? 3 : plan === 'Basic' ? 2 : 1
}

function nextPlan(plan: BillingPlan): BillingPlan {
  if (plan === 'Starter') return 'Basic'
  if (plan === 'Basic') return 'Pro'
  if (plan === 'Pro') return 'Elite'
  return 'Elite'
}

function previousPlan(plan: BillingPlan): BillingPlan {
  if (plan === 'Elite') return 'Pro'
  if (plan === 'Pro') return 'Basic'
  if (plan === 'Basic') return 'Starter'
  return 'Starter'
}

function Panel({ children, className = '' }: { children: ReactNode; className?: string; key?: string }) {
  return <section className={`${panelClass} ${className}`}>{children}</section>
}

function SectionTitle({ icon: Icon, title, action }: { icon: typeof CreditCard; title: string; action?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 text-gold" />
        <h3 className="text-sm font-black uppercase tracking-[0.16em] text-white/75">{title}</h3>
      </div>
      {action}
    </div>
  )
}

function Badge({ children, tone = 'gold' }: { children: ReactNode; tone?: 'gold' | 'green' | 'red' | 'cyan' | 'yellow' }) {
  const toneClass = tone === 'green' ? 'border-green-400/30 bg-green-400/10 text-green-300'
    : tone === 'red' ? 'border-red-400/30 bg-red-500/10 text-red-200'
      : tone === 'cyan' ? 'border-cyan-400/30 bg-cyan-400/10 text-cyan-200'
        : tone === 'yellow' ? 'border-yellow-400/30 bg-yellow-400/10 text-yellow-200'
          : 'border-gold/30 bg-gold/[0.08] text-gold'
  return <span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[10px] font-black uppercase tracking-[0.12em] ${toneClass}`}>{children}</span>
}

function ProgressBar({ value, tone = 'gold' }: { value: number; tone?: 'gold' | 'cyan' | 'green' | 'red' }) {
  const color = tone === 'cyan' ? 'bg-cyan-300' : tone === 'green' ? 'bg-green-400' : tone === 'red' ? 'bg-red-400' : 'bg-gold'
  return (
    <div className="h-2 rounded-full bg-white/10">
      <div className={`h-full rounded-full ${color} shadow-[0_0_16px_currentColor]`} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
    </div>
  )
}

function ToggleRow({ title, description, checked, onChange, disabled }: { title: string; description: string; checked: boolean; onChange: (checked: boolean) => void; disabled?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-white/10 bg-white/[0.025] p-3">
      <div>
        <div className="text-sm font-bold text-white/85">{title}</div>
        <div className="mt-0.5 text-xs text-white/40">{description}</div>
      </div>
      <button
        type="button"
        aria-pressed={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative h-7 w-12 shrink-0 rounded-full border transition disabled:cursor-not-allowed disabled:opacity-50 ${checked ? 'border-gold/50 bg-gold/35' : 'border-white/15 bg-white/10'}`}
      >
        <span className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition ${checked ? 'left-6' : 'left-1'}`} />
      </button>
    </div>
  )
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-dashed border-white/10 bg-white/[0.02] p-6 text-center text-sm text-white/35">
      {text}
    </div>
  )
}

function Modal({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4 backdrop-blur-sm">
      <div role="dialog" aria-modal="true" aria-label={title} className="w-full max-w-3xl overflow-hidden rounded-lg border border-gold/20 bg-[#050b15] shadow-[0_0_60px_rgba(212,175,55,0.18)]">
        <div className="flex items-center justify-between border-b border-white/10 px-5 py-4">
          <h3 className="text-sm font-black uppercase tracking-[0.16em] text-white/80">{title}</h3>
          <button type="button" aria-label="Close modal" className="rounded-lg border border-white/10 p-2 text-white/45 hover:text-white" onClick={onClose}>
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[78vh] overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  )
}

function PlanComparisonModal({ plans, currentPlan, onClose }: { plans: BillingPlanDefinition[]; currentPlan: BillingPlan; onClose: () => void }) {
  return (
    <Modal title="Plan Comparison" onClose={onClose}>
      <div className="grid gap-4 lg:grid-cols-3">
        {plans.map((plan) => (
          <div key={plan.name} className={`rounded-lg border p-4 ${plan.name === currentPlan ? 'border-gold/45 bg-gold/[0.06]' : 'border-white/10 bg-white/[0.025]'}`}>
            <div className="mb-3 flex items-center justify-between gap-2">
              <h4 className="text-lg font-black text-white">{plan.name}</h4>
              {plan.name === currentPlan && <Badge>Current</Badge>}
            </div>
            <div className="text-2xl font-black text-gold">{money(plan.monthlyCents)}<span className="text-xs text-white/40"> / mo</span></div>
            <div className="mt-1 text-xs text-white/45">{money(plan.annualCents)} annually</div>
            <div className="mt-4 space-y-2 text-xs text-white/60">
              <div>Team members: <span className="font-bold text-white/80">{plan.teamMembers}</span></div>
              <div>Storage: <span className="font-bold text-white/80">{formatBytes(plan.storageBytes)}</span></div>
              <div>Scan quota: <span className="font-bold text-white/80">{plan.scanQuota}</span></div>
              <div>API quota: <span className="font-bold text-white/80">{plan.apiQuota.toLocaleString()}</span></div>
              <div>Vault capacity: <span className="font-bold text-white/80">{formatBytes(plan.vaultCapacityBytes)}</span></div>
              <div>QRNG usage: <span className="font-bold text-white/80">{plan.qrngQuota.toLocaleString()}</span></div>
            </div>
            <div className="mt-4 border-t border-white/10 pt-4">
              <div className="mb-2 text-[10px] font-black uppercase tracking-[0.14em] text-white/35">Advanced Modules</div>
              <div className="space-y-2">
                {plan.advancedModules.map((item) => (
                  <div key={item} className="flex gap-2 text-xs text-white/60">
                    <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-green-300" />
                    {item}
                  </div>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </Modal>
  )
}

function ConfirmModal({ pending, saving, onConfirm, onClose }: { pending: PendingAction; saving: boolean; onConfirm: () => void; onClose: () => void }) {
  return (
    <Modal title="Confirm Billing Action" onClose={onClose}>
      <div className="space-y-5">
        <div className={`rounded-lg border p-4 ${pending.danger ? 'border-red-400/25 bg-red-500/10' : 'border-gold/20 bg-gold/[0.05]'}`}>
          <div className="flex items-center gap-3">
            {pending.danger ? <AlertTriangle className="h-5 w-5 text-red-300" /> : <ShieldCheck className="h-5 w-5 text-gold" />}
            <div>
              <div className="text-lg font-black text-white">{pending.title}</div>
              <div className="mt-1 text-sm text-white/50">{pending.description}</div>
            </div>
          </div>
        </div>
        <div className="grid gap-3 text-xs text-white/50 md:grid-cols-3">
          <div className={subtlePanelClass}>Audit logging records this action with your authenticated user, IP address, and user agent.</div>
          <div className={subtlePanelClass}>Subscription state is synchronized through the billing API, database row updates, and SSE telemetry.</div>
          <div className={subtlePanelClass}>Paid upgrades require the configured payment provider checkout session.</div>
        </div>
        <div className="flex flex-wrap justify-end gap-3">
          <button type="button" className={ghostButtonClass} onClick={onClose} disabled={saving}>Keep Current State</button>
          <button type="button" className={pending.danger ? dangerButtonClass : primaryButtonClass} onClick={onConfirm} disabled={saving}>
            {saving ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <ArrowRight className="h-3.5 w-3.5" />}
            Confirm
          </button>
        </div>
      </div>
    </Modal>
  )
}

function PaymentMethodModal({
  method,
  saving,
  onSave,
  onClose,
}: {
  method: BillingPaymentMethod
  saving: boolean
  onSave: (updates: Partial<BillingPaymentMethod>) => Promise<void>
  onClose: () => void
}) {
  const [draft, setDraft] = useState({
    billingName: method.billingName || '',
    country: method.country || '',
    taxRegion: method.taxRegion || '',
    expMonth: method.expMonth || new Date().getUTCMonth() + 1,
    expYear: method.expYear || new Date().getUTCFullYear(),
    addressLine1: String(method.billingAddress?.line1 || ''),
    city: String(method.billingAddress?.city || ''),
    postalCode: String(method.billingAddress?.postalCode || ''),
  })

  async function submit() {
    await onSave({
      billingName: draft.billingName,
      country: draft.country,
      taxRegion: draft.taxRegion,
      expMonth: draft.expMonth,
      expYear: draft.expYear,
      billingAddress: {
        line1: draft.addressLine1,
        city: draft.city,
        postalCode: draft.postalCode,
      },
    } as Partial<BillingPaymentMethod>)
    onClose()
  }

  return (
    <Modal title="Payment Method Metadata" onClose={onClose}>
      <div className="mb-4 rounded-lg border border-cyan-400/20 bg-cyan-400/10 p-3 text-xs text-cyan-100">
        QGuard stores tokenized provider references, brand, last four digits, and billing metadata only. Full card numbers and CVV are never collected here.
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <label>
          <span className={labelClass}>Billing Name</span>
          <input className={inputClass} value={draft.billingName} onChange={(event) => setDraft((prev) => ({ ...prev, billingName: event.target.value }))} />
        </label>
        <label>
          <span className={labelClass}>Country / Tax Region</span>
          <input className={inputClass} value={draft.taxRegion} onChange={(event) => setDraft((prev) => ({ ...prev, taxRegion: event.target.value }))} />
        </label>
        <label>
          <span className={labelClass}>Country</span>
          <input className={inputClass} value={draft.country} onChange={(event) => setDraft((prev) => ({ ...prev, country: event.target.value }))} />
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label>
            <span className={labelClass}>Exp Month</span>
            <input className={inputClass} type="number" min={1} max={12} value={draft.expMonth} onChange={(event) => setDraft((prev) => ({ ...prev, expMonth: Number(event.target.value) }))} />
          </label>
          <label>
            <span className={labelClass}>Exp Year</span>
            <input className={inputClass} type="number" min={new Date().getUTCFullYear()} value={draft.expYear} onChange={(event) => setDraft((prev) => ({ ...prev, expYear: Number(event.target.value) }))} />
          </label>
        </div>
        <label className="md:col-span-2">
          <span className={labelClass}>Billing Address</span>
          <input className={inputClass} value={draft.addressLine1} onChange={(event) => setDraft((prev) => ({ ...prev, addressLine1: event.target.value }))} />
        </label>
        <label>
          <span className={labelClass}>City</span>
          <input className={inputClass} value={draft.city} onChange={(event) => setDraft((prev) => ({ ...prev, city: event.target.value }))} />
        </label>
        <label>
          <span className={labelClass}>Postal Code</span>
          <input className={inputClass} value={draft.postalCode} onChange={(event) => setDraft((prev) => ({ ...prev, postalCode: event.target.value }))} />
        </label>
      </div>
      <div className="mt-5 flex justify-end gap-3">
        <button type="button" className={ghostButtonClass} onClick={onClose}>Cancel</button>
        <button type="button" className={primaryButtonClass} disabled={saving} onClick={submit}>Save Metadata</button>
      </div>
    </Modal>
  )
}

function SubscriptionOverview({ billing, openAction, onCompare }: { billing: BillingBundle; openAction: (action: PendingAction) => void; onCompare: () => void }) {
  const { subscription, usage } = billing
  const topMetrics = usage.metrics.filter((metric) => ['api_requests', 'scans', 'vault_storage', 'generated_keys'].includes(metric.key))
  const cycleTarget = subscription.billingCycle === 'monthly' ? 'annual' : 'monthly'

  return (
    <Panel>
      <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <Badge>{subscription.currentPlan}</Badge>
            <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[10px] font-black uppercase tracking-[0.12em] ${statusTone(subscription.status)}`}>
              {statusLabel(subscription.status)}
            </span>
            <Badge tone={subscription.autoRenew ? 'green' : 'yellow'}>{subscription.autoRenew ? 'Auto Renew On' : 'Auto Renew Off'}</Badge>
          </div>
          <h2 className="text-2xl font-black text-white">Billing & Subscription</h2>
          <p className="mt-1 max-w-3xl text-sm text-white/45">
            Manage authenticated account subscription state, usage limits, payment methods, invoices, and provider-backed billing workflows.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" className={ghostButtonClass} onClick={onCompare}>
            <Layers className="h-3.5 w-3.5" />
            Compare Plans
          </button>
          <button
            type="button"
            className={primaryButtonClass}
            disabled={!billing.permissions.canManageBilling || subscription.currentPlan === 'Elite'}
            onClick={() => openAction({
              action: 'upgrade',
              plan: nextPlan(subscription.currentPlan),
              billingCycle: subscription.billingCycle,
              title: `Upgrade to ${nextPlan(subscription.currentPlan)}`,
              description: 'A secure provider checkout session will be created for paid upgrades.',
            })}
          >
            <Sparkles className="h-3.5 w-3.5" />
            Upgrade
          </button>
        </div>
      </div>

      <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {[
          ['Billing Cycle', statusLabel(subscription.billingCycle)],
          ['Renewal Date', formatDate(subscription.renewalDate)],
          ['Trial Expiration', formatDate(subscription.trialExpirationDate)],
          ['Account Created', formatDate(subscription.accountCreationDate)],
          ['Subscription ID', subscription.subscriptionId || 'Not provisioned'],
          ['Provider', subscription.provider || 'QGuard account state'],
          ['Current Period', `${formatDate(subscription.currentPeriodStart)} - ${formatDate(subscription.currentPeriodEnd)}`],
          ['Last Sync', formatDateTime(billing.telemetry.lastSyncAt)],
        ].map(([label, value]) => (
          <div key={label} className={subtlePanelClass}>
            <div className="text-[10px] font-black uppercase tracking-[0.16em] text-white/35">{label}</div>
            <div className="mt-2 truncate text-sm font-bold text-white/80" title={value}>{value}</div>
          </div>
        ))}
      </div>

      <div className="mt-5 grid gap-3 lg:grid-cols-4">
        {topMetrics.map((metric) => (
          <div key={metric.key} className={subtlePanelClass}>
            <div className="mb-2 flex items-center justify-between gap-3 text-[10px] font-black uppercase tracking-[0.14em] text-white/35">
              <span>{metric.label}</span>
              <span className={metric.percent >= 90 ? 'text-red-300' : metric.percent >= 70 ? 'text-yellow-300' : 'text-cyan-300'}>{metric.percent}%</span>
            </div>
            <ProgressBar value={metric.percent} tone={metric.percent >= 90 ? 'red' : metric.percent >= 70 ? 'gold' : 'cyan'} />
            <div className="mt-2 text-xs text-white/45">
              {formatMetricValue(metric.used, metric.unit)} / {metric.limit ? formatMetricValue(metric.limit, metric.unit) : 'No limit tracked'}
            </div>
          </div>
        ))}
      </div>

      <div className="mt-5 flex flex-wrap gap-2 border-t border-white/10 pt-4">
        <button
          type="button"
          className={ghostButtonClass}
          disabled={!billing.permissions.canManageBilling || subscription.currentPlan === 'Starter'}
          onClick={() => openAction({
            action: 'downgrade',
            plan: previousPlan(subscription.currentPlan),
            billingCycle: subscription.billingCycle,
            title: `Downgrade to ${previousPlan(subscription.currentPlan)}`,
            description: 'This updates the account subscription tier and records the action in billing audit logs.',
          })}
        >
          Downgrade Plan
        </button>
        <button type="button" className={ghostButtonClass} disabled={!billing.permissions.canManageBilling} onClick={() => openAction({ action: 'renew', plan: subscription.currentPlan, billingCycle: subscription.billingCycle, title: 'Renew Subscription', description: 'Renewal keeps paid modules available and may create a provider checkout session when required.' })}>Renew</button>
        <button type="button" className={ghostButtonClass} disabled={!billing.permissions.canManageBilling} onClick={() => openAction({ action: 'switch-cycle', billingCycle: cycleTarget, title: `Switch to ${cycleTarget} billing`, description: 'Billing cycle changes are synchronized through the subscription API and provider hooks when configured.' })}>Switch to {cycleTarget}</button>
        <button type="button" className={ghostButtonClass} disabled={!billing.permissions.canManageBilling} onClick={() => openAction({ action: subscription.autoRenew ? 'disable-auto-renew' : 'enable-auto-renew', title: subscription.autoRenew ? 'Disable Auto-Renew' : 'Enable Auto-Renew', description: 'Auto-renew changes are applied to the tenant subscription state and reflected by live telemetry.' })}>{subscription.autoRenew ? 'Disable' : 'Enable'} Auto-Renew</button>
        {subscription.status === 'cancelled' ? (
          <button type="button" className={primaryButtonClass} disabled={!billing.permissions.canManageBilling} onClick={() => openAction({ action: 'reactivate', title: 'Reactivate Subscription', description: 'Reactivation restores active subscription status for the current plan.' })}>Reactivate</button>
        ) : (
          <button type="button" className={dangerButtonClass} disabled={!billing.permissions.canManageBilling} onClick={() => openAction({ action: 'cancel', title: 'Cancel Subscription', description: 'Cancellation disables auto-renew and marks the subscription for cancellation.', danger: true })}>Cancel Subscription</button>
        )}
      </div>
    </Panel>
  )
}

function PaymentMethodsSection({
  methods,
  providerConfigured,
  saving,
  canManage,
  onSetup,
  onSetDefault,
  onRemove,
  onEdit,
}: {
  methods: BillingPaymentMethod[]
  providerConfigured: boolean
  saving: boolean
  canManage: boolean
  onSetup: () => Promise<void>
  onSetDefault: (method: BillingPaymentMethod) => Promise<void>
  onRemove: (method: BillingPaymentMethod) => Promise<void>
  onEdit: (method: BillingPaymentMethod) => void
}) {
  return (
    <Panel>
      <SectionTitle
        icon={WalletCards}
        title="Payment Methods"
        action={(
          <button type="button" className={primaryButtonClass} disabled={saving || !canManage || !providerConfigured} title={providerConfigured ? 'Create a secure provider setup session' : 'Payment provider is not configured'} onClick={onSetup}>
            <CreditCard className="h-3.5 w-3.5" />
            Add Card
          </button>
        )}
      />
      <div className="mb-4 rounded-lg border border-cyan-400/20 bg-cyan-400/10 p-3 text-xs text-cyan-100">
        Payment methods are provider-tokenized. QGuard displays brand, last four digits, expiration, and billing metadata only.
      </div>
      <div className="space-y-3">
        {methods.length === 0 && <EmptyState text="No saved payment methods are connected to this authenticated account." />}
        {methods.map((method) => (
          <div key={method.id} className="flex flex-col gap-3 rounded-lg border border-white/10 bg-white/[0.025] p-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <CreditCard className="h-4 w-4 text-gold" />
                <span className="font-mono text-sm font-black text-white">{method.brand} •••• •••• •••• {method.last4 || '----'}</span>
                {method.isDefault && <Badge tone="green">Default</Badge>}
              </div>
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-white/40">
                <span>Exp {method.expMonth || '--'}/{method.expYear || '----'}</span>
                <span>Last used {formatDate(method.lastUsedAt)}</span>
                <span>{method.country || 'Country not recorded'}</span>
                <span>{method.taxRegion || 'Tax region not recorded'}</span>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button type="button" className={ghostButtonClass} disabled={saving || !canManage || method.isDefault} onClick={() => onSetDefault(method)}>Set Default</button>
              <button type="button" className={ghostButtonClass} disabled={saving || !canManage} onClick={() => onEdit(method)}>Update</button>
              <button type="button" className={dangerButtonClass} disabled={saving || !canManage} onClick={() => onRemove(method)}>
                <Trash2 className="h-3.5 w-3.5" />
                Remove
              </button>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  )
}

function UsageAnalytics({ billing }: { billing: BillingBundle }) {
  const groups = useMemo(() => {
    const map = new Map<string, typeof billing.usage.metrics>()
    for (const metric of billing.usage.metrics) {
      map.set(metric.group, [...(map.get(metric.group) || []), metric])
    }
    return Array.from(map.entries())
  }, [billing.usage.metrics])

  const trends = billing.usage.trends

  return (
    <Panel>
      <SectionTitle icon={BarChart3} title="Usage & Consumption Analytics" action={<Badge tone={billing.usage.rateLimitStatus === 'within-limit' ? 'green' : 'red'}>{statusLabel(billing.usage.rateLimitStatus)}</Badge>} />
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
        <div className="space-y-5">
          {groups.map(([group, metrics]) => (
            <div key={group}>
              <div className="mb-3 text-[10px] font-black uppercase tracking-[0.16em] text-white/35">{group}</div>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {metrics.map((metric) => (
                  <div key={metric.key} className={subtlePanelClass}>
                    <div className="mb-2 flex items-start justify-between gap-3">
                      <div className="text-sm font-bold text-white/80">{metric.label}</div>
                      <span className="font-mono text-xs text-white/45">{metric.percent}%</span>
                    </div>
                    <ProgressBar value={metric.percent} tone={metric.percent >= 90 ? 'red' : metric.percent >= 70 ? 'gold' : 'cyan'} />
                    <div className="mt-2 flex justify-between gap-3 text-xs text-white/40">
                      <span>{formatMetricValue(metric.used, metric.unit)} used</span>
                      <span>{metric.limit ? `${formatMetricValue(metric.remaining, metric.unit)} left` : 'Tracked only'}</span>
                    </div>
                    <div className="mt-2 text-[10px] uppercase tracking-[0.12em] text-white/25">{statusLabel(metric.status)}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="space-y-4">
          <div className={subtlePanelClass}>
            <div className="mb-3 flex items-center gap-2">
              <Gauge className="h-4 w-4 text-gold" />
              <div className="text-sm font-black text-white/80">Live Telemetry</div>
            </div>
            <div className="space-y-2 text-xs text-white/45">
              <div className="flex justify-between gap-3"><span>Usage events</span><span className="font-mono text-white/75">{billing.usage.telemetry.usageEvents}</span></div>
              <div className="flex justify-between gap-3"><span>Runtime events</span><span className="font-mono text-white/75">{billing.usage.telemetry.runtimeEvents}</span></div>
              <div className="flex justify-between gap-3"><span>Runtime 24h</span><span className="font-mono text-white/75">{billing.usage.telemetry.runtimeEvents24h}</span></div>
              <div className="flex justify-between gap-3"><span>Last sync</span><span className="font-mono text-white/75">{formatDateTime(billing.usage.telemetry.lastSyncAt)}</span></div>
            </div>
          </div>
          <div className={subtlePanelClass}>
            <div className="mb-3 text-sm font-black text-white/80">Historical Trend</div>
            {trends.length === 0 ? (
              <EmptyState text="No metered usage events have been recorded for the current billing period." />
            ) : (
              <div className="flex h-36 items-end gap-1">
                {trends.map((day) => {
                  const total = Object.entries(day).reduce((sum, [key, value]) => key === 'date' ? sum : sum + Number(value || 0), 0)
                  const max = Math.max(1, ...trends.map((item) => Object.entries(item).reduce((sum, [key, value]) => key === 'date' ? sum : sum + Number(value || 0), 0)))
                  return <div key={String(day.date)} title={`${day.date}: ${total}`} className="flex-1 rounded-t bg-gold/70 shadow-[0_0_12px_rgba(212,175,55,0.2)]" style={{ height: `${Math.max(6, (total / max) * 100)}%` }} />
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </Panel>
  )
}

function InvoicesSection({
  invoices,
  saving,
  onDownload,
}: {
  invoices: BillingInvoice[]
  saving: boolean
  onDownload: (invoiceId: string, kind: 'invoice' | 'receipt') => Promise<void>
}) {
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('all')
  const [sort, setSort] = useState<'newest' | 'oldest' | 'amount'>('newest')
  const [page, setPage] = useState(1)
  const [details, setDetails] = useState<BillingInvoice | null>(null)
  const pageSize = 5

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return invoices
      .filter((invoice) => status === 'all' || invoice.status === status)
      .filter((invoice) => !q || [
        invoice.invoiceId,
        invoice.transactionId,
        invoice.paymentMethod,
        invoice.subscriptionPlan,
        invoice.status,
      ].filter(Boolean).join(' ').toLowerCase().includes(q))
      .sort((a, b) => {
        if (sort === 'amount') return b.amountPaidCents - a.amountPaidCents
        const diff = new Date(a.paymentDate || a.createdAt || 0).getTime() - new Date(b.paymentDate || b.createdAt || 0).getTime()
        return sort === 'oldest' ? diff : -diff
      })
  }, [invoices, query, sort, status])

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const pageItems = filtered.slice((page - 1) * pageSize, page * pageSize)

  return (
    <Panel>
      <SectionTitle icon={ReceiptText} title="Billing History & Invoices" />
      <div className="mb-4 grid gap-3 lg:grid-cols-[minmax(0,1fr)_180px_180px]">
        <label className="relative">
          <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-white/30" />
          <input className={`${inputClass} pl-9`} value={query} placeholder="Search invoices, transactions, plans..." onChange={(event) => { setQuery(event.target.value); setPage(1) }} />
        </label>
        <select className={inputClass} value={status} onChange={(event) => { setStatus(event.target.value); setPage(1) }}>
          <option value="all">All statuses</option>
          <option value="paid">Paid</option>
          <option value="failed">Failed</option>
          <option value="pending">Pending</option>
          <option value="refunded">Refunded</option>
        </select>
        <select className={inputClass} value={sort} onChange={(event) => setSort(event.target.value as typeof sort)}>
          <option value="newest">Newest first</option>
          <option value="oldest">Oldest first</option>
          <option value="amount">Highest amount</option>
        </select>
      </div>

      <div className="overflow-x-auto rounded-lg border border-white/10">
        <table className="min-w-[980px] w-full text-left text-sm">
          <thead className="bg-white/[0.035] text-[10px] uppercase tracking-[0.14em] text-white/35">
            <tr>
              <th className="px-4 py-3">Invoice</th>
              <th className="px-4 py-3">Transaction</th>
              <th className="px-4 py-3">Payment Date</th>
              <th className="px-4 py-3">Amount</th>
              <th className="px-4 py-3">Tax</th>
              <th className="px-4 py-3">Method</th>
              <th className="px-4 py-3">Plan</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {pageItems.map((invoice) => (
              <tr key={invoice.id} className="border-t border-white/10">
                <td className="px-4 py-3 font-mono text-xs text-white/80">{invoice.invoiceId}</td>
                <td className="px-4 py-3 font-mono text-xs text-white/45">{invoice.transactionId || 'Not recorded'}</td>
                <td className="px-4 py-3 text-white/60">{formatDate(invoice.paymentDate)}</td>
                <td className="px-4 py-3 font-bold text-white">{money(invoice.amountPaidCents, invoice.currency)}</td>
                <td className="px-4 py-3 text-white/60">{money(invoice.taxCents, invoice.currency)}</td>
                <td className="px-4 py-3 text-white/60">{invoice.paymentMethod}</td>
                <td className="px-4 py-3 text-gold">{invoice.subscriptionPlan}</td>
                <td className="px-4 py-3"><span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase ${statusTone(invoice.status)}`}>{invoice.status}</span></td>
                <td className="px-4 py-3">
                  <div className="flex justify-end gap-2">
                    <button type="button" aria-label={`Download receipt ${invoice.invoiceId}`} className={ghostButtonClass} disabled={saving} onClick={() => onDownload(invoice.invoiceId, 'receipt')} title="Download Receipt PDF">
                      <Download className="h-3.5 w-3.5" />
                    </button>
                    <button type="button" aria-label={`Download invoice ${invoice.invoiceId}`} className={ghostButtonClass} disabled={saving} onClick={() => onDownload(invoice.invoiceId, 'invoice')} title="Download Invoice PDF">
                      <FileText className="h-3.5 w-3.5" />
                    </button>
                    <button type="button" className={ghostButtonClass} onClick={() => setDetails(invoice)}>Details</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {pageItems.length === 0 && <div className="p-4"><EmptyState text="No invoices match the current filters." /></div>}
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-xs text-white/40">
        <span>{filtered.length} invoice records</span>
        <div className="flex items-center gap-2">
          <button type="button" className={ghostButtonClass} disabled={page <= 1} onClick={() => setPage((current) => Math.max(1, current - 1))}>Previous</button>
          <span>Page {page} of {totalPages}</span>
          <button type="button" className={ghostButtonClass} disabled={page >= totalPages} onClick={() => setPage((current) => Math.min(totalPages, current + 1))}>Next</button>
        </div>
      </div>

      {details && (
        <Modal title="Transaction Details" onClose={() => setDetails(null)}>
          <div className="grid gap-3 md:grid-cols-2">
            {[
              ['Invoice ID', details.invoiceId],
              ['Transaction ID', details.transactionId || 'Not recorded'],
              ['Payment Date', formatDateTime(details.paymentDate)],
              ['Amount Paid', money(details.amountPaidCents, details.currency)],
              ['Tax', money(details.taxCents, details.currency)],
              ['Payment Method', details.paymentMethod],
              ['Subscription Plan', details.subscriptionPlan],
              ['Status', details.status],
            ].map(([label, value]) => (
              <div key={label} className={subtlePanelClass}>
                <div className="text-[10px] font-black uppercase tracking-[0.16em] text-white/35">{label}</div>
                <div className="mt-2 text-sm font-bold text-white/80">{value}</div>
              </div>
            ))}
          </div>
        </Modal>
      )}
    </Panel>
  )
}

function NotificationsSection({
  notifications,
  settings,
  saving,
  onSave,
}: {
  notifications: BillingBundle['notifications']
  settings: BillingNotificationSettings
  saving: boolean
  onSave: (settings: BillingNotificationSettings) => Promise<BillingNotificationSettings>
}) {
  const [draft, setDraft] = useState(settings)

  useEffect(() => {
    setDraft(settings)
  }, [settings])

  async function save() {
    await onSave(draft)
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
      <Panel>
        <SectionTitle icon={Bell} title="Billing Notifications & Alerts" />
        <div className="space-y-3">
          {notifications.length === 0 && <EmptyState text="No billing notifications or usage alerts are currently active." />}
          {notifications.map((notification) => (
            <div key={notification.id} className={`rounded-lg border p-4 ${statusTone(notification.severity)}`}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-black text-white">{notification.title}</div>
                  <div className="mt-1 text-xs text-white/60">{notification.message}</div>
                </div>
                <span className="text-[10px] uppercase tracking-[0.12em] text-white/45">{statusLabel(notification.type)}</span>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel>
        <SectionTitle icon={Webhook} title="Notification Controls" />
        <div className="space-y-3">
          <ToggleRow title="Email notifications" description="Renewals, failed payments, receipts, and usage warnings." checked={draft.emailNotifications} disabled={saving} onChange={(value) => setDraft((prev) => ({ ...prev, emailNotifications: value }))} />
          <ToggleRow title="In-app alerts" description="Display billing alerts inside the QGuard dashboard." checked={draft.inAppAlerts} disabled={saving} onChange={(value) => setDraft((prev) => ({ ...prev, inAppAlerts: value }))} />
          <ToggleRow title="Webhook notifications" description="Send billing events to your tenant webhook endpoint." checked={draft.webhookNotifications} disabled={saving} onChange={(value) => setDraft((prev) => ({ ...prev, webhookNotifications: value }))} />
          <label>
            <span className={labelClass}>Webhook URL</span>
            <input className={inputClass} value={draft.webhookUrl || ''} placeholder="https://example.com/qguard/billing" onChange={(event) => setDraft((prev) => ({ ...prev, webhookUrl: event.target.value }))} />
          </label>
          <button type="button" className={primaryButtonClass} disabled={saving} onClick={save}>
            <Bell className="h-3.5 w-3.5" />
            Save Alerts
          </button>
        </div>
      </Panel>
    </div>
  )
}

function SecurityCompliance({ billing }: { billing: BillingBundle }) {
  const items = [
    ['Secure backend payment handling', billing.providerStatus.stripeConfigured ? 'Provider configured' : 'Provider not configured'],
    ['Tokenized payment processing', 'Full card numbers are never stored'],
    ['User isolation', 'Authenticated user and RLS scoped records'],
    ['RBAC permission checks', billing.permissions.canManageBilling ? 'Billing manager access' : 'View-only billing access'],
    ['Audit logging', 'Billing actions are written to audit streams'],
    ['Realtime sync', billing.telemetry.live ? 'SSE and database subscriptions active' : 'Polling fallback'],
  ]

  return (
    <Panel>
      <SectionTitle icon={LockKeyhole} title="Security & Compliance" />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {items.map(([title, value]) => (
          <div key={title} className={subtlePanelClass}>
            <ShieldCheck className="mb-3 h-4 w-4 text-green-300" />
            <div className="text-sm font-bold text-white/80">{title}</div>
            <div className="mt-1 text-xs text-white/40">{value}</div>
          </div>
        ))}
      </div>
    </Panel>
  )
}

export default function BillingTab({
  billing,
  loading,
  saving,
  error,
  schemaReady,
  sseConnected,
  onRefresh,
  onAction,
  onSetupPaymentMethod,
  onUpdatePaymentMethod,
  onRemovePaymentMethod,
  onUpdateNotifications,
  onDownloadInvoice,
  onNotice,
}: {
  billing: BillingBundle | null
  loading: boolean
  saving: boolean
  error: string | null
  schemaReady: boolean
  sseConnected: boolean
  onRefresh: () => Promise<void>
  onAction: (action: BillingAction, payload?: { plan?: BillingPlan; billingCycle?: BillingCycle }) => Promise<{ status: string; redirectUrl?: string }>
  onSetupPaymentMethod: () => Promise<{ status: string; redirectUrl?: string }>
  onUpdatePaymentMethod: (id: string, updates: Partial<BillingPaymentMethod>) => Promise<BillingPaymentMethod>
  onRemovePaymentMethod: (id: string) => Promise<void>
  onUpdateNotifications: (settings: BillingNotificationSettings) => Promise<BillingNotificationSettings>
  onDownloadInvoice: (invoiceId: string, kind: 'invoice' | 'receipt') => Promise<void>
  onNotice: (message: string) => void
}) {
  const [compareOpen, setCompareOpen] = useState(false)
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null)
  const [editingMethod, setEditingMethod] = useState<BillingPaymentMethod | null>(null)

  async function confirmAction() {
    if (!pendingAction) return
    const action = pendingAction
    const result = await onAction(action.action, { plan: action.plan, billingCycle: action.billingCycle })
    setPendingAction(null)
    if (result.redirectUrl) {
      window.location.assign(result.redirectUrl)
      return
    }
    onNotice('Billing action completed.')
  }

  async function setupPaymentMethod() {
    const result = await onSetupPaymentMethod()
    if (result.redirectUrl) {
      window.location.assign(result.redirectUrl)
      return
    }
    onNotice('Payment setup session created.')
  }

  async function download(invoiceId: string, kind: 'invoice' | 'receipt') {
    await onDownloadInvoice(invoiceId, kind)
    onNotice(`${kind === 'invoice' ? 'Invoice' : 'Receipt'} downloaded.`)
  }

  if (loading) {
    return (
      <div className="grid gap-4 md:grid-cols-3">
        {[0, 1, 2, 3, 4, 5].map((item) => <div key={item} className="h-44 animate-pulse rounded-lg border border-gold/15 bg-white/[0.03]" />)}
      </div>
    )
  }

  if (!billing || !schemaReady) {
    return (
      <Panel className="mx-auto max-w-2xl text-center">
        <AlertTriangle className="mx-auto mb-4 h-9 w-9 text-yellow-300" />
        <h2 className="text-xl font-black text-white">Billing schema is not ready</h2>
        <p className="mt-2 text-sm text-white/45">
          {error || 'Install the Supabase billing schema so subscription, usage, invoice, and payment method records can be read from the database.'}
        </p>
        <div className="mt-4 rounded-lg border border-white/10 bg-white/[0.025] p-3 font-mono text-xs text-white/55">
          supabase/billing-subscription-schema.sql
        </div>
        <button type="button" className={`${primaryButtonClass} mt-5`} onClick={onRefresh}>
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </button>
      </Panel>
    )
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-gold/15 bg-[#07101e]/70 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={sseConnected ? 'green' : 'yellow'}>
            <span className={`h-2 w-2 rounded-full ${sseConnected ? 'bg-green-400' : 'bg-yellow-400'} ${sseConnected ? 'animate-pulse' : ''}`} />
            {sseConnected ? 'Realtime Billing Sync' : 'Polling Billing Sync'}
          </Badge>
          <Badge tone={billing.providerStatus.checkoutConfigured ? 'green' : 'yellow'}>
            Payment Provider {billing.providerStatus.checkoutConfigured ? 'Ready' : 'Needs Config'}
          </Badge>
          <Badge tone={billing.providerStatus.webhookConfigured ? 'green' : 'yellow'}>
            Provider Webhooks {billing.providerStatus.webhookConfigured ? 'Verified' : 'Not Configured'}
          </Badge>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link className={ghostButtonClass} to="/docs">
            <LifeBuoy className="h-3.5 w-3.5" />
            Billing Docs
          </Link>
          <button type="button" className={ghostButtonClass} disabled={saving} onClick={onRefresh}>
            <RefreshCw className={`h-3.5 w-3.5 ${saving ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-100">
          {error}
        </div>
      )}

      <SubscriptionOverview billing={billing} openAction={setPendingAction} onCompare={() => setCompareOpen(true)} />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
        <PaymentMethodsSection
          methods={billing.paymentMethods}
          providerConfigured={billing.providerStatus.stripeConfigured}
          saving={saving}
          canManage={billing.permissions.canManageBilling}
          onSetup={setupPaymentMethod}
          onSetDefault={(method) => onUpdatePaymentMethod(method.id, { isDefault: true }).then(() => onNotice('Default payment method updated.'))}
          onRemove={(method) => onRemovePaymentMethod(method.id).then(() => onNotice('Payment method removed.'))}
          onEdit={setEditingMethod}
        />

        <Panel>
          <SectionTitle icon={KeyRound} title="Quick Links" />
          <div className="space-y-3">
            {[
              ['/dashboard/scanner', 'Review scan quota and scanner jobs'],
              ['/dashboard/vault', 'Inspect Quantum Vault storage'],
              ['/dashboard/qrng', 'Review QRNG key usage'],
              ['/dashboard/runtime-telemetry', 'Monitor runtime telemetry'],
            ].map(([href, label]) => (
              <Link key={href} to={href} className="flex items-center justify-between gap-3 rounded-lg border border-white/10 bg-white/[0.025] p-3 text-sm font-bold text-white/70 transition hover:border-gold/30 hover:text-gold">
                {label}
                <ExternalLink className="h-3.5 w-3.5" />
              </Link>
            ))}
          </div>
        </Panel>
      </div>

      <UsageAnalytics billing={billing} />

      <InvoicesSection invoices={billing.invoices} saving={saving} onDownload={download} />

      <NotificationsSection notifications={billing.notifications} settings={billing.notificationSettings} saving={saving} onSave={onUpdateNotifications} />

      <SecurityCompliance billing={billing} />

      {compareOpen && <PlanComparisonModal plans={billing.planCatalog} currentPlan={billing.subscription.currentPlan} onClose={() => setCompareOpen(false)} />}
      {pendingAction && <ConfirmModal pending={pendingAction} saving={saving} onConfirm={confirmAction} onClose={() => setPendingAction(null)} />}
      {editingMethod && (
        <PaymentMethodModal
          method={editingMethod}
          saving={saving}
          onClose={() => setEditingMethod(null)}
          onSave={(updates) => onUpdatePaymentMethod(editingMethod.id, updates).then(() => onNotice('Payment method updated.'))}
        />
      )}
    </div>
  )
}
