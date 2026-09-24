// Owner Admin > Plans & Billing — the ONE billing-console model.
//
// Every money figure uses src/lib/billing/revenue-model.ts (the model Revenue
// Intelligence reads): MRR counts only provider-billed, access-granting rows;
// complimentary (QA seeds, comps) and manual (admin grants) rows are counted
// and disclosed but never priced as revenue or listed as upcoming invoices.
// Plan access per row is the directory's entitlement (the API gateway's rule).

import {
  classifySubscription,
  invoiceAmountCents,
  invoicePaidAt,
  invoiceRefundCents,
  normalizePlanTier,
  providerLabel,
  subscriptionChargeCents,
  subscriptionCurrency,
  subscriptionMrrCents,
  type InvoiceRecord,
  type RevenueClass,
  type SubscriptionRecord,
} from '@/lib/billing/revenue-model'
import { PLAN_TIERS, planChargeCents, type PlanTier } from '@/lib/billing/plan-pricing'
import { isAccessGrantingStatus } from '@/lib/subscription-access'
import type { DirectoryUser } from './user-directory'
import { lower, modelVersion, paginate, text, timeOf, type IntegrityCheck } from './model-utils'

const DAY_MS = 24 * 60 * 60_000

export const SUBSCRIPTION_STATUSES = ['active', 'trial', 'pending_renewal', 'past_due', 'suspended', 'cancelled', 'expired', 'incomplete'] as const

export interface BillingSubscriptionRow extends SubscriptionRecord {
  tenant_id?: string | null
  approval_status?: string | null
  provider_subscription_id?: string | null
  subscription_id?: string | null
}

export interface PaymentMethodRow {
  id: string
  user_id: string
  provider: string | null
  brand: string | null
  last4: string | null
  exp_month: number | null
  exp_year: number | null
  is_default: boolean | null
  updated_at: string | null
}

export type RenewalMode = 'auto' | 'ends_at_period_end' | 'manual' | 'ended'

export interface BillingRow {
  id: string
  userId: string
  user: { email: string; name: string; isOwner: boolean } | null
  tenantName: string | null
  plan: string
  status: string
  grantsAccess: boolean
  revenueClass: RevenueClass
  revenueClassReason: string
  provider: string | null
  providerLabel: string | null
  providerManaged: boolean
  billingCycle: 'monthly' | 'annual'
  amountCents: number
  priceSource: 'contract' | 'catalog' | 'unknown'
  currency: string
  mrrCents: number
  periodEnd: string | null
  daysToPeriodEnd: number | null
  renewal: RenewalMode
  approvalStatus: string | null
  lastInvoice: { status: string; amountCents: number; at: string | null } | null
  paymentMethod: { brand: string; last4: string } | null
  createdAt: string | null
  updatedAt: string | null
}

export interface BillingInvoice {
  id: string
  userId: string
  email: string | null
  plan: string | null
  status: string
  amountCents: number
  refundedCents: number
  currency: string
  paidAt: string | null
  provider: string | null
  reference: string | null
  receiptUrl: string | null
}

export interface BillingStats {
  mrrCents: number
  arrCents: number
  subscriptions: number
  byStatus: Record<string, number>
  grantingAccess: number
  byClass: Record<RevenueClass, number>
  pastDue: number
  endingAtPeriodEnd: number
  nextProviderRenewal: { at: string; subscriptionId: string; email: string | null; amountCents: number; currency: string } | null
  invoices: number
  collectedYtdCents: number
  refundedYtdCents: number
  failedPayments30d: number
  pendingInvoices: number
  paymentMethods: number
  nonUsdExcluded: number
}

export interface PlanCatalogEntry {
  plan: PlanTier
  monthlyCents: number
  yearlyCents: number
  subscribers: number
  paying: number
  complimentary: number
  manual: number
}

export interface BillingConsole {
  rows: BillingRow[]
  invoices: BillingInvoice[]
  paymentMethods: Array<{ id: string; email: string | null; brand: string; last4: string; expires: string | null; isDefault: boolean; provider: string | null }>
  plans: PlanCatalogEntry[]
  stats: BillingStats
  integrity: IntegrityCheck[]
  version: string
  generatedAt: string
}

function renewalMode(row: BillingSubscriptionRow, grantsAccess: boolean, revenueClass: RevenueClass): RenewalMode {
  if (!grantsAccess) return 'ended'
  if (row.cancel_at_period_end) return 'ends_at_period_end'
  if (revenueClass === 'provider' && row.auto_renew !== false) return 'auto'
  return 'manual'
}

export function buildBillingConsole(input: {
  subscriptions: BillingSubscriptionRow[]
  invoices: InvoiceRecord[]
  paymentMethods: PaymentMethodRow[]
  users: DirectoryUser[]
  tenants: Array<{ id: string; name: string | null }>
  now?: number
}): BillingConsole {
  const now = input.now ?? Date.now()
  const usersById = new Map(input.users.map((user) => [user.id, user]))
  const tenantNames = new Map(input.tenants.map((tenant) => [tenant.id, text(tenant.name) || null]))
  const invoicesByUser = new Map<string, InvoiceRecord[]>()
  for (const invoice of input.invoices) {
    const list = invoicesByUser.get(invoice.user_id) || []
    list.push(invoice)
    invoicesByUser.set(invoice.user_id, list)
  }
  const methodByUser = new Map<string, PaymentMethodRow>()
  for (const method of input.paymentMethods) {
    const current = methodByUser.get(method.user_id)
    if (!current || (method.is_default && !current.is_default)) methodByUser.set(method.user_id, method)
  }

  const rows: BillingRow[] = input.subscriptions.map((row): BillingRow => {
    const user = usersById.get(row.user_id) || null
    const classification = classifySubscription(row)
    const grantsAccess = isAccessGrantingStatus(row.status)
    const charge = subscriptionChargeCents(row)
    const provider = lower(row.provider) || null
    const invoices = (invoicesByUser.get(row.user_id) || []).slice().sort((a, b) => (invoicePaidAt(b) ?? 0) - (invoicePaidAt(a) ?? 0))
    const lastInvoice = invoices[0] || null
    const periodEndMs = timeOf(row.current_period_end || row.renewal_date)
    const method = methodByUser.get(row.user_id) || null
    const tenantId = text(row.tenant_id) || user?.tenantId || null
    return {
      id: row.id,
      userId: row.user_id,
      user: user ? { email: user.email, name: user.name, isOwner: user.isOwner } : null,
      tenantName: tenantId ? tenantNames.get(tenantId) || null : null,
      plan: normalizePlanTier(row.plan) || text(row.plan) || 'Unknown',
      status: lower(row.status) || 'unknown',
      grantsAccess,
      revenueClass: classification.revenueClass,
      revenueClassReason: classification.reason,
      provider,
      providerLabel: provider ? providerLabel(provider) : null,
      providerManaged: provider === 'paypal' || provider === 'google_play',
      billingCycle: lower(row.billing_cycle).includes('annual') || lower(row.billing_cycle).includes('year') ? 'annual' : 'monthly',
      amountCents: charge.cents,
      priceSource: charge.priceSource,
      currency: subscriptionCurrency(row),
      mrrCents: subscriptionMrrCents(row),
      periodEnd: periodEndMs === null ? null : new Date(periodEndMs).toISOString(),
      daysToPeriodEnd: periodEndMs === null ? null : Math.ceil((periodEndMs - now) / DAY_MS),
      renewal: renewalMode(row, grantsAccess, classification.revenueClass),
      approvalStatus: text(row.approval_status) || null,
      lastInvoice: lastInvoice ? { status: lower(lastInvoice.status), amountCents: invoiceAmountCents(lastInvoice), at: new Date(invoicePaidAt(lastInvoice) ?? now).toISOString() } : null,
      paymentMethod: method ? { brand: text(method.brand) || 'Card', last4: text(method.last4) } : null,
      createdAt: row.created_at || null,
      updatedAt: row.updated_at || null,
    }
  }).sort((a, b) => (timeOf(b.updatedAt) ?? 0) - (timeOf(a.updatedAt) ?? 0))

  const invoices: BillingInvoice[] = input.invoices.map((invoice) => ({
    id: invoice.id,
    userId: invoice.user_id,
    email: usersById.get(invoice.user_id)?.email || null,
    plan: invoice.subscription_plan,
    status: lower(invoice.status) || 'unknown',
    amountCents: invoiceAmountCents(invoice),
    refundedCents: invoiceRefundCents(invoice),
    currency: text(invoice.currency).toUpperCase() || 'USD',
    paidAt: (() => { const at = invoicePaidAt(invoice); return at === null ? null : new Date(at).toISOString() })(),
    provider: text((invoice.metadata || {} as Record<string, unknown>).provider) || null,
    reference: invoice.provider_invoice_id || invoice.invoice_id || invoice.transaction_id || null,
    receiptUrl: text((invoice as unknown as Record<string, unknown>).receipt_url) || text((invoice as unknown as Record<string, unknown>).hosted_invoice_url) || null,
  })).sort((a, b) => (timeOf(b.paidAt) ?? 0) - (timeOf(a.paidAt) ?? 0))

  const ytdStart = Date.UTC(new Date(now).getUTCFullYear(), 0, 1)
  const count = (predicate: (row: BillingRow) => boolean) => rows.reduce((sum, row) => sum + (predicate(row) ? 1 : 0), 0)
  const byStatus: Record<string, number> = {}
  for (const row of rows) byStatus[row.status] = (byStatus[row.status] || 0) + 1
  const upcoming = rows
    .filter((row) => row.revenueClass === 'provider' && row.renewal === 'auto' && row.periodEnd && (timeOf(row.periodEnd) ?? 0) >= now)
    .sort((a, b) => (timeOf(a.periodEnd) ?? 0) - (timeOf(b.periodEnd) ?? 0))
  const mrrCents = rows.reduce((sum, row) => sum + row.mrrCents, 0)
  const usdInvoices = invoices.filter((invoice) => invoice.currency === 'USD')
  const stats: BillingStats = {
    mrrCents,
    arrCents: mrrCents * 12,
    subscriptions: rows.length,
    byStatus,
    grantingAccess: count((row) => row.grantsAccess),
    byClass: { provider: count((row) => row.revenueClass === 'provider'), manual: count((row) => row.revenueClass === 'manual'), complimentary: count((row) => row.revenueClass === 'complimentary') },
    pastDue: count((row) => row.status === 'past_due'),
    endingAtPeriodEnd: count((row) => row.renewal === 'ends_at_period_end'),
    nextProviderRenewal: upcoming[0] ? { at: upcoming[0].periodEnd!, subscriptionId: upcoming[0].id, email: upcoming[0].user?.email || null, amountCents: upcoming[0].amountCents, currency: upcoming[0].currency } : null,
    invoices: invoices.length,
    collectedYtdCents: usdInvoices.filter((invoice) => invoice.status === 'paid' || invoice.status === 'refunded').filter((invoice) => (timeOf(invoice.paidAt) ?? 0) >= ytdStart).reduce((sum, invoice) => sum + invoice.amountCents, 0),
    refundedYtdCents: usdInvoices.filter((invoice) => (timeOf(invoice.paidAt) ?? 0) >= ytdStart).reduce((sum, invoice) => sum + invoice.refundedCents, 0),
    failedPayments30d: invoices.filter((invoice) => invoice.status === 'failed' && (timeOf(invoice.paidAt) ?? 0) >= now - 30 * DAY_MS).length,
    pendingInvoices: invoices.filter((invoice) => invoice.status === 'pending').length,
    paymentMethods: input.paymentMethods.length,
    nonUsdExcluded: invoices.length - usdInvoices.length,
  }

  const plans: PlanCatalogEntry[] = PLAN_TIERS.map((plan) => {
    const holders = rows.filter((row) => row.grantsAccess && row.plan === plan)
    return {
      plan,
      monthlyCents: planChargeCents(plan, 'monthly'),
      yearlyCents: planChargeCents(plan, 'yearly'),
      subscribers: holders.length,
      paying: holders.filter((row) => row.revenueClass === 'provider').length,
      complimentary: holders.filter((row) => row.revenueClass === 'complimentary').length,
      manual: holders.filter((row) => row.revenueClass === 'manual').length,
    }
  })

  const statusSum = Object.values(byStatus).reduce((sum, value) => sum + value, 0)
  const classSum = stats.byClass.provider + stats.byClass.manual + stats.byClass.complimentary
  const payingOnlyMrr = rows.filter((row) => row.mrrCents > 0).every((row) => row.revenueClass === 'provider' && row.grantsAccess)
  const integrity: IntegrityCheck[] = [
    { id: 'status-partition', label: 'Status buckets sum to all subscriptions', ok: statusSum === rows.length, detail: `${statusSum} of ${rows.length}` },
    { id: 'class-partition', label: 'Every subscription is provider, manual or complimentary', ok: classSum === rows.length, detail: `${stats.byClass.provider} provider + ${stats.byClass.manual} manual + ${stats.byClass.complimentary} complimentary` },
    { id: 'mrr-rule', label: 'MRR counts only provider-billed rows that grant access', ok: payingOnlyMrr, detail: payingOnlyMrr ? `MRR from ${stats.byClass.provider} provider-billed row(s)` : 'A non-provider row carries MRR' },
    { id: 'user-link', label: 'Every subscription belongs to a known account', ok: rows.every((row) => row.user), detail: `${rows.filter((row) => !row.user).length} orphaned subscription row(s)` },
  ]
  const model = { rows, invoices, paymentMethods: input.paymentMethods.map((method) => ({
    id: method.id,
    email: usersById.get(method.user_id)?.email || null,
    brand: text(method.brand) || 'Card',
    last4: text(method.last4),
    expires: method.exp_month && method.exp_year ? `${String(method.exp_month).padStart(2, '0')}/${String(method.exp_year).slice(-2)}` : null,
    isDefault: Boolean(method.is_default),
    provider: text(method.provider) || null,
  })), plans, stats, integrity }
  return { ...model, version: modelVersion(model), generatedAt: new Date(now).toISOString() }
}

export interface BillingQuery {
  search?: string
  status?: string
  plan?: string
  revenueClass?: string
  page?: number
  limit?: number
}

export function queryBillingRows(model: BillingConsole, query: BillingQuery) {
  const search = lower(query.search)
  const filtered = model.rows.filter((row) => {
    if (search && !`${row.user?.email || ''} ${row.user?.name || ''} ${row.id} ${row.userId} ${row.tenantName || ''} ${row.plan}`.toLowerCase().includes(search)) return false
    if (query.status && query.status !== 'all' && (query.status === 'granting' ? !row.grantsAccess : row.status !== query.status)) return false
    if (query.plan && query.plan !== 'all' && row.plan.toLowerCase() !== query.plan.toLowerCase()) return false
    if (query.revenueClass && query.revenueClass !== 'all' && row.revenueClass !== query.revenueClass) return false
    return true
  })
  return paginate(filtered, query.page, query.limit)
}
