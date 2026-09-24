import { useEffect, useState } from 'react'
import { AlertTriangle, BadgeCheck, Bell, CalendarClock, CalendarPlus, CreditCard, Download, ExternalLink, FileText, KeyRound, MoreHorizontal, Receipt, RefreshCw, Search, Trash2, Wallet, X, XCircle } from 'lucide-react'
import type { AdminDashboard, AdminUser } from '@/hooks/use-admin-dashboard'
import type { BillingRow } from '@/lib/admin/billing-console'
import { ActionMenu, Chip, Field, formatCount, formatDate, formatDateTime, timeAgo, useNow, type MenuEntry, type Tone } from '../_shared/primitives'
import { ConfirmDialog, ConsoleHeader, EmptyState, ErrorBanner, IntegrityStrip, Kpi, KpiGrid, Pager, Panel, ProvenanceNote } from '../_shared/console'
import { ManagePlanDialog } from '../_users/UserDialogs'

const ICON = 'h-4 w-4'

export function money(cents: number | null | undefined, currency = 'USD') {
  if (cents === null || cents === undefined) return '—'
  return new Intl.NumberFormat('en-US', { style: 'currency', currency, minimumFractionDigits: cents % 100 ? 2 : 0, maximumFractionDigits: 2 }).format(cents / 100)
}

const CLASS_META: Record<BillingRow['revenueClass'], { label: string; tone: Tone }> = {
  provider: { label: 'Paid', tone: 'ok' },
  manual: { label: 'Manual · not billed', tone: 'neutral' },
  complimentary: { label: 'Complimentary', tone: 'violet' },
}

const RENEWAL_LABEL: Record<BillingRow['renewal'], string> = {
  auto: 'Renews automatically',
  ends_at_period_end: 'Ends at period end',
  manual: 'No automatic renewal',
  ended: 'Ended',
}

type BillingSection = 'subscriptions' | 'invoices' | 'plans' | 'methods' | 'events'
type BillingDialog =
  | { kind: 'extend'; row: BillingRow }
  | { kind: 'notify'; row: BillingRow }
  | { kind: 'cancel'; row: BillingRow }
  | { kind: 'approve'; row: BillingRow }
  | { kind: 'delete'; row: BillingRow }

export function BillingTab({ admin }: { admin: AdminDashboard }) {
  const resource = admin.billing
  const { data, query } = resource
  const [section, setSection] = useState<BillingSection>('subscriptions')
  const [dialog, setDialog] = useState<BillingDialog | null>(null)
  const [planTarget, setPlanTarget] = useState<AdminUser | null>(null)
  const [days, setDays] = useState('30')
  const now = useNow()
  const { ensureLoaded } = resource
  useEffect(() => { ensureLoaded() }, [ensureLoaded])
  const stats = data?.stats
  const activeFilters = (['status', 'plan', 'class'] as const).filter((key) => query[key] !== 'all').length + (query.search ? 1 : 0)

  const openManagePlan = async (row: BillingRow) => {
    try {
      setPlanTarget(await admin.loadDirectoryUser(row.userId))
    } catch (err) {
      admin.pushNotice({ tone: 'error', title: 'Could not open the plan dialog', message: err instanceof Error ? err.message : String(err) })
    }
  }

  const menuFor = (row: BillingRow): MenuEntry[] => {
    const providerLocked = row.providerManaged && row.grantsAccess
    return [
      { kind: 'item', label: 'Manage plan…', description: providerLocked ? `Billed by ${row.providerLabel} — view only` : 'Change plan, cycle or access', icon: <KeyRound className={ICON} />, disabled: !row.user || row.user.isOwner, disabledReason: 'Account not found', onSelect: () => void openManagePlan(row) },
      { kind: 'item', label: 'Extend period…', icon: <CalendarPlus className={ICON} />, disabled: row.providerManaged || !row.grantsAccess, disabledReason: row.providerManaged ? `The period is set by ${row.providerLabel}` : 'Only an active subscription can be extended', onSelect: () => { setDays('30'); setDialog({ kind: 'extend', row }) } },
      { kind: 'item', label: 'Notify customer…', description: 'In-app reminder in Settings > Billing', icon: <Bell className={ICON} />, onSelect: () => setDialog({ kind: 'notify', row }) },
      ...(row.approvalStatus && !['approved', 'not_required'].includes(row.approvalStatus)
        ? [{ kind: 'item' as const, label: 'Approve…', icon: <BadgeCheck className={ICON} />, onSelect: () => setDialog({ kind: 'approve', row }) }]
        : []),
      { kind: 'separator' },
      { kind: 'item', label: 'Cancel subscription…', danger: true, icon: <XCircle className={ICON} />, disabled: !row.grantsAccess || row.provider === 'google_play', disabledReason: row.provider === 'google_play' ? 'Cancel in the Play Console' : 'Not active', onSelect: () => setDialog({ kind: 'cancel', row }) },
      { kind: 'item', label: 'Delete record…', danger: true, icon: <Trash2 className={ICON} />, disabled: providerLocked, disabledReason: 'Cancel the provider subscription first', onSelect: () => setDialog({ kind: 'delete', row }) },
    ]
  }

  const sections: Array<{ id: BillingSection; label: string }> = [
    { id: 'subscriptions', label: `Subscriptions${stats ? ` (${stats.subscriptions})` : ''}` },
    { id: 'invoices', label: `Invoices${stats ? ` (${stats.invoices})` : ''}` },
    { id: 'plans', label: 'Plans' },
    { id: 'methods', label: `Payment methods${stats ? ` (${stats.paymentMethods})` : ''}` },
    { id: 'events', label: 'Billing events' },
  ]

  return (
    <div className="qgu space-y-5">
      <ConsoleHeader
        title="Plans & Billing"
        description="Subscriptions, plan access and money — every figure from the same revenue model Revenue Intelligence uses."
        admin={admin}
        updatedAt={data?.generatedAt}
        actions={(
          <>
            <button type="button" className="qgu-btn" onClick={() => void admin.exportBilling()} disabled={admin.mutating === 'export-billing'}>
              <Download className="h-4 w-4" />
              Export CSV
            </button>
            <button type="button" className="qgu-btn" onClick={() => void resource.refresh()} disabled={resource.loading}>
              <RefreshCw className={`h-4 w-4 ${resource.loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </>
        )}
      />

      <KpiGrid loading={!stats}>
        {stats && (
          <>
            <Kpi icon={<Wallet className="h-4 w-4" />} label="MRR (billed)" value={money(stats.mrrCents)} sub={stats.byClass.provider ? `ARR ${money(stats.arrCents)} · ${stats.byClass.provider} paying` : 'No provider-billed subscription yet'} />
            <Kpi icon={<KeyRound className="h-4 w-4" />} label="Granting access" value={`${formatCount(stats.grantingAccess)} / ${formatCount(stats.subscriptions)}`} sub={`${stats.byClass.complimentary} complimentary · ${stats.byClass.manual} manual`} onClick={() => resource.setQuery({ status: query.status === 'granting' ? 'all' : 'granting' })} active={query.status === 'granting'} />
            <Kpi icon={<AlertTriangle className="h-4 w-4" />} label="Past due" value={formatCount(stats.pastDue)} sub={`${stats.failedPayments30d} failed payment(s) in 30 days`} subTone={stats.pastDue || stats.failedPayments30d ? 'bad' : undefined} onClick={() => resource.setQuery({ status: query.status === 'past_due' ? 'all' : 'past_due' })} active={query.status === 'past_due'} />
            <Kpi icon={<Receipt className="h-4 w-4" />} label="Collected YTD" value={money(stats.collectedYtdCents)} sub={`${money(stats.refundedYtdCents)} refunded · ${stats.invoices} invoice(s)`} />
            <Kpi icon={<CalendarClock className="h-4 w-4" />} label="Next billed renewal" value={stats.nextProviderRenewal ? formatDate(stats.nextProviderRenewal.at) : 'None'} sub={stats.nextProviderRenewal ? `${stats.nextProviderRenewal.email || 'unknown'} · ${money(stats.nextProviderRenewal.amountCents, stats.nextProviderRenewal.currency)}` : 'No provider-billed auto-renewal'} />
            <Kpi icon={<CalendarClock className="h-4 w-4" />} label="Ending at period end" value={formatCount(stats.endingAtPeriodEnd)} sub="cancelled; access until period end" subTone={stats.endingAtPeriodEnd ? 'warn' : undefined} />
          </>
        )}
      </KpiGrid>

      <IntegrityStrip checks={data?.integrity} notes={stats?.nonUsdExcluded ? [`${stats.nonUsdExcluded} non-USD invoice(s) excluded from USD totals.`] : []} />

      <nav className="qgu-panel qgu-tabs rounded-xl" role="tablist" aria-label="Billing sections">
        {sections.map((item) => (
          <button key={item.id} type="button" role="tab" aria-selected={section === item.id} className="qgu-tab" onClick={() => setSection(item.id)}>{item.label}</button>
        ))}
      </nav>

      {resource.error && <ErrorBanner message={`Billing could not be loaded: ${resource.error}`} onRetry={() => void resource.refresh()} />}

      {section === 'subscriptions' && (
        <>
          <div className="qgu-panel grid gap-2 p-4 lg:grid-cols-[minmax(0,1fr)_repeat(3,minmax(0,180px))]">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 qgu-muted" aria-hidden />
              <input className="qgu-field pl-9 pr-9" aria-label="Search subscriptions" placeholder="Search customer email, name, tenant or ID" value={query.search} onChange={(event) => resource.setQuery({ search: event.target.value })} />
              {query.search && <button type="button" className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 qgu-muted" aria-label="Clear search" onClick={() => resource.setQuery({ search: '' })}><X className="h-4 w-4" /></button>}
            </div>
            <select className="qgu-field" aria-label="Status filter" value={query.status} onChange={(event) => resource.setQuery({ status: event.target.value })}>
              <option value="all">All statuses</option>
              <option value="granting">Granting access</option>
              {['active', 'trial', 'pending_renewal', 'past_due', 'suspended', 'cancelled', 'expired', 'incomplete'].map((status) => <option key={status} value={status}>{status.replace(/_/g, ' ')}{stats?.byStatus[status] ? ` (${stats.byStatus[status]})` : ''}</option>)}
            </select>
            <select className="qgu-field" aria-label="Plan filter" value={query.plan} onChange={(event) => resource.setQuery({ plan: event.target.value })}>
              <option value="all">All plans</option>
              {['Starter', 'Basic', 'Pro', 'Elite'].map((plan) => <option key={plan} value={plan}>{plan}</option>)}
            </select>
            <select className="qgu-field" aria-label="Billing class filter" value={query.class} onChange={(event) => resource.setQuery({ class: event.target.value })}>
              <option value="all">Any billing</option>
              <option value="provider">Paid (provider)</option>
              <option value="complimentary">Complimentary</option>
              <option value="manual">Manual · not billed</option>
            </select>
          </div>
          <div className="qgu-panel overflow-hidden">
            <div className="max-h-[70vh] overflow-auto">
              <table className="qgu-table min-w-[1080px]">
                <thead>
                  <tr>
                    <th scope="col">Customer</th>
                    <th scope="col">Plan</th>
                    <th scope="col">Status</th>
                    <th scope="col">Billing</th>
                    <th scope="col">Renewal</th>
                    <th scope="col" className="text-right">MRR</th>
                    <th scope="col" className="text-right"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody aria-busy={resource.loading}>
                  {!data && !resource.error ? (
                    Array.from({ length: 3 }, (_, index) => <tr key={index}><td colSpan={7}><div className="qgu-skeleton h-10" /></td></tr>)
                  ) : data && data.subscriptions.length === 0 ? (
                    <tr><td colSpan={7}><EmptyState icon={<CreditCard className="h-6 w-6" />} title={activeFilters ? 'No subscriptions match' : 'No subscriptions yet'} body={activeFilters ? 'Widen or clear the filters.' : 'Subscriptions appear when a customer checks out, or when you grant a plan from Users.'} action={activeFilters ? <button type="button" className="qgu-btn" onClick={resource.resetQuery}>Clear filters</button> : undefined} /></td></tr>
                  ) : data?.subscriptions.map((row) => (
                    <tr key={row.id}>
                      <td>
                        <div className="max-w-[260px]">
                          <div className="truncate font-bold qgu-strong">{row.user?.email || <span className="qgu-tone-warn">Unknown account</span>}</div>
                          {row.user?.name && <div className="truncate text-xs qgu-soft">{row.user.name}</div>}
                          {row.tenantName && <div className="text-[11px] qgu-muted">{row.tenantName}</div>}
                        </div>
                      </td>
                      <td>
                        <Chip tone={row.grantsAccess ? 'ok' : 'neutral'} icon={<KeyRound className="h-3.5 w-3.5" />}>{row.plan}</Chip>
                        <div className="mt-1 text-[11px] qgu-muted">{row.billingCycle}</div>
                      </td>
                      <td>
                        <Chip tone={row.grantsAccess ? 'ok' : row.status === 'past_due' ? 'bad' : 'warn'}>{row.status.replace(/_/g, ' ')}</Chip>
                        <div className="mt-1 text-[11px] qgu-muted">{row.grantsAccess ? 'grants access' : 'no access'}</div>
                      </td>
                      <td>
                        <Chip tone={CLASS_META[row.revenueClass].tone} title={row.revenueClassReason}>{CLASS_META[row.revenueClass].label}</Chip>
                        <div className="mt-1 text-[11px] qgu-muted">
                          {row.providerLabel ? `${row.providerLabel} · ` : ''}{money(row.amountCents, row.currency)}/{row.billingCycle === 'annual' ? 'yr' : 'mo'}{row.priceSource === 'catalog' ? ' (list price)' : ''}
                        </div>
                      </td>
                      <td className="text-xs">
                        <div className="qgu-soft">{RENEWAL_LABEL[row.renewal]}</div>
                        {row.periodEnd && <div className={`qgu-num ${row.daysToPeriodEnd !== null && row.daysToPeriodEnd < 0 ? 'qgu-tone-bad' : row.daysToPeriodEnd !== null && row.daysToPeriodEnd <= 14 ? 'qgu-tone-warn' : 'qgu-muted'}`} title={formatDateTime(row.periodEnd)}>{formatDate(row.periodEnd)} · {timeAgo(row.periodEnd, now)}</div>}
                      </td>
                      <td className="text-right font-mono font-bold qgu-num">{row.mrrCents ? money(row.mrrCents) : <span className="qgu-muted" title={row.revenueClassReason}>—</span>}</td>
                      <td className="text-right">
                        {admin.mutating === `subscription-action:${row.id}` || admin.mutating === `subscription:${row.userId}` ? <RefreshCw className="ml-auto h-4 w-4 animate-spin qgu-tone-info" /> : <ActionMenu label={`Actions for ${row.user?.email || row.id}`} trigger={<MoreHorizontal className="h-4 w-4" />} entries={menuFor(row)} />}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager pagination={data?.pagination} noun="subscriptions" loading={resource.loading} onPage={(page) => void resource.refresh(page)} />
          </div>
        </>
      )}

      {section === 'invoices' && (
        <Panel title={`Invoices${data && data.invoicesTotal > data.invoices.length ? ` — latest ${data.invoices.length} of ${data.invoicesTotal}` : ''}`}>
          {!data ? <div className="qgu-skeleton h-20" /> : data.invoices.length === 0 ? (
            <EmptyState icon={<FileText className="h-6 w-6" />} title="No invoices recorded" body="Invoices are written by the payment-provider webhooks (PayPal, Google Play) when a charge succeeds, fails or is refunded. Complimentary and manual plans never produce invoices." />
          ) : (
            <div className="overflow-auto">
              <table className="qgu-table min-w-[820px]">
                <thead><tr><th>Paid</th><th>Customer</th><th>Plan</th><th className="text-right">Amount</th><th>Status</th><th>Reference</th></tr></thead>
                <tbody>
                  {data.invoices.map((invoice) => (
                    <tr key={invoice.id}>
                      <td className="text-xs qgu-soft" title={formatDateTime(invoice.paidAt)}>{formatDate(invoice.paidAt)}</td>
                      <td className="text-xs qgu-strong">{invoice.email || invoice.userId}</td>
                      <td className="text-xs">{invoice.plan || '—'}</td>
                      <td className="text-right font-mono font-bold qgu-num">{money(invoice.amountCents, invoice.currency)}{invoice.refundedCents ? <div className="text-[11px] qgu-tone-warn">−{money(invoice.refundedCents, invoice.currency)} refunded</div> : null}</td>
                      <td><Chip tone={invoice.status === 'paid' ? 'ok' : invoice.status === 'failed' ? 'bad' : invoice.status === 'refunded' ? 'warn' : 'neutral'}>{invoice.status}</Chip></td>
                      <td className="text-xs">
                        <span className="font-mono qgu-muted">{invoice.reference || '—'}</span>
                        {invoice.receiptUrl && <a className="ml-2 inline-flex items-center gap-1 qgu-tone-info hover:underline" href={invoice.receiptUrl} target="_blank" rel="noopener noreferrer">Receipt <ExternalLink className="h-3 w-3" /></a>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}

      {section === 'plans' && (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {(data?.plans || []).map((plan) => (
            <div key={plan.plan} className="qgu-panel p-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-black qgu-strong">{plan.plan}</h3>
                <Chip tone={plan.subscribers ? 'ok' : 'neutral'}>{plan.subscribers} with access</Chip>
              </div>
              <div className="mt-2 font-mono text-2xl font-black qgu-strong">{money(plan.monthlyCents)}<span className="text-sm font-bold qgu-muted">/mo</span></div>
              <div className="text-xs qgu-muted">{money(plan.yearlyCents)}/yr billed annually</div>
              <div className="mt-3 space-y-1 text-xs qgu-soft">
                <div className="flex justify-between"><span>Paying</span><span className="font-mono">{plan.paying}</span></div>
                <div className="flex justify-between"><span>Complimentary</span><span className="font-mono">{plan.complimentary}</span></div>
                <div className="flex justify-between"><span>Manual</span><span className="font-mono">{plan.manual}</span></div>
              </div>
            </div>
          ))}
          {!data && Array.from({ length: 4 }, (_, index) => <div key={index} className="qgu-skeleton h-44" />)}
        </div>
      )}

      {section === 'methods' && (
        <Panel title="Payment methods on file">
          {!data ? <div className="qgu-skeleton h-20" /> : data.paymentMethods.length === 0 ? (
            <EmptyState icon={<CreditCard className="h-6 w-6" />} title="No payment methods on file" body="Customers add payment methods through the provider checkout (PayPal / Google Play); administrators cannot add them. Card data is never stored here." />
          ) : (
            <ul className="grid gap-2 md:grid-cols-2">
              {data.paymentMethods.map((method) => (
                <li key={method.id} className="qgu-inset flex items-center justify-between gap-3 p-3 text-sm">
                  <div>
                    <div className="font-bold qgu-strong">{method.brand}{method.last4 ? ` •••• ${method.last4}` : ''}</div>
                    <div className="text-xs qgu-muted">{method.email || 'Unknown account'}{method.expires ? ` · expires ${method.expires}` : ''}{method.provider ? ` · ${method.provider}` : ''}</div>
                  </div>
                  {method.isDefault && <Chip tone="info">Default</Chip>}
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}

      {section === 'events' && (
        <Panel title="Billing events (latest 50)">
          {!data ? <div className="qgu-skeleton h-20" /> : data.events.length === 0 ? (
            <EmptyState icon={<Receipt className="h-6 w-6" />} title="No billing events" body="Subscription activations, plan changes, cancellations and reminders appear here as they are recorded." />
          ) : (
            <ul className="space-y-2">
              {data.events.map((event) => (
                <li key={event.id} className="qgu-inset p-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs qgu-soft">{event.action}</span>
                    <span className="text-xs qgu-muted">{event.target || ''}</span>
                    <span className="ml-auto text-xs qgu-muted" title={formatDateTime(event.at)}>{timeAgo(event.at, now)}</span>
                  </div>
                  {event.detail && <p className="mt-1 qgu-strong">{event.detail}</p>}
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}

      <ProvenanceNote>
        MRR counts only provider-billed subscriptions that grant access (the Revenue Intelligence rule); complimentary QA seeds and admin grants are shown but never priced as revenue or listed as upcoming invoices. Payments are processed by PayPal / Google Play; this console stores no card data.
      </ProvenanceNote>

      {planTarget && <ManagePlanDialog admin={admin} user={planTarget} onClose={() => setPlanTarget(null)} />}
      {dialog?.kind === 'extend' && (
        <ConfirmDialog
          title={`Extend period — ${dialog.row.user?.email || dialog.row.id}`}
          icon={<CalendarPlus className="h-5 w-5 qgu-tone-info" />}
          effects={[`The access period moves forward from ${dialog.row.periodEnd && Date.parse(dialog.row.periodEnd) > Date.now() ? formatDate(dialog.row.periodEnd) : 'today'}.`, 'No charge is made — this subscription is not provider-billed.', 'The customer sees the change in Settings > Billing.']}
          extra={(
            <Field label="Days to add (1–366)" htmlFor="qgu-extend-days">
              <input id="qgu-extend-days" className="qgu-field" type="number" min={1} max={366} value={days} onChange={(event) => setDays(event.target.value)} />
            </Field>
          )}
          confirmLabel="Extend"
          busy={admin.mutating === `subscription-action:${dialog.row.id}`}
          onClose={() => setDialog(null)}
          onConfirm={() => admin.subscriptionAction(dialog.row.id, 'extend', { days: Number(days) })}
        />
      )}
      {dialog?.kind === 'notify' && (
        <ConfirmDialog
          title={`Notify customer — ${dialog.row.user?.email || dialog.row.id}`}
          icon={<Bell className="h-5 w-5 qgu-tone-info" />}
          effects={['Delivers an in-app notification to the customer (Settings > Billing, live) about their plan and its period end.', 'Recorded in the customer’s billing trail and the admin audit trail.', 'No e-mail is sent.']}
          confirmLabel="Send reminder"
          busy={admin.mutating === `subscription-action:${dialog.row.id}`}
          onClose={() => setDialog(null)}
          onConfirm={() => admin.subscriptionAction(dialog.row.id, 'notify')}
        />
      )}
      {dialog?.kind === 'approve' && (
        <ConfirmDialog
          title={`Approve — ${dialog.row.user?.email || dialog.row.id}`}
          icon={<BadgeCheck className="h-5 w-5 qgu-tone-ok" />}
          effects={['Marks the pending approval as approved and the subscription active (grants plan access).']}
          confirmLabel="Approve"
          busy={admin.mutating === `subscription-action:${dialog.row.id}`}
          onClose={() => setDialog(null)}
          onConfirm={() => admin.subscriptionAction(dialog.row.id, 'approve')}
        />
      )}
      {dialog?.kind === 'cancel' && (
        <ConfirmDialog
          title={`Cancel subscription — ${dialog.row.user?.email || dialog.row.id}`}
          icon={<XCircle className="h-5 w-5 qgu-tone-bad" />}
          effects={[
            dialog.row.provider === 'paypal' ? 'PayPal is told to stop billing FIRST; if PayPal does not confirm, nothing changes.' : 'No payment provider is involved.',
            'Plan access ends immediately (status cancelled).',
            'The customer is notified in Settings > Billing.',
          ]}
          confirmLabel="Cancel subscription"
          danger
          busy={admin.mutating === `subscription-action:${dialog.row.id}`}
          onClose={() => setDialog(null)}
          onConfirm={() => admin.subscriptionAction(dialog.row.id, 'cancel')}
        />
      )}
      {dialog?.kind === 'delete' && (
        <ConfirmDialog
          title={`Delete subscription record — ${dialog.row.user?.email || dialog.row.id}`}
          icon={<Trash2 className="h-5 w-5 qgu-tone-bad" />}
          effects={['Removes the billing_subscriptions row; the account loses plan access.', 'Invoices and the billing trail are kept.', 'Prefer Cancel — deletion erases the subscription’s own history.']}
          confirmLabel="Delete record"
          danger
          typeToConfirm={dialog.row.user?.email || ''}
          busy={admin.mutating === `subscription-action:${dialog.row.id}`}
          onClose={() => setDialog(null)}
          onConfirm={({ typed }) => admin.subscriptionAction(dialog.row.id, 'delete', { confirmEmail: typed })}
        />
      )}
    </div>
  )
}
