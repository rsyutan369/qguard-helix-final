/**
 * Billing operations health — the store-lifecycle side of Revenue Intelligence
 * (Qguard_Wiki/GooglePlay_Billing §14.1).
 *
 * Pure data → data, computed from REAL rows only:
 *   - public.play_webhook_events (the Google Play RTDN inbox + verification ledger)
 *   - public.billing_audit_events (lifecycle events written by the billing service)
 *   - public.billing_subscriptions (current payment-issue states)
 * Nothing is estimated here; an empty inbox reports zeros plus `rtdnSeen: false`
 * so the dashboard can say "no Google Play notification received yet" instead
 * of implying a healthy pipeline it has never observed.
 */

export interface InboxRecord {
  id: string
  event_id: string
  notification_type: string | null
  status: string | null
  attempts: number | null
  received_at: string | null
  claimed_at: string | null
  processed_at: string | null
  last_error: string | null
}

export interface OpsAuditRecord {
  action: string | null
  created_at: string
}

export interface OpsSubscriptionRecord {
  provider: string | null
  status: string | null
}

export interface BillingOps {
  windowDays: number
  inbox: {
    rtdnSeen: boolean
    received: number
    processed: number
    processing: number
    failed: number
    deadLetter: number
    /** Oldest message not yet processed (processing/failed), null when none. */
    oldestUnprocessedAt: string | null
    lastReceivedAt: string | null
    lastError: string | null
  }
  lifecycle: {
    activations: number
    renewals: number
    cancellations: number
    expirations: number
    revocations: number
    refunds: number
    onHold: number
    gracePeriods: number
    recoveries: number
    planChanges: number
  }
  verification: {
    verified: number
    rejected: number
    failures: number
    acknowledgeFailures: number
    reconciliationErrors: number
    pendingPurchases: number
    restores: number
  }
  paymentIssues: { googlePlay: number; paypal: number; other: number }
}

const DAY_MS = 86_400_000

const COUNTED: Record<string, [keyof BillingOps['lifecycle'] | keyof BillingOps['verification'], 'lifecycle' | 'verification']> = {
  'subscription.activated': ['activations', 'lifecycle'],
  'subscription.renewed': ['renewals', 'lifecycle'],
  'subscription.cancelled': ['cancellations', 'lifecycle'],
  'subscription.expired': ['expirations', 'lifecycle'],
  'subscription.access_ended': ['expirations', 'lifecycle'],
  'subscription.revoked': ['revocations', 'lifecycle'],
  'payment.refunded': ['refunds', 'lifecycle'],
  'subscription.on_hold': ['onHold', 'lifecycle'],
  'subscription.in_grace_period': ['gracePeriods', 'lifecycle'],
  'subscription.recovered': ['recoveries', 'lifecycle'],
  'subscription.upgraded': ['planChanges', 'lifecycle'],
  'subscription.downgraded': ['planChanges', 'lifecycle'],
  'subscription.replaced': ['planChanges', 'lifecycle'],
  'purchase.verified': ['verified', 'verification'],
  'purchase.rejected': ['rejected', 'verification'],
  'purchase.verification_failed': ['failures', 'verification'],
  'purchase.acknowledge_failed': ['acknowledgeFailures', 'verification'],
  'billing.reconciliation_error': ['reconciliationErrors', 'verification'],
  'purchase.pending': ['pendingPurchases', 'verification'],
  'restore.completed': ['restores', 'verification'],
}

export function buildBillingOps(input: {
  now: Date
  inbox: InboxRecord[]
  auditEvents: OpsAuditRecord[]
  subscriptions: OpsSubscriptionRecord[]
  windowDays?: number
}): BillingOps {
  const windowDays = input.windowDays ?? 30
  const since = input.now.getTime() - windowDays * DAY_MS
  const rtdn = input.inbox.filter((row) => String(row.event_id).startsWith('rtdn_'))
  const status = (row: InboxRecord) => String(row.status ?? 'processed').toLowerCase()
  const unprocessed = rtdn.filter((row) => status(row) === 'processing' || status(row) === 'failed')
  const byTime = (field: 'received_at' | 'claimed_at') => (a: InboxRecord, b: InboxRecord) =>
    (Date.parse(String(a[field] ?? '')) || 0) - (Date.parse(String(b[field] ?? '')) || 0)
  const latest = [...rtdn].sort(byTime('received_at')).pop() ?? null
  const latestError = [...rtdn].filter((row) => row.last_error && status(row) !== 'processed').sort(byTime('claimed_at')).pop() ?? null

  const lifecycle: BillingOps['lifecycle'] = { activations: 0, renewals: 0, cancellations: 0, expirations: 0, revocations: 0, refunds: 0, onHold: 0, gracePeriods: 0, recoveries: 0, planChanges: 0 }
  const verification: BillingOps['verification'] = { verified: 0, rejected: 0, failures: 0, acknowledgeFailures: 0, reconciliationErrors: 0, pendingPurchases: 0, restores: 0 }
  for (const event of input.auditEvents) {
    const at = Date.parse(event.created_at)
    if (!Number.isFinite(at) || at < since) continue
    const target = COUNTED[String(event.action ?? "")]
    if (!target) continue
    if (target[1] === 'lifecycle') lifecycle[target[0] as keyof BillingOps['lifecycle']] += 1
    else verification[target[0] as keyof BillingOps['verification']] += 1
  }

  const paymentIssues = { googlePlay: 0, paypal: 0, other: 0 }
  for (const sub of input.subscriptions) {
    const value = String(sub.status ?? '').toLowerCase()
    if (value !== 'past_due' && value !== 'pending_renewal') continue
    if (sub.provider === 'google_play') paymentIssues.googlePlay += 1
    else if (sub.provider === 'paypal') paymentIssues.paypal += 1
    else paymentIssues.other += 1
  }

  return {
    windowDays,
    inbox: {
      rtdnSeen: rtdn.length > 0,
      received: rtdn.filter((row) => (Date.parse(String(row.received_at ?? '')) || 0) >= since).length,
      processed: rtdn.filter((row) => status(row) === 'processed').length,
      processing: rtdn.filter((row) => status(row) === 'processing').length,
      failed: rtdn.filter((row) => status(row) === 'failed').length,
      deadLetter: rtdn.filter((row) => status(row) === 'dead_letter').length,
      oldestUnprocessedAt: [...unprocessed].sort(byTime('received_at'))[0]?.received_at ?? null,
      lastReceivedAt: latest?.received_at ?? null,
      lastError: latestError?.last_error ? latestError.last_error.slice(0, 200) : null,
    },
    lifecycle,
    verification,
    paymentIssues,
  }
}
