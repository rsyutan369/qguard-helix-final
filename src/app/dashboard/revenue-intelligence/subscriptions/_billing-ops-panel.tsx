import { Inbox, ShieldAlert } from 'lucide-react';
import { AMBER, CYAN, EMERALD, RED, SLATE, Panel, SectionTitle } from '@/app/dashboard/quantum-readiness/_shared';
import type { BillingOps } from '@/lib/billing/billing-ops';
import { countFmt, dateFmt, timeAgo } from '../_shared';

function Tile({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-2">
      <span className="inline-flex items-center gap-2 text-[11px] text-white/65">
        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} aria-hidden="true" />
        {label}
      </span>
      <span className="font-mono text-sm font-bold text-white/90">{countFmt(value)}</span>
    </div>
  );
}

/**
 * Store-lifecycle and Google Play RTDN pipeline health (Qguard_Wiki/GooglePlay_Billing §14.1).
 * Every figure is a count of real rows: the RTDN inbox (play_webhook_events)
 * and the billing audit trail. Nothing is estimated.
 */
export function BillingOpsPanel({ ops }: { ops: BillingOps }) {
  const inbox = ops.inbox;
  const backlog = inbox.processing + inbox.failed;
  const days = ops.windowDays;
  const issues = ops.paymentIssues.googlePlay + ops.paymentIssues.paypal + ops.paymentIssues.other;
  return (
    <div className="grid gap-3 xl:grid-cols-3">
      <Panel className="p-4">
        <SectionTitle suffix={<Inbox size={14} aria-hidden="true" />}>Google Play notifications (RTDN)</SectionTitle>
        {!inbox.rtdnSeen ? (
          <p className="text-[11px] leading-relaxed text-white/55">
            No Google Play Real-Time Developer Notification has been received yet. Renewals, cancellations, refunds and
            expirations from Google Play appear here once Pub/Sub push delivery to the billing service is configured.
          </p>
        ) : (
          <div className="grid grid-cols-2 gap-2">
            <Tile label={`Received (${days}d)`} value={inbox.received} color={CYAN} />
            <Tile label="Processed" value={inbox.processed} color={EMERALD} />
            <Tile label="Pending / retrying" value={backlog} color={backlog > 0 ? AMBER : SLATE} />
            <Tile label="Dead-lettered" value={inbox.deadLetter} color={inbox.deadLetter > 0 ? RED : SLATE} />
          </div>
        )}
        <p className="mt-3 text-[10px] text-white/35">
          {inbox.lastReceivedAt ? `Last notification ${timeAgo(inbox.lastReceivedAt)}.` : 'Awaiting first notification.'}
          {inbox.oldestUnprocessedAt ? ` Oldest unprocessed since ${dateFmt(inbox.oldestUnprocessedAt)}.` : ''}
        </p>
        {inbox.lastError && (
          <p className="mt-2 break-words text-[10px] leading-relaxed" style={{ color: RED }}>
            Last processing error: {inbox.lastError}
          </p>
        )}
      </Panel>
      <Panel className="p-4">
        <SectionTitle>{`Lifecycle events (${days} days)`}</SectionTitle>
        <div className="grid grid-cols-2 gap-2">
          <Tile label="New subscriptions" value={ops.lifecycle.activations} color={EMERALD} />
          <Tile label="Renewals" value={ops.lifecycle.renewals} color={EMERALD} />
          <Tile label="Cancellations" value={ops.lifecycle.cancellations} color={SLATE} />
          <Tile label="Expired" value={ops.lifecycle.expirations} color={AMBER} />
          <Tile label="Refunds" value={ops.lifecycle.refunds} color={AMBER} />
          <Tile label="Revocations" value={ops.lifecycle.revocations} color={RED} />
          <Tile label="Grace period / on hold" value={ops.lifecycle.gracePeriods + ops.lifecycle.onHold} color={AMBER} />
          <Tile label="Plan changes" value={ops.lifecycle.planChanges} color={CYAN} />
        </div>
      </Panel>
      <Panel className="p-4">
        <SectionTitle suffix={<ShieldAlert size={14} aria-hidden="true" />}>{`Verification & reconciliation (${days}d)`}</SectionTitle>
        <div className="grid grid-cols-2 gap-2">
          <Tile label="Purchases verified" value={ops.verification.verified} color={EMERALD} />
          <Tile label="Rejected purchases" value={ops.verification.rejected} color={ops.verification.rejected > 0 ? RED : SLATE} />
          <Tile label="Verification failures" value={ops.verification.failures} color={ops.verification.failures > 0 ? AMBER : SLATE} />
          <Tile label="Acknowledge failures" value={ops.verification.acknowledgeFailures} color={ops.verification.acknowledgeFailures > 0 ? RED : SLATE} />
          <Tile label="Reconciliation errors" value={ops.verification.reconciliationErrors} color={ops.verification.reconciliationErrors > 0 ? RED : SLATE} />
          <Tile label="Payment issues now" value={issues} color={issues > 0 ? AMBER : SLATE} />
        </div>
        <p className="mt-3 text-[10px] text-white/35">
          Payment issues: {countFmt(ops.paymentIssues.googlePlay)} Google Play · {countFmt(ops.paymentIssues.paypal)} PayPal (grace period or on hold).
        </p>
      </Panel>
    </div>
  );
}
