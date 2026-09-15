/**
 * Refund Policy — /refund
 *
 * PayPal requires a published, reachable refund policy for a recurring-billing
 * merchant, and the Terms link here for the commercial detail. Every number in
 * this document (window length, processing time, whether renewals refund) comes
 * from REFUND_POLICY in src/lib/site-identity.ts, and every price from
 * src/lib/billing/plan-pricing.ts, so the policy cannot drift from what the
 * billing code actually does.
 */
import { Link } from 'react-router-dom';
import { LegalLayout, P, UL, LI, Term, Notice, type LegalSection } from './_legal-shared';
import { SITE, REFUND_POLICY, planPriceRows } from '@/lib/site-identity';

const SECTIONS: LegalSection[] = [
  {
    id: 'scope',
    heading: 'What this policy covers',
    body: (
      <>
        <P>
          This policy applies to every subscription to {SITE.productName} purchased from {SITE.providerName} and billed
          through PayPal. It forms part of the{' '}
          <Link to="/terms" className="font-semibold text-gold no-underline hover:underline">
            Terms of Service
          </Link>
          ; where the two documents describe the same thing, this one governs refunds.
        </P>
        <P>
          It does not cover purchases made through a third party — for example a subscription bought inside the Android
          app through Google Play. Those are refunded under that store&rsquo;s own policy, and you should raise the
          request there first.
        </P>
      </>
    ),
  },
  {
    id: 'window',
    heading: `Your ${REFUND_POLICY.initialWindowDays}-day money-back window`,
    body: (
      <>
        <Notice title="The short version">
          If the platform is not what you needed, tell us within {REFUND_POLICY.initialWindowDays} days of your{' '}
          <Term>first payment</Term> for a plan and we refund that payment in full. You do not have to justify the
          request.
        </Notice>
        <UL>
          <LI>
            <Term>What qualifies.</Term> The first charge on a plan — the initial monthly or yearly payment taken when
            you subscribe, or when you move up to a higher tier for the first time.
          </LI>
          <LI>
            <Term>How long you have.</Term> {REFUND_POLICY.initialWindowDays} calendar days from the date PayPal took
            that payment, not from the date you first used the platform.
          </LI>
          <LI>
            <Term>How much comes back.</Term> The full amount charged. We do not pro-rate the days you used, and we do
            not deduct a handling fee.
          </LI>
          <LI>
            <Term>What happens to the subscription.</Term> A refund cancels the subscription. Paid features stop, and
            your tenant drops to the free surface as described below.
          </LI>
        </UL>
      </>
    ),
  },
  {
    id: 'renewals',
    heading: 'Renewal charges',
    body: (
      <>
        <P>
          Subscriptions renew automatically until you cancel. Renewal charges are{' '}
          <Term>{REFUND_POLICY.renewalsRefundable ? 'refundable' : 'not refundable'}</Term> — the money-back window
          applies to your first payment for a plan, not to each period after it.
        </P>
        <P>
          Cancelling is how you stop a renewal, and it is free and immediate to do. Cancel at any time before the
          renewal date from <Term>Settings → Billing</Term> in the platform, or from the subscriptions section of your
          PayPal account. Access continues to the {REFUND_POLICY.cancellationTakesEffect} you have already paid for —
          cancelling does not cut you off early.
        </P>
        <Notice tone="cyan" title="Renewal reminder">
          PayPal shows the next billing date on the subscription record in your PayPal account, and the same date
          appears in Settings → Billing. If you do not intend to continue, cancel before that date rather than after it.
        </Notice>
      </>
    ),
  },
  {
    id: 'exceptions',
    heading: 'When we refund outside the window',
    body: (
      <>
        <P>
          The {REFUND_POLICY.initialWindowDays}-day window is a floor, not a ceiling. We will refund a charge outside it
          in these situations:
        </P>
        <UL>
          <LI>
            <Term>Duplicate charge.</Term> The same subscription was billed twice for the same period.
          </LI>
          <LI>
            <Term>Charge after cancellation.</Term> A renewal was taken after you had already cancelled.
          </LI>
          <LI>
            <Term>Billing error on our side.</Term> You were charged the wrong amount, or charged for a tier you did not
            select.
          </LI>
          <LI>
            <Term>Extended unavailability.</Term> A fault on our side made the paid features unusable for a sustained
            period and we could not resolve it — we refund the affected period.
          </LI>
        </UL>
        <P>
          These are handled on request and are not limited by the {REFUND_POLICY.initialWindowDays}-day clock. Nothing
          in this policy limits rights you have under the consumer law of {SITE.jurisdiction} or of the country you live
          in.
        </P>
      </>
    ),
  },
  {
    id: 'not-refundable',
    heading: 'What is not refundable',
    body: (
      <>
        <UL>
          <LI>Renewal charges, except in the situations listed in the section above.</LI>
          <LI>
            A period you used and then cancelled partway through — cancellation stops the next charge rather than
            refunding the current one.
          </LI>
          <LI>
            A subscription terminated for breach of the{' '}
            <Link to="/terms#acceptable-use" className="font-semibold text-gold no-underline hover:underline">
              acceptable use
            </Link>{' '}
            or{' '}
            <Link to="/terms#authorised-scanning" className="font-semibold text-gold no-underline hover:underline">
              authorised scanning
            </Link>{' '}
            clauses — for example scanning infrastructure you have no permission to test.
          </LI>
          <LI>
            Dissatisfaction with a finding, score or grade that the platform reported accurately. Scan results are
            evidence-based decision support; a result you did not want is not a defect. If you believe a result is
            wrong, send us the evidence and we will investigate it as a bug.
          </LI>
        </UL>
      </>
    ),
  },
  {
    id: 'how-to-request',
    heading: 'How to request a refund',
    body: (
      <>
        <P>
          Email{' '}
          <a href={`mailto:${SITE.supportEmail}`} className="font-semibold text-gold no-underline hover:underline">
            {SITE.supportEmail}
          </a>{' '}
          with the subject <Term>Refund request</Term>, or use the{' '}
          <Link to="/contact" className="font-semibold text-gold no-underline hover:underline">
            contact page
          </Link>
          . Include:
        </P>
        <UL>
          <LI>The email address on the account.</LI>
          <LI>The PayPal transaction ID or subscription ID of the charge.</LI>
          <LI>The plan and billing cycle (for example Pro, yearly).</LI>
          <LI>Optionally, what did not work for you — it is not required, but it is how the product improves.</LI>
        </UL>
        <P>You do not need to cancel first. An approved refund cancels the subscription as part of processing it.</P>
      </>
    ),
  },
  {
    id: 'processing',
    heading: 'How long it takes',
    body: (
      <>
        <UL>
          <LI>
            <Term>Acknowledgement.</Term> We reply within {SITE.supportResponseTarget}, confirming the request or asking
            for the transaction details we are missing.
          </LI>
          <LI>
            <Term>Issuing.</Term> Approved refunds are issued through PayPal within {REFUND_POLICY.processingDays}{' '}
            business days of approval.
          </LI>
          <LI>
            <Term>Arrival.</Term> The money returns to the funding source PayPal charged — a PayPal balance, bank
            account or card. How long it then takes to appear is set by PayPal and your bank or card issuer, not by us.
          </LI>
          <LI>
            <Term>Currency.</Term> Refunds are issued in United States dollars, the currency of the original charge. If
            your account is in another currency, your provider&rsquo;s exchange rate on the refund date applies, so the
            amount you receive can differ slightly from what you paid.
          </LI>
        </UL>
      </>
    ),
  },
  {
    id: 'after-refund',
    heading: 'What happens to your data after a refund',
    body: (
      <>
        <P>
          A refund ends the paid subscription. Your account itself is not deleted: you keep access to the free surface,
          and your scan history, cryptographic inventory and reports remain in your tenant so you can export them.
        </P>
        <P>
          Paid-tier features stop working immediately — scheduled scans, agent collection, exports and the dashboards
          gated to your former tier. Retention and deletion of everything already stored is governed by the{' '}
          <Link to="/privacy#retention" className="font-semibold text-gold no-underline hover:underline">
            Privacy Policy
          </Link>
          , and you can ask us to delete the account entirely at any time.
        </P>
        <Notice title="Zero-knowledge data">
          Quantum Vault files and QGuard Messaging content are encrypted on your device. We cannot read them, and a
          refund does not give us the ability to recover them. Export anything you need from those apps before you
          uninstall them.
        </Notice>
      </>
    ),
  },
  {
    id: 'chargebacks',
    heading: 'Disputes and chargebacks',
    body: (
      <>
        <P>
          If you disagree with our decision on a request, reply to the same thread and ask for it to be reviewed. We
          would rather resolve it directly than through a dispute.
        </P>
        <P>
          You keep the right to open a dispute in PayPal&rsquo;s Resolution Center or with your card issuer. We respond
          to those with the account, subscription and correspondence records. Accounts with an unresolved chargeback may
          be suspended until it is settled.
        </P>
      </>
    ),
  },
  {
    id: 'prices',
    heading: 'Prices this policy applies to',
    body: (
      <>
        <P>
          Current list prices, billed in United States dollars. A yearly plan is a single charge covering twelve months.
        </P>
        <div className="mb-4 overflow-x-auto">
          <table className="w-full min-w-[26rem] border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 font-mono text-[10px] uppercase tracking-wider text-slate-500">
                <th className="py-2 pr-4 font-bold">Plan</th>
                <th className="py-2 pr-4 font-bold">Monthly</th>
                <th className="py-2 font-bold">Yearly</th>
              </tr>
            </thead>
            <tbody>
              {planPriceRows().map((row) => (
                <tr key={row.tier} className="border-b border-slate-100 last:border-0">
                  <td className="py-2.5 pr-4 font-semibold text-slate-900">{row.tier}</td>
                  <td className="py-2.5 pr-4 font-mono text-slate-600">{row.monthly}</td>
                  <td className="py-2.5 font-mono text-slate-600">{row.yearly}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <P>
          Prices exclude any taxes that apply where you are located. Where tax was added to a charge, it is refunded
          with it.
        </P>
      </>
    ),
  },
  {
    id: 'changes',
    heading: 'Changes to this policy',
    body: (
      <>
        <P>
          We may update this policy. The version in force for a given charge is the one published on the date that
          charge was taken, so a change never shortens the window on a payment you have already made.
        </P>
        <P>
          Material changes are announced by email or in-product notification before they take effect, and the effective
          date at the top of this page is updated.
        </P>
      </>
    ),
  },
  {
    id: 'contact',
    heading: 'Contact',
    body: (
      <>
        <P>
          Refund and billing enquiries:{' '}
          <a href={`mailto:${SITE.supportEmail}`} className="font-semibold text-gold no-underline hover:underline">
            {SITE.supportEmail}
          </a>{' '}
          or the{' '}
          <Link to="/contact" className="font-semibold text-gold no-underline hover:underline">
            contact page
          </Link>
          .
        </P>
        <P>
          {SITE.providerName} — {SITE.city}, {SITE.province}, {SITE.country}. Web: {SITE.domain}
        </P>
      </>
    ),
  },
];

export default function RefundPage() {
  return (
    <LegalLayout
      kicker="Legal // Refund Policy"
      title="Refund Policy"
      summary={[
        `Full refund on your first payment for a plan if you ask within ${REFUND_POLICY.initialWindowDays} days — no reason required.`,
        'Renewal charges are not refundable, so cancel before a renewal date to stop it; access runs to the end of the period you paid for.',
        'Duplicate charges, charges after cancellation and billing errors are refunded whenever they happen, not just inside the window.',
        `Approved refunds are issued through PayPal within ${REFUND_POLICY.processingDays} business days.`,
      ]}
      sections={SECTIONS}
    />
  );
}
