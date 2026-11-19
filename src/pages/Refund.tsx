/**
 * Refund Policy — /refund
 *
 * PayPal requires a published, reachable refund policy for a recurring-billing
 * merchant, and the Terms link here for the commercial detail. Every number in
 * this document (money-back guarantee, processing time, whether renewals refund) comes
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
          app through Google Play. Those are refunded under Google Play&rsquo;s own refund policy, and you should raise
          the request there first. When Google Play refunds or revokes a purchase, your subscription is updated
          automatically.
        </P>
      </>
    ),
  },
  {
    id: 'window',
    heading: 'Paid plans, no trial, no money-back guarantee',
    body: (
      <>
        <Notice title="The short version">
          Every plan is paid from the first day. There is no free trial and{' '}
          <Term>{REFUND_POLICY.moneyBackGuarantee ? 'a' : 'no'} promotional money-back guarantee</Term>. Cancel any time
          to stop the next renewal; you keep access to the {REFUND_POLICY.cancellationTakesEffect}.
        </Notice>
        <UL>
          <LI>
            <Term>Your legal rights are unaffected.</Term> Not offering a money-back guarantee does not limit any refund
            right you have under the consumer law of {SITE.jurisdiction} or of the country you live in, or under an app
            store&rsquo;s refund policy.
          </LI>
          <LI>
            <Term>Errors are always corrected.</Term> Duplicate charges, charges after cancellation and billing errors
            are refunded whenever they happen — see below.
          </LI>
          <LI>
            <Term>What a refund does to the subscription.</Term> A full refund of your first payment for a plan cancels
            the subscription, because that plan was never paid for. Refunds of a later period correct that charge and
            leave the subscription running.
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
          <Term>{REFUND_POLICY.renewalsRefundable ? 'refundable' : 'not refundable'}</Term>, except for the errors
          listed below or where the law requires a refund.
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
    heading: 'When we refund',
    body: (
      <>
        <P>We refund a charge, whenever it was taken, in these situations:</P>
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
          These are handled on request, with no time limit. Nothing in this policy limits rights you have under the
          consumer law of {SITE.jurisdiction} or of the country you live in.
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
          <LI>A change of mind after paying — there is no money-back guarantee, so cancel to stop the next renewal.</LI>
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
        <P>You do not need to cancel first. A full refund of a first payment cancels the subscription as part of processing it.</P>
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
          A refund that cancels the subscription ends paid access. Your account itself is not deleted: you can still
          sign in, see your billing history and subscribe again, and your scan history, cryptographic inventory and
          reports remain in your tenant.
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
          refund does not give us the ability to recover them. A refund or an expired subscription never deletes the
          files on your device.
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
          charge was taken, so a change never removes a refund that applied to a payment you have already made.
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
        'All plans are paid: no free trial and no promotional money-back guarantee. Your legal and app-store refund rights are unaffected.',
        'Renewal charges are not refundable, so cancel before a renewal date to stop it; access runs to the end of the period you paid for.',
        'Duplicate charges, charges after cancellation and billing errors are refunded whenever they happen, not just inside the window.',
        `Approved refunds are issued through PayPal within ${REFUND_POLICY.processingDays} business days.`,
      ]}
      sections={SECTIONS}
    />
  );
}
