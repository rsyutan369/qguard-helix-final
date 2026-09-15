/**
 * Terms of Service — /terms
 *
 * Written against what the platform actually does: authenticated scanning of
 * infrastructure the customer controls, storage of the resulting cryptographic
 * inventory in Supabase, on-device-only encryption in Quantum Vault and Quantum
 * Messaging, and PayPal-billed subscriptions. Anything the service cannot do
 * (recover a lost Vault passphrase, guarantee a scan finds every algorithm) is
 * stated here rather than implied.
 */
import { Link } from 'react-router-dom';
import { LegalLayout, P, UL, LI, Term, Notice, type LegalSection } from './_legal-shared';
import { SITE, REFUND_POLICY, planPriceRows } from '@/lib/site-identity';

const SECTIONS: LegalSection[] = [
  {
    id: 'agreement',
    heading: 'Agreement to these terms',
    body: (
      <>
        <P>
          These Terms of Service govern your use of {SITE.productName} (the <Term>Service</Term>) — the web platform at{' '}
          {SITE.domain}, the QGuard Messaging and Quantum Vault desktop and mobile applications, the scanning agents, and
          the APIs. The Service is provided by {SITE.providerName}, an independent software provider operating from{' '}
          {SITE.city}, {SITE.province}, {SITE.country} (<Term>we</Term>, <Term>us</Term>).
        </P>
        <P>
          By creating an account, installing an agent or application, or paying for a subscription, you agree to these
          terms. If you are agreeing on behalf of an organisation, you confirm you are authorised to bind it, and{' '}
          <Term>you</Term> means that organisation.
        </P>
        <P>
          If you do not agree with these terms, do not use the Service. These terms work together with the{' '}
          <Link to="/privacy" className="font-semibold text-gold no-underline hover:underline">
            Privacy Policy
          </Link>{' '}
          and the{' '}
          <Link to="/refund" className="font-semibold text-gold no-underline hover:underline">
            Refund Policy
          </Link>
          , which form part of this agreement.
        </P>
      </>
    ),
  },
  {
    id: 'service',
    heading: 'What the Service does',
    body: (
      <>
        <P>The Service helps organisations find and migrate cryptography that quantum computers will eventually break. It provides:</P>
        <UL>
          <LI>
            <Term>Discovery and assessment</Term> — scanning of endpoints, certificates, source repositories and
            dependencies you identify, producing a cryptographic bill of materials (CBOM) and a quantum readiness score.
          </LI>
          <LI>
            <Term>Migration planning and operations</Term> — prioritised remediation plans, migration workflows,
            simulation sandboxes and rollback snapshots.
          </LI>
          <LI>
            <Term>Governance and reporting</Term> — compliance mapping, audit evidence, exportable reports and
            cryptographically signed readiness certificates.
          </LI>
          <LI>
            <Term>Quantum Messaging and Quantum Vault</Term> — end-to-end encrypted messaging, calls, and on-device file
            and folder encryption using post-quantum algorithms.
          </LI>
        </UL>
        <P>
          Features available to you depend on your subscription tier. We may add, change or withdraw features; where a
          change materially reduces what your paid tier includes, section 11 applies.
        </P>
      </>
    ),
  },
  {
    id: 'eligibility',
    heading: 'Accounts and eligibility',
    body: (
      <>
        <P>
          You must be at least 18 years old to hold an account. You are responsible for the accuracy of your registration
          details, for keeping your credentials and multi-factor authentication secret, and for all activity under your
          account.
        </P>
        <UL>
          <LI>Do not share credentials, and do not let more people use a seat than your tier allows.</LI>
          <LI>Tell us promptly at {SITE.supportEmail} if you believe your account has been compromised.</LI>
          <LI>
            Accounts are tenant-isolated. You must not attempt to reach another tenant's data, and you must not probe the
            Service's authorisation boundaries except under a written security-testing agreement with us.
          </LI>
        </UL>
      </>
    ),
  },
  {
    id: 'authorised-scanning',
    heading: 'Authorised scanning — your responsibility',
    body: (
      <>
        <Notice title="Read this before you scan anything" tone="gold">
          You may only scan systems you own or are explicitly authorised in writing to test. Scanning third-party
          infrastructure without permission may be unlawful in your jurisdiction and is a breach of these terms.
        </Notice>
        <P>
          The Service performs active network probing, certificate retrieval, repository analysis and agent-based
          inspection against the targets you supply. You are solely responsible for having the authority to submit each
          target, including targets belonging to your vendors, customers or cloud providers.
        </P>
        <UL>
          <LI>
            You warrant that every host, domain, repository, credential and cloud account you connect is one you are
            authorised to assess.
          </LI>
          <LI>
            You are responsible for any impact of a scan on your own systems, including rate-sensitive endpoints and
            production availability. Scan scheduling and scope controls are provided for this purpose.
          </LI>
          <LI>
            We may suspend scanning that appears unauthorised, abusive, or that threatens the stability of the Service or
            a third party.
          </LI>
        </UL>
      </>
    ),
  },
  {
    id: 'acceptable-use',
    heading: 'Acceptable use',
    body: (
      <>
        <P>You agree not to:</P>
        <UL>
          <LI>Use the Service to attack, disrupt or gain unauthorised access to any system.</LI>
          <LI>Reverse engineer, decompile or attempt to extract source code, except where that right cannot lawfully be excluded.</LI>
          <LI>Resell, sublicense or provide the Service to third parties as a service without our written agreement.</LI>
          <LI>Circumvent tier limits, licensing checks, quotas or subscription gating.</LI>
          <LI>Upload malware, or content that is unlawful or that you have no right to process.</LI>
          <LI>Use the Service to develop a competing product, or to benchmark it for publication without our consent.</LI>
        </UL>
        <P>
          We may suspend or terminate access for a material breach of this section, immediately where the breach creates
          legal risk or endangers other users.
        </P>
      </>
    ),
  },
  {
    id: 'subscriptions',
    heading: 'Subscriptions, billing and renewal',
    body: (
      <>
        <P>
          Paid tiers are billed in United States dollars through PayPal, which acts as the payment processor. Current
          list prices are:
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
        <UL>
          <LI>
            <Term>Automatic renewal.</Term> Subscriptions renew automatically at the end of each billing period —
            monthly or yearly, as you selected — until cancelled. PayPal charges the payment method on your PayPal
            account.
          </LI>
          <LI>
            <Term>Cancellation.</Term> You can cancel at any time from Settings → Billing, or from your PayPal account.
            Cancellation stops future charges; access continues to the {REFUND_POLICY.cancellationTakesEffect}.
          </LI>
          <LI>
            <Term>Refunds.</Term> The{' '}
            <Link to="/refund" className="font-semibold text-gold no-underline hover:underline">
              Refund Policy
            </Link>{' '}
            applies: a full refund is available within {REFUND_POLICY.initialWindowDays} days of your first payment for a
            plan.
          </LI>
          <LI>
            <Term>Price changes.</Term> We may change prices with at least 30 days' notice by email or in-product
            notification. A change takes effect at your next renewal; if you do not accept it, cancel before that date.
          </LI>
          <LI>
            <Term>Failed payments.</Term> If a renewal fails, the subscription moves to past-due, we notify you, and
            paid features may be suspended until payment succeeds.
          </LI>
          <LI>
            <Term>Taxes.</Term> Prices exclude any taxes that may apply where you are located; you are responsible for
            those.
          </LI>
        </UL>
      </>
    ),
  },
  {
    id: 'your-data',
    heading: 'Your data and our licence to use it',
    body: (
      <>
        <P>
          You keep all rights to the data you submit — asset inventories, scan results, telemetry, uploaded files,
          configuration and reports (<Term>Customer Data</Term>). You grant us a limited, non-exclusive licence to host,
          process and transmit Customer Data strictly to operate the Service for you, secure it, and provide support.
        </P>
        <P>
          We do not sell Customer Data, and we do not use it to train machine-learning models for other customers. How
          it is handled is described in the{' '}
          <Link to="/privacy" className="font-semibold text-gold no-underline hover:underline">
            Privacy Policy
          </Link>
          .
        </P>
        <P>
          You are responsible for having a lawful basis to submit any personal data contained in Customer Data, and for
          not submitting data you are not permitted to process.
        </P>
      </>
    ),
  },
  {
    id: 'zero-knowledge',
    heading: 'Zero-knowledge encryption — what we cannot recover',
    body: (
      <>
        <Notice title="No passphrase recovery" tone="cyan">
          Quantum Vault and Quantum Messaging encrypt on your device with keys derived from your passphrase or PIN. We
          never receive those keys. If you lose your passphrase and your recovery key, <Term>your data cannot be
          recovered by anyone, including us</Term>. This is a deliberate security property, not a limitation we can lift.
        </Notice>
        <UL>
          <LI>Generate and store your recovery key somewhere safe and offline before you rely on the Vault.</LI>
          <LI>Message content and call media are end-to-end encrypted; we cannot read them or produce their plaintext.</LI>
          <LI>Deleting a device or reinstalling without your recovery material may permanently end access to data sealed on it.</LI>
          <LI>Keeping your own backups of critical files is your responsibility.</LI>
        </UL>
      </>
    ),
  },
  {
    id: 'availability',
    heading: 'Availability, support and beta features',
    body: (
      <>
        <P>
          We aim to keep the Service available continuously, but we do not commit to a specific uptime percentage unless
          we have signed a separate written service level agreement with you. Maintenance, third-party outages (including
          Supabase, PayPal and cloud providers) and factors outside our control can interrupt access.
        </P>
        <UL>
          <LI>Support is provided by email at {SITE.supportEmail}, with a target first response within {SITE.supportResponseTarget}.</LI>
          <LI>
            Features labelled beta, preview or experimental are provided as-is, may change or be withdrawn, and should
            not be relied on for production decisions.
          </LI>
          <LI>We may perform maintenance that briefly interrupts scanning, telemetry or dashboards.</LI>
        </UL>
      </>
    ),
  },
  {
    id: 'accuracy',
    heading: 'Accuracy of findings — no security guarantee',
    body: (
      <>
        <P>
          The Service reports what it can observe and states the limits of each observation. It is a decision-support
          tool, not a guarantee of security or compliance.
        </P>
        <UL>
          <LI>
            A scan can miss cryptography it cannot reach — unreachable hosts, private repositories without credentials,
            binaries without symbols, or systems outside the scope you configured.
          </LI>
          <LI>
            Readiness scores, risk ratings and certificates describe evidence collected at a point in time. They are not
            a warranty that a system is secure, nor legal certification of compliance with any regulation.
          </LI>
          <LI>
            You remain responsible for your own security decisions, for validating findings, and for testing changes
            before applying them to production.
          </LI>
          <LI>
            Migration guidance, remediation playbooks and AI-assisted advice are recommendations. Review them before
            acting.
          </LI>
        </UL>
      </>
    ),
  },
  {
    id: 'ip',
    heading: 'Intellectual property',
    body: (
      <>
        <P>
          The Service, its software, detection rules, scoring models, documentation and branding remain our property and
          that of our licensors. These terms grant you a limited, revocable, non-transferable right to use the Service
          during your subscription, and nothing more.
        </P>
        <P>
          Reports, exports and certificates you generate from your own Customer Data are yours to use within your
          organisation and with your auditors and regulators.
        </P>
        <P>
          If you send us feedback or suggestions, we may use them without obligation or compensation to you.
        </P>
      </>
    ),
  },
  {
    id: 'changes',
    heading: 'Changes to these terms',
    body: (
      <>
        <P>
          We may update these terms as the Service evolves. The effective date at the top of this page always reflects
          the current version.
        </P>
        <UL>
          <LI>
            For material changes — those that reduce your rights or materially change what a paid tier includes — we will
            give at least 30 days' notice by email or in-product notification before they take effect.
          </LI>
          <LI>
            Continuing to use the Service after a change takes effect means you accept the updated terms. If you do not
            accept them, cancel your subscription before the effective date; the{' '}
            <Link to="/refund" className="font-semibold text-gold no-underline hover:underline">
              Refund Policy
            </Link>{' '}
            still applies to your most recent charge if it falls within the refund window.
          </LI>
        </UL>
      </>
    ),
  },
  {
    id: 'termination',
    heading: 'Suspension and termination',
    body: (
      <>
        <P>
          You may stop using the Service and delete your account at any time from Settings. We may suspend or terminate
          access if you materially breach these terms, if payment fails and remains unresolved, or if required by law.
        </P>
        <UL>
          <LI>
            On termination, paid features stop. You can export your reports and inventory before your access ends —
            export while your account is active.
          </LI>
          <LI>
            After account deletion we remove or anonymise Customer Data on the schedule described in the Privacy Policy,
            except records we must keep for tax, accounting or legal reasons.
          </LI>
          <LI>Sections on intellectual property, disclaimers, liability and governing law survive termination.</LI>
        </UL>
      </>
    ),
  },
  {
    id: 'liability',
    heading: 'Disclaimers and limitation of liability',
    body: (
      <>
        <P>
          To the fullest extent permitted by law, the Service is provided <Term>as is</Term> and{' '}
          <Term>as available</Term>, without warranties of any kind, whether express or implied, including merchantability,
          fitness for a particular purpose and non-infringement.
        </P>
        <P>
          To the fullest extent permitted by law, we are not liable for indirect, incidental, special, consequential or
          punitive damages, nor for lost profits, lost data, or business interruption, arising out of or relating to your
          use of the Service.
        </P>
        <P>
          Our total aggregate liability arising out of or relating to the Service is limited to the amount you actually
          paid us for the Service in the twelve months immediately before the event giving rise to the claim.
        </P>
        <P>
          Nothing in these terms excludes or limits liability that cannot lawfully be excluded or limited, including
          liability for fraud, or any consumer rights you have under Philippine law that cannot be waived.
        </P>
      </>
    ),
  },
  {
    id: 'governing-law',
    heading: 'Governing law and disputes',
    body: (
      <>
        <P>
          These terms are governed by the laws of {SITE.jurisdiction}, without regard to conflict-of-law rules. You and
          we submit to the exclusive jurisdiction of {SITE.courts}, except that either party may seek injunctive relief
          in any competent court to protect its intellectual property or confidential information.
        </P>
        <P>
          Before filing a claim, contact us at {SITE.supportEmail} so we can try to resolve the matter directly. Most
          issues are resolved this way.
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
          Questions, notices and legal correspondence about these terms should go to {SITE.supportEmail}, or through the{' '}
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

export default function TermsPage() {
  return (
    <LegalLayout
      kicker="Legal // Terms of Service"
      title="Terms of Service"
      summary={[
        'You may only scan systems you own or have written permission to test — that responsibility is yours, not ours.',
        'Subscriptions renew automatically until you cancel, and you can cancel any time from Settings → Billing or in PayPal.',
        'Quantum Vault and Quantum Messaging are zero-knowledge: if you lose your passphrase and recovery key, nobody — including us — can recover your data.',
        'Scan results and readiness scores are evidence-based decision support, not a guarantee that a system is secure or compliant.',
      ]}
      sections={SECTIONS}
    />
  );
}
