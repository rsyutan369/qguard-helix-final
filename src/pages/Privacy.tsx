/**
 * Privacy Policy — /privacy
 *
 * Describes what the platform genuinely collects, verified against the code:
 * Supabase-backed accounts and tenant data, scan/CBOM/telemetry records, audit
 * logs that store IP address and user agent, PayPal as the payment processor
 * (no card data ever reaches us), zero-knowledge Vault/Messaging content we
 * cannot read, and NO third-party advertising or analytics trackers — there is
 * no analytics SDK in the codebase, so this document does not claim one.
 */
import { Link } from 'react-router-dom';
import { LegalLayout, P, UL, LI, Term, Notice, type LegalSection } from './_legal-shared';
import { SITE } from '@/lib/site-identity';

const SECTIONS: LegalSection[] = [
  {
    id: 'scope',
    heading: 'Who this policy covers',
    body: (
      <>
        <P>
          This policy explains how {SITE.providerName} handles personal data when you use {SITE.productName} — the
          platform at {SITE.domain}, the QGuard Messaging and Quantum Vault applications, the scanning agents, and the
          APIs.
        </P>
        <P>
          We are the controller of the account and billing data described below. For the cryptographic inventory,
          telemetry and files you put into the platform (<Term>Customer Data</Term>), you are the controller and we act
          as your processor, handling it only to run the Service for you.
        </P>
        <P>
          Questions, access requests and complaints: {SITE.privacyEmail}. We are based in {SITE.city}, {SITE.province},{' '}
          {SITE.country}.
        </P>
      </>
    ),
  },
  {
    id: 'what-we-collect',
    heading: 'What we collect',
    body: (
      <>
        <P>
          <Term>Account data.</Term> Email address, display name, password hash (we never see your password in the
          clear), multi-factor authentication settings, subscription tier, and profile details you choose to add such as
          an avatar or organisation name.
        </P>
        <P>
          <Term>Billing data.</Term> Subscription plan, billing cycle, status, renewal date, invoice records and the
          PayPal subscription and transaction identifiers. Payment card and PayPal login details are handled entirely by
          PayPal — <Term>they never reach our servers</Term>.
        </P>
        <P>
          <Term>Customer Data from scanning.</Term> The assets, hostnames, certificates, algorithms, key sizes,
          repositories, dependency manifests, findings, migration records and telemetry produced when you scan systems
          you control. This can include IP addresses and hostnames of your own infrastructure.
        </P>
        <P>
          <Term>Security and audit data.</Term> Sign-in events, device and session records, and audit log entries for
          sensitive actions. These include your <Term>IP address</Term> and <Term>browser user agent</Term>, which we
          keep to detect unauthorised access and to give you an audit trail.
        </P>
        <P>
          <Term>Support and contact data.</Term> Your name, email, organisation and the message you send through the
          contact page or by email.
        </P>
        <P>
          <Term>Technical logs.</Term> Server logs needed to operate and debug the Service, such as request paths, error
          traces and timestamps.
        </P>
      </>
    ),
  },
  {
    id: 'zero-knowledge',
    heading: 'What we deliberately cannot see',
    body: (
      <>
        <Notice title="End-to-end encrypted by design" tone="cyan">
          Quantum Vault file contents, Quantum Messaging message bodies, and voice and video call media are encrypted on
          your device with keys we never receive. We cannot read them, cannot produce their plaintext for anyone, and
          cannot recover them if you lose your passphrase and recovery key.
        </Notice>
        <P>What we do hold for those features is limited to what delivery and sync require:</P>
        <UL>
          <LI>Ciphertext, which is meaningless without keys held only on your devices.</LI>
          <LI>Public key material and device identifiers used to establish trust between your devices and your contacts.</LI>
          <LI>Metadata such as message timestamps, sender and recipient account identifiers, delivery state and file sizes.</LI>
        </UL>
        <P>
          Public scans run from the marketing site are logged as target host plus outcome only — we do not attach them to
          a visitor identity.
        </P>
      </>
    ),
  },
  {
    id: 'why-we-use-it',
    heading: 'Why we use it, and our legal basis',
    body: (
      <>
        <UL>
          <LI>
            <Term>To provide the Service</Term> — authenticate you, run scans you request, store your inventory, produce
            reports. Basis: performance of our contract with you.
          </LI>
          <LI>
            <Term>To take payment</Term> — create and manage subscriptions, record invoices, handle refunds. Basis:
            performance of our contract, and legal obligations for financial records.
          </LI>
          <LI>
            <Term>To keep accounts secure</Term> — detect unauthorised access, maintain audit trails, enforce tenant
            isolation and rate limits. Basis: our legitimate interest in securing the Service, and yours in a protected
            account.
          </LI>
          <LI>
            <Term>To support you</Term> — answer enquiries and diagnose problems you report. Basis: performance of our
            contract and our legitimate interest in supporting customers.
          </LI>
          <LI>
            <Term>To meet legal obligations</Term> — tax and accounting records, and lawful requests from competent
            authorities. Basis: legal obligation.
          </LI>
        </UL>
        <P>
          We do not use Customer Data to train machine-learning models for other customers, and we do not sell personal
          data to anyone.
        </P>
      </>
    ),
  },
  {
    id: 'ai-features',
    heading: 'AI-assisted features',
    body: (
      <>
        <P>
          The platform includes AI-assisted advisory features (for example the Sophia security copilot and the advisory
          report narratives). When you use them, the relevant context from your tenant — such as findings, asset
          summaries and posture scores — is processed to generate a response.
        </P>
        <UL>
          <LI>These features run on your own tenant's data, scoped by the same tenant isolation as the rest of the platform.</LI>
          <LI>Outputs are recommendations for you to review, not automated decisions with legal effect.</LI>
          <LI>Your Customer Data is not used to train models offered to other customers.</LI>
        </UL>
      </>
    ),
  },
  {
    id: 'sharing',
    heading: 'Who we share data with',
    body: (
      <>
        <P>We share personal data only with the service providers needed to run the platform, and only as far as needed:</P>
        <UL>
          <LI>
            <Term>Supabase</Term> — database, authentication and storage for accounts and Customer Data.
          </LI>
          <LI>
            <Term>PayPal</Term> — subscription billing and payment processing. PayPal is an independent controller of the
            payment data you give it; its own privacy notice applies.
          </LI>
          <LI>
            <Term>Google Play</Term> — only where you purchase a subscription through the Android app, for purchase
            verification.
          </LI>
          <LI>
            <Term>Cloudflare</Term> — network delivery and TLS termination for {SITE.domain}.
          </LI>
          <LI>
            <Term>Hosting and infrastructure providers</Term> — to run the application servers.
          </LI>
        </UL>
        <P>
          We may also disclose data where required by law, to enforce our terms, or to protect the rights and safety of
          users. If the business is ever transferred, we will give notice before your data becomes subject to a different
          privacy policy.
        </P>
        <P>
          <Term>No advertising or analytics trackers.</Term> The platform does not embed third-party advertising
          networks, analytics SDKs or cross-site tracking pixels.
        </P>
      </>
    ),
  },
  {
    id: 'international',
    heading: 'International transfers',
    body: (
      <P>
        We operate from {SITE.country}, and our providers — including Supabase, PayPal and Cloudflare — process data on
        infrastructure that may be located outside it. Where personal data moves across borders, we rely on the
        providers' contractual data protection commitments and take reasonable steps to ensure a comparable level of
        protection, as required by the Philippine Data Privacy Act.
      </P>
    ),
  },
  {
    id: 'retention',
    heading: 'How long we keep it',
    body: (
      <>
        <UL>
          <LI>
            <Term>Account data</Term> — while your account exists, and for a short wind-down period after deletion.
          </LI>
          <LI>
            <Term>Customer Data (scans, inventory, telemetry, reports)</Term> — for the retention period of your
            subscription tier, and removed or anonymised after account deletion.
          </LI>
          <LI>
            <Term>Billing records (invoices, refunds)</Term> — kept as long as tax and accounting law requires, even
            after account deletion.
          </LI>
          <LI>
            <Term>Security and audit logs</Term> — kept for a limited period appropriate to investigating incidents.
          </LI>
          <LI>
            <Term>Encrypted Vault and message content</Term> — until you or your retention settings delete it;
            disappearing messages are removed on their timer.
          </LI>
        </UL>
      </>
    ),
  },
  {
    id: 'your-rights',
    heading: 'Your rights',
    body: (
      <>
        <P>
          Under the Philippine Data Privacy Act of 2012 — and, where they apply to you, comparable laws such as the GDPR
          — you have the right to be informed, to access your data, to correct it, to object to certain processing, to
          request erasure or blocking, to data portability, and to damages for a violation.
        </P>
        <UL>
          <LI>Much of this is self-service: review and edit your profile, export reports and inventory, and delete your account from Settings.</LI>
          <LI>
            For anything else, email {SITE.privacyEmail}. We will respond within 30 days and may need to verify your
            identity first.
          </LI>
          <LI>
            You can complain to the National Privacy Commission of the Philippines if you believe we have mishandled your
            data. We would appreciate the chance to put it right first.
          </LI>
        </UL>
        <P>
          Note the limit set by the encryption design: we can delete your encrypted content, but we cannot produce,
          decrypt or export the plaintext of zero-knowledge Vault files or end-to-end encrypted messages, because we do
          not hold the keys.
        </P>
      </>
    ),
  },
  {
    id: 'cookies',
    heading: 'Cookies and local storage',
    body: (
      <>
        <P>We use only what the product needs to function:</P>
        <UL>
          <LI>
            <Term>Authentication cookies and tokens</Term> — keep you signed in and protect the session. Without these
            you cannot use an account.
          </LI>
          <LI>
            <Term>Local storage</Term> — remembers interface preferences and, briefly, a pending checkout intent so it
            survives sign-in.
          </LI>
          <LI>
            <Term>Desktop and mobile applications</Term> — store encrypted keys and settings in the platform keystore or
            an encrypted file on your own device.
          </LI>
        </UL>
        <P>We do not set advertising or cross-site tracking cookies.</P>
      </>
    ),
  },
  {
    id: 'security',
    heading: 'How we protect data',
    body: (
      <>
        <UL>
          <LI>TLS in transit, with post-quantum hybrid key exchange where the client supports it.</LI>
          <LI>End-to-end and on-device encryption for Vault and Messaging content, using ML-KEM and ML-DSA with AES-256-GCM.</LI>
          <LI>Row-level security in the database and server-side tenant isolation on every request.</LI>
          <LI>Role-based access control, optional multi-factor authentication, and audit logging of sensitive actions.</LI>
          <LI>Secrets and service keys held server-side only and never exposed to the browser.</LI>
        </UL>
        <P>
          No system is perfectly secure. If a breach affects your personal data, we will notify you and the National
          Privacy Commission as the law requires. Report a suspected vulnerability to {SITE.supportEmail}.
        </P>
      </>
    ),
  },
  {
    id: 'children',
    heading: "Children's data",
    body: (
      <P>
        The Service is for business and professional use and is not directed at children. We do not knowingly collect
        personal data from anyone under 18. If you believe a child has given us data, contact {SITE.privacyEmail} and we
        will delete it.
      </P>
    ),
  },
  {
    id: 'changes',
    heading: 'Changes to this policy',
    body: (
      <P>
        We will update this policy as the platform changes. The effective date at the top always reflects the current
        version, and we will give notice by email or in-product notification before a material change takes effect.
        Continuing to use the Service after that date means you accept the updated policy.
      </P>
    ),
  },
  {
    id: 'contact',
    heading: 'Contact us',
    body: (
      <>
        <P>
          Privacy questions, data requests and complaints: {SITE.privacyEmail}, or use the{' '}
          <Link to="/contact" className="font-semibold text-gold no-underline hover:underline">
            contact page
          </Link>
          .
        </P>
        <P>
          {SITE.providerName} — {SITE.city}, {SITE.province}, {SITE.country}.
        </P>
      </>
    ),
  },
];

export default function PrivacyPage() {
  return (
    <LegalLayout
      kicker="Legal // Privacy Policy"
      title="Privacy Policy"
      summary={[
        'We collect what the platform needs: your account, your billing record, the scan data you create, and security logs that include your IP address and user agent.',
        'Vault files, messages and calls are end-to-end encrypted — we hold ciphertext and cannot read or recover their contents.',
        'Payment details go to PayPal directly and never reach our servers.',
        'No advertising networks, no analytics SDKs, no cross-site tracking, and we never sell your data.',
      ]}
      sections={SECTIONS}
    />
  );
}
