/**
 * Contact — /contact
 *
 * The reachable support surface the Terms, Privacy Policy and Refund Policy all
 * point at, and the one PayPal expects a recurring-billing merchant to publish.
 *
 * The composer below is deliberately a MAILTO builder, not a fake form: there is
 * no transactional-mail service wired into this codebase, so a Send button that
 * POSTed somewhere would either drop the message or need an inbox nobody reads.
 * Instead the page assembles a correctly-routed, pre-filled message and hands it
 * to the sender's own mail client, with a copy-to-clipboard fallback for anyone
 * without one — every path here actually delivers.
 *
 * Every address, location and response target comes from src/lib/site-identity.ts.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import { Mail, CreditCard, ShieldCheck, Scale, LifeBuoy, MapPin, Clock, Copy, Check, ExternalLink } from 'lucide-react';
import { SolutionLayout, Reveal } from './_solution-shared';
import { NAV_LINKS } from './_legal-shared';
import { SITE, REFUND_POLICY, formatLegalDate } from '@/lib/site-identity';

/**
 * Enquiry routing. One mailbox receives everything, so the subject prefix is
 * what actually routes the message — keep these prefixes stable and filter on
 * them in the mailbox rather than inventing addresses that do not exist.
 */
type Topic = {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  blurb: string;
  subject: string;
  /** Prompts pre-filled into the message body so a first reply can be useful. */
  prompts: string[];
};

const TOPICS: Topic[] = [
  {
    id: 'support',
    label: 'Product support',
    icon: LifeBuoy,
    blurb: 'A scan behaving unexpectedly, an agent not reporting, a dashboard number you want explained.',
    subject: 'Support',
    prompts: [
      'Account email:',
      'Where it happened (page or module):',
      'What you expected vs what you saw:',
      'Approximate time it happened:',
    ],
  },
  {
    id: 'billing',
    label: 'Billing and refunds',
    icon: CreditCard,
    blurb: `Subscription changes, invoices, cancellations, billing errors and refund requests (cancelling keeps access to the ${REFUND_POLICY.cancellationTakesEffect}).`,
    subject: 'Billing',
    prompts: [
      'Account email:',
      'Plan and billing cycle:',
      'PayPal transaction or subscription ID:',
      'What you would like us to do:',
    ],
  },
  {
    id: 'privacy',
    label: 'Privacy and data requests',
    icon: ShieldCheck,
    blurb: 'Access, correction, export or deletion of your personal data, and privacy complaints.',
    subject: 'Privacy request',
    prompts: [
      'Account email:',
      'Request type (access / correction / export / deletion):',
      'Anything that helps us locate the records:',
    ],
  },
  {
    id: 'security',
    label: 'Security disclosure',
    icon: Mail,
    blurb: 'Report a vulnerability in the platform, the agents, or the messaging and vault applications.',
    subject: 'Security disclosure',
    prompts: [
      'Affected component and version:',
      'Steps to reproduce:',
      'Impact you were able to demonstrate:',
      'Whether you are willing to be credited:',
    ],
  },
  {
    id: 'legal',
    label: 'Legal and notices',
    icon: Scale,
    blurb: 'Formal notices, questions about the Terms, and correspondence that needs a written record.',
    subject: 'Legal notice',
    prompts: ['Organisation (if any):', 'Document or clause this concerns:', 'The notice itself:'],
  },
];

function buildBody(topic: Topic, name: string, accountEmail: string, message: string): string {
  const lines: string[] = [];
  if (name.trim()) lines.push(`Name: ${name.trim()}`);
  if (accountEmail.trim()) lines.push(`Account email: ${accountEmail.trim()}`);
  if (lines.length) lines.push('');
  if (message.trim()) {
    lines.push(message.trim());
  } else {
    lines.push(...topic.prompts, '');
  }
  lines.push('', '---', `Sent from ${SITE.domain}/contact`);
  return lines.join('\n');
}

const inputClass =
  'w-full rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-[15px] text-slate-900 outline-none transition-colors placeholder:text-slate-400 focus:border-gold';

const labelClass = 'mb-1.5 block font-mono text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500';

export default function ContactPage() {
  const [topicId, setTopicId] = React.useState<string>(TOPICS[0].id);
  const [name, setName] = React.useState('');
  const [accountEmail, setAccountEmail] = React.useState('');
  const [message, setMessage] = React.useState('');
  const [copied, setCopied] = React.useState<'none' | 'address' | 'message'>('none');

  const topic = TOPICS.find((t) => t.id === topicId) ?? TOPICS[0];
  const subject = `[${topic.subject}] `;
  const body = buildBody(topic, name, accountEmail, message);
  const mailto = `mailto:${SITE.supportEmail}?subject=${encodeURIComponent(subject.trim())}&body=${encodeURIComponent(body)}`;

  const copy = async (what: 'address' | 'message', text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(what);
      window.setTimeout(() => setCopied('none'), 2000);
    } catch {
      /* Clipboard unavailable (insecure context or denied) — the text stays
         selectable on screen, so there is nothing to recover from here. */
    }
  };

  return (
    <SolutionLayout
      homePath="/"
      brandTitle="QGuard Helix"
      brandSubtitle="Contact"
      navLinks={NAV_LINKS}
    >
      <section className="relative px-6 pb-8 pt-16 md:pt-24">
        <div className="mx-auto max-w-[72rem]">
          <Reveal>
            <p className="font-mono text-[10px] font-bold uppercase tracking-[0.35em] text-gold">Support // Contact</p>
            <h1 className="mt-4 text-3xl font-black tracking-tight text-slate-900 md:text-5xl">Talk to us</h1>
            <p className="mt-5 max-w-2xl text-[15px] leading-relaxed text-slate-600">
              One mailbox, answered by the people who build the platform. Pick what your message is about so it lands in
              the right queue, and we will reply within {SITE.supportResponseTarget}.
            </p>
          </Reveal>

          <Reveal delay={0.08}>
            <div className="mt-8 grid gap-3 sm:grid-cols-3">
              {[
                { icon: Mail, label: 'Email', value: SITE.supportEmail },
                { icon: Clock, label: 'Response target', value: SITE.supportResponseTarget },
                { icon: MapPin, label: 'Operating from', value: `${SITE.city}, ${SITE.province}, ${SITE.country}` },
              ].map((item) => (
                <div key={item.label} className="rounded-2xl border border-slate-200 bg-white/80 p-5 backdrop-blur-xl">
                  <div className="mb-2 flex items-center gap-2 text-slate-400">
                    <item.icon className="h-4 w-4" />
                    <span className="font-mono text-[10px] font-bold uppercase tracking-[0.2em]">{item.label}</span>
                  </div>
                  <p className="text-[15px] font-semibold leading-snug text-slate-900">{item.value}</p>
                </div>
              ))}
            </div>
          </Reveal>
        </div>
      </section>

      <section className="relative px-6 pb-24">
        <div className="mx-auto grid max-w-[72rem] gap-10 lg:grid-cols-[minmax(0,1fr)_20rem]">
          <div className="min-w-0 space-y-6">
            <Reveal>
              <div className="rounded-2xl border border-slate-200 bg-white/80 p-6 backdrop-blur-xl md:p-8">
                <h2 className="mb-1 text-xl font-black tracking-tight text-slate-900">What is it about?</h2>
                <p className="mb-5 text-sm text-slate-500">
                  This sets the subject prefix we filter on, and pre-fills the details we would otherwise have to ask
                  for.
                </p>

                <div className="grid gap-2.5 sm:grid-cols-2">
                  {TOPICS.map((t) => {
                    const active = t.id === topicId;
                    return (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => setTopicId(t.id)}
                        aria-pressed={active}
                        className={`flex gap-3 rounded-xl border p-4 text-left transition-colors ${
                          active ? 'border-gold bg-gold/[0.06]' : 'border-slate-200 bg-white hover:border-slate-300'
                        }`}
                      >
                        <t.icon className={`mt-0.5 h-4 w-4 shrink-0 ${active ? 'text-gold' : 'text-slate-400'}`} />
                        <span className="min-w-0">
                          <span className="block text-sm font-bold text-slate-900">{t.label}</span>
                          {/* The light override sheet paints `bg-gold/*` a solid cyan, so the
                              selected card needs the darker body colour to stay readable. */}
                          <span className={`mt-1 block text-[13px] leading-relaxed ${active ? 'text-slate-700' : 'text-slate-500'}`}>
                            {t.blurb}
                          </span>
                        </span>
                      </button>
                    );
                  })}
                </div>

                <div className="mt-7 grid gap-4 sm:grid-cols-2">
                  <div>
                    <label className={labelClass} htmlFor="contact-name">
                      Your name <span className="text-slate-300">(optional)</span>
                    </label>
                    <input
                      id="contact-name"
                      className={inputClass}
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Jane Reyes"
                      autoComplete="name"
                    />
                  </div>
                  <div>
                    <label className={labelClass} htmlFor="contact-email">
                      Account email <span className="text-slate-300">(optional)</span>
                    </label>
                    <input
                      id="contact-email"
                      type="email"
                      className={inputClass}
                      value={accountEmail}
                      onChange={(e) => setAccountEmail(e.target.value)}
                      placeholder="you@company.com"
                      autoComplete="email"
                    />
                  </div>
                </div>

                <div className="mt-4">
                  <label className={labelClass} htmlFor="contact-message">
                    Message
                  </label>
                  <textarea
                    id="contact-message"
                    rows={7}
                    className={`${inputClass} resize-y font-sans leading-relaxed`}
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder={topic.prompts.join('\n')}
                  />
                  <p className="mt-2 text-xs text-slate-400">
                    Leave this blank and we will pre-fill the checklist above so you can answer it in your mail client.
                  </p>
                </div>

                <div className="mt-6 flex flex-wrap items-center gap-3">
                  <a
                    href={mailto}
                    className="inline-flex items-center gap-2 rounded-xl bg-slate-900 px-5 py-3 text-sm font-bold text-[#f8fafc] no-underline transition-colors hover:bg-slate-800"
                  >
                    <Mail className="h-4 w-4" />
                    Open in your email app
                    <ExternalLink className="h-3.5 w-3.5 opacity-60" />
                  </a>
                  <button
                    type="button"
                    onClick={() => copy('message', `To: ${SITE.supportEmail}\nSubject: ${subject.trim()}\n\n${body}`)}
                    className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-5 py-3 text-sm font-bold text-slate-700 transition-colors hover:border-slate-300"
                  >
                    {copied === 'message' ? <Check className="h-4 w-4 text-emerald-600" /> : <Copy className="h-4 w-4" />}
                    {copied === 'message' ? 'Copied' : 'Copy the message'}
                  </button>
                </div>

                <p className="mt-4 text-xs leading-relaxed text-slate-400">
                  Nothing you type here is sent to us by this page, and nothing is stored in your browser — the button
                  hands the message to your own mail client, so the email comes from your address and you keep a copy in
                  your sent folder.
                </p>
              </div>
            </Reveal>

            <Reveal delay={0.06}>
              <div className="rounded-2xl border border-slate-200 bg-white/80 p-6 backdrop-blur-xl md:p-8">
                <h2 className="mb-4 text-xl font-black tracking-tight text-slate-900">Before you write</h2>
                <ul className="space-y-3">
                  {[
                    <>
                      <strong className="font-semibold text-slate-900">Refunds and cancellations</strong> are answered
                      fastest with the PayPal transaction or subscription ID. The{' '}
                      <Link to="/refund" className="font-semibold text-gold no-underline hover:underline">
                        Refund Policy
                      </Link>{' '}
                      sets out what qualifies.
                    </>,
                    <>
                      <strong className="font-semibold text-slate-900">Cancelling does not need us</strong> — do it any
                      time from Settings → Billing, or from your PayPal account. Access runs to the{' '}
                      {REFUND_POLICY.cancellationTakesEffect}.
                    </>,
                    <>
                      <strong className="font-semibold text-slate-900">We cannot recover Vault or Messaging data.</strong>{' '}
                      Those are encrypted on your device; without your passphrase and recovery key nobody can decrypt
                      them, including us.
                    </>,
                    <>
                      <strong className="font-semibold text-slate-900">Never send us secrets.</strong> No passwords,
                      private keys, recovery keys, API tokens or service-role credentials — we will never ask for them,
                      and email is not a safe place for them.
                    </>,
                    <>
                      <strong className="font-semibold text-slate-900">Scan questions</strong> are easier to answer with
                      the scan ID or the target and time, so we can look at the same evidence you are looking at.
                    </>,
                  ].map((line, i) => (
                    <li key={i} className="flex gap-3 text-[15px] leading-relaxed text-slate-600">
                      <span className="mt-[9px] h-1.5 w-1.5 shrink-0 rounded-full bg-gold" />
                      <span className="min-w-0">{line}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </Reveal>
          </div>

          <aside className="space-y-6 lg:sticky lg:top-24 lg:self-start">
            <Reveal delay={0.1}>
              <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 backdrop-blur-xl">
                <p className="mb-3 font-mono text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500">
                  Service provider
                </p>
                <p className="text-sm font-black text-slate-900">{SITE.providerName}</p>
                <p className="mt-1 text-[13px] leading-relaxed text-slate-600">
                  {SITE.city}, {SITE.province}
                  <br />
                  {SITE.country}
                </p>
                <div className="mt-4 space-y-2 border-t border-slate-200 pt-4 text-[13px]">
                  <div className="flex items-start justify-between gap-2">
                    <a
                      href={`mailto:${SITE.supportEmail}`}
                      className="min-w-0 break-all font-semibold text-gold no-underline hover:underline"
                    >
                      {SITE.supportEmail}
                    </a>
                    <button
                      type="button"
                      onClick={() => copy('address', SITE.supportEmail)}
                      aria-label="Copy email address"
                      className="shrink-0 text-slate-400 transition-colors hover:text-gold"
                    >
                      {copied === 'address' ? (
                        <Check className="h-3.5 w-3.5 text-emerald-600" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                    </button>
                  </div>
                  <p className="text-slate-500">{SITE.domain}</p>
                </div>
              </div>
            </Reveal>

            <Reveal delay={0.14}>
              <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 backdrop-blur-xl">
                <p className="mb-3 font-mono text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500">
                  Policies
                </p>
                <ul className="space-y-1.5">
                  {[
                    { to: '/terms', label: 'Terms of Service' },
                    { to: '/privacy', label: 'Privacy Policy' },
                    { to: '/refund', label: 'Refund Policy' },
                  ].map((link) => (
                    <li key={link.to}>
                      <Link
                        to={link.to}
                        className="text-[13px] text-slate-600 no-underline transition-colors hover:text-gold"
                      >
                        {link.label}
                      </Link>
                    </li>
                  ))}
                </ul>
                <p className="mt-4 border-t border-slate-200 pt-3 text-xs text-slate-400">
                  In force since {formatLegalDate()}.
                </p>
              </div>
            </Reveal>

            <Reveal delay={0.18}>
              <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 backdrop-blur-xl">
                <p className="mb-3 font-mono text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500">
                  Answer it yourself
                </p>
                <ul className="space-y-1.5">
                  {[
                    { to: '/docs', label: 'Documentation' },
                    { to: '/public-scan', label: 'Free public scan' },
                    { to: '/downloads', label: 'Agents and applications' },
                    { to: '/qguard-helix-features', label: 'What the platform does' },
                  ].map((link) => (
                    <li key={link.to}>
                      <Link
                        to={link.to}
                        className="text-[13px] text-slate-600 no-underline transition-colors hover:text-gold"
                      >
                        {link.label}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            </Reveal>
          </aside>
        </div>
      </section>
    </SolutionLayout>
  );
}
