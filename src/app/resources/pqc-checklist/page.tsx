import { ChangeEvent, FormEvent, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Download,
  FileCheck,
  Lock,
  Mail,
  ShieldCheck,
} from 'lucide-react';

type ChecklistForm = {
  workEmail: string;
  firstName: string;
  lastName: string;
  company: string;
  title: string;
  country: string;
  consent: boolean;
  website: string;
};

type FormErrors = Partial<Record<keyof ChecklistForm | 'form', string>>;

const CHECKLIST_PDF_PATH = '/PQC_Checklist.pdf';
const DOWNLOAD_FILENAME = 'Qguard-Helix-PQC-Checklist.pdf';
const FORM_READY_DELAY_MS = 1200;

const BLOCKED_EMAIL_DOMAINS = new Set([
  'aol.com',
  'gmail.com',
  'googlemail.com',
  'hotmail.com',
  'icloud.com',
  'live.com',
  'mail.com',
  'msn.com',
  'outlook.com',
  'pm.me',
  'proton.me',
  'protonmail.com',
  'yahoo.com',
  'yandex.com',
  'zoho.com',
]);

const COUNTRY_OPTIONS = [
  'United States',
  'Canada',
  'United Kingdom',
  'Australia',
  'Germany',
  'France',
  'Singapore',
  'Japan',
  'South Korea',
  'Philippines',
  'India',
  'United Arab Emirates',
  'Netherlands',
  'Switzerland',
  'Other',
];

const REQUIRED_TEXT_FIELDS: Array<keyof Pick<
  ChecklistForm,
  'workEmail' | 'firstName' | 'lastName' | 'company' | 'title' | 'country'
>> = ['workEmail', 'firstName', 'lastName', 'company', 'title', 'country'];

const FIELD_LABELS: Record<(typeof REQUIRED_TEXT_FIELDS)[number], string> = {
  workEmail: 'Work Email',
  firstName: 'First Name',
  lastName: 'Last Name',
  company: 'Company',
  title: 'Title',
  country: 'Country',
};

const CHECKLIST_BENEFITS = [
  {
    emphasis: 'Uncover hidden cryptographic risk',
    text: ' across cloud, runtime, and telemetry',
  },
  {
    emphasis: 'Identify weak algorithms, exposed keys, and quantum-vulnerable assets',
    text: '',
  },
  {
    emphasis: 'Enforce cryptographic policies',
    text: ' and automate asset rotation',
  },
  {
    emphasis: 'Assess governance, compliance, and NIST-aligned PQC readiness',
    text: '',
  },
  {
    emphasis: 'Prepare for 90-day certificates',
    text: ' and post-quantum migration mandates',
  },
];

const INITIAL_FORM: ChecklistForm = {
  workEmail: '',
  firstName: '',
  lastName: '',
  company: '',
  title: '',
  country: '',
  consent: false,
  website: '',
};

function getEmailDomain(email: string) {
  return email.trim().toLowerCase().split('@')[1] ?? '';
}

function isDisposableDomain(domain: string) {
  return /(^|\.)((10minutemail|guerrillamail|mailinator|tempmail|throwawaymail|yopmail)\.)/i.test(`${domain}.`);
}

function triggerChecklistDownload() {
  const link = document.createElement('a');
  link.href = CHECKLIST_PDF_PATH;
  link.download = DOWNLOAD_FILENAME;
  link.rel = 'noopener';
  document.body.appendChild(link);
  link.click();
  link.remove();
}

export default function PqcChecklistPage() {
  const [form, setForm] = useState<ChecklistForm>(INITIAL_FORM);
  const [errors, setErrors] = useState<FormErrors>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [downloadStarted, setDownloadStarted] = useState(false);
  const [loadedAt] = useState(() => Date.now());

  const fieldRows = useMemo(
    () => [
      { name: 'workEmail' as const, type: 'email', autoComplete: 'email' },
      { name: 'firstName' as const, type: 'text', autoComplete: 'given-name' },
      { name: 'lastName' as const, type: 'text', autoComplete: 'family-name' },
      { name: 'company' as const, type: 'text', autoComplete: 'organization' },
      { name: 'title' as const, type: 'text', autoComplete: 'organization-title' },
    ],
    []
  );

  const validateForm = () => {
    const nextErrors: FormErrors = {};

    REQUIRED_TEXT_FIELDS.forEach((field) => {
      if (!form[field].trim()) {
        nextErrors[field] = `${FIELD_LABELS[field]} is required.`;
      }
    });

    const email = form.workEmail.trim().toLowerCase();
    const domain = getEmailDomain(email);
    const isEmailFormatValid = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);

    if (form.workEmail.trim() && !isEmailFormatValid) {
      nextErrors.workEmail = 'Enter a valid work email address.';
    } else if (domain && (BLOCKED_EMAIL_DOMAINS.has(domain) || isDisposableDomain(domain))) {
      nextErrors.workEmail = 'Use a company email address to access the checklist.';
    }

    if (!form.consent) {
      nextErrors.consent = 'Consent is required before the checklist can be downloaded.';
    }

    if (form.website.trim()) {
      nextErrors.form = 'The checklist request could not be verified.';
    }

    if (Date.now() - loadedAt < FORM_READY_DELAY_MS) {
      nextErrors.form = 'Please review the form before submitting.';
    }

    return nextErrors;
  };

  const handleFieldChange = (event: ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const target = event.target;
    const name = target.name as keyof ChecklistForm;
    const value = target instanceof HTMLInputElement && target.type === 'checkbox'
      ? target.checked
      : target.value;

    setForm((current) => ({
      ...current,
      [name]: value,
    }));
    setErrors((current) => ({
      ...current,
      [name]: undefined,
      form: undefined,
    }));
    setDownloadStarted(false);
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const nextErrors = validateForm();

    if (Object.keys(nextErrors).length > 0) {
      setErrors(nextErrors);
      setDownloadStarted(false);
      return;
    }

    setIsSubmitting(true);
    window.setTimeout(() => {
      triggerChecklistDownload();
      setDownloadStarted(true);
      setIsSubmitting(false);
    }, 250);
  };

  return (
    <div className="min-h-screen overflow-x-hidden bg-[#f8fbff] text-[#0f172a]">
      <header className="homepage-nav homepage-nav--scrolled sticky top-0 z-50 border-b backdrop-blur-2xl">
        <div className="mx-auto flex h-16 max-w-[96rem] items-center justify-between px-4 sm:px-6">
          <Link to="/" className="homepage-nav__brand group flex min-w-0 items-center gap-3 no-underline">
            <img
              src="/NEW_LOGO.png"
              alt="Qguard Helix logo"
              className="homepage-nav__logo h-16 w-auto shrink-0 object-contain"
            />
            <span className="hidden min-w-0 flex-col leading-none sm:flex">
              <span className="homepage-nav__wordmark whitespace-nowrap text-lg font-black tracking-[0.03em] transition-colors group-hover:text-cyan-600">
                Qguard Helix
              </span>
              <span className="homepage-logo-subtitle homepage-nav__tagline mt-1 whitespace-nowrap bg-gradient-to-r from-cyan-500 via-slate-600 to-violet-600 bg-clip-text font-mono text-[10px] font-black uppercase tracking-[0.32em] text-transparent">
                Quantum Cyber Defense
              </span>
            </span>
          </Link>
          <Link
            to="/"
            className="inline-flex h-10 items-center gap-2 rounded-md border-2 border-[#090d16] bg-white px-4 text-sm font-black uppercase tracking-[0.12em] text-[#090d16] no-underline shadow-[4px_4px_0_rgba(9,13,22,0.08)] transition hover:border-[#00c5eb] hover:bg-[#00c5eb]"
          >
            <ArrowLeft className="h-4 w-4" />
            Home
          </Link>
        </div>
      </header>

      <main className="relative overflow-hidden bg-[#f8fbff]">
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-[linear-gradient(rgba(226,232,240,0.72)_1px,transparent_1px),linear-gradient(90deg,rgba(226,232,240,0.72)_1px,transparent_1px)] bg-[size:44px_44px]"
        />
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-[radial-gradient(circle_at_78%_18%,rgba(0,197,235,0.16),transparent_26rem),radial-gradient(circle_at_12%_8%,rgba(124,58,237,0.12),transparent_24rem),radial-gradient(circle_at_78%_76%,rgba(16,185,129,0.11),transparent_28rem)]"
        />

        <section className="relative mx-auto grid max-w-7xl gap-10 px-5 py-14 sm:px-8 lg:min-h-[calc(100vh-4rem)] lg:grid-cols-[minmax(0,1.12fr)_minmax(360px,0.82fr)] lg:gap-14 lg:py-20">
          <div className="flex min-w-0 flex-col justify-center">
            <div className="mb-8 inline-flex w-fit items-center gap-3 rounded-md border-2 border-[#090d16] bg-white px-4 py-2 font-mono text-xs font-black uppercase tracking-[0.2em] text-[#090d16] shadow-[4px_4px_0_rgba(0,197,235,0.22)]">
              <FileCheck className="h-4 w-4" />
              The CPM Checklist
            </div>

            <h1 className="max-w-3xl text-4xl font-black leading-[1.06] tracking-normal text-[#080d1f] sm:text-5xl lg:text-6xl">
              Enterprise Cryptography Posture Management (CPM)
            </h1>

            <div className="mt-8 max-w-3xl space-y-5 text-base leading-8 text-[#334155] sm:text-lg">
              <p>
                Traditional CLM tools manage certificates &mdash; but modern cryptographic risk extends across runtime memory, cloud infrastructure, machine identities, APIs, and third-party software supply chains.
              </p>
              <p>
                The Qguard Helix CPM Checklist provides a practical framework for evaluating enterprise cryptographic visibility, governance, operational resilience, and post-quantum readiness.
              </p>
            </div>

            <div className="mt-9 max-w-3xl">
              <p className="text-lg font-black text-[#090d16]">
                Download the checklist to learn how to:
              </p>
              <ul className="mt-5 space-y-4 text-base leading-7 text-[#334155]">
                {CHECKLIST_BENEFITS.map((benefit) => (
                  <li className="flex gap-3" key={benefit.emphasis}>
                    <CheckCircle2 className="mt-1 h-5 w-5 shrink-0 text-[#00a6cf]" />
                    <span>
                      <strong className="font-black text-[#090d16]">{benefit.emphasis}</strong>
                      {benefit.text}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            <p className="mt-9 max-w-3xl text-base leading-8 text-[#334155] sm:text-lg">
              If you're evaluating CPM solutions or preparing for the transition to post-quantum cryptography, this checklist provides a fast, defensible way to benchmark your readiness.
            </p>

            <div className="mt-10 flex flex-wrap items-center gap-4 border-t border-slate-200 pt-6">
              <span className="inline-flex items-center gap-2 rounded-md border border-cyan-300/35 bg-cyan-100/70 px-4 py-2 text-sm font-bold text-[#075985]">
                <ShieldCheck className="h-4 w-4" />
                Qguard Helix &mdash; Quantum Cyber Defense
              </span>
              <span className="inline-flex items-center gap-2 rounded-md border border-slate-200 bg-white/80 px-4 py-2 text-sm font-semibold text-[#475569] shadow-[0_12px_30px_rgba(15,23,42,0.06)]">
                <Lock className="h-4 w-4 text-[#00a6cf]" />
                Form-gated download
              </span>
            </div>
          </div>

          <aside className="self-start rounded-lg border-2 border-[#090d16] bg-white/94 p-6 shadow-[10px_10px_0_rgba(0,197,235,0.18),0_26px_90px_rgba(15,23,42,0.12)] backdrop-blur-xl sm:p-8 lg:sticky lg:top-8">
            <div className="mb-7 text-center">
              <div className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-md border-2 border-[#090d16] bg-cyan-100 text-[#090d16] shadow-[4px_4px_0_rgba(9,13,22,0.08)]">
                <Download className="h-5 w-5" />
              </div>
              <h2 className="text-2xl font-black text-[#090d16]">
                Download The CPM Checklist
              </h2>
              <p className="mt-2 text-sm leading-6 text-[#64748b]">
                Complete the required business details to start the secure PDF download.
              </p>
            </div>

            {errors.form && (
              <div className="mb-5 flex gap-3 rounded-md border border-red-300 bg-red-50 p-3 text-sm font-semibold text-red-700">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{errors.form}</span>
              </div>
            )}

            <form className="space-y-6" onSubmit={handleSubmit} noValidate>
              <input
                aria-hidden="true"
                autoComplete="off"
                className="hidden"
                name="website"
                tabIndex={-1}
                value={form.website}
                onChange={handleFieldChange}
              />

              {fieldRows.map((field) => (
                <div key={field.name}>
                  <label htmlFor={field.name} className="text-sm font-black text-[#0f172a]">
                    {FIELD_LABELS[field.name]}:
                  </label>
                  <input
                    id={field.name}
                    name={field.name}
                    type={field.type}
                    autoComplete={field.autoComplete}
                    value={form[field.name]}
                    onChange={handleFieldChange}
                    aria-invalid={Boolean(errors[field.name])}
                    aria-describedby={errors[field.name] ? `${field.name}-error` : undefined}
                    className="mt-2 h-11 w-full border-0 border-b border-slate-300 bg-transparent px-0 text-base text-[#0f172a] outline-none transition placeholder:text-slate-400 focus:border-[#00a6cf]"
                  />
                  {errors[field.name] && (
                    <p id={`${field.name}-error`} className="mt-2 text-xs font-bold text-red-600">
                      {errors[field.name]}
                    </p>
                  )}
                </div>
              ))}

              <div>
                <label htmlFor="country" className="text-sm font-black text-[#0f172a]">
                  Country:
                </label>
                <select
                  id="country"
                  name="country"
                  value={form.country}
                  onChange={handleFieldChange}
                  aria-invalid={Boolean(errors.country)}
                  aria-describedby={errors.country ? 'country-error' : undefined}
                  className="mt-2 h-11 w-full border-0 border-b border-slate-300 bg-white px-0 text-base text-[#0f172a] outline-none transition focus:border-[#00a6cf]"
                >
                  <option value="">Select...</option>
                  {COUNTRY_OPTIONS.map((country) => (
                    <option value={country} key={country}>
                      {country}
                    </option>
                  ))}
                </select>
                {errors.country && (
                  <p id="country-error" className="mt-2 text-xs font-bold text-red-600">
                    {errors.country}
                  </p>
                )}
              </div>

              <label className="flex items-start gap-3 text-xs font-semibold leading-5 text-[#475569]">
                <input
                  type="checkbox"
                  name="consent"
                  checked={form.consent}
                  onChange={handleFieldChange}
                  aria-invalid={Boolean(errors.consent)}
                  className="mt-1 h-4 w-4 shrink-0 accent-[#00a6cf]"
                />
                <span>
                  I agree to receive communications from Qguard Helix in accordance with its{' '}
                  <Link to="/docs" className="font-black text-[#0284c7] underline-offset-4 hover:underline">
                    privacy policy
                  </Link>
                  .
                  {errors.consent && (
                    <span className="mt-2 block font-bold text-red-600">{errors.consent}</span>
                  )}
                </span>
              </label>

              <button
                type="submit"
                disabled={isSubmitting}
                className="inline-flex h-12 items-center justify-center gap-2 rounded-md border-2 border-[#090d16] bg-[#050914] px-7 text-base font-black text-[#ffffff] shadow-[4px_4px_0_rgba(9,13,22,0.12)] transition hover:border-[#00c5eb] hover:bg-[#00c5eb] hover:text-[#050914] disabled:cursor-not-allowed disabled:opacity-65"
              >
                {isSubmitting ? 'Preparing...' : 'Submit'}
                <Download className="h-4 w-4" />
              </button>

              {downloadStarted && (
                <div className="flex items-start gap-3 rounded-md border border-emerald-300 bg-emerald-50 p-3 text-sm font-semibold text-emerald-700">
                  <Mail className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>
                    Download started. Your browser will save {DOWNLOAD_FILENAME}.
                  </span>
                </div>
              )}
            </form>
          </aside>
        </section>
      </main>
    </div>
  );
}
