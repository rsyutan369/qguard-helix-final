import { ChangeEvent, FormEvent, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  FileCheck,
} from 'lucide-react';
import { NAV_LINKS } from '@/pages/_legal-shared';
import { SolutionLayout } from '@/pages/_solution-shared';
import { invalidChecklistEmail } from '@/lib/checklist-request';
import './checklist.css';

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
    const isEmailFormatValid = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);

    if (form.workEmail.trim() && !isEmailFormatValid) {
      nextErrors.workEmail = 'Enter a valid work email address.';
    } else if (invalidChecklistEmail(email)) {
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

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (isSubmitting) return;

    const nextErrors = validateForm();

    if (Object.keys(nextErrors).length > 0) {
      setErrors(nextErrors);
      setDownloadStarted(false);
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await fetch('/api/v1/checklist-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
        signal: AbortSignal.timeout(15_000),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok || payload?.ok !== true) {
        throw new Error(payload?.error?.message || 'Could not record your checklist request. Please try again.');
      }
      triggerChecklistDownload();
      setDownloadStarted(true);
    } catch (error) {
      setErrors({ form: error instanceof Error ? error.message : 'Could not record your checklist request.' });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <SolutionLayout
      homePath="/"
      brandTitle="QGuard Helix"
      brandSubtitle="PQC resources"
      navLinks={NAV_LINKS}
    >
      <section className="pqc-checklist" aria-labelledby="checklist-title">
        <div className="pqc-checklist__intro">
          <p className="pqc-checklist__kicker"><span aria-hidden="true" /> The CPM Checklist</p>
          <h1 id="checklist-title">Enterprise Cryptography Posture Management</h1>
          <p>
            Traditional CLM tools manage certificates, but modern cryptographic risk extends across runtime memory,
            cloud infrastructure, machine identities, APIs, and third-party software supply chains.
          </p>
          <p>
            Use the QGuard Helix CPM Checklist to evaluate cryptographic visibility, governance,
            operational resilience, and post-quantum readiness.
          </p>

          <h2>What the checklist covers</h2>
          <ul className="pqc-checklist__benefits">
            {CHECKLIST_BENEFITS.map((benefit) => (
              <li key={benefit.emphasis}>
                <CheckCircle2 aria-hidden="true" size={18} />
                <span><strong>{benefit.emphasis}</strong>{benefit.text}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="pqc-checklist__panel" data-sky-static>
          <div className="pqc-checklist__panel-heading">
            <span><FileCheck aria-hidden="true" size={24} /></span>
            <div>
              <h2 id="checklist-download-title">Download the checklist</h2>
              <p>Your business details are saved when you request the PDF.</p>
            </div>
          </div>

          {errors.form && (
            <div className="pqc-checklist__notice" data-error="true" role="alert">
              <AlertCircle aria-hidden="true" size={18} /><span>{errors.form}</span>
            </div>
          )}

          <form className="pqc-checklist__form" aria-labelledby="checklist-download-title" onSubmit={handleSubmit} noValidate>
            <input
              aria-hidden="true"
              autoComplete="off"
              className="hidden"
              name="website"
              tabIndex={-1}
              value={form.website}
              onChange={handleFieldChange}
            />

            <div className="pqc-checklist__fields">
              {fieldRows.map((field) => (
                <div className={field.name === 'workEmail' ? 'pqc-checklist__email' : undefined} key={field.name}>
                  <label htmlFor={field.name}>{FIELD_LABELS[field.name]}</label>
                  <input
                    id={field.name}
                    name={field.name}
                    type={field.type}
                    autoComplete={field.autoComplete}
                    value={form[field.name]}
                    onChange={handleFieldChange}
                    required
                    aria-invalid={Boolean(errors[field.name])}
                    aria-describedby={errors[field.name] ? `${field.name}-error` : undefined}
                  />
                  {errors[field.name] && <p className="pqc-checklist__error" id={`${field.name}-error`}>{errors[field.name]}</p>}
                </div>
              ))}

              <div>
                <label htmlFor="country">Country</label>
                <select
                  id="country"
                  name="country"
                  value={form.country}
                  onChange={handleFieldChange}
                  required
                  aria-invalid={Boolean(errors.country)}
                  aria-describedby={errors.country ? 'country-error' : undefined}
                >
                  <option value="">Select a country</option>
                  {COUNTRY_OPTIONS.map((country) => <option value={country} key={country}>{country}</option>)}
                </select>
                {errors.country && <p className="pqc-checklist__error" id="country-error">{errors.country}</p>}
              </div>
            </div>

            <div className="pqc-checklist__consent">
              <input
                id="checklist-consent"
                type="checkbox"
                name="consent"
                checked={form.consent}
                onChange={handleFieldChange}
                required
                aria-invalid={Boolean(errors.consent)}
                aria-describedby={errors.consent ? 'checklist-consent-error' : undefined}
              />
              <div>
                <label htmlFor="checklist-consent">I agree to receive communications from QGuard Helix.</label>
                {' '}<Link to="/privacy">Privacy policy</Link>
                {errors.consent && <p className="pqc-checklist__error" id="checklist-consent-error">{errors.consent}</p>}
              </div>
            </div>

            <button className="pqc-checklist__download" type="submit" disabled={isSubmitting}>
              <Download aria-hidden="true" size={18} />
              {isSubmitting ? 'Preparing PDF…' : 'Download PDF'}
            </button>

            {downloadStarted && (
              <div className="pqc-checklist__notice" role="status">
                <CheckCircle2 aria-hidden="true" size={18} /><span>Download started. Your browser will save {DOWNLOAD_FILENAME}.</span>
              </div>
            )}
          </form>
        </div>
      </section>
    </SolutionLayout>
  );
}
