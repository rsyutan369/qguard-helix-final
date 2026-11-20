import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useParams } from 'react-router-dom';
import { ArrowRight, BadgeCheck, Building2, Fingerprint, LoaderCircle, Search, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import type { PublicCertificateVerification } from '@/types/quantum-certification';
import { NAV_LINKS } from './_legal-shared';
import { SolutionLayout } from './_solution-shared';
import './verify-certificate.css';

const STATUSES = {
  active: { label: 'Active', tone: 'success', icon: ShieldCheck },
  suspended: { label: 'Suspended', tone: 'warning', icon: ShieldAlert },
  expired: { label: 'Expired', tone: 'warning', icon: ShieldAlert },
  revoked: { label: 'Revoked', tone: 'error', icon: ShieldX },
  superseded: { label: 'Superseded', tone: 'neutral', icon: ShieldAlert },
  not_found: { label: 'Certificate not found', tone: 'neutral', icon: Search },
};

function fmtDate(value: string | null, time = false): string {
  if (!value) return '—';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  if (time) return date.toLocaleString();
  return date.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
}

function EvidenceCheck({ label, value, algorithm }: { label: string; value: boolean | null; algorithm: string }) {
  const state = value === true ? 'Verified' : value === false ? 'Failed' : 'Unavailable';
  const Icon = value === true ? BadgeCheck : value === false ? ShieldX : ShieldAlert;

  return (
    <div className="qc-verify__notice" data-tone={value === true ? 'success' : value === false ? 'error' : 'neutral'}>
      <Icon aria-hidden="true" size={20} />
      <div>
        <strong>{label} · {state}</strong>
        {algorithm && <p>{algorithm}</p>}
      </div>
    </div>
  );
}

function VerificationResult({ result }: { result: PublicCertificateVerification }) {
  const status = STATUSES[result.status];
  const evidenceFailed = result.integrityValid === false || result.signatureValid === false;
  const evidencePending = result.integrityValid !== true || result.signatureValid !== true;
  const statusDisplay = result.status === 'active' && evidencePending
    ? { label: 'Active registry record', tone: 'neutral', icon: ShieldAlert }
    : status;
  const Icon = evidenceFailed ? ShieldX : statusDisplay.icon;

  return (
    <article className="qc-verify__result">
      <header className="qc-verify__result-header" data-tone={evidenceFailed ? 'error' : statusDisplay.tone}>
        <span className="qc-verify__icon"><Icon aria-hidden="true" size={24} /></span>
        <div className="min-w-0">
          <h2>{evidenceFailed ? 'Verification failed' : statusDisplay.label}</h2>
          <p>{result.found ? result.statusDetail : `No registry record matches “${result.certificateId}”.`}</p>
        </div>
        {result.found && (
          <div className="qc-verify__score">
            <span className="qc-verify__meta">Trust score</span>
            <strong>{result.trustScore}<small> / 1000</small></strong>
          </div>
        )}
      </header>

      {result.found && (
        <div className="qc-verify__result-body">
          <div>
            <p className="qc-verify__meta">{result.levelLabel || result.level}</p>
            <h3 className="qc-verify__organization">{result.organization}</h3>
          </div>

          {result.certified === false ? (
            <div className="qc-verify__notice" data-tone="warning">
              <ShieldAlert aria-hidden="true" size={20} />
              <div>
                <strong>Baseline attestation only</strong>
                <p>This record captures the measured cryptographic posture at assessment. It met {result.criteriaMet} of {result.criteriaTotal} certification criteria at issuance. Quantum Trust certification begins at Silver.</p>
              </div>
            </div>
          ) : (
            <div className="qc-verify__notice" data-tone="neutral">
              <BadgeCheck aria-hidden="true" size={20} />
              <div>
                <strong>Quantum Trust Certified™ record</strong>
                <p>Measured evidence met {result.criteriaMet} of {result.criteriaTotal} certification criteria at issuance.</p>
              </div>
            </div>
          )}

          <div className="qc-verify__checks">
            <EvidenceCheck label="Integrity" value={result.integrityValid} algorithm="SHA3-256 certificate hash" />
            <EvidenceCheck label="Digital signature" value={result.signatureValid} algorithm={result.signatureAlgorithm} />
          </div>

          <dl className="qc-verify__fields">
            {[
              ['Certificate ID', result.certificateId],
              ['Overall readiness', `${result.overallReadiness}%`],
              ['Issued', fmtDate(result.issuedAt)],
              ['PQC adoption', `${result.pqcAdoption}%`],
              ['Expires', fmtDate(result.expiresAt)],
              ['Residual risk', result.residualRiskLevel || '—'],
              ['Assessment version', result.assessmentVersion || '—'],
              ['Last validated', fmtDate(result.lastValidatedAt)],
            ].map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>

          {result.certifiedAlgorithms.length > 0 && (
            <div>
              <h3 className="qc-verify__meta">{result.certified ? 'Certified algorithm stack' : 'Recorded algorithm stack'}</h3>
              <ul className="qc-verify__algorithms">
                {result.certifiedAlgorithms.map(({ category, algorithm, standard }, index) => (
                  <li key={index}>{category} · <strong>{algorithm}</strong>{standard && ` (${standard})`}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="qc-verify__hash">
            <h3 className="qc-verify__meta">Certificate hash · SHA3-256</h3>
            <p>{result.certificateHash || '—'}</p>
          </div>
          <p className="qc-verify__timestamp">Verified at {fmtDate(result.verifiedAt, true)}</p>
        </div>
      )}
    </article>
  );
}


interface CompanyMatch {
  certificateId: string;
  organization: string;
  status: string;
  level: string;
  trustScore: number;
  issuedAt: string;
  expiresAt: string;
}

export default function VerifyCertificate() {
  const { certificateId } = useParams();
  const [query, setQuery] = useState(certificateId || '');
  const [mode, setMode] = useState<'id' | 'company'>('id');
  const [result, setResult] = useState<PublicCertificateVerification | null>(null);
  const [matches, setMatches] = useState<CompanyMatch[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const lookupById = useCallback(async (id: string, via?: string) => {
    const clean = id.trim();
    if (!clean) return;
    setLoading(true);
    setErrorMsg(null);
    setMatches(null);
    setResult(null);
    try {
      const response = await fetch(`/api/v1/certificate-verification/${encodeURIComponent(clean)}${via ? `?via=${via}` : ''}`);
      const payload = await response.json().catch(() => ({}));
      if (response.status === 429) throw new Error('Too many verification requests — please retry in a minute.');
      // A 404 carries a not-found RESULT; any other failure is not a verdict.
      if (!response.ok && response.status !== 404) throw new Error(payload?.error?.message || 'The certificate registry could not be read — please retry.');
      setResult((payload.data as PublicCertificateVerification) || null);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Verification failed');
      setResult(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const lookupByCompany = useCallback(async (company: string) => {
    const clean = company.trim();
    if (!clean) return;
    setLoading(true);
    setErrorMsg(null);
    setResult(null);
    setMatches(null);
    try {
      const response = await fetch(`/api/v1/certificate-verification/lookup?company=${encodeURIComponent(clean)}`);
      const payload = await response.json().catch(() => ({}));
      if (response.status === 429) throw new Error('Too many verification requests — please retry in a minute.');
      if (!response.ok) throw new Error(payload?.error?.message || 'The certificate registry could not be read — please retry.');
      setMatches((payload.data as CompanyMatch[]) || []);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Search failed');
      setMatches(null);
    } finally {
      setLoading(false);
    }
  }, []);

  // Deep-link: /verify-certificate/:id (from the QR code) auto-verifies.
  useEffect(() => {
    if (certificateId) {
      setQuery(certificateId);
      setMode('id');
      void lookupById(certificateId, 'qr');
    }
  }, [certificateId, lookupById]);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (mode === 'id') void lookupById(query);
    else void lookupByCompany(query);
  };

  const byId = mode === 'id';
  const queryLabel = byId ? 'Certificate ID' : 'Company name';

  return (
    <SolutionLayout
      homePath="/"
      brandTitle="QGuard Helix"
      brandSubtitle="Certificate verification"
      navLinks={NAV_LINKS}
    >
      <div className="qc-verify">
        <section className="qc-verify__hero" aria-labelledby="verify-title">
          <div className="qc-verify__intro">
            <p className="qc-verify__eyebrow"><span aria-hidden="true" /> Public certificate registry</p>
            <h1 id="verify-title">Quantum Trust Certificate Verification</h1>
            <p className="qc-verify__description">Check the current status, digital signature, and integrity of a QGuard Helix Quantum Trust Certificate™.</p>
          </div>

          <form className="qc-verify__form" onSubmit={onSubmit} data-sky-static>
            <div className="qc-verify__form-heading">
              <span className="qc-verify__icon"><ShieldCheck aria-hidden="true" size={23} /></span>
              <h2>Find a certificate</h2>
            </div>

            <div className="qc-verify__modes" role="group" aria-label="Lookup method">
              <button type="button" aria-pressed={byId} disabled={loading} onClick={() => setMode('id')}>
                <Fingerprint aria-hidden="true" size={17} /> Certificate ID
              </button>
              <button type="button" aria-pressed={!byId} disabled={loading} onClick={() => setMode('company')}>
                <Building2 aria-hidden="true" size={17} /> Company name
              </button>
            </div>

            <label htmlFor="certificate-query">{queryLabel}</label>
            <div className="qc-verify__input-row">
              <input
                id="certificate-query"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={byId ? 'Enter certificate ID' : 'Enter company name'}
                autoComplete="off"
                spellCheck={false}
                required
              />
              <button type="submit" className="qc-verify__submit" disabled={loading}>
                {loading ? <LoaderCircle aria-hidden="true" size={17} className="qc-verify__spinner" /> : <Search aria-hidden="true" size={17} />}
                {loading ? (byId ? 'Verifying…' : 'Searching…') : (byId ? 'Verify' : 'Search')}
              </button>
            </div>
          </form>
        </section>

        <div className="qc-verify__output" aria-live="polite" aria-busy={loading}>
          {errorMsg && (
            <div className="qc-verify__notice qc-verify__entry" data-tone="error">
              <ShieldAlert aria-hidden="true" size={20} />
              <p>{errorMsg}</p>
            </div>
          )}

          {matches && (
            <article className="qc-verify__result qc-verify__result-body" aria-labelledby="certificate-matches">
              <h2 id="certificate-matches">{matches.length} certificate{matches.length === 1 ? '' : 's'} found</h2>
              {matches.length === 0 ? (
                <p>No certificates match that organization name.</p>
              ) : (
                <ul className="qc-verify__matches">
                  {matches.map((match) => (
                    <li key={match.certificateId}>
                      <button
                        type="button"
                        onClick={() => {
                          setQuery(match.certificateId);
                          setMode('id');
                          void lookupById(match.certificateId);
                        }}
                      >
                        <span className="min-w-0">
                          <strong>{match.organization}</strong>
                          <span className="qc-verify__match-id">{match.certificateId}</span>
                        </span>
                        <span className="qc-verify__match-detail">
                          {match.level} · {match.trustScore}/1000
                          <ArrowRight aria-hidden="true" size={17} />
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </article>
          )}

          {result && <VerificationResult result={result} />}
        </div>
      </div>
    </SolutionLayout>
  );
}
