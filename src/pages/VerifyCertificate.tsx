import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Award, BadgeCheck, Building2, Fingerprint, Search, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import type { PublicCertificateVerification } from '@/types/quantum-certification';

/**
 * Public Quantum Trust Certificate verification portal.
 *
 * Anyone (no auth) can verify a certificate by ID — the QR code on every
 * certificate points here (verify.qguardhelix.com/{id} → /verify-certificate/:id).
 * The backend recomputes the SHA3-256 integrity hash from the stored canonical
 * payload and verifies the ML-DSA-65 signature live on every lookup, so tamper
 * detection is structural. Company-name search is also supported.
 */

const STATUS_STYLES: Record<string, { color: string; ring: string; label: string; icon: typeof ShieldCheck }> = {
  active: { color: '#16A34A', ring: 'border-emerald-400/40 bg-emerald-400/10', label: 'VALID', icon: ShieldCheck },
  suspended: { color: '#D97706', ring: 'border-amber-400/40 bg-amber-400/10', label: 'SUSPENDED', icon: ShieldAlert },
  expired: { color: '#EA580C', ring: 'border-orange-400/40 bg-orange-400/10', label: 'EXPIRED', icon: ShieldAlert },
  revoked: { color: '#DC2626', ring: 'border-red-400/40 bg-red-400/10', label: 'REVOKED', icon: ShieldX },
  superseded: { color: '#64748B', ring: 'border-slate-400/40 bg-slate-400/10', label: 'SUPERSEDED', icon: ShieldAlert },
  not_found: { color: '#DC2626', ring: 'border-red-400/40 bg-red-400/10', label: 'NOT FOUND', icon: ShieldX },
};

const LEVEL_COLORS: Record<string, string> = {
  bronze: '#B87333',
  silver: '#9AA6BC',
  gold: '#D4A017',
  platinum: '#A78BFA',
  diamond: '#22D3EE',
};

function fmtDate(value: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (!Number.isFinite(d.getTime())) return '—';
  return d.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
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
  const params = useParams();
  const [query, setQuery] = useState(params.certificateId || '');
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
    try {
      const response = await fetch(`/api/v1/certificate-verification/${encodeURIComponent(clean)}${via ? `?via=${via}` : ''}`);
      const payload = await response.json().catch(() => ({}));
      if (response.status === 429) throw new Error('Too many verification requests — please retry in a minute.');
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
    try {
      const response = await fetch(`/api/v1/certificate-verification/lookup?company=${encodeURIComponent(clean)}`);
      const payload = await response.json().catch(() => ({}));
      if (response.status === 429) throw new Error('Too many verification requests — please retry in a minute.');
      setMatches((payload.data as CompanyMatch[]) || []);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Search failed');
      setMatches([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // Deep-link: /verify-certificate/:id (from the QR code) auto-verifies.
  useEffect(() => {
    if (params.certificateId) {
      setQuery(params.certificateId);
      setMode('id');
      void lookupById(params.certificateId, 'qr');
    }
  }, [params.certificateId, lookupById]);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (mode === 'id') void lookupById(query);
    else void lookupByCompany(query);
  };

  const status = result ? STATUS_STYLES[result.status] || STATUS_STYLES.not_found : null;
  const StatusIcon = status?.icon || ShieldCheck;
  const integrityOk = result?.found && result.integrityValid !== false && result.signatureValid !== false;

  const trustColor = useMemo(() => (result?.level ? LEVEL_COLORS[result.level] || '#A78BFA' : '#A78BFA'), [result]);

  return (
    <div className="min-h-screen bg-[#050A17] px-4 py-14 text-white">
      <div className="mx-auto max-w-3xl">
        {/* Brand header */}
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-3 flex items-center gap-2">
            <span className="grid h-11 w-11 place-items-center rounded-full bg-gradient-to-br from-violet-500 to-blue-600 font-serif text-2xl font-bold">Q</span>
            <span className="text-2xl font-black">
              <span className="text-violet-400">Qguard</span> <span className="text-cyan-400">Helix</span>
            </span>
          </div>
          <h1 className="text-2xl font-black tracking-tight md:text-3xl">Quantum Trust Certificate Verification</h1>
          <p className="mt-2 max-w-xl text-sm text-white/55">
            Verify the authenticity, integrity and live status of any QGuard Helix Quantum Trust Certificate™. Each
            certificate is signed with ML-DSA-65 (FIPS 204) and re-verified from its cryptographic hash on every lookup.
          </p>
        </div>

        {/* Search */}
        <form onSubmit={onSubmit} className="rounded-2xl border border-white/10 bg-white/[0.03] p-5 backdrop-blur">
          <div className="mb-3 flex gap-2">
            <button
              type="button"
              onClick={() => setMode('id')}
              className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-bold transition ${mode === 'id' ? 'border-violet-400/50 bg-violet-500/15 text-violet-200' : 'border-white/10 bg-black/20 text-white/55'}`}
            >
              <Fingerprint className="h-3.5 w-3.5" /> Certificate ID
            </button>
            <button
              type="button"
              onClick={() => setMode('company')}
              className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-bold transition ${mode === 'company' ? 'border-violet-400/50 bg-violet-500/15 text-violet-200' : 'border-white/10 bg-black/20 text-white/55'}`}
            >
              <Building2 className="h-3.5 w-3.5" /> Company Name
            </button>
          </div>
          <div className="flex gap-2">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={mode === 'id' ? 'QTH-2026-000123' : 'ACME Corporation'}
              className="w-full rounded-lg border border-white/12 bg-black/40 px-4 py-2.5 text-sm outline-none focus:border-violet-400/50"
            />
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-lg border border-violet-400/40 bg-gradient-to-r from-violet-600 to-blue-600 px-5 py-2.5 text-sm font-bold text-white disabled:opacity-50"
            >
              <Search className="h-4 w-4" /> {loading ? 'Verifying…' : 'Verify'}
            </button>
          </div>
        </form>

        {errorMsg ? <div className="mt-4 rounded-lg border border-red-400/30 bg-red-400/10 px-4 py-3 text-sm text-red-200">{errorMsg}</div> : null}

        {/* Company matches */}
        {matches ? (
          <div className="mt-6 rounded-2xl border border-white/10 bg-white/[0.03] p-5">
            <div className="mb-3 text-sm font-bold text-white/80">
              {matches.length} certificate{matches.length === 1 ? '' : 's'} found
            </div>
            {matches.length === 0 ? (
              <div className="text-sm text-white/45">No certificates match that organization name.</div>
            ) : (
              <div className="space-y-2">
                {matches.map((m) => (
                  <button
                    key={m.certificateId}
                    type="button"
                    onClick={() => {
                      setQuery(m.certificateId);
                      setMode('id');
                      void lookupById(m.certificateId);
                    }}
                    className="flex w-full items-center justify-between rounded-lg border border-white/8 bg-black/20 px-4 py-3 text-left transition hover:border-violet-400/40"
                  >
                    <div>
                      <div className="text-sm font-bold">{m.organization}</div>
                      <div className="font-mono text-[11px] text-white/45">{m.certificateId}</div>
                    </div>
                    <div className="text-right">
                      <div className="text-xs font-bold uppercase" style={{ color: LEVEL_COLORS[m.level] || '#A78BFA' }}>
                        {m.level}
                      </div>
                      <div className="text-[11px] text-white/45">{m.trustScore}/1000</div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        ) : null}

        {/* Verification result */}
        {result ? (
          <div className="mt-6 overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03]">
            {/* Status banner */}
            <div className={`flex items-center gap-4 border-b border-white/10 px-6 py-5 ${status?.ring}`}>
              <StatusIcon className="h-10 w-10" style={{ color: status?.color }} />
              <div className="flex-1">
                <div className="text-lg font-black" style={{ color: status?.color }}>
                  {status?.label}
                </div>
                <div className="text-sm text-white/60">{result.statusDetail}</div>
              </div>
              {result.found ? (
                <div className="text-right">
                  <div className="text-3xl font-black" style={{ color: trustColor }}>
                    {result.trustScore}
                  </div>
                  <div className="text-[10px] uppercase tracking-wide text-white/40">Trust Score /1000</div>
                </div>
              ) : null}
            </div>

            {result.found ? (
              <div className="p-6">
                <div className="mb-5 flex items-center gap-3">
                  <Award className="h-6 w-6" style={{ color: trustColor }} />
                  <div>
                    <div className="text-xl font-black">{result.organization}</div>
                    <div className="text-xs font-bold uppercase tracking-wide" style={{ color: trustColor }}>
                      {result.levelLabel} · {result.level?.toUpperCase()}
                    </div>
                  </div>
                </div>

                {/* A verified signature proves AUTHENTICITY, not that the estate
                    is quantum-safe. Anyone reading this page must be able to
                    tell a measured baseline from a certification. */}
                {result.certified === false ? (
                  <div className="mb-5 rounded-lg border border-amber-400/30 bg-amber-400/[0.07] px-4 py-3">
                    <div className="flex items-center gap-2 text-xs font-black uppercase tracking-wide text-amber-300">
                      <ShieldAlert className="h-4 w-4" /> Baseline attestation — not a certification
                    </div>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-white/60">
                      This is an authentic, signed record of a completed Quantum Readiness Assessment. It states the
                      cryptographic posture that was <strong>measured</strong> — it does <strong>not</strong> attest that
                      the organization is quantum-safe. {result.criteriaMet} of {result.criteriaTotal} certification
                      criteria were met at issuance. Quantum Trust Certified™ status begins at Silver.
                    </p>
                  </div>
                ) : (
                  <div className="mb-5 rounded-lg border border-emerald-400/30 bg-emerald-400/[0.07] px-4 py-3">
                    <div className="flex items-center gap-2 text-xs font-black uppercase tracking-wide text-emerald-300">
                      <BadgeCheck className="h-4 w-4" /> Quantum Trust Certified™
                    </div>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-white/60">
                      All {result.criteriaTotal || 10} required certification criteria were met by measured evidence at
                      issuance, and continuous monitoring re-validates this certificate on every assessment.
                    </p>
                  </div>
                )}

                {/* Integrity + signature */}
                <div className="mb-5 grid gap-3 sm:grid-cols-2">
                  <div className={`flex items-center gap-2.5 rounded-lg border px-4 py-3 ${integrityOk ? 'border-emerald-400/30 bg-emerald-400/[0.06]' : 'border-red-400/30 bg-red-400/[0.06]'}`}>
                    {integrityOk ? <BadgeCheck className="h-5 w-5 text-emerald-400" /> : <ShieldX className="h-5 w-5 text-red-400" />}
                    <div>
                      <div className="text-xs font-bold">{integrityOk ? 'Integrity Verified' : 'Integrity Failure'}</div>
                      <div className="text-[10px] text-white/45">SHA3-256 hash {result.integrityValid === false ? 'mismatch' : 'matches'}</div>
                    </div>
                  </div>
                  <div className={`flex items-center gap-2.5 rounded-lg border px-4 py-3 ${result.signatureValid !== false ? 'border-emerald-400/30 bg-emerald-400/[0.06]' : 'border-red-400/30 bg-red-400/[0.06]'}`}>
                    {result.signatureValid !== false ? <ShieldCheck className="h-5 w-5 text-emerald-400" /> : <ShieldX className="h-5 w-5 text-red-400" />}
                    <div>
                      <div className="text-xs font-bold">Digital Signature {result.signatureValid === false ? 'Invalid' : 'Valid'}</div>
                      <div className="text-[10px] text-white/45">{result.signatureAlgorithm}</div>
                    </div>
                  </div>
                </div>

                {/* Fields */}
                <div className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
                  {[
                    ['Certificate ID', result.certificateId],
                    ['Overall Readiness', `${result.overallReadiness}%`],
                    ['Issued', fmtDate(result.issuedAt)],
                    ['PQC Adoption', `${result.pqcAdoption}%`],
                    ['Expires', fmtDate(result.expiresAt)],
                    ['Residual Risk', result.residualRiskLevel || '—'],
                    ['Assessment Version', result.assessmentVersion || '—'],
                    ['Last Validated', fmtDate(result.lastValidatedAt)],
                  ].map(([label, value]) => (
                    <div key={label} className="flex items-center justify-between border-b border-white/6 pb-1.5 text-sm">
                      <span className="text-white/45">{label}</span>
                      <span className="font-mono text-white/80">{value}</span>
                    </div>
                  ))}
                </div>

                {/* Certified algorithms */}
                {result.certifiedAlgorithms.length ? (
                  <div className="mt-5">
                    <div className="mb-2 text-[11px] font-bold uppercase tracking-wide text-violet-300">Certified Algorithm Stack</div>
                    <div className="flex flex-wrap gap-2">
                      {result.certifiedAlgorithms.map((a, i) => (
                        <span key={i} className="rounded-md border border-white/10 bg-black/30 px-2.5 py-1 text-[11px]">
                          <span className="text-white/50">{a.category}:</span> <span className="font-bold text-white/85">{a.algorithm}</span>
                          {a.standard ? <span className="text-white/40"> ({a.standard})</span> : null}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}

                {/* Hash */}
                <div className="mt-5 rounded-lg border border-white/8 bg-black/30 px-4 py-3">
                  <div className="text-[10px] font-bold uppercase tracking-wide text-white/40">Certificate Hash (SHA3-256)</div>
                  <div className="mt-1 break-all font-mono text-[11px] text-white/60">{result.certificateHash}</div>
                </div>
                <div className="mt-3 text-[10px] text-white/35">Verified at {new Date(result.verifiedAt).toLocaleString()}.</div>
              </div>
            ) : (
              <div className="p-6 text-sm text-white/55">No certificate with ID “{result.certificateId}” exists in the QGuard Helix registry.</div>
            )}
          </div>
        ) : null}

        <div className="mt-8 text-center text-xs text-white/35">
          <Link to="/" className="text-violet-300 no-underline hover:text-violet-200">
            ← Back to QGuard Helix
          </Link>
        </div>
      </div>
    </div>
  );
}
