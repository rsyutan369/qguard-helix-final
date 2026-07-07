import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { UnsecuredJWT } from 'jose';
import { BadgeCheck, FileSearch, ShieldAlert, ShieldCheck } from 'lucide-react';

/**
 * Public report-verification page (Reports Improvements_04 #9).
 *
 * Every generated report is sealed with a SHA3-256 integrity hash and a
 * verification token (printed — and QR-encoded — on the report's Executive
 * Certification Summary page). This page decodes the token and displays the
 * report identity + hash it attests to, so a reader can confirm the hash
 * printed on the document matches the one carried by the token. Any alteration
 * of the report content changes its SHA3-256 hash.
 *
 * Verification is fully client-side: the token never leaves the browser.
 */

interface DecodedVerification {
  reportId: string;
  kind: string;
  hash: string;
  issuedAt: string | null;
  issuer: string;
}

function decodeToken(token: string): DecodedVerification {
  const { payload } = UnsecuredJWT.decode(token.trim());
  const hash = typeof payload.hash === 'string' ? payload.hash : '';
  const reportId = typeof payload.reportId === 'string' ? payload.reportId : String(payload.sub || '');
  if (!hash || !reportId) throw new Error('Token payload is missing the report hash or id.');
  return {
    reportId,
    kind: typeof payload.kind === 'string' ? payload.kind : 'unknown',
    hash,
    issuedAt: payload.iat ? new Date(payload.iat * 1000).toLocaleString() : null,
    issuer: String(payload.iss || 'unknown'),
  };
}

export default function VerifyReport() {
  const [params] = useSearchParams();
  const [token, setToken] = useState(() => params.get('token') || '');

  useEffect(() => {
    const fromUrl = params.get('token');
    if (fromUrl) setToken(fromUrl);
  }, [params]);

  const result = useMemo(() => {
    if (!token.trim()) return null;
    try {
      return { ok: true as const, decoded: decodeToken(token) };
    } catch {
      return { ok: false as const };
    }
  }, [token]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-cyber-black px-6 py-24 text-white">
      <div className="w-full max-w-2xl rounded-2xl border border-gold/20 bg-cyber-navy/40 p-10 shadow-[0_30px_120px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
        <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full border border-gold/40 bg-gold/10">
          <FileSearch className="h-9 w-9 text-gold" />
        </div>

        <h1 className="text-center text-2xl font-black tracking-tight text-white md:text-3xl">Report Verification</h1>
        <p className="mt-3 text-center text-sm leading-relaxed text-muted-foreground">
          Paste the verification token printed on a QGuard Helix report — or scan the QR code on its Executive
          Certification Summary page to arrive here with the token pre-filled. The decoded SHA3-256 hash must match the
          integrity hash printed on the document.
        </p>

        <label className="mt-6 block">
          <span className="font-mono text-[11px] uppercase tracking-widest text-gold">Verification token</span>
          <textarea
            value={token}
            onChange={(e) => setToken(e.target.value)}
            rows={4}
            spellCheck={false}
            placeholder="eyJhbGciOiJub25lIn0..."
            className="mt-2 w-full resize-none rounded-xl border border-white/10 bg-black/30 px-4 py-3 font-mono text-xs text-white outline-none transition-colors focus:border-gold/50"
          />
        </label>

        {result === null ? null : result.ok ? (
          <div className="mt-6 rounded-xl border border-emerald-400/25 bg-emerald-400/[0.06] p-5">
            <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-widest text-emerald-300">
              <ShieldCheck className="h-4 w-4" /> Token decoded successfully
            </div>
            <dl className="mt-4 space-y-3 text-sm">
              <div>
                <dt className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Report ID</dt>
                <dd className="mt-0.5 break-all font-mono text-xs text-white/90">{result.decoded.reportId}</dd>
              </div>
              <div>
                <dt className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Report type · Issuer{result.decoded.issuedAt ? ' · Signed at' : ''}</dt>
                <dd className="mt-0.5 text-xs text-white/80 capitalize">
                  {result.decoded.kind} · {result.decoded.issuer}
                  {result.decoded.issuedAt ? ` · ${result.decoded.issuedAt}` : ''}
                </dd>
              </div>
              <div>
                <dt className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Attested SHA3-256 integrity hash</dt>
                <dd className="mt-0.5 break-all rounded-lg border border-white/10 bg-black/30 px-3 py-2 font-mono text-[11px] leading-relaxed text-emerald-200">
                  {result.decoded.hash}
                </dd>
              </div>
            </dl>
            <p className="mt-4 flex items-start gap-2 text-xs leading-relaxed text-muted-foreground">
              <BadgeCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
              Compare this hash with the “Report integrity (SHA3-256)” value printed on the report’s Executive
              Certification Summary / Evidence Sources page. If they match, the document you hold is the one that was
              signed; if they differ, the document has been altered since generation.
            </p>
          </div>
        ) : (
          <div className="mt-6 flex items-start gap-3 rounded-xl border border-red-400/25 bg-red-400/[0.06] p-5 text-sm text-red-200">
            <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0" />
            <span>
              This token could not be decoded. Check that the full token was pasted (they are long) and that it comes
              from a QGuard Helix report. Tokens are read locally — nothing is uploaded.
            </span>
          </div>
        )}

        <div className="mt-8 text-center">
          <Link to="/" className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground transition-colors hover:text-gold">
            Back to home
          </Link>
        </div>
      </div>
    </div>
  );
}
