'use client';

import { useMemo, useState } from 'react';
import { Activity, AlertTriangle, BarChart3, CheckCircle2, Clock, Eye, KeyRound, Ruler, XCircle } from 'lucide-react';
import { AMBER, CYAN, GREEN, RED, SLATE, VIOLET, fmtInt, fullTimestamp, relativeTime } from '../_components/intel/kit';
import type { IdentityQuantumClass, PQAuthSigningKey, PQAuthSnapshot } from '@/types/pqauth-dashboard';
import {
  Badge, Card, ClassBadge, DetailDrawer, EvidenceUrl, Field, FilterChips, Notice, Pager, Reveal, RouteLink, SearchBox, fmtBytes, td, th, usePaged,
  ink,
} from './_ui';

/** Common default limit on total request-header size (e.g. NGINX `large_client_header_buffers 4 8k`). A reference line, not a measurement. */
const HEADER_REFERENCE_BYTES = 8 * 1024;

export function TokensView({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const { tokens } = snapshot.identity;
  const [query, setQuery] = useState('');
  const [cls, setCls] = useState<'all' | IdentityQuantumClass>('all');
  const [lifecycle, setLifecycle] = useState<'published' | 'all'>('published');
  const [open, setOpen] = useState<PQAuthSigningKey | null>(null);

  const keys = useMemo(() => {
    const q = query.trim().toLowerCase();
    return tokens.keys.filter((k) =>
      (lifecycle === 'all' || k.lifecycle === 'published')
      && (cls === 'all' || k.quantumClass === cls)
      && (!q || `${k.providerLabel} ${k.keyId} ${k.displayAlgorithm} ${k.keyType}`.toLowerCase().includes(q)));
  }, [tokens.keys, query, cls, lifecycle]);
  const paged = usePaged(keys, 10);
  const published = tokens.keys.filter((k) => k.lifecycle === 'published');
  const signing = published.filter((k) => k.use !== 'encryption');
  const vulnerable = signing.filter((k) => k.quantumClass === 'vulnerable');
  const rotated = tokens.keys.filter((k) => k.lifecycle === 'no-longer-published');
  const pqcAdvertisers = new Set(tokens.advertised.filter((a) => a.role === 'signing' && (a.quantumClass === 'safe' || a.quantumClass === 'hybrid') && /ML-?DSA|SLH-?DSA/i.test(a.algorithm)).map((a) => a.providerId)).size;
  const count = (c: IdentityQuantumClass) => published.filter((k) => k.quantumClass === c).length;

  if (!tokens.keys.length && !tokens.advertised.length) {
    return (
      <div className="space-y-4">
        <VerificationLevels />
        <Card title="Token signing intelligence" icon={KeyRound}>
          <Notice tone="info" icon={Eye} title="No token-signing evidence has been observed">
            This page analyses the keys that sign your identity tokens, read from each provider&apos;s published JWKS. No identity provider has been discovered yet,
            so there is nothing to analyse — no token or key data is invented in its place.
          </Notice>
          <div className="mt-3"><RouteLink to="/dashboard/pqauth/discovery">Run identity discovery</RouteLink></div>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Reveal><VerificationLevels /></Reveal>

      <Reveal delay={0.03} className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Kpi label="Signing keys published" value={fmtInt(signing.length)} color={CYAN} detail="in the most recent JWKS reads" />
        <Kpi label="Quantum-vulnerable" value={fmtInt(vulnerable.length)} color={vulnerable.length ? RED : GREEN} detail="RSA / ECDSA / EdDSA signing keys" />
        <Kpi label="Rotated out" value={fmtInt(rotated.length)} color={SLATE} detail="seen before, absent from the latest JWKS" />
        <Kpi label="Advertise ML-DSA" value={fmtInt(pqcAdvertisers)} color={pqcAdvertisers ? GREEN : AMBER} detail="providers with a PQC signing alg in discovery" />
        <Kpi label="Runtime token ops" value={tokens.runtime.measured ? fmtInt(tokens.runtime.operations) : '—'} color={VIOLET} detail={tokens.runtime.measured ? `observed by agents · ${tokens.runtime.latestAt ? relativeTime(tokens.runtime.latestAt) : 'none recent'}` : 'Awaiting runtime telemetry'} />
      </Reveal>

      <Reveal delay={0.06}>
        <Card title="Signing-key ledger" icon={KeyRound} meta={`${keys.length} shown`}>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <SearchBox value={query} onChange={setQuery} placeholder="Search provider, kid or algorithm…" label="Search keys" />
            <FilterChips label="Posture" value={cls} onChange={setCls} options={[
              { key: 'all', label: 'All' }, { key: 'vulnerable', label: 'Vulnerable', count: count('vulnerable') },
              { key: 'hybrid', label: 'Hybrid', count: count('hybrid') }, { key: 'safe', label: 'Post-quantum', count: count('safe') },
              { key: 'unknown', label: 'Undetermined', count: count('unknown') },
            ]} />
            <FilterChips label="Lifecycle" value={lifecycle} onChange={setLifecycle} options={[{ key: 'published', label: 'Published' }, { key: 'all', label: 'Include rotated', count: rotated.length }]} />
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px]">
              <thead>
                <tr className="border-b border-white/10">
                  <th className={th()}>Provider</th><th className={th()}>Key (kid)</th><th className={th()}>Algorithm</th><th className={th()}>Use</th>
                  <th className={th()}>Posture</th><th className={th()}>Migration target</th><th className={th('text-right')}>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {paged.slice.map((k) => (
                  <tr key={k.id} className="cursor-pointer border-b border-white/[0.05] transition hover:bg-white/[0.03]" onClick={() => setOpen(k)}>
                    <td className={td('font-semibold text-white')}>{k.providerLabel}</td>
                    <td className={td()}>
                      <button type="button" onClick={(e) => { e.stopPropagation(); setOpen(k); }} className="font-mono text-cyan-200 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">{k.keyId}</button>
                      {k.lifecycle === 'no-longer-published' ? <div className="text-[9.5px] text-white/50">rotated out</div> : null}
                    </td>
                    <td className={td('font-mono')}>
                      {k.displayAlgorithm}
                      <div className="text-[9.5px] text-white/50">{k.keyType}{k.keySize ? ` · ${k.keySize}-bit` : ''}{k.curve ? ` · ${k.curve}` : ''}{k.algorithm ? '' : ' · alg not stated'}</div>
                    </td>
                    <td className={td()}>{k.use}</td>
                    <td className={td()}><ClassBadge value={k.quantumClass} /></td>
                    <td className={td('text-white/60')}>{k.pqcTarget ?? '—'}</td>
                    <td className={td('text-right text-white/45')} title={fullTimestamp(k.lastSeenAt)}>{relativeTime(k.lastSeenAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!paged.total ? <p className="py-4 text-center text-[11px] text-white/50">No key matches the filters.</p> : null}
          <Pager page={paged.page} pages={paged.pages} total={paged.total} setPage={paged.setPage} />
        </Card>
      </Reveal>

      <Reveal delay={0.09} className="grid gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <SizeImpact snapshot={snapshot} />
        <Card title="Advertised algorithms" icon={BarChart3} meta="from discovery documents">
          {tokens.conflicts.length ? (
            <div className="mb-3 space-y-2">
              {tokens.conflicts.map((c, i) => (
                <Notice key={`${c.providerId}-${i}`} tone={/none/.test(c.detail) ? 'critical' : 'warning'} icon={AlertTriangle} title={`${c.providerLabel}: advertised ≠ observed`}>{c.detail}</Notice>
              ))}
            </div>
          ) : null}
          {tokens.advertised.length ? (
            <div className="max-h-[360px] overflow-y-auto">
              <table className="w-full">
                <thead><tr className="border-b border-white/10"><th className={th()}>Provider</th><th className={th()}>Algorithm</th><th className={th()}>Role</th><th className={th()}>Posture</th></tr></thead>
                <tbody>
                  {tokens.advertised.map((a, i) => (
                    <tr key={`${a.providerId}-${a.role}-${a.algorithm}-${i}`} className="border-b border-white/[0.05] last:border-0">
                      <td className={td('text-white/60')}>{a.providerLabel}</td>
                      <td className={td('font-mono text-white')}>{a.algorithm}</td>
                      <td className={td('text-white/55')}>{a.role}</td>
                      <td className={td()}><ClassBadge value={a.quantumClass} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="text-[11px] text-white/50">No provider document advertises signing or encryption algorithms.</p>}
          <p className="mt-2 text-[10px] leading-relaxed text-white/50">“Advertised” means the provider says it supports an algorithm. What it actually signs with is the JWKS ledger above.</p>
        </Card>
      </Reveal>

      <Reveal delay={0.12}><KeyTimeline keys={tokens.keys} /></Reveal>

      <DetailDrawer open={Boolean(open)} onClose={() => setOpen(null)} title={open ? `${open.displayAlgorithm} · kid ${open.keyId}` : ''} subtitle={open?.providerLabel}>
        {open ? <KeyDetail k={open} snapshot={snapshot} /> : null}
      </DetailDrawer>
    </div>
  );
}

function Kpi({ label, value, color, detail }: { label: string; value: string; color: string; detail: string }) {
  return (
    <div className="qg-executive-panel rounded-xl p-4 text-white">
      <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/45">{label}</div>
      <div className="mt-2 font-mono text-[26px] font-black leading-none" style={{ color: ink(color) }}>{value}</div>
      <div className="mt-2 text-[10.5px] leading-snug text-white/45">{detail}</div>
    </div>
  );
}

/** The three claims a token page could make, and which of them this one makes. */
function VerificationLevels() {
  const levels = [
    { icon: CheckCircle2, hex: GREEN, title: 'Metadata inspected', state: 'Performed', body: 'Public discovery documents and JWKS were read and parsed: issuer, published keys, algorithms, sizes.' },
    { icon: XCircle, hex: SLATE, title: 'Signature verified', state: 'Not performed', body: 'No token was captured, so no token signature was cryptographically verified. Key posture describes what CAN sign, not a checked token.' },
    { icon: XCircle, hex: SLATE, title: 'Authentication observed', state: 'Runtime agents only', body: 'Successful logins and token validations are only known from runtime telemetry, shown in Runtime Identity Telemetry.' },
  ];
  return (
    <section aria-label="What this page verifies" className="grid gap-2.5 md:grid-cols-3">
      {levels.map((level) => (
        <div key={level.title} className="rounded-xl border border-white/10 bg-white/[0.02] p-3.5">
          <div className="flex items-center gap-2">
            <level.icon className="h-4 w-4" style={{ color: ink(level.hex) }} aria-hidden="true" />
            <span className="text-[11.5px] font-black text-white">{level.title}</span>
            <span className="ml-auto text-[9px] font-black uppercase tracking-wider" style={{ color: ink(level.hex) }}>{level.state}</span>
          </div>
          <p className="mt-1.5 text-[10.5px] leading-relaxed text-white/50">{level.body}</p>
        </div>
      ))}
      <p className="text-[10px] text-white/50 md:col-span-3">Raw tokens, refresh tokens and private keys are never collected, stored or displayed. Key ids (kid) are public JWKS metadata.</p>
    </section>
  );
}

function SizeImpact({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const rows = snapshot.identity.tokens.projections;
  const max = Math.max(1, ...rows.map((r) => Math.ceil((r.targetSignatureBytes * 4) / 3)));
  return (
    <Card title="Token size impact" icon={Ruler} meta="projected · FIPS 204 sizes">
      {rows.length ? (
        <>
          <p className="mb-3 text-[11px] leading-relaxed text-white/50">
            Growth of the base64url signature segment of a compact JWT if each classical key is replaced by its ML-DSA target. Computed from published signature
            sizes — projected, not measured from a live token.
          </p>
          <ul className="space-y-3">
            {rows.slice(0, 8).map((r) => {
              const cur = Math.ceil((r.currentSignatureBytes * 4) / 3);
              const tgt = Math.ceil((r.targetSignatureBytes * 4) / 3);
              return (
                <li key={r.keyRef}>
                  <div className="mb-1 flex items-center justify-between gap-2 text-[10.5px]">
                    <span className="truncate text-white/70">{r.providerLabel} · <span className="font-mono">{r.currentAlgorithm}</span> → <span className="font-mono text-violet-200">{r.targetAlgorithm}</span></span>
                    <span className="shrink-0 font-mono text-amber-200">+{fmtBytes(r.encodedDeltaBytes)} · {r.expansion}×</span>
                  </div>
                  <div className="space-y-1">
                    <div className="h-2 rounded-full bg-cyan-400/80" style={{ width: `${Math.max(1.5, (cur / max) * 100)}%` }} title={`Current: ${fmtBytes(cur)} encoded`} />
                    <div className="h-2 rounded-full bg-violet-400/80" style={{ width: `${(tgt / max) * 100}%` }} title={`Projected: ${fmtBytes(tgt)} encoded`} />
                  </div>
                </li>
              );
            })}
          </ul>
          <div className="mt-3 flex flex-wrap gap-4 text-[10px] text-white/45">
            <span><span className="mr-1 inline-block h-2 w-3 rounded-sm bg-cyan-400/80 align-middle" />Current signature</span>
            <span><span className="mr-1 inline-block h-2 w-3 rounded-sm bg-violet-400/80 align-middle" />Projected ML-DSA signature</span>
          </div>
          <Notice tone="warning" icon={AlertTriangle} title={`Reference: ${fmtBytes(HEADER_REFERENCE_BYTES)} request-header budget`}>
            Many proxies and servers default to an {fmtBytes(HEADER_REFERENCE_BYTES)} header buffer. An ML-DSA-65 signature alone adds about {fmtBytes(rows[0]?.encodedDeltaBytes ?? 0)} to every bearer token
            and cookie — validate gateway, CDN, cookie (4 KB) and mobile limits before switching. Model it in the Digital Twin.
          </Notice>
        </>
      ) : (
        <p className="text-[11px] leading-relaxed text-white/50">No published classical signing key with a known signature size — there is nothing to project.</p>
      )}
    </Card>
  );
}

function KeyTimeline({ keys }: { keys: PQAuthSigningKey[] }) {
  const dated = keys.filter((k) => k.firstSeenAt && k.lastSeenAt);
  if (!dated.length) return null;
  const start = Math.min(...dated.map((k) => Date.parse(k.firstSeenAt!)));
  const end = Math.max(Date.now(), ...dated.map((k) => Date.parse(k.lastSeenAt!)));
  const span = Math.max(1, end - start);
  return (
    <Card title="Key lifecycle timeline" icon={Clock} meta="first → last observation per key">
      <ul className="space-y-1.5">
        {dated.slice(0, 16).map((k) => {
          const a = ((Date.parse(k.firstSeenAt!) - start) / span) * 100;
          const b = ((Date.parse(k.lastSeenAt!) - start) / span) * 100;
          const hex = k.quantumClass === 'vulnerable' ? RED : k.quantumClass === 'safe' ? GREEN : k.quantumClass === 'hybrid' ? CYAN : SLATE;
          return (
            <li key={k.id} className="grid grid-cols-[180px_minmax(0,1fr)] items-center gap-3 text-[10.5px]">
              <span className="truncate text-white/60" title={`${k.providerLabel} · ${k.keyId}`}>{k.displayAlgorithm} · <span className="font-mono">{k.keyId}</span></span>
              <span className="relative h-3 rounded-full bg-white/[0.04]">
                <span className="absolute top-0 h-3 rounded-full" style={{ left: `${a}%`, width: `${Math.max(1.2, b - a)}%`, backgroundColor: hex, opacity: k.lifecycle === 'published' ? 0.85 : 0.35 }} title={`${fullTimestamp(k.firstSeenAt)} → ${fullTimestamp(k.lastSeenAt)}`} />
              </span>
            </li>
          );
        })}
      </ul>
      <div className="mt-2 flex justify-between font-mono text-[9.5px] text-white/50"><span>{fullTimestamp(new Date(start).toISOString())}</span><span>now</span></div>
      <p className="mt-2 text-[10px] leading-relaxed text-white/50">Key lifecycle is observed from successive JWKS reads. Token expiry and revocation are not shown: tokens are never captured.</p>
    </Card>
  );
}

function KeyDetail({ k, snapshot }: { k: PQAuthSigningKey; snapshot: PQAuthSnapshot }) {
  const projection = snapshot.identity.tokens.projections.find((p) => p.keyRef === k.id);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1.5"><ClassBadge value={k.quantumClass} /><Badge meta={{ label: k.lifecycle === 'published' ? 'Published' : 'Rotated out', hex: k.lifecycle === 'published' ? CYAN : SLATE, glyph: k.lifecycle === 'published' ? '●' : '○', hint: 'From successive JWKS reads' }} /></div>
      <dl>
        <Field label="Provider">{k.providerLabel}</Field>
        <Field label="kid"><span className="break-all font-mono">{k.keyId}</span></Field>
        <Field label="JWK alg">{k.algorithm ?? <span className="text-white/50">Not stated — classified from key type</span>}</Field>
        <Field label="Key type">{k.keyType}{k.keySize ? ` · ${k.keySize}-bit` : ''}{k.curve ? ` · ${k.curve}` : ''}</Field>
        <Field label="Use / purpose">{k.use} · {k.purpose}</Field>
        <Field label="Why">{k.rationale ?? '—'}</Field>
        <Field label="Target">{k.pqcTarget ?? 'No migration required'}{k.standard ? ` (${k.standard})` : ''}</Field>
        <Field label="Signature size">{k.signatureBytes ? `${fmtBytes(k.signatureBytes)} raw` : 'Not applicable / unknown'}</Field>
        {projection ? <Field label="Projected">{projection.targetAlgorithm}: {fmtBytes(projection.targetSignatureBytes)} raw · +{fmtBytes(projection.encodedDeltaBytes)} per token (base64url)</Field> : null}
        <Field label="First seen">{fullTimestamp(k.firstSeenAt)}</Field>
        <Field label="Last seen">{fullTimestamp(k.lastSeenAt)}</Field>
        <Field label="Evidence"><EvidenceUrl url={k.sourceUrl} /></Field>
      </dl>
      <div className="flex flex-wrap gap-1.5">
        <RouteLink to={`/dashboard/pqauth/trust-graph?focus=key:${k.id}`} tone="ghost">Show in trust graph</RouteLink>
        <RouteLink to="/dashboard/pqauth/digital-twin" tone="ghost">Simulate migration</RouteLink>
      </div>
      <p className="text-[10px] leading-relaxed text-white/50"><Activity className="mr-1 inline h-3 w-3" aria-hidden="true" />Only public JWK parameters are stored. Signing keys migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); ML-KEM is a key-encapsulation mechanism and never replaces a signing key.</p>
    </div>
  );
}
