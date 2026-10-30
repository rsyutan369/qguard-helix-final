'use client';

import { Activity, Database, KeyRound, Scale, ShieldAlert } from 'lucide-react';
import { AMBER, CYAN, GREEN, RED, SLATE, VIOLET, fmtInt, relativeTime } from '../_components/intel/kit';
import type { PQAuthRow, PQAuthSnapshot } from '@/types/pqauth-dashboard';
import { Badge, Card, Notice, Pager, Reveal, RouteLink, td, th, usePaged, ink } from './_ui';

/*
 * The four estate-wide PQAuth modules. They read tenant crypto inventory,
 * runtime telemetry, compliance evidence and key tables rather than the
 * identity discovery records, and say so on the page.
 */

function Tile({ label, value, detail, color }: { label: string; value: string; detail: string; color: string }) {
  return (
    <div className="qg-executive-panel rounded-xl p-4 text-white">
      <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/45">{label}</div>
      <div className="mt-2 font-mono text-[26px] font-black leading-none" style={{ color: ink(color) }}>{value}</div>
      <div className="mt-2 text-[10.5px] leading-snug text-white/45">{detail}</div>
    </div>
  );
}

function RowTable({ rows, empty }: { rows: PQAuthRow[]; empty: string }) {
  const paged = usePaged(rows, 12);
  if (!rows.length) return <p className="rounded-lg border border-dashed border-white/12 px-4 py-6 text-center text-[11px] text-white/50">{empty}</p>;
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px]">
          <thead><tr className="border-b border-white/10"><th className={th()}>Subject</th><th className={th()}>Algorithm</th><th className={th()}>Type / status</th><th className={th()}>Source</th><th className={th('text-right')}>Observed</th></tr></thead>
          <tbody>
            {paged.slice.map((row) => (
              <tr key={`${row.sourceTable}:${row.id}`} className="border-b border-white/[0.05] last:border-0">
                <td className={td('font-semibold text-white')}>{row.name}{row.detail ? <div className="line-clamp-2 text-[10px] font-normal text-white/50">{row.detail}</div> : null}</td>
                <td className={td('font-mono')}>{row.algorithm ?? '—'}</td>
                <td className={td('text-white/55')}>{[row.type, row.status, row.severity].filter(Boolean).join(' · ') || '—'}</td>
                <td className={td('font-mono text-[10px] text-white/45')}>{row.sourceTable}</td>
                <td className={td('text-right text-white/45')}>{relativeTime(row.lastUpdated)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager page={paged.page} pages={paged.pages} total={paged.total} setPage={paged.setPage} />
    </>
  );
}

export function ExposureView({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const m = snapshot.metrics;
  const keys = snapshot.identity.readiness;
  return (
    <div className="space-y-4">
      <Reveal className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile label="Classical signing keys" value={fmtInt(keys.vulnerableKeys)} color={keys.vulnerableKeys ? RED : GREEN} detail="identity providers' published JWKS keys" />
        <Tile label="Vulnerable components" value={`${fmtInt(m.vulnerableComponents)} / ${fmtInt(m.totalComponents)}`} color={m.vulnerableComponents ? ORANGE_HEX : GREEN} detail="crypto inventory, certificates and keys with a classical algorithm" />
        <Tile label="PQC-ready components" value={fmtInt(m.pqcReadyComponents)} color={CYAN} detail="explicit PQC flag or a named PQC algorithm" />
        <Tile label="Critical findings" value={fmtInt(m.criticalFindings)} color={m.criticalFindings ? RED : GREEN} detail={`of ${fmtInt(m.totalFindings)} findings (severity field only)`} />
      </Reveal>
      <Reveal delay={0.04} className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
        <Card title="Classical algorithm signals" icon={ShieldAlert} meta="estate-wide">
          {snapshot.algorithms.length ? (
            <ul className="space-y-2">
              {snapshot.algorithms.map((a) => (
                <li key={a.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                  <div className="flex items-center justify-between gap-2"><span className="text-[12px] font-black text-white">{a.label}</span><span className="font-mono text-[16px] font-black text-red-300">{fmtInt(a.count)}</span></div>
                  <div className="text-[10px] text-white/50">{a.family} · {a.sourceTables.join(', ')}</div>
                  <div className="mt-1 text-[10.5px] text-white/60">Replace with: {a.replacement}</div>
                </li>
              ))}
            </ul>
          ) : <p className="text-[11px] text-white/50">No classical algorithm is named in the descriptive fields of the inventory.</p>}
          <p className="mt-2 text-[10px] leading-relaxed text-white/50">Counted from algorithm and name fields only — never from ids or hashes. A record can name more than one algorithm.</p>
        </Card>
        <Card title="Exposure evidence" icon={ShieldAlert} meta={`${snapshot.exposureRows.length} newest records`}>
          <RowTable rows={snapshot.exposureRows} empty="No classical-algorithm evidence in the crypto inventory or findings." />
        </Card>
      </Reveal>
      <Notice tone="info" icon={ShieldAlert} title="Harvest-now-decrypt-later exposure has its own module">
        Signature algorithms (RSA / ECDSA signing) are a forgery risk, not a HNDL risk. Long-lived confidentiality exposure is assessed in <a className="text-cyan-200" href="/dashboard/harvest-now">Harvest Now, Decrypt Later</a>.
      </Notice>
    </div>
  );
}

const ORANGE_HEX = '#fb923c';

export function RuntimeView({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <div className="space-y-4">
      <Reveal className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {snapshot.runtimeMetrics.map((metric) => (
          <Tile key={metric.id} label={metric.label} value={metric.measured ? fmtInt(metric.value) : '—'} color={metric.measured ? (metric.id === 'trust-failures' || metric.id === 'identity-drift') && metric.value ? AMBER : CYAN : SLATE} detail={metric.measured ? metric.detail : 'Awaiting telemetry — not measured'} />
        ))}
      </Reveal>
      <Reveal delay={0.04}>
        <Card title="Runtime identity telemetry ledger" icon={Activity} meta={`${snapshot.runtimeEvents.length} newest events`}>
          <RowTable rows={snapshot.runtimeEvents} empty="No runtime identity telemetry has been received. Deploy runtime agents to observe authentication and token operations." />
          <p className="mt-2 text-[10px] text-white/50">Session token hashes, IP addresses and user agents are never sent to this page. E-mail addresses in event text are masked.</p>
        </Card>
      </Reveal>
      <RouteLink to="/dashboard/runtime-crypto-intel" tone="ghost">Runtime Cryptographic Intelligence</RouteLink>
    </div>
  );
}

export function ComplianceView({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const coverage = snapshot.identity.readiness.coverage;
  return (
    <div className="space-y-4">
      <Reveal className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <Tile label="Identity PQC signing coverage" value={coverage === null ? '—' : `${coverage}%`} color={coverage === null ? SLATE : coverage >= 80 ? GREEN : AMBER} detail="post-quantum or hybrid share of classified signing keys" />
        <Tile label="Frameworks with evidence" value={`${snapshot.complianceRows.filter((r) => r.assessed).length} / ${snapshot.complianceRows.length}`} color={VIOLET} detail="frameworks named by at least one evidence record" />
        <Tile label="Evidence records" value={fmtInt(snapshot.complianceRows.reduce((s, r) => s + r.evidenceCount, 0))} color={CYAN} detail="attributed exactly once across frameworks" />
      </Reveal>
      <Reveal delay={0.04}>
        <Card title="Framework coverage" icon={Scale}>
          <div className="grid gap-2.5 md:grid-cols-2 xl:grid-cols-4">
            {snapshot.complianceRows.map((row) => (
              <div key={row.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[12px] font-black text-white">{row.label}</span>
                  {row.assessed ? <span className="font-mono text-[12px] text-white/80">{row.evidenceCount} rec.</span> : <Badge meta={{ label: 'Not assessed', hex: SLATE, glyph: '?', hint: 'No evidence names this framework' }} />}
                </div>
                <p className="mt-1.5 text-[10px] text-white/50">{row.assessed ? `${row.evidence} · ${row.sourceTables.join(', ')} · ${relativeTime(row.latestAt)}` : 'Evidence required — no record names this framework.'}</p>
              </div>
            ))}
          </div>
          <p className="mt-2 text-[10px] text-white/50">Control-level status and audit evidence live in <a className="text-cyan-300" href="/dashboard/compliance">Compliance</a>; this view only shows which frameworks identity evidence exists for.</p>
        </Card>
      </Reveal>
    </div>
  );
}

export function QkmsView({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <div className="space-y-4">
      <Reveal className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <Card title="Identity key domains" icon={KeyRound} action={<RouteLink to="/dashboard/qkms/overview" tone="ghost">Open QKMS</RouteLink>}>
          <div className="grid gap-2.5 md:grid-cols-2">
            {snapshot.qkmsKeyDomains.map((row) => (
              <div key={row.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                <div className="flex items-center justify-between gap-2"><span className="text-[12px] font-black text-white">{row.label}</span><span className="font-mono text-[18px] font-black text-cyan-200">{fmtInt(row.count)}</span></div>
                <p className="mt-1 text-[10.5px] text-white/45">{row.detail}</p>
                <p className="mt-0.5 font-mono text-[9.5px] text-white/50">{row.sourceTables?.join(', ')}</p>
              </div>
            ))}
          </div>
        </Card>
        <Card title="Lifecycle controls" icon={Database}>
          <ul className="space-y-2">
            {snapshot.lifecycleControls.map((row) => (
              <li key={row.id} className="flex items-center justify-between gap-3 rounded-lg border border-white/10 bg-white/[0.02] p-3">
                <div><div className="text-[11.5px] font-bold text-white/80">{row.label}</div><div className="text-[10px] text-white/50">{row.detail}</div></div>
                <span className="flex items-center gap-2"><span className="font-mono text-white/70">{fmtInt(row.count)}</span><Badge meta={row.count ? { label: 'Evidence', hex: CYAN, glyph: '●', hint: 'Records exist for this control' } : { label: 'None', hex: SLATE, glyph: '○', hint: 'No record exists for this control' }} /></span>
              </li>
            ))}
          </ul>
        </Card>
      </Reveal>
    </div>
  );
}
