'use client';

import { Link } from 'react-router-dom';
import { ShieldHalf } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { PqcTlsPosture } from '@/lib/tls-pki/types';
import { Panel, Pill, SectionLabel, Term, TONE, fmtNumber, fmtPercent, type Tone } from './primitives';

/**
 * The unified PQC TLS Posture Dashboard (brief section 5).
 *
 * Rendered identically at the top of all four pages so the operator carries the
 * same numbers with them as they move TLS Telemetry -> PKI Visibility ->
 * Protocol Analytics -> TLS Orchestrator. Because every page receives this block
 * from the same server model, the figures cannot drift between them.
 *
 * Honesty rules encoded here:
 *   - Percentages are labelled with their denominator ("of 12 measured
 *     endpoints"), never floated free.
 *   - Coverage is stated up front: a 100% adoption figure over 2 of 40 assets
 *     is a coverage problem, not a success, and the strip says so.
 *   - `quantumReadinessScore` is the Quantum Readiness Engine's own number,
 *     reproduced rather than recomputed, so this page cannot contradict it.
 */

function Metric({
  label,
  value,
  basis,
  tone = 'neutral',
  hint,
  href,
}: {
  label: string;
  value: string;
  basis: string;
  tone?: Tone;
  hint?: string;
  href?: string;
}) {
  const body = (
    <>
      <div className="flex items-center gap-1.5 text-[9px] font-black uppercase tracking-[0.12em] text-white/40">
        {label}
        {hint ? <Term hint={hint} label={label} /> : null}
      </div>
      <div className={cn('mt-1.5 text-[22px] font-black leading-none', TONE[tone].text)}>{value}</div>
      <div className="mt-1 text-[9.5px] font-medium leading-snug text-white/35">{basis}</div>
    </>
  );
  if (href) {
    return (
      <Link
        to={href}
        className="block rounded-lg border border-white/8 bg-black/20 p-3 no-underline transition hover:border-cyan-400/35 hover:bg-black/35 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      >
        {body}
      </Link>
    );
  }
  return <div className="rounded-lg border border-white/8 bg-black/20 p-3">{body}</div>;
}

export function PostureStrip({ posture, totals }: { posture: PqcTlsPosture; totals: { endpoints: number; certificates: number } }) {
  const measured = posture.tlsEnabledAssets;
  const basisEndpoints = measured === 1 ? 'of 1 measured endpoint' : `of ${fmtNumber(measured)} measured endpoints`;
  const lowCoverage = posture.transportCoveragePercent < 60;

  return (
    <Panel>
      <SectionLabel
        icon={ShieldHalf}
        meta={
          <span className="normal-case tracking-normal">
            End-to-End Visibility · Hybrid TLS · NIST / CNSA 2.0
          </span>
        }
        hint="One posture model shared by TLS Telemetry, PKI Visibility, Protocol Analytics and the TLS Orchestrator. Every figure is computed from the same tenant evidence at the same instant."
      >
        PQC TLS Posture
      </SectionLabel>

      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6">
        <Metric
          label="TLS endpoints"
          value={fmtNumber(measured)}
          basis={`${fmtPercent(posture.transportCoveragePercent)} of the estate has transport evidence`}
          tone="neutral"
          hint="Endpoints with at least one measured transport observation or certificate. Assets with no TLS evidence at all are counted separately, never as 'secure'."
          href="/dashboard/tls-telemetry"
        />
        <Metric
          label="TLS 1.3 adoption"
          value={fmtNumber(posture.tls13Endpoints)}
          basis={`${basisEndpoints} · ${fmtPercent((posture.tls13Endpoints / Math.max(1, measured)) * 100)}`}
          tone={posture.tls13Endpoints >= measured * 0.8 ? 'good' : 'warning'}
          hint="TLS 1.3 is a prerequisite for hybrid ML-KEM key agreement — the cheapest route to post-quantum transport protection."
          href="/dashboard/protocol-analytics"
        />
        <Metric
          label="Hybrid + PQC"
          value={fmtPercent(posture.pqcAdoptionPercent)}
          basis={`${fmtNumber(posture.hybridEndpoints + posture.pqcEndpoints)} ${basisEndpoints}`}
          tone={posture.pqcAdoptionPercent > 0 ? 'good' : 'warning'}
          hint="Endpoints where a hybrid (X25519 + ML-KEM) or fully post-quantum key agreement was actually observed. A quantum-resistant bulk cipher such as AES-256-GCM does not count — only the key agreement decides quantum posture."
          href="/dashboard/protocol-analytics"
        />
        <Metric
          label="Legacy TLS"
          value={fmtNumber(posture.legacyEndpoints)}
          basis={posture.legacyEndpoints ? 'TLS 1.0 / 1.1 / SSL 3.0 observed (RFC 8996)' : 'No deprecated protocol observed'}
          tone={posture.legacyEndpoints ? 'critical' : 'good'}
          hint="RFC 8996 deprecates TLS 1.0 and 1.1; RFC 7568 deprecates SSL 3.0. An endpoint that still answers on them keeps a downgrade path open."
          href="/dashboard/protocol-analytics"
        />
        <Metric
          label="Quantum vulnerable"
          value={fmtNumber(posture.quantumVulnerableEndpoints)}
          basis={`${basisEndpoints} on classical key agreement`}
          tone={posture.quantumVulnerableEndpoints ? 'critical' : 'good'}
          hint="Endpoints whose observed key agreement or signature is breakable by Shor's algorithm on a cryptographically relevant quantum computer."
          href="/dashboard/tls-orchestrator"
        />
        <Metric
          label="Certificates at risk"
          value={fmtNumber(posture.certificatesAtRisk)}
          basis={`${fmtNumber(posture.certificatesExpiring30d)} expiring · ${fmtNumber(posture.certificatesExpired)} expired · ${fmtNumber(totals.certificates)} total`}
          tone={posture.certificatesAtRisk ? 'warning' : 'good'}
          hint="Certificates rated critical or high: expired, revoked, inside the 30-day renewal window, weakly signed, or self-signed outside a managed trust hierarchy."
          href="/dashboard/pki-visibility"
        />
      </div>

      <div className="mt-3 grid gap-2 lg:grid-cols-[1fr_auto]">
        <div className="flex flex-wrap items-center gap-1.5">
          <Pill tone="neutral" title="Reproduced verbatim from the Quantum Readiness Engine so this page cannot contradict it.">
            Quantum readiness {fmtPercent(posture.quantumReadinessScore)}
          </Pill>
          <Pill tone={posture.quantumRiskScore >= 65 ? 'critical' : posture.quantumRiskScore >= 35 ? 'warning' : 'good'}>
            Quantum risk {fmtPercent(posture.quantumRiskScore)} · {posture.quantumRiskLevel}
          </Pill>
          <Pill tone="info">X25519 only: {fmtNumber(posture.x25519Observations)}</Pill>
          <Pill tone={posture.hybridMlKemObservations ? 'good' : 'neutral'}>
            X25519 + ML-KEM: {fmtNumber(posture.hybridMlKemObservations)}
          </Pill>
          <Pill tone={posture.mlKemObservations ? 'good' : 'neutral'}>ML-KEM: {fmtNumber(posture.mlKemObservations)}</Pill>
          <Pill tone={posture.remediationRequiredEndpoints ? 'warning' : 'good'}>
            Remediation required: {fmtNumber(posture.remediationRequiredEndpoints)}
          </Pill>
        </div>
        <Link
          to="/dashboard/tls-orchestrator"
          className="inline-flex items-center justify-center rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-cyan-200 no-underline transition hover:bg-cyan-500/25"
        >
          Open remediation queue
        </Link>
      </div>

      {lowCoverage && measured > 0 ? (
        <p className="mt-3 rounded-lg border border-amber-500/25 bg-amber-500/5 p-2.5 text-[10.5px] leading-relaxed text-amber-200/85">
          <strong className="font-black uppercase tracking-wider">Coverage caveat.</strong> Transport evidence exists for only{' '}
          {fmtPercent(posture.transportCoveragePercent)} of assessed assets ({fmtNumber(posture.assetsWithoutTransportEvidence)} without any).
          Percentages above describe the measured subset, not the whole estate — deploy collectors or scan the remaining assets before treating
          them as a program-level figure.
        </p>
      ) : null}
    </Panel>
  );
}
