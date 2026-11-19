'use client';

import { Link } from 'react-router-dom';
import { ShieldHalf } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { DataProtectionPosture } from '@/lib/encryption/types';
import { Panel, Pill, SectionLabel, Term, TONE, fmtNumber, fmtPercent, type Tone } from './primitives';

/**
 * Data Protection Posture — the Encryption Monitoring counterpart of the
 * PQC TLS Posture strip.
 *
 * Deliberately a different set of headline numbers, because the questions are
 * different. The TLS strip answers "what does the estate negotiate"; this one
 * answers "what protects the data, and does it meet CNSA 2.0".
 *
 * Two honesty rules are enforced here in particular:
 *   1. Every percentage names its denominator. `cnsa2CompliancePercent` is a
 *      share of ASSESSED primitives, not of all of them — a primitive whose
 *      parameters were never recorded cannot pass or fail.
 *   2. Key material, at-rest and vault tiles read "Not measured" when the
 *      tenant has no such source. The page this replaced reported 338 key
 *      rotations for a tenant holding zero keys.
 */

function Metric({
  label,
  value,
  basis,
  tone = 'neutral',
  hint,
  href,
  unmeasured,
}: {
  label: string;
  value: string;
  basis: string;
  tone?: Tone;
  hint?: string;
  href?: string;
  unmeasured?: boolean;
}) {
  const body = (
    <>
      <div className="flex items-center gap-1.5 text-[9px] font-black uppercase tracking-[0.12em] text-white/40">
        {label}
        {/* Above the stretched link so the explanation stays independently focusable. */}
        {hint ? <span className="pointer-events-auto relative z-10"><Term hint={hint} label={label} /></span> : null}
      </div>
      <div className={cn('mt-1.5 text-[22px] font-black leading-none', unmeasured ? 'text-white/30' : TONE[tone].text)}>
        {unmeasured ? 'Not measured' : value}
      </div>
      <div className="mt-1 text-[9.5px] font-medium leading-snug text-white/35">{basis}</div>
    </>
  );
  if (href) {
    // Stretched link (sibling of the body) — wrapping the body nested the hint's <button> inside an <a>.
    return (
      <div className="relative rounded-lg border border-white/8 bg-black/20 p-3 transition focus-within:ring-2 focus-within:ring-cyan-300/70 hover:border-cyan-400/35 hover:bg-black/35">
        <Link
          to={href}
          aria-label={`${label}: ${unmeasured ? 'not measured' : value} — ${basis}`}
          className="absolute inset-0 z-0 rounded-lg no-underline focus-visible:outline-none"
        />
        <div className="pointer-events-none relative">{body}</div>
      </div>
    );
  }
  return <div className="rounded-lg border border-white/8 bg-black/20 p-3">{body}</div>;
}

export function EncryptionPostureStrip({
  posture,
  totals,
}: {
  posture: DataProtectionPosture;
  totals: { keys: number; vaultFiles: number; atRestRecords: number; observations: number };
}) {
  const lowCoverage = posture.evidenceCoveragePercent < 60 && posture.assetsWithEvidence > 0;

  return (
    <Panel>
      <SectionLabel
        icon={ShieldHalf}
        meta={<span className="normal-case tracking-normal">Data at Rest · Key Material · CNSA 2.0</span>}
        hint="Computed from the same tenant evidence as the TLS suite, at the same instant, but scoped to what protects DATA rather than what is negotiated on the wire."
      >
        Data Protection Posture
      </SectionLabel>

      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-7">
        <Metric
          label="Primitives measured"
          value={fmtNumber(posture.algorithmsObserved)}
          basis={`Symmetric, hash, MAC, KDF and application-declared · ${fmtNumber(posture.observationsAnalysed)} distinct measurement(s)`}
          tone="neutral"
          hint="Distinct symmetric ciphers, hashes, MACs, KDFs and application-declared algorithms. Transport cipher suites are counted on Protocol Analytics, never twice."
        />
        <Metric
          label="CNSA 2.0 algorithm match"
          value={fmtPercent(posture.cnsa2CompliancePercent)}
          basis={
            posture.cnsa2Assessed
              ? `of ${fmtNumber(posture.cnsa2Assessed)} distinct identified cipher or hash label(s)`
              : 'No primitive had recordable parameters'
          }
          tone={posture.cnsa2CompliancePercent >= 80 ? 'good' : posture.cnsa2CompliancePercent >= 50 ? 'warning' : 'critical'}
          unmeasured={posture.cnsa2Assessed === 0}
          hint="Counts identified cipher and hash labels matching AES-256, SHA-384 or SHA-512. CNSA 2.0 applies to National Security Systems; this comparison does not evaluate modes, implementation or compliance."
        />
        <Metric
          label="Broken classically"
          value={fmtNumber(posture.brokenAlgorithms)}
          basis={posture.brokenAlgorithms ? '3DES / RC4 / SHA-1 / MD5 in use' : 'None observed'}
          tone={posture.brokenAlgorithms ? 'critical' : 'good'}
          hint="Broken by classical cryptanalysis — no quantum computer required. These outrank every post-quantum migration item, because they are exploitable today."
        />
        <Metric
          label="Quantum vulnerable"
          value={fmtNumber(posture.quantumVulnerableAlgorithms)}
          basis={posture.quantumVulnerableAlgorithms ? 'RSA / ECC protecting data' : 'None observed'}
          tone={posture.quantumVulnerableAlgorithms ? 'critical' : 'good'}
          hint="Sound against classical attack today, but recovered outright by Shor on a CRQC. Deliberately separate from 'broken' — conflating the two overstates today's risk and contradicts the transport pages."
        />
        <Metric
          label="Weakened by Grover"
          value={fmtNumber(posture.weakenedAlgorithms)}
          basis={posture.weakenedAlgorithms ? 'AES-128 class — halved, not broken' : 'None observed'}
          tone={posture.weakenedAlgorithms ? 'warning' : 'good'}
          hint="Grover's quadratic speedup halves the effective key strength. AES-128 falls to ~64 bits: weakened for long-lived data, but there is no quantum attack reading it today."
        />
        <Metric
          label="Key material"
          value={fmtNumber(posture.keysManaged)}
          basis={posture.keysManaged ? `${fmtNumber(posture.keysAtRisk)} at risk` : 'No key store connected'}
          tone={posture.keysAtRisk ? 'warning' : 'good'}
          unmeasured={totals.keys === 0}
          hint="Keys managed by QKMS, with entropy source and lifecycle. Nothing here is inferred from asset counts."
          href="/dashboard/qkms/inventory"
        />
        <Metric
          label="Encryption at rest"
          value={fmtPercent(posture.atRestCoveragePercent)}
          basis={
            totals.atRestRecords
              ? `${fmtNumber(posture.atRestAssetsCovered)} asset(s) with storage policy evidence`
              : 'No storage or KMS policy evidence'
          }
          tone={posture.atRestCoveragePercent >= 80 ? 'good' : 'warning'}
          unmeasured={totals.atRestRecords === 0}
          hint="Requires cloud connector or agent evidence describing storage, database or KMS policy. With no such source this reads 'Not measured' — an absent instrument is not an unencrypted estate."
        />
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        <Pill tone="neutral" title="Reproduced verbatim from the Quantum Readiness Engine so this page cannot contradict it.">
          Quantum readiness {fmtPercent(posture.quantumReadinessScore)}
        </Pill>
        <Pill tone={posture.quantumRiskScore >= 65 ? 'critical' : posture.quantumRiskScore >= 35 ? 'warning' : 'good'}>
          Quantum risk {fmtPercent(posture.quantumRiskScore)} · {posture.quantumRiskLevel}
        </Pill>
        <Pill tone={posture.hndlRiskScore >= 65 ? 'critical' : posture.hndlRiskScore >= 35 ? 'warning' : 'good'} title="Harvest-now-decrypt-later: data captured today and decrypted once a CRQC exists.">
          HNDL {fmtPercent(posture.hndlRiskScore)} · {posture.hndlRiskLevel}
        </Pill>
        <Pill tone={totals.vaultFiles ? 'good' : 'neutral'}>Vault files protected: {fmtNumber(posture.vaultFilesProtected)}</Pill>
        <Pill tone="info">
          Evidence coverage {fmtPercent(posture.evidenceCoveragePercent)} ({fmtNumber(posture.assetsWithEvidence)} of {fmtNumber(posture.assetsTotal)} assets)
        </Pill>
        {posture.unattributedObservations ? (
          <Pill
            tone="neutral"
            title="Observations from a host, process or file that is not mapped to a tenant asset. Real evidence, kept out of the coverage denominator so it cannot inflate it."
          >
            Unattributed observations: {fmtNumber(posture.unattributedObservations)}
          </Pill>
        ) : null}
      </div>

      {lowCoverage ? (
        <p className="mt-3 rounded-lg border border-amber-500/25 bg-amber-500/5 p-2.5 text-[10.5px] leading-relaxed text-amber-200/85">
          <strong className="font-black uppercase tracking-wider">Coverage caveat.</strong> Data-protection evidence exists for only{' '}
          {fmtPercent(posture.evidenceCoveragePercent)} of assessed assets. The grades above describe the measured subset — extend collection before
          treating them as a programme-level figure.
        </p>
      ) : null}
    </Panel>
  );
}
