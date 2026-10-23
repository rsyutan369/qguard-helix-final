/**
 * Quantum Visualization Engine™ — node inspector HUD.
 *
 * Clicking a category node opens this glass callout *over* the visualization band
 * rather than inside the card, so the cloned hero layout never reflows and the
 * beams never move under the pointer.
 *
 * Two of the panels are the engine spec's named deliverables:
 *
 *   • TLS         — the animated handshake: Client Hello → Server Hello → Cipher →
 *                   Certificate → Key Exchange → Session, with the *measured*
 *                   millisecond timings from the scanner's own socket, and the
 *                   hybrid X25519 + ML-KEM-768 → AES-256 chain when it was
 *                   actually negotiated.
 *   • Certificate — the real served chain, Leaf → Intermediate → Root, each link
 *                   lighting in turn with CT and OCSP validation state.
 *
 * Everything shown is read from the completed report. Before a scan the panel
 * says what will be measured; it never shows placeholder values.
 */
'use client';

import React from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import { ArrowRight, Award, Clock, KeyRound, ScrollText, ShieldCheck, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { PublicScanReport } from '@/lib/scanner/public-scan/types';
import { resolveNodeVerdict, QVE_COLOR, type QveNode, type QveNodeKey } from '../types';
import { qveAccentOn, useQvePalette, type QvePalette } from '../theme';

export interface NodeInspectorProps {
  node: QveNode | null;
  report: PublicScanReport | null;
  onClose: () => void;
  animate: boolean;
}

/* ------------------------------------------------------------------ handshake - */

const HANDSHAKE_ORDER = ['client-hello', 'server-hello', 'cipher', 'certificate', 'key-exchange', 'session'];

function HandshakeFlow({ report, animate }: { report: PublicScanReport; animate: boolean }) {
  const palette = useQvePalette();
  const steps = React.useMemo(
    () =>
      HANDSHAKE_ORDER.map((key) => report.handshake.find((step) => step.key === key)).filter(
        (step): step is NonNullable<typeof step> => Boolean(step),
      ),
    [report],
  );

  const hybrid = report.evidence.keyAgreement.hybridGroups;
  const cipher = report.evidence.tls?.cipherSuite ?? null;

  return (
    <div className="space-y-3">
      <ol className="space-y-1.5">
        {steps.map((step, index) => (
          <li key={step.key} className="relative pl-6">
            {/* Connector with a travelling packet — one per phase, so the flow
                reads in the order the handshake actually happened. */}
            {index < steps.length - 1 && (
              <span aria-hidden className="absolute left-[7px] top-[18px] h-full w-px bg-white/[0.09]">
                {animate && step.observed && (
                  <motion.span
                    className="absolute -left-[2px] h-1.5 w-1.5 rounded-full"
                    style={{ backgroundColor: QVE_COLOR.cyan, boxShadow: `0 0 8px ${QVE_COLOR.cyan}` }}
                    initial={{ top: 0, opacity: 0 }}
                    animate={{ top: ['0%', '100%'], opacity: [0, 1, 0] }}
                    transition={{ duration: 1.5, repeat: Infinity, delay: index * 0.28, ease: 'easeInOut' }}
                  />
                )}
              </span>
            )}
            <span
              aria-hidden
              className="absolute left-0 top-[5px] h-3.5 w-3.5 rounded-full border"
              style={{
                borderColor: step.observed ? `${palette.accentCyan}88` : palette.track,
                backgroundColor: step.observed ? `${palette.accentCyan}22` : 'transparent',
              }}
            />
            <div className="flex flex-wrap items-baseline justify-between gap-x-3">
              <p className="text-[11.5px] font-bold text-slate-200">{step.label}</p>
              <p className="font-mono text-[10.5px] font-semibold" style={{ color: step.observed ? palette.accentCyan : palette.inkMuted }}>
                {step.value}
                {step.timingMs !== null && (
                  <span className="ml-1.5 inline-flex items-center gap-0.5 text-slate-500">
                    <Clock className="h-2.5 w-2.5" />
                    {step.timingMs}ms
                  </span>
                )}
              </p>
            </div>
            <p className="text-[10px] leading-snug text-slate-500">{step.detail}</p>
          </li>
        ))}
      </ol>

      {/* Negotiated cryptographic chain. Rendered only from observed values. */}
      <div className="rounded-lg border border-white/[0.07] bg-white/[0.02] px-2.5 py-2">
        <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">Negotiated chain</p>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          {(hybrid.length
            ? [
                { label: 'X25519', tone: QVE_COLOR.cyan },
                { label: hybrid[0].replace(/^X25519/i, '') || 'ML-KEM-768', tone: QVE_COLOR.quantum },
                { label: cipher?.includes('AES_256') || cipher?.includes('AES-256') ? 'AES-256-GCM' : (cipher ?? 'symmetric'), tone: QVE_COLOR.pass },
              ]
            : [
                { label: report.evidence.keyAgreement.primaryGroup ?? report.evidence.tls?.keyExchange ?? 'classical group', tone: QVE_COLOR.warning },
                { label: cipher ?? 'negotiated suite', tone: QVE_COLOR.scanning },
              ]
          ).map((item, index, all) => (
            <React.Fragment key={item.label}>
              <span
                className="rounded-md px-1.5 py-0.5 font-mono text-[9.5px] font-bold"
                style={{ backgroundColor: `${item.tone}18`, color: item.tone }}
              >
                {item.label}
              </span>
              {index < all.length - 1 && <ArrowRight className="h-2.5 w-2.5 text-slate-600" />}
            </React.Fragment>
          ))}
        </div>
        <p className="mt-1.5 text-[10px] leading-snug text-slate-500">
          {hybrid.length
            ? 'Hybrid post-quantum key establishment proven by offering the named group alone.'
            : 'No hybrid post-quantum group was accepted — key establishment is classical only.'}
        </p>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- cert chain - */

function CertificateChain({ report, animate }: { report: PublicScanReport; animate: boolean }) {
  const palette = useQvePalette();
  const certificate = report.evidence.certificate;
  const extras = report.evidence.certificateExtras;
  const chain = certificate?.chain ?? [];

  /** Position label from the chain's shape — never guessed. */
  const roleFor = (index: number): string => {
    if (index === 0) return 'Leaf';
    if (index === chain.length - 1) return chain.length > 2 ? 'Root / anchor' : 'Issuer';
    return 'Intermediate';
  };

  if (!chain.length) {
    return (
      <p className="text-[11px] leading-relaxed text-slate-400">
        The served chain could not be collected, so no link can be shown. Chain depth, SAN coverage and trust
        verification all require a completed TLS handshake.
      </p>
    );
  }

  return (
    <div className="space-y-2.5">
      <ol className="space-y-1.5">
        {chain.map((entry, index) => (
          <motion.li
            key={`${entry.subject}-${index}`}
            initial={animate ? { opacity: 0, x: -8 } : false}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.35, delay: index * 0.12 }}
            className="rounded-lg border border-white/[0.07] bg-white/[0.02] px-2.5 py-1.5"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[9px] font-bold uppercase tracking-[0.14em] text-cyan-400/80">
                {roleFor(index)}
              </span>
              <span
                className="font-mono text-[9.5px] font-bold"
                style={{ color: entry.isExpired ? QVE_COLOR.critical : QVE_COLOR.pass }}
              >
                {entry.isExpired ? 'expired' : `to ${new Date(entry.validTo).toISOString().slice(0, 10)}`}
              </span>
            </div>
            <p className="mt-0.5 truncate text-[11px] font-semibold text-slate-200" title={entry.subject}>
              {entry.subject || '—'}
            </p>
            <p className="truncate text-[10px] text-slate-500" title={`Issued by ${entry.issuer}`}>
              {entry.publicKeyAlgorithm}
              {entry.publicKeySize ? ` ${entry.publicKeySize}` : ''} · {entry.signatureAlgorithm}
            </p>
          </motion.li>
        ))}
      </ol>

      <div className="grid grid-cols-2 gap-1.5">
        {[
          {
            label: 'Trust store',
            value: extras?.chainTrusted ? 'Verified' : 'Not verified',
            good: Boolean(extras?.chainTrusted),
            icon: ShieldCheck,
          },
          {
            label: 'Transparency',
            value: extras?.signedCertificateTimestamps ? `${extras.sctCount} SCT` : 'No SCTs',
            good: Boolean(extras?.signedCertificateTimestamps),
            icon: ScrollText,
          },
          {
            label: 'OCSP',
            value: extras?.ocspStapled ? 'Stapled' : extras?.ocspUri ? 'Not stapled' : 'No responder',
            good: Boolean(extras?.ocspStapled),
            icon: Award,
          },
          {
            label: 'Key',
            value: certificate ? `${certificate.publicKeyAlgorithm} ${certificate.publicKeySize || ''}`.trim() : '—',
            good: false,
            icon: KeyRound,
          },
        ].map((item) => (
          <div key={item.label} className="rounded-lg border border-white/[0.06] bg-white/[0.015] px-2 py-1.5">
            <p className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-[0.12em] text-slate-500">
              <item.icon className="h-2.5 w-2.5" /> {item.label}
            </p>
            <p
              className="mt-0.5 truncate text-[10.5px] font-bold"
              style={{ color: item.good ? qveAccentOn(QVE_COLOR.pass, palette) : palette.ink }}
            >
              {item.value}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- generic body - */

interface EvidenceRow {
  label: string;
  value: string;
  tone?: string;
}

function evidenceFor(key: QveNodeKey, report: PublicScanReport): EvidenceRow[] {
  const dns = report.evidence.engines.dns.data;
  const http = report.evidence.http;
  const extras = report.evidence.certificateExtras;
  const keyAgreement = report.evidence.keyAgreement;
  const fingerprint = report.evidence.engines.http.data.fingerprint;

  switch (key) {
    case 'dns':
      return [
        { label: 'A / AAAA records', value: `${dns.ipv4.length} IPv4 · ${dns.ipv6.length} IPv6` },
        { label: 'Nameservers', value: dns.nameservers.length ? dns.nameservers.slice(0, 2).join(', ') : 'not observable' },
        {
          // The `dns-caa` row's rule: absence is a finding only once the climb
          // to the registrable domain completed — policy is inherited from it.
          label: 'CAA policy',
          value: dns.caaPresent
            ? dns.caaRecords.map((record) => record.value).slice(0, 2).join(', ')
            : dns.caaQueryable && dns.caaClimbComplete
              ? 'no CAA RRset'
              : dns.caaQueryable
                ? 'undetermined — climb incomplete'
                : 'not observable',
          tone: dns.caaPresent ? QVE_COLOR.pass : dns.caaQueryable && dns.caaClimbComplete ? QVE_COLOR.warning : undefined,
        },
        {
          label: 'DNSSEC',
          value: dns.dnssecQueryable ? (dns.dnssecSigned ? (dns.dnssecValidated ? 'signed, AD validated' : 'signed') : 'unsigned') : 'not observable',
          tone: dns.dnssecSigned ? QVE_COLOR.pass : undefined,
        },
        { label: 'Resolved via', value: dns.resolvedVia },
      ];
    case 'headers':
      return [
        { label: 'Status', value: http.reachable ? `HTTP ${http.statusCode}` : (http.error ?? 'unreachable') },
        { label: 'Server', value: http.server ?? 'not disclosed' },
        { label: 'ALPN', value: report.evidence.alpn ?? 'not negotiated' },
        { label: 'Infrastructure', value: [fingerprint.cdn, fingerprint.waf, fingerprint.cloudProvider].filter(Boolean).join(' · ') || 'no signature' },
        ...http.headers.slice(0, 5).map((header) => ({
          label: header.name,
          // A superseded header is exempt from the tally, so it is not "absent".
          value:
            header.applicable === false
              ? `not required — ${header.supersededBy ?? 'superseded'}`
              : header.present
                ? header.secure
                  ? 'hardened'
                  : 'present, weak'
                : 'absent',
          tone:
            header.applicable === false
              ? undefined
              : header.secure
                ? QVE_COLOR.pass
                : header.present
                  ? QVE_COLOR.warning
                  : QVE_COLOR.critical,
        })),
      ];
    case 'ocsp':
      return [
        { label: 'Stapling', value: extras?.ocspStapled ? 'enabled' : 'not stapled', tone: extras?.ocspStapled ? QVE_COLOR.pass : QVE_COLOR.warning },
        { label: 'Responder', value: extras?.ocspUri ?? 'none published' },
        { label: 'must-staple', value: extras?.mustStaple ? 'asserted' : 'not asserted' },
        { label: 'CT SCTs', value: extras ? String(extras.sctCount) : '—' },
        { label: 'Days remaining', value: extras ? `${extras.daysRemaining}` : '—' },
      ];
    case 'quantum':
      return [
        {
          // "none accepted" is only true for a settled refusal; read the
          // Post-Quantum Key Agreement row, which knows which case this is.
          label: 'Hybrid groups',
          value: keyAgreement.hybridGroups.length
            ? keyAgreement.hybridGroups.join(', ')
            : (report.findings.find((finding) => finding.id === 'pq-key-agreement')?.finding ?? 'not observable'),
          tone: keyAgreement.hybridGroups.length
            ? QVE_COLOR.quantum
            : report.executive.postQuantumKeyAgreement === 'not-measured'
              ? undefined
              : QVE_COLOR.warning,
        },
        { label: 'Classical groups', value: keyAgreement.classicalGroups.join(', ') || 'not observable' },
        {
          label: 'PQ readiness',
          value:
            report.executive.postQuantumReadiness === null
              ? 'not measured'
              : `${report.executive.postQuantumReadiness}%`,
        },
        { label: 'Exposure', value: report.intelligence.quantumVulnerability },
        { label: 'Migration target', value: report.intelligence.migrationTargets.map((target) => target.name).slice(0, 2).join(', ') || '—' },
      ];
    default:
      return [];
  }
}

/* -------------------------------------------------------------------- export - */

export function NodeInspector({ node, report, onClose, animate }: NodeInspectorProps) {
  const palette = useQvePalette();
  const reduce = useReducedMotion();
  const motionEnabled = animate && !reduce;

  // Escape closes — the panel is a transient HUD, not a route.
  React.useEffect(() => {
    if (!node) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [node, onClose]);

  return (
    <AnimatePresence>
      {node && (
        <motion.div
          initial={motionEnabled ? { opacity: 0, y: 10, scale: 0.98 } : false}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={motionEnabled ? { opacity: 0, y: 6, scale: 0.99 } : { opacity: 0 }}
          transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
          role="dialog"
          aria-label={`${node.title} evidence`}
          className={cn(
            'absolute inset-x-3 bottom-3 z-30 max-h-[78%] overflow-y-auto rounded-xl border border-cyan-400/25',
            'bg-[#050a15]/96 p-3.5 shadow-[0_30px_80px_-30px_rgba(0,0,0,0.95)] backdrop-blur-2xl',
            'sm:inset-x-auto sm:left-1/2 sm:w-[26rem] sm:-translate-x-1/2',
          )}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.2em] text-cyan-400/80">
                {node.title}
              </p>
              {/* Same resolver the card uses — the panel and the card it
                  opened from can never state different verdicts. */}
              <p className="mt-0.5 text-[13px] font-black" style={{ color: resolveNodeVerdict(node, palette.surface).color }} title={resolveNodeVerdict(node, palette.surface).basis}>
                {resolveNodeVerdict(node, palette.surface).label}
              </p>
              {node.hasEvidence && node.verdict && node.verdict !== resolveNodeVerdict(node, palette.surface).label && (
                <p className="text-[10.5px] leading-snug text-slate-400">{node.verdict}</p>
              )}
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close evidence panel"
              className="grid h-7 w-7 shrink-0 place-items-center rounded-lg text-slate-400 transition-colors hover:bg-white/[0.07] hover:text-white"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="mt-3">
            {!report ? (
              <p className="text-[11px] leading-relaxed text-slate-400">
                No evidence yet. Run an assessment and this panel will show exactly what the scanner observed for
                this category — nothing is pre-filled.
              </p>
            ) : node.key === 'tls' ? (
              <HandshakeFlow report={report} animate={motionEnabled} />
            ) : node.key === 'certificate' ? (
              <CertificateChain report={report} animate={motionEnabled} />
            ) : (
              <dl className="space-y-1">
                {evidenceFor(node.key, report).map((row) => (
                  <div key={row.label} className="flex items-baseline justify-between gap-3 border-b border-white/[0.05] pb-1 last:border-0">
                    <dt className="shrink-0 font-mono text-[9.5px] uppercase tracking-[0.12em] text-slate-500">
                      {row.label}
                    </dt>
                    <dd
                      className="truncate text-right text-[10.5px] font-semibold"
                      style={{ color: row.tone ?? palette.ink }}
                      title={row.value}
                    >
                      {row.value}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
