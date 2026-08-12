'use client';

import { useCallback, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Award,
  BadgeCheck,
  CalendarClock,
  CheckCircle2,
  Download,
  ExternalLink,
  FileJson,
  FileText,
  Image as ImageIcon,
  Loader2,
  Lock,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  Upload,
  XCircle,
} from 'lucide-react';
import { useSubscription } from '@/hooks/use-subscription';
import { useQuantumCertification } from '@/hooks/use-quantum-certification';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { QuantumTrustCertificate } from '@/components/certification/QuantumTrustCertificate';
import {
  exportAuditPackage,
  exportCertificateJson,
  exportCertificatePdf,
  exportCertificatePng,
  exportCertificateSvg,
} from '@/services/certification/certificate-export';
import type { CertificationLevel, QuantumTrustCertificate as Cert } from '@/types/quantum-certification';
import {
  Badge,
  EmptyState,
  HeaderButton,
  MetricCard,
  Panel,
  PrimaryButton,
  QuantumReadinessSubnav,
  Ring,
  SectionTitle,
  TrendChart,
  integerFmt,
  longDate,
  relativeTime,
  AMBER,
  BLUE,
  CYAN,
  EMERALD,
  GOLD,
  GREEN,
  ORANGE,
  RED,
  VIOLET,
} from '../quantum-readiness/_shared';

const LEVEL_COLORS: Record<CertificationLevel, string> = {
  bronze: '#B87333',
  silver: '#9AA6BC',
  gold: GOLD,
  platinum: '#A78BFA',
  diamond: CYAN,
};

const STATUS_META: Record<string, { color: string; label: string }> = {
  active: { color: EMERALD, label: 'Active' },
  suspended: { color: AMBER, label: 'Suspended' },
  revoked: { color: RED, label: 'Revoked' },
  expired: { color: ORANGE, label: 'Expired' },
  superseded: { color: '#64748B', label: 'Superseded' },
};

function fileToDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(new Error('Failed to read logo'));
    reader.readAsDataURL(file);
  });
}

export default function QuantumCertificationPage() {
  const { tier } = useSubscription();
  const {
    data,
    state,
    error,
    sseConnected,
    busy,
    refresh,
    issueCertificate,
    renewCertificate,
    suspendCertificate,
    revokeCertificate,
    reinstateCertificate,
    recordDownload,
    fetchPackage,
  } = useQuantumCertification();

  const [orgName, setOrgName] = useState('');
  const [logoDataUrl, setLogoDataUrl] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [previewCert, setPreviewCert] = useState<Cert | null>(null);
  const certRef = useRef<HTMLDivElement>(null);

  const { eligibility, certificate } = data;
  const activeCert = certificate && (certificate.status === 'active' || certificate.status === 'suspended') ? certificate : null;
  const shownCert = previewCert || activeCert || certificate;

  const levelCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const c of data.certificates) counts[c.level] = (counts[c.level] || 0) + 1;
    return counts;
  }, [data.certificates]);

  const activeCount = data.certificates.filter((c) => c.status === 'active').length;
  const suspendedCount = data.certificates.filter((c) => c.status === 'suspended').length;

  const svgFromRef = (): SVGSVGElement | null => certRef.current?.querySelector('svg') || null;

  const doExport = useCallback(
    async (kind: 'pdf' | 'png' | 'svg' | 'json' | 'audit-package') => {
      if (!shownCert) return;
      try {
        if (kind === 'json') {
          exportCertificateJson(shownCert);
        } else if (kind === 'audit-package') {
          const pkg = await fetchPackage(shownCert.certificateId);
          if (pkg) exportAuditPackage(pkg, shownCert.certificateId);
          else throw new Error('Audit package unavailable');
        } else {
          const svg = svgFromRef();
          if (!svg) throw new Error('Certificate not ready for export');
          if (kind === 'pdf') await exportCertificatePdf(svg, shownCert);
          if (kind === 'png') await exportCertificatePng(svg, shownCert);
          if (kind === 'svg') await exportCertificateSvg(svg, shownCert);
        }
        void recordDownload(shownCert.certificateId, kind);
        setActionMsg({ kind: 'ok', text: `Exported ${shownCert.certificateId} as ${kind.toUpperCase()}` });
      } catch (err) {
        setActionMsg({ kind: 'err', text: err instanceof Error ? err.message : 'Export failed' });
      }
    },
    [shownCert, fetchPackage, recordDownload],
  );

  const onIssue = useCallback(async () => {
    const name = orgName.trim();
    if (!name) {
      setActionMsg({ kind: 'err', text: 'Enter your organization name to issue a certificate.' });
      return;
    }
    const result = await issueCertificate(name, logoDataUrl);
    if (result.ok) {
      setActionMsg({ kind: 'ok', text: `Certificate issued for ${name}.` });
      setPreviewCert(null);
    } else {
      setActionMsg({ kind: 'err', text: result.message || 'Issuance failed.' });
    }
  }, [orgName, logoDataUrl, issueCertificate]);

  const onLifecycle = useCallback(
    async (fn: () => Promise<{ ok: boolean; message?: string }>, okText: string) => {
      const result = await fn();
      setActionMsg(result.ok ? { kind: 'ok', text: okText } : { kind: 'err', text: result.message || 'Action failed.' });
    },
    [],
  );

  const trustColor = shownCert ? LEVEL_COLORS[shownCert.level] : eligibility.level ? LEVEL_COLORS[eligibility.level] : VIOLET;

  return (
    <div className="min-h-screen bg-[#030711] px-4 py-5 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1560px] space-y-4">
        <QuantumReadinessSubnav />
        <WorkflowRail activeStage="certification" />

        {/* Header */}
        <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <Award className="h-6 w-6 text-amber-300" />
              <h1 className="text-2xl font-semibold tracking-normal text-white">Quantum Trust Certification™</h1>
              <Badge color={VIOLET}>Certify · Verify · Build Quantum Trust</Badge>
              {tier ? <Badge color={CYAN}>{tier.toUpperCase()} PLAN</Badge> : null}
            </div>
            <p className="mt-1 max-w-3xl text-sm text-white/58">
              Evidence-driven Post-Quantum Readiness certificates. Issued only when every published criterion is met by
              measured assessment evidence — signed with ML-DSA-65 (FIPS 204), publicly verifiable, and continuously
              re-validated.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
              Refresh
            </HeaderButton>
            <a href="/verify-certificate" target="_blank" rel="noreferrer" className="no-underline">
              <HeaderButton icon={ExternalLink}>Public Verify Portal</HeaderButton>
            </a>
          </div>
        </header>

        {/* Schema setup banner */}
        {!data.schemaReady ? (
          <div className="rounded-md border border-amber-400/30 bg-amber-400/[0.08] px-4 py-3 text-sm text-amber-100/90">
            <strong className="font-bold">Setup required:</strong> the certification database schema has not been applied
            yet. Run <code className="rounded bg-black/40 px-1.5 py-0.5 font-mono text-[12px]">supabase/quantum-certification-schema.sql</code>{' '}
            in the Supabase SQL Editor to enable issuing, signing and public verification. Eligibility below is still
            computed live from your assessment evidence.
          </div>
        ) : null}

        {actionMsg ? (
          <div
            className={`rounded-md border px-4 py-2.5 text-sm ${
              actionMsg.kind === 'ok'
                ? 'border-emerald-400/30 bg-emerald-400/[0.08] text-emerald-100/90'
                : 'border-red-400/30 bg-red-400/[0.08] text-red-100/90'
            }`}
          >
            {actionMsg.text}
          </div>
        ) : null}

        {error && state === 'error' ? (
          <div className="rounded-md border border-red-400/30 bg-red-400/[0.08] px-4 py-3 text-sm text-red-100/90">
            Failed to load the certification engine: {error}
          </div>
        ) : null}

        {/* Not eligible → Intelligent Quantum Remediation Engine CTA */}
        {eligibility.hasData && !eligibility.eligible ? (
          <div className="flex flex-col gap-3 rounded-md border border-cyan-400/30 bg-cyan-400/[0.06] px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-sm text-cyan-100/90">
              <strong className="font-bold">Not Quantum Ready yet?</strong> The Intelligent Quantum Remediation Engine™
              analyzes every discovered asset and shows exactly how to resolve each blocker — with the Certification
              Readiness Score™ projected after every recommendation.
            </div>
            <Link to="/dashboard/quantum-readiness/remediation" className="shrink-0 no-underline">
              <PrimaryButton icon={Sparkles}>Open Remediation Roadmap</PrimaryButton>
            </Link>
          </div>
        ) : null}

        {/* KPI row */}
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <div>
            <MetricCard
              label="Certification Status"
              value={
                activeCert
                  ? activeCert.certified === false
                    ? 'Baseline Attested'
                    : STATUS_META[activeCert.status].label
                  : eligibility.eligible
                    ? 'Eligible'
                    : eligibility.issuable
                      ? 'Baseline Available'
                      : 'Not Assessed'
              }
              detail={activeCert ? activeCert.certificateId : eligibility.hasData ? `${eligibility.requiredMet}/${eligibility.requiredTotal} criteria met` : 'No evidence yet'}
              color={activeCert ? STATUS_META[activeCert.status].color : eligibility.eligible ? EMERALD : ORANGE}
              icon={activeCert?.status === 'active' ? ShieldCheck : activeCert?.status === 'suspended' ? ShieldAlert : eligibility.eligible ? BadgeCheck : ShieldX}
            />
          </div>
          <div>
            <MetricCard
              label="Quantum Trust Score™"
              value={integerFmt(shownCert?.trustScore ?? eligibility.trustScore)}
              suffix="/1000"
              detail={shownCert ? `${shownCert.levelLabel}` : eligibility.levelLabel}
              color={trustColor}
              ring={(shownCert?.trustScore ?? eligibility.trustScore) / 10}
            />
          </div>
          <div>
            <MetricCard
              label="Certification Level"
              value={shownCert ? shownCert.level.toUpperCase() : eligibility.level ? eligibility.level.toUpperCase() : '—'}
              detail={shownCert ? shownCert.levelLabel : eligibility.level ? eligibility.levelLabel : 'Meet all criteria to qualify'}
              color={trustColor}
              icon={Award}
            />
          </div>
          <div>
            <MetricCard
              label="Renewal"
              value={data.renewal.daysRemaining != null ? `${data.renewal.daysRemaining}d` : '—'}
              detail={data.renewal.expiresAt ? `Expires ${longDate(data.renewal.expiresAt)}` : 'No active certificate'}
              color={data.renewal.daysRemaining != null && data.renewal.daysRemaining <= 30 ? AMBER : BLUE}
              icon={CalendarClock}
            />
          </div>
          <div>
            <MetricCard
              label="Overall Readiness"
              value={`${shownCert?.overallReadiness ?? 0}`}
              suffix="%"
              detail={`${activeCount} active · ${suspendedCount} suspended`}
              color={EMERALD}
              ring={shownCert?.overallReadiness ?? 0}
            />
          </div>
        </div>

        {/* Certificate + eligibility gate */}
        <div className="grid gap-3 xl:grid-cols-[1.35fr_1fr]">
          {/* Certificate preview / issuance */}
          <Panel className="p-4">
            <SectionTitle
              suffix={
                shownCert ? (
                  <Badge color={STATUS_META[shownCert.status]?.color || VIOLET}>{STATUS_META[shownCert.status]?.label || shownCert.status}</Badge>
                ) : null
              }
            >
              {shownCert ? 'Quantum Trust Certificate' : 'Certificate Issuance'}
            </SectionTitle>

            {shownCert ? (
              <div className="space-y-3">
                <div ref={certRef} className="overflow-hidden rounded-lg border border-white/10 bg-white shadow-[0_20px_60px_rgba(0,0,0,0.5)]">
                  <QuantumTrustCertificate certificate={shownCert} />
                </div>
                <div className="flex flex-wrap gap-2">
                  <HeaderButton icon={FileText} onClick={() => void doExport('pdf')}>
                    PDF
                  </HeaderButton>
                  <HeaderButton icon={ImageIcon} onClick={() => void doExport('png')}>
                    PNG
                  </HeaderButton>
                  <HeaderButton icon={Download} onClick={() => void doExport('svg')}>
                    SVG
                  </HeaderButton>
                  <HeaderButton icon={FileJson} onClick={() => void doExport('json')}>
                    JSON
                  </HeaderButton>
                  <HeaderButton icon={FileText} onClick={() => void doExport('audit-package')}>
                    Audit Package
                  </HeaderButton>
                  <a href={shownCert.verificationUrl} target="_blank" rel="noreferrer" className="no-underline">
                    <HeaderButton icon={ExternalLink}>Verify</HeaderButton>
                  </a>
                </div>
                {activeCert ? (
                  <div className="flex flex-wrap gap-2 border-t border-white/8 pt-3">
                    {data.renewal.autoRenewEligible ? (
                      <HeaderButton icon={RotateCcw} onClick={() => void onLifecycle(() => renewCertificate(activeCert.certificateId), `Renewed ${activeCert.certificateId}.`)}>
                        Renew
                      </HeaderButton>
                    ) : null}
                    {activeCert.status === 'active' ? (
                      <HeaderButton icon={ShieldAlert} onClick={() => void onLifecycle(() => suspendCertificate(activeCert.certificateId, 'Suspended by certificate owner'), `Suspended ${activeCert.certificateId}.`)}>
                        Suspend
                      </HeaderButton>
                    ) : (
                      <HeaderButton icon={ShieldCheck} onClick={() => void onLifecycle(() => reinstateCertificate(activeCert.certificateId), `Reinstated ${activeCert.certificateId}.`)}>
                        Reinstate
                      </HeaderButton>
                    )}
                    <HeaderButton icon={ShieldX} onClick={() => void onLifecycle(() => revokeCertificate(activeCert.certificateId, 'Revoked by certificate owner'), `Revoked ${activeCert.certificateId}.`)}>
                      Revoke
                    </HeaderButton>
                    {busy ? <span className="inline-flex items-center gap-1.5 text-xs text-white/50"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Working…</span> : null}
                  </div>
                ) : null}
              </div>
            ) : !eligibility.hasData ? (
              <EmptyState
                label="No assessment evidence yet."
                hint="Run a PQC discovery scan and complete a Quantum Readiness Assessment — certification is computed from measured evidence."
              />
            ) : (
              <div className="space-y-4">
                <div
                  className={`rounded-md border px-4 py-3 text-sm ${
                    eligibility.eligible
                      ? 'border-emerald-400/30 bg-emerald-400/[0.07] text-emerald-100/90'
                      : 'border-amber-400/30 bg-amber-400/[0.07] text-amber-100/90'
                  }`}
                >
                  {eligibility.eligible ? (
                    <>
                      <strong className="font-bold">Eligible for {eligibility.levelLabel}.</strong> All{' '}
                      {eligibility.requiredTotal} required criteria are met (Quantum Trust Score™ {eligibility.trustScore}/1000).
                      Issue your signed, publicly verifiable certificate below.
                    </>
                  ) : eligibility.issuable ? (
                    <>
                      <strong className="font-bold">Ready to issue your Initial Readiness attestation.</strong>{' '}
                      {eligibility.requiredMet}/{eligibility.requiredTotal} certification criteria met (Quantum Trust Score™{' '}
                      {eligibility.trustScore}/1000). This Bronze attestation is a signed, publicly verifiable record of your{' '}
                      <em>measured</em> baseline — it does not claim your estate is quantum-safe. Certified status begins at
                      Silver, once every criterion passes.
                    </>
                  ) : (
                    <>
                      <strong className="font-bold">No assessment evidence yet.</strong> Run a discovery scan first — a
                      certificate attests to measured evidence, and nothing has been measured for this tenant.
                    </>
                  )}
                </div>
                <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                  <label className="block">
                    <span className="font-mono text-[10px] uppercase tracking-widest text-white/45">Organization name</span>
                    <input
                      value={orgName}
                      onChange={(e) => setOrgName(e.target.value)}
                      placeholder="ACME Corporation"
                      maxLength={160}
                      className="mt-1 w-full rounded-md border border-white/12 bg-black/30 px-3 py-2 text-sm text-white outline-none focus:border-blue-400/50"
                    />
                  </label>
                  <label className="flex cursor-pointer flex-col justify-end">
                    <span className="font-mono text-[10px] uppercase tracking-widest text-white/45">Logo (optional)</span>
                    <span className="mt-1 inline-flex h-[38px] items-center gap-2 rounded-md border border-white/12 bg-black/30 px-3 text-xs text-white/70 hover:border-blue-400/40">
                      <Upload className="h-3.5 w-3.5" /> {logoDataUrl ? 'Logo added' : 'Upload'}
                      <input
                        type="file"
                        accept="image/png,image/jpeg,image/svg+xml,image/webp"
                        className="hidden"
                        onChange={async (e) => {
                          const file = e.target.files?.[0];
                          if (file) {
                            try {
                              setLogoDataUrl(await fileToDataUrl(file));
                            } catch {
                              setActionMsg({ kind: 'err', text: 'Could not read logo file.' });
                            }
                          }
                        }}
                      />
                    </span>
                  </label>
                </div>
                {/* Issuance is gated on the EVIDENCE floor, not on certification
                    criteria: a measured tenant can always issue its Bronze
                    baseline. Only an unmeasured estate is blocked. */}
                <PrimaryButton icon={eligibility.issuable ? BadgeCheck : Lock} onClick={() => void onIssue()} disabled={!eligibility.issuable || busy}>
                  {busy
                    ? 'Issuing…'
                    : eligibility.eligible
                      ? 'Issue Quantum Trust Certificate'
                      : eligibility.issuable
                        ? 'Issue Initial Readiness Attestation (Bronze)'
                        : 'Run a Discovery Scan First'}
                </PrimaryButton>
              </div>
            )}
          </Panel>

          {/* Eligibility checklist */}
          <Panel className="p-4">
            <SectionTitle
              suffix={<Badge color={eligibility.eligible ? EMERALD : ORANGE}>{eligibility.requiredMet}/{eligibility.requiredTotal} required</Badge>}
            >
              Certification Eligibility Criteria
            </SectionTitle>
            {eligibility.checks.length === 0 ? (
              <EmptyState label="Run an assessment to evaluate certification eligibility." />
            ) : (
              <div className="space-y-2">
                {eligibility.checks.map((check) => (
                  <div
                    key={check.id}
                    className="flex items-start gap-2.5 rounded-md border border-white/6 bg-white/[0.015] px-3 py-2"
                  >
                    {check.met ? (
                      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
                    ) : check.severity === 'required' ? (
                      <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
                    ) : (
                      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
                    )}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-white/85">{check.criterion}</span>
                        <span className={`text-[10px] font-bold ${check.met ? 'text-emerald-300' : check.severity === 'required' ? 'text-red-300' : 'text-amber-300'}`}>
                          {check.actual}
                        </span>
                      </div>
                      <div className="mt-0.5 text-[10px] text-white/40">
                        Requires {check.required} · {check.evidence}
                        {check.severity === 'advisory' ? ' · advisory' : ''}
                      </div>
                      {!check.met ? <div className="mt-1 text-[10px] text-amber-200/70">{check.remediation}</div> : null}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>

        {/* Trend + level distribution + AI advisor */}
        <div className="grid gap-3 xl:grid-cols-3">
          <Panel className="p-4">
            <SectionTitle>Quantum Trust Score™ Over Time</SectionTitle>
            {data.trend.length ? (
              <TrendChart points={data.trend.map((t) => ({ label: t.label, readiness: t.readiness, risk: Math.round(t.trustScore / 10) }))} />
            ) : (
              <EmptyState label="No validation history yet." hint="Trust-score history builds as monitoring re-validates your certificate." />
            )}
            <p className="mt-2 text-[10px] text-white/35">Series: measured readiness and normalized Quantum Trust Score™ from each validation run.</p>
          </Panel>

          <Panel className="p-4">
            <SectionTitle suffix={<Badge color={VIOLET}>{data.certificates.length} total</Badge>}>Certification Level Distribution</SectionTitle>
            {data.certificates.length ? (
              <div className="space-y-2.5">
                {(['diamond', 'platinum', 'gold', 'silver', 'bronze'] as CertificationLevel[]).map((lvl) => {
                  const count = levelCounts[lvl] || 0;
                  const pct = data.certificates.length ? Math.round((count / data.certificates.length) * 100) : 0;
                  return (
                    <div key={lvl}>
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-bold uppercase tracking-wide" style={{ color: LEVEL_COLORS[lvl] }}>
                          {lvl}
                        </span>
                        <span className="font-mono text-white/60">
                          {count} ({pct}%)
                        </span>
                      </div>
                      <div className="mt-1 h-2 overflow-hidden rounded-full bg-white/5">
                        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: LEVEL_COLORS[lvl] }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <EmptyState label="No certificates issued yet." />
            )}
          </Panel>

          <Panel className="p-4">
            <SectionTitle suffix={<Sparkles className="h-4 w-4 text-violet-300" />}>AI Advisor™ — {data.advisor.headline || 'Assessment'}</SectionTitle>
            <div className="space-y-2 text-[11px] leading-relaxed text-white/70">
              {data.advisor.explanation.length ? (
                data.advisor.explanation.map((line, i) => (
                  <p key={i} className="border-l-2 border-violet-400/40 pl-2.5">
                    {line}
                  </p>
                ))
              ) : (
                <EmptyState label="Advisor explanation appears once evidence exists." />
              )}
              {data.advisor.businessImpact.length ? (
                <div className="mt-3 border-t border-white/8 pt-2">
                  <div className="mb-1 text-[10px] font-bold uppercase tracking-wide text-white/45">Business Impact</div>
                  {data.advisor.businessImpact.map((line, i) => (
                    <p key={i} className="mb-1 text-white/60">
                      • {line}
                    </p>
                  ))}
                </div>
              ) : null}
              {data.advisor.nextSteps.length ? (
                <div className="mt-3 border-t border-white/8 pt-2">
                  <div className="mb-1 text-[10px] font-bold uppercase tracking-wide text-white/45">Recommended Next Steps</div>
                  {data.advisor.nextSteps.map((step, i) => (
                    <a key={i} href={step.route} className="mb-1 block text-blue-300 no-underline hover:text-blue-200">
                      → {step.title}: <span className="text-white/55">{step.detail}</span>
                    </a>
                  ))}
                </div>
              ) : null}
            </div>
          </Panel>
        </div>

        {/* Recent certifications table */}
        <Panel className="p-4">
          <SectionTitle suffix={<Badge color={BLUE}>{data.certificates.length}</Badge>}>Certification History</SectionTitle>
          {data.certificates.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] text-left text-xs">
                <thead>
                  <tr className="border-b border-white/10 text-[10px] uppercase tracking-wide text-white/40">
                    <th className="px-2 py-2 font-bold">Certificate ID</th>
                    <th className="px-2 py-2 font-bold">Level</th>
                    <th className="px-2 py-2 font-bold">Trust Score</th>
                    <th className="px-2 py-2 font-bold">Readiness</th>
                    <th className="px-2 py-2 font-bold">Issued</th>
                    <th className="px-2 py-2 font-bold">Expires</th>
                    <th className="px-2 py-2 font-bold">Status</th>
                    <th className="px-2 py-2 font-bold">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {data.certificates.map((c) => (
                    <tr key={c.certificateId} className="border-b border-white/5 hover:bg-white/[0.02]">
                      <td className="px-2 py-2 font-mono text-white/80">{c.certificateId}</td>
                      <td className="px-2 py-2">
                        <span className="font-bold uppercase" style={{ color: LEVEL_COLORS[c.level] }}>
                          {c.level}
                        </span>
                      </td>
                      <td className="px-2 py-2 font-mono text-white/75">{c.trustScore}/1000</td>
                      <td className="px-2 py-2 text-white/70">{c.overallReadiness}%</td>
                      <td className="px-2 py-2 text-white/55">{longDate(c.issuedAt)}</td>
                      <td className="px-2 py-2 text-white/55">{longDate(c.expiresAt)}</td>
                      <td className="px-2 py-2">
                        <span
                          className="rounded px-2 py-0.5 text-[10px] font-bold"
                          style={{ color: STATUS_META[c.status]?.color, backgroundColor: `${STATUS_META[c.status]?.color}1a` }}
                        >
                          {STATUS_META[c.status]?.label || c.status}
                        </span>
                      </td>
                      <td className="px-2 py-2">
                        <button
                          type="button"
                          onClick={() => setPreviewCert(c)}
                          className="text-blue-300 underline-offset-2 hover:text-blue-200 hover:underline"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState label="No certificates issued yet." hint="Meet the eligibility criteria and issue your first Quantum Trust Certificate." />
          )}
        </Panel>

        {/* Activity + notifications + verification */}
        <div className="grid gap-3 xl:grid-cols-3">
          <Panel className="p-4">
            <SectionTitle>Certification Activity</SectionTitle>
            {data.history.length ? (
              <div className="space-y-2.5">
                {data.history.slice(0, 10).map((h) => (
                  <div key={h.id} className="flex items-start gap-2.5">
                    <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: eventColor(h.event) }} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-white/80">{eventLabel(h.event)}</span>
                        <span className="text-[10px] text-white/35">{relativeTime(h.createdAt)}</span>
                      </div>
                      <div className="truncate text-[10px] text-white/45">{h.detail || h.certificateId}</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState label="No lifecycle activity yet." />
            )}
          </Panel>

          <Panel className="p-4">
            <SectionTitle suffix={data.notifications.some((n) => !n.read) ? <Badge color={AMBER}>{data.notifications.filter((n) => !n.read).length} new</Badge> : null}>
              Notifications
            </SectionTitle>
            {data.notifications.length ? (
              <div className="space-y-2">
                {data.notifications.slice(0, 8).map((n) => (
                  <div key={n.id} className="rounded-md border border-white/6 bg-white/[0.015] px-3 py-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[10px] font-bold uppercase tracking-wide" style={{ color: notifColor(n.kind) }}>
                        {n.kind.replace(/_/g, ' ')}
                      </span>
                      <span className="text-[10px] text-white/35">{relativeTime(n.createdAt)}</span>
                    </div>
                    <div className="mt-0.5 text-[11px] text-white/65">{n.message}</div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState label="No notifications." />
            )}
          </Panel>

          <Panel className="p-4">
            <SectionTitle>Verification & Downloads</SectionTitle>
            <div className="mb-3">
              <div className="mb-1.5 text-[10px] font-bold uppercase tracking-wide text-white/45">Public Verification Activity</div>
              {data.verificationActivity.length ? (
                <div className="space-y-1.5">
                  {data.verificationActivity.slice(0, 5).map((v, i) => (
                    <div key={i} className="flex items-center justify-between text-[11px]">
                      <span className="font-mono text-white/70">{v.certificateId}</span>
                      <span className="flex items-center gap-2">
                        <span style={{ color: v.result === 'valid' || v.result === 'active' ? EMERALD : v.result === 'tampered' ? RED : AMBER }}>{v.result}</span>
                        <span className="text-white/30">{relativeTime(v.createdAt)}</span>
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-[11px] text-white/40">No verification lookups yet.</div>
              )}
            </div>
            <div className="border-t border-white/8 pt-2">
              <div className="mb-1.5 text-[10px] font-bold uppercase tracking-wide text-white/45">Recent Downloads</div>
              {data.downloads.length ? (
                <div className="space-y-1.5">
                  {data.downloads.slice(0, 5).map((d, i) => (
                    <div key={i} className="flex items-center justify-between text-[11px]">
                      <span className="font-mono text-white/70">{d.certificateId}</span>
                      <span className="flex items-center gap-2">
                        <span className="uppercase text-white/55">{d.format}</span>
                        <span className="text-white/30">{relativeTime(d.createdAt)}</span>
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-[11px] text-white/40">No downloads recorded yet.</div>
              )}
            </div>
          </Panel>
        </div>

        {/* Issuer + connection footer */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1 text-[11px] text-white/35">
          <span className="inline-flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${sseConnected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]' : 'bg-amber-300 animate-pulse'}`} />
            {sseConnected ? 'Live certification stream & lifecycle subscriptions connected' : 'Connecting certification streams'}
          </span>
          {data.issuer ? (
            <span>
              Issuer: {data.issuer.algorithm} · key {data.issuer.keyId} · last sync {longDate(data.generatedAt)}
            </span>
          ) : (
            <span>Last sync {longDate(data.generatedAt)}</span>
          )}
        </div>
      </div>

      {previewCert && previewCert !== activeCert ? (
        <button
          type="button"
          aria-label="Close preview"
          onClick={() => setPreviewCert(null)}
          className="fixed bottom-6 right-6 z-50 inline-flex items-center gap-1.5 rounded-md border border-white/15 bg-black/70 px-3 py-2 text-xs font-bold text-white/80 backdrop-blur hover:border-blue-400/40"
        >
          <XCircle className="h-4 w-4" /> Showing {previewCert.certificateId} — back to current
        </button>
      ) : null}
    </div>
  );
}

function eventColor(event: string): string {
  switch (event) {
    case 'issued':
    case 'renewed':
    case 'reinstated':
      return EMERALD;
    case 'suspended':
      return AMBER;
    case 'revoked':
    case 'expired':
      return RED;
    case 'validated':
      return BLUE;
    case 'verification_requested':
      return VIOLET;
    default:
      return '#64748B';
  }
}
function eventLabel(event: string): string {
  const map: Record<string, string> = {
    issued: 'Certificate Issued',
    renewed: 'Certificate Renewed',
    revoked: 'Certificate Revoked',
    suspended: 'Certificate Suspended',
    reinstated: 'Certificate Reinstated',
    expired: 'Certificate Expired',
    superseded: 'Certificate Superseded',
    validated: 'Re-Validated',
    downloaded: 'Certificate Downloaded',
    verification_requested: 'Verification Requested',
  };
  return map[event] || event;
}
function notifColor(kind: string): string {
  switch (kind) {
    case 'renewed':
    case 'reinstated':
      return EMERALD;
    case 'expiring_soon':
      return GOLD;
    case 'suspended':
    case 'drift_detected':
      return AMBER;
    case 'expired':
    case 'revoked':
      return RED;
    default:
      return GREEN;
  }
}
