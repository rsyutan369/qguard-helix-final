'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle, BadgeCheck, Building2, CheckCircle2, ClipboardList, Download, FileCheck2,
  FlaskConical, Globe2, Link2, Loader2, Send, ShieldCheck, Sparkles,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { WorkflowRail } from '@/components/workflow/WorkflowRail'
import { useExternalTrustActions, useVendorReadiness } from '@/hooks/use-external-trust'
import {
  ALIGNMENT_LABEL, EVIDENCE_REQUEST_LABEL, EVIDENCE_STAGE_LABEL, EVIDENCE_STAGE_ORDER,
  MIGRATION_SUPPORT_LABEL, OBLIGATION_LABEL, READINESS_LABEL, RISK_LABEL,
  type EvidenceRequestType, type Readiness, type VendorRecord,
} from '@/lib/ecosystem/external-trust-intelligence'
import {
  AskSophiaButton, Block, CapabilityNotice, Chip, ColumnToggle, Drawer, DrawerLink,
  EmptyState, ErrorState, EvidenceChip, Field, KpiStrip, PageHeader, Pagination,
  ProvenanceFooter, ReadinessChip, RiskChip, SearchInput, SectionCard, Select,
  SkeletonPage, SuiteRail, VerdictChip, csvCell, dateFmt, downloadTextFile, numberFmt,
  pctFmt, relativeTime, useQueryParam,
} from '../_components/external-trust/_shared'

/**
 * Vendor PQC Readiness.
 *
 * One job: **Review → Request Evidence → Track Commitment**.
 *
 * The page keeps a vendor's CLAIM and QGuard's MEASUREMENT visibly apart — a
 * roadmap promise is never rendered as a capability.
 */

type ColumnKey =
  | 'vendor' | 'service' | 'owner' | 'criticality' | 'readiness' | 'standards'
  | 'evidence' | 'contract' | 'support' | 'lastAssessment' | 'nextReview'

const COLUMNS: Array<{ key: ColumnKey; label: string; locked?: boolean }> = [
  { key: 'vendor', label: 'Vendor', locked: true },
  { key: 'service', label: 'Service' },
  { key: 'owner', label: 'Business Owner' },
  { key: 'criticality', label: 'Criticality' },
  { key: 'readiness', label: 'PQC Readiness', locked: true },
  { key: 'standards', label: 'Standards' },
  { key: 'evidence', label: 'Evidence' },
  { key: 'contract', label: 'Contract' },
  { key: 'support', label: 'Migration Support' },
  { key: 'lastAssessment', label: 'Last Assessment' },
  { key: 'nextReview', label: 'Next Review' },
]

const REQUEST_TYPES = Object.keys(EVIDENCE_REQUEST_LABEL) as EvidenceRequestType[]

export default function VendorPqcReadiness() {
  const navigate = useNavigate()
  const focusVendor = useQueryParam('vendor')
  const { data, state, error, live, lastGoodAt, refresh } = useVendorReadiness()
  const { requestEvidence, updateEvidenceRequest } = useExternalTrustActions()

  const [search, setSearch] = useState('')
  const [readiness, setReadiness] = useState('all')
  const [risk, setRisk] = useState('all')
  const [evidence, setEvidence] = useState('all')
  const [owner, setOwner] = useState('all')
  const [criticality, setCriticality] = useState('all')
  const [support, setSupport] = useState('all')
  const [page, setPage] = useState(0)
  const [hiddenColumns, setHiddenColumns] = useState<Set<ColumnKey>>(new Set(['nextReview']))
  const [selected, setSelected] = useState<VendorRecord | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [requestType, setRequestType] = useState<EvidenceRequestType>('pqc-roadmap')
  const [requestDue, setRequestDue] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<{ tone: 'good' | 'critical'; message: string } | null>(null)

  const pageSize = 12
  useEffect(() => { setPage(0) }, [search, readiness, risk, evidence, owner, criticality, support])

  const records = useMemo(() => {
    if (!data) return []
    const term = search.trim().toLowerCase()
    return data.records.filter((record) => {
      if (term && !`${record.name} ${record.category} ${record.services.join(' ')} ${record.businessOwner} ${record.observedHosts.join(' ')}`.toLowerCase().includes(term)) return false
      if (readiness !== 'all' && record.readiness !== readiness) return false
      if (risk !== 'all' && record.risk !== risk) return false
      if (evidence !== 'all' && record.evidenceState !== evidence) return false
      if (owner !== 'all' && record.businessOwner !== owner) return false
      if (criticality !== 'all' && record.criticality !== criticality) return false
      if (support !== 'all' && record.migrationSupport !== support) return false
      return true
    })
  }, [data, search, readiness, risk, evidence, owner, criticality, support])

  // A cross-page link (?vendor=) opens straight into that vendor's drawer.
  useEffect(() => {
    if (!focusVendor || !data || selected) return
    const match = data.records.find((record) => record.id === focusVendor)
    if (match) setSelected(match)
  }, [focusVendor, data, selected])

  const pages = Math.max(1, Math.ceil(records.length / pageSize))
  const current = Math.min(page, pages - 1)
  const visible = records.slice(current * pageSize, current * pageSize + pageSize)

  const vendorRequests = useMemo(
    () => (selected && data ? data.evidenceRequests.filter((request) => request.vendor === selected.name) : []),
    [selected, data],
  )

  const toggleColumn = useCallback((key: ColumnKey) => {
    setHiddenColumns((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }, [])

  const shown = (key: ColumnKey) => !hiddenColumns.has(key)

  const submitRequest = async (vendor: VendorRecord) => {
    setBusy(true)
    setNotice(null)
    try {
      await requestEvidence(vendor.id, { requestType, dueAt: requestDue || undefined })
      setNotice({ tone: 'good', message: `${EVIDENCE_REQUEST_LABEL[requestType]} requested from ${vendor.name}.` })
      await refresh(true)
    } catch (err) {
      setNotice({ tone: 'critical', message: err instanceof Error ? err.message : 'Request failed' })
    } finally {
      setBusy(false)
    }
  }

  const advanceRequest = async (id: string, stage: string) => {
    setBusy(true)
    try {
      await updateEvidenceRequest(id, { stage })
      await refresh(true)
    } catch (err) {
      setNotice({ tone: 'critical', message: err instanceof Error ? err.message : 'Update failed' })
    } finally {
      setBusy(false)
    }
  }

  const exportCsv = () => {
    const header = ['Vendor', 'Category', 'Service', 'Business Owner', 'Criticality', 'Vendor Commitment', 'QGuard Assessment', 'Published Readiness', 'Standards', 'Evidence', 'Contract', 'Migration Support', 'Risk', 'Risk Score', 'Linked Assets', 'Last Assessment', 'Risk Explanation']
    const lines = records.map((record) => [
      record.name, record.category, record.services.join(' | '), record.businessOwner, RISK_LABEL[record.criticality],
      READINESS_LABEL[record.vendorCommitment], READINESS_LABEL[record.assessedReadiness], READINESS_LABEL[record.readiness],
      ALIGNMENT_LABEL[record.standardsSummary], record.evidenceState, OBLIGATION_LABEL[record.obligationSummary],
      MIGRATION_SUPPORT_LABEL[record.migrationSupport], RISK_LABEL[record.risk], record.riskScore,
      record.linkedAssetCount, record.lastAssessmentAt ?? 'never', record.riskExplanation,
    ].map(csvCell).join(','))
    downloadTextFile(`qguard-vendor-readiness-${new Date().toISOString().slice(0, 10)}.csv`, [header.map(csvCell).join(','), ...lines].join('\n'), 'text/csv;charset=utf-8')
  }

  if (state === 'error' && !data) {
    return (
      <div className="min-h-screen space-y-4 p-3 lg:p-5">
        <SuiteRail current="vendor" />
        <ErrorState message={error || 'Unknown error'} onRetry={() => void refresh(true)} lastGoodAt={lastGoodAt} />
      </div>
    )
  }

  return (
    <div className="external-trust-shell min-h-screen space-y-4 p-3 lg:p-5">
      <style>{`
        .external-trust-shell { background: var(--qg-dashboard-bg, #0a1020); }
        @media (prefers-reduced-motion: reduce) {
          .external-trust-shell *, .external-trust-shell *::before, .external-trust-shell *::after {
            animation-duration: 0.001ms !important; transition-duration: 0.001ms !important;
          }
        }
      `}</style>

      <WorkflowRail activeStage="assessment" />
      <SuiteRail current="vendor" />

      <PageHeader
        title="Vendor PQC Readiness"
        subtitle="Track vendor post-quantum readiness, standards alignment, contractual commitments, evidence, and migration support."
        icon={BadgeCheck}
        live={live}
        generatedAt={data?.generatedAt}
        refreshing={state === 'loading'}
        onRefresh={() => void refresh(true)}
        sophiaPrompt="Which vendors are blocking our PQC migration, and which have missing or overdue evidence?"
        actions={
          <button type="button" onClick={exportCsv} disabled={!records.length}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:border-cyan-400/40 hover:text-cyan-300 disabled:opacity-40">
            <Download className="h-3.5 w-3.5" /> Export
          </button>
        }
      />

      {error && data && (
        <CapabilityNotice title="Live refresh failed — showing the last successful assessment" detail={`${error} · captured ${relativeTime(lastGoodAt)}`} />
      )}

      {state === 'loading' && !data ? <SkeletonPage rows={3} /> : data && (
        <>
          <KpiStrip items={[
            { key: 'assessed', label: 'Vendors Assessed', value: numberFmt(data.summary.assessed), detail: `of ${numberFmt(data.totalUnfiltered)} discovered`, tone: 'neutral', title: 'Vendors carrying at least one observed cryptographic signal or a recorded assessment.' },
            { key: 'ready', label: 'PQC Ready', value: numberFmt(data.summary.ready + data.summary.hybridReady), detail: `${data.summary.ready} ready · ${data.summary.hybridReady} hybrid`, tone: 'good', onClick: () => setReadiness('ready') },
            { key: 'preparing', label: 'Preparing / Committed', value: numberFmt(data.summary.preparingOrCommitted), detail: 'in progress or announced', tone: 'warning', onClick: () => setReadiness('preparing') },
            { key: 'evidence', label: 'Evidence Pending', value: numberFmt(data.summary.evidencePending), detail: 'requested, pending or overdue', tone: 'info', onClick: () => setEvidence('requested') },
            { key: 'critical', label: 'Critical Vendor Risks', value: numberFmt(data.summary.criticalRisks), detail: 'critical risk score', tone: data.summary.criticalRisks ? 'critical' : 'good', onClick: () => setRisk('critical') },
            { key: 'overall', label: 'Overall Readiness', value: pctFmt(data.summary.overallReadinessPct), detail: 'measured vendors only', tone: 'neutral', title: data.summary.readinessBasis },
          ]} />

          {!data.persistenceAvailable && (
            <CapabilityNotice
              title="Evidence request workflow is not provisioned"
              detail="Requests can be composed but not stored until supabase/external-trust-schema.sql is applied to this project. Nothing is faked in the meantime — the workflow simply reports as unavailable."
            />
          )}

          {/* Readiness distribution — click to filter the register */}
          <SectionCard title="Vendor Readiness Distribution" icon={ShieldCheck}
            right={<span className="font-mono text-[9px] uppercase tracking-widest text-white/30">{numberFmt(data.totalUnfiltered)} vendors</span>}>
            {data.totalUnfiltered === 0 ? (
              <EmptyState icon={Building2} title="No vendor assessments"
                detail="No vendor PQC readiness assessments have been completed yet. Vendors are discovered from connectors, certificate issuers and observed external hosts."
                cta={{ label: 'Run Discovery', href: '/dashboard/scanner' }} />
            ) : (
              <div className="space-y-2">
                {data.distribution.map((bucket) => (
                  <button key={bucket.readiness} type="button"
                    onClick={() => setReadiness(readiness === bucket.readiness ? 'all' : bucket.readiness)}
                    aria-pressed={readiness === bucket.readiness}
                    className={cn(
                      'grid w-full grid-cols-[140px_minmax(0,1fr)_56px] items-center gap-3 rounded-lg border px-3 py-2 text-left transition',
                      readiness === bucket.readiness ? 'border-cyan-400/50 bg-cyan-500/10' : 'border-white/6 bg-white/[0.015] hover:border-white/15',
                    )}>
                    <span className="flex items-center gap-1.5"><ReadinessChip value={bucket.readiness as Readiness} /></span>
                    <span className="h-2.5 overflow-hidden rounded-full bg-white/8">
                      <span className="block h-full rounded-full bg-cyan-400/70 transition-all duration-700" style={{ width: `${bucket.share}%` }} />
                    </span>
                    <span className="text-right font-mono text-[12px] font-black text-white/85">{numberFmt(bucket.count)}</span>
                  </button>
                ))}
                <p className="pt-1 text-[10px] leading-relaxed text-white/35">{data.summary.readinessBasis}</p>
              </div>
            )}
          </SectionCard>

          {/* Sophia recommendation */}
          {data.summary.evidencePending + data.summary.criticalRisks > 0 && (
            <div className="rounded-xl border border-violet-400/25 bg-violet-500/[0.06] p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-start gap-2.5">
                  <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-violet-300" />
                  <div>
                    <div className="text-[12px] font-black text-white/90">
                      Sophia identified {numberFmt(data.summary.criticalRisks)} critical vendor risk(s) and {numberFmt(data.summary.evidencePending)} with outstanding evidence.
                    </div>
                    <div className="mt-0.5 text-[10.5px] text-white/45">
                      Evidence confidence is the largest single input to vendor risk — closing it moves the score more than any other action.
                    </div>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button type="button" onClick={() => { setRisk('critical'); setEvidence('all') }}
                    className="rounded-lg border border-cyan-400/40 bg-cyan-500/12 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200">Review</button>
                  <AskSophiaButton question="Which vendors have missing evidence and which commitments are overdue?" context="Vendor PQC Readiness" />
                </div>
              </div>
            </div>
          )}

          {/* Register */}
          <SectionCard
            id="register" title="Vendor Readiness Register" icon={ClipboardList}
            right={
              <div className="flex items-center gap-2">
                <span className="font-mono text-[9px] uppercase tracking-widest text-white/30">{numberFmt(records.length)} / {numberFmt(data.totalUnfiltered)}</span>
                <ColumnToggle columns={COLUMNS} hidden={hiddenColumns} onToggle={toggleColumn} />
              </div>
            }
          >
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <SearchInput value={search} onChange={setSearch} label="Search vendors" placeholder="Search vendors, services, owners, hosts…" />
              <Select label="Readiness" value={readiness} onChange={setReadiness}
                options={[['all', 'All readiness'], ['ready', 'Ready'], ['hybrid-ready', 'Hybrid Ready'], ['preparing', 'Preparing'], ['committed', 'Committed'], ['not-ready', 'Not Ready'], ['unknown', 'Unknown']]} />
              <Select label="Risk" value={risk} onChange={setRisk}
                options={[['all', 'All risk'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['unknown', 'Unknown']]} />
              <Select label="Evidence" value={evidence} onChange={setEvidence}
                options={[['all', 'All evidence'], ['complete', 'Complete'], ['partial', 'Partial'], ['requested', 'Requested'], ['pending', 'Pending'], ['overdue', 'Overdue'], ['rejected', 'Rejected'], ['unknown', 'Unknown']]} />
              <Select label="Criticality" value={criticality} onChange={setCriticality}
                options={[['all', 'All criticality'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['unknown', 'Unknown']]} />
              <Select label="Migration support" value={support} onChange={setSupport}
                options={[['all', 'All support'], ['full', 'Full Support'], ['partial', 'Partial Support'], ['roadmap-only', 'Roadmap Only'], ['none', 'No Support'], ['unknown', 'Unknown']]} />
              <Select label="Business owner" value={owner} onChange={setOwner}
                options={[['all', 'All owners'], ...data.filters.owners.map((value) => [value, value] as [string, string])]} />
            </div>

            {data.totalUnfiltered === 0 ? (
              <EmptyState icon={Building2} title="No Vendor Assessments"
                detail="No vendor PQC readiness assessments have been completed yet."
                cta={{ label: 'Start Assessment', href: '/dashboard/scanner' }} />
            ) : records.length === 0 ? (
              <EmptyState icon={ClipboardList} title="No vendors match the current filters" detail="Adjust or clear the filters to see the full register." />
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[1080px] border-collapse text-left">
                    <caption className="sr-only">Vendor register with readiness, standards alignment, evidence state, contractual coverage, migration support and assessment dates.</caption>
                    <thead>
                      <tr className="border-b border-white/10">
                        <th scope="col" className="w-8 px-2 py-2">
                          <span className="sr-only">Select</span>
                        </th>
                        {COLUMNS.filter((column) => shown(column.key)).map((column) => (
                          <th key={column.key} scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">{column.label}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {visible.map((record) => (
                        <tr key={record.id} className="cursor-pointer transition hover:bg-cyan-500/[0.05]" onClick={() => setSelected(record)}>
                          <td className="px-2 py-2" onClick={(event) => event.stopPropagation()}>
                            <input
                              type="checkbox" aria-label={`Select ${record.name}`}
                              checked={selectedIds.has(record.id)}
                              onChange={() => setSelectedIds((current) => {
                                const next = new Set(current)
                                if (next.has(record.id)) next.delete(record.id); else next.add(record.id)
                                return next
                              })}
                              className="h-3 w-3 accent-cyan-400"
                            />
                          </td>
                          {shown('vendor') && (
                            <td className="px-2.5 py-2">
                              <div className="max-w-[210px] truncate text-[11.5px] font-black text-white/90" title={record.name}>{record.name}</div>
                              <div className="mt-0.5 truncate text-[8.5px] uppercase tracking-wider text-white/30">{record.category}</div>
                            </td>
                          )}
                          {shown('service') && (
                            <td className="px-2.5 py-2"><div className="max-w-[150px] truncate text-[10px] text-white/55">{record.services.join(', ') || '—'}</div></td>
                          )}
                          {shown('owner') && (
                            <td className="px-2.5 py-2"><div className="max-w-[130px] truncate text-[10px] text-white/55">{record.businessOwner}</div></td>
                          )}
                          {shown('criticality') && <td className="px-2.5 py-2"><RiskChip value={record.criticality} /></td>}
                          {shown('readiness') && (
                            <td className="px-2.5 py-2">
                              <ReadinessChip value={record.readiness} />
                              <div className="mt-1 text-[8.5px] text-white/30" title={record.assessedReadinessBasis}>
                                measured: {READINESS_LABEL[record.assessedReadiness]}
                              </div>
                            </td>
                          )}
                          {shown('standards') && (
                            <td className="px-2.5 py-2"><Chip tone={record.standardsSummary === 'aligned' ? 'good' : record.standardsSummary === 'not-aligned' ? 'critical' : 'info'}>{ALIGNMENT_LABEL[record.standardsSummary]}</Chip></td>
                          )}
                          {shown('evidence') && (
                            <td className="px-2.5 py-2">
                              <EvidenceChip value={record.evidenceState} />
                              {record.overdueRequests > 0 && <div className="mt-1 text-[8.5px] font-bold text-red-300">{record.overdueRequests} overdue</div>}
                            </td>
                          )}
                          {shown('contract') && (
                            <td className="px-2.5 py-2"><Chip tone={record.obligationSummary === 'covered' ? 'good' : record.obligationSummary === 'missing' ? 'critical' : 'warning'}>{OBLIGATION_LABEL[record.obligationSummary]}</Chip></td>
                          )}
                          {shown('support') && (
                            <td className="px-2.5 py-2"><div className="text-[10px] text-white/55">{MIGRATION_SUPPORT_LABEL[record.migrationSupport]}</div></td>
                          )}
                          {shown('lastAssessment') && (
                            <td className="px-2.5 py-2 font-mono text-[10px] text-white/50">{relativeTime(record.lastAssessmentAt)}</td>
                          )}
                          {shown('nextReview') && (
                            <td className="px-2.5 py-2 font-mono text-[10px] text-white/50">{dateFmt(record.nextReviewAt)}</td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {selectedIds.size > 0 && (
                  <div className="mt-2 flex flex-wrap items-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-2">
                    <span className="text-[10px] font-black uppercase tracking-wider text-cyan-200">{selectedIds.size} selected</span>
                    <button type="button" onClick={() => { const first = records.find((record) => selectedIds.has(record.id)); if (first) setSelected(first) }}
                      className="rounded border border-white/15 bg-white/5 px-2.5 py-1 text-[9px] font-black uppercase tracking-wider text-white/70">Open first</button>
                    <button type="button" onClick={() => setSelectedIds(new Set())}
                      className="rounded border border-white/15 bg-white/5 px-2.5 py-1 text-[9px] font-black uppercase tracking-wider text-white/70">Clear</button>
                  </div>
                )}
                <Pagination page={current} pages={pages} onPage={setPage} />
              </>
            )}
          </SectionCard>

          <ProvenanceFooter evidence={data.evidence} generatedAt={data.generatedAt} />
        </>
      )}

      {/* Vendor detail drawer */}
      <Drawer
        open={Boolean(selected)}
        title={selected?.name || ''}
        subtitle={selected ? `${selected.category} · ${selected.linkedAssetCount} linked asset(s)` : ''}
        tone={selected ? (selected.risk === 'critical' ? 'critical' : selected.risk === 'high' ? 'warning' : 'neutral') : 'neutral'}
        onClose={() => { setSelected(null); setNotice(null) }}
        footer={selected && (
          <div className="flex flex-wrap gap-2">
            <DrawerLink href={`/dashboard/ecosystem-dependency-map?focus=${encodeURIComponent(`vendor:${selected.id}`)}`} primary>
              <Globe2 className="h-3 w-3" /> View Dependencies
            </DrawerLink>
            <DrawerLink href={`/dashboard/trust-chain-analyzer?vendor=${encodeURIComponent(selected.id)}`}>
              <Link2 className="h-3 w-3" /> Analyze Trust Impact
            </DrawerLink>
            <DrawerLink href={`/dashboard/hybrid-crypto-lab?vendor=${encodeURIComponent(selected.id)}`}>
              <FlaskConical className="h-3 w-3" /> Run Hybrid Test
            </DrawerLink>
            <DrawerLink href="/dashboard/migration-planner">Add to Migration Plan</DrawerLink>
            <AskSophiaButton question={`Assess vendor ${selected.name}: what is blocking their PQC readiness and what evidence should we request first?`} context="Vendor PQC Readiness" />
          </div>
        )}
      >
        {selected && (
          <>
            {notice && (
              <div className={cn('rounded-lg border p-2.5 text-[10.5px]',
                notice.tone === 'good' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200' : 'border-red-500/30 bg-red-500/10 text-red-200')}>
                {notice.message}
              </div>
            )}

            <div className="flex flex-wrap gap-1.5">
              <ReadinessChip value={selected.readiness} />
              <RiskChip value={selected.risk} />
              <EvidenceChip value={selected.evidenceState} />
              <Chip tone="info">{MIGRATION_SUPPORT_LABEL[selected.migrationSupport]}</Chip>
            </div>

            <Block title="Vendor Overview">
              <div className="grid grid-cols-2 gap-2">
                <Field label="Business owner" value={selected.businessOwner} />
                <Field label="Technical owner" value={selected.technicalOwner} />
                <Field label="Criticality" value={RISK_LABEL[selected.criticality]} />
                <Field label="Linked assets" value={numberFmt(selected.linkedAssetCount)} mono />
                <Field label="Last assessment" value={relativeTime(selected.lastAssessmentAt)} />
                <Field label="Next review" value={dateFmt(selected.nextReviewAt)} />
              </div>
            </Block>

            {/* The claim/measurement split — the core honesty guarantee (§14) */}
            <Block title="Commitment vs Assessment">
              <div className="grid gap-2 sm:grid-cols-2">
                <div className="rounded-lg border border-white/8 bg-black/25 p-2.5">
                  <div className="text-[8px] font-black uppercase tracking-widest text-amber-300/80">Vendor commitment (claim)</div>
                  <div className="mt-1 text-[12px] font-black text-white/85">{READINESS_LABEL[selected.vendorCommitment]}</div>
                  <p className="mt-1 text-[10px] leading-relaxed text-white/45">{selected.vendorCommitmentBasis}</p>
                </div>
                <div className="rounded-lg border border-cyan-400/25 bg-cyan-500/[0.06] p-2.5">
                  <div className="text-[8px] font-black uppercase tracking-widest text-cyan-300">QGuard assessment (measured)</div>
                  <div className="mt-1 text-[12px] font-black text-white/85">{READINESS_LABEL[selected.assessedReadiness]}</div>
                  <p className="mt-1 text-[10px] leading-relaxed text-white/45">{selected.assessedReadinessBasis}</p>
                </div>
              </div>
              <p className="mt-1.5 text-[9.5px] leading-relaxed text-white/35">
                A vendor promise is never treated as a verified capability. The published readiness above is the conservative combination of the two.
              </p>
            </Block>

            <Block title="PQC Position">
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {([
                  ['Hybrid', selected.position.hybridSupport, 'hybrid'],
                  ['KEM', selected.position.kemSupport, 'kem'],
                  ['Signature', selected.position.signatureSupport, 'signature'],
                  ['TLS', selected.position.tlsSupport, 'tls'],
                  ['Certificate', selected.position.certificateSupport, 'certificate'],
                  ['Key mgmt', selected.position.keyManagementSupport, 'keyManagement'],
                ] as Array<[string, 'pass' | 'fail' | 'unknown', string]>).map(([label, verdict, key]) => (
                  <div key={label} className="rounded-lg border border-white/8 bg-black/25 px-2.5 py-2">
                    <div className="text-[8px] font-black uppercase tracking-widest text-white/40">{label}</div>
                    <div className="mt-1"><VerdictChip value={verdict} /></div>
                    <div className="mt-1 text-[8.5px] text-white/30">
                      {selected.position.provenance[key] === 'measured' ? 'measured' : selected.position.provenance[key] === 'vendor-claim' ? 'vendor claim only' : 'no evidence'}
                    </div>
                  </div>
                ))}
              </div>
              <p className="mt-1.5 text-[10px] leading-relaxed text-white/40">{selected.position.basis}</p>
              {selected.position.currentAlgorithms.length > 0 && (
                <div className="mt-2 rounded-lg border border-white/8 bg-black/25 p-2.5">
                  <div className="text-[8px] font-black uppercase tracking-widest text-cyan-300/60">Observed algorithms</div>
                  <div className="mt-1 font-mono text-[10px] text-white/70">{selected.position.currentAlgorithms.join(', ')}</div>
                </div>
              )}
            </Block>

            <Block title="Standards Alignment">
              <div className="space-y-1">
                {selected.standards.map((standard) => (
                  <div key={standard.key} className="rounded-lg border border-white/8 bg-black/25 px-2.5 py-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-[10.5px] font-bold text-white/80">{standard.label}</span>
                      <Chip tone={standard.alignment === 'aligned' ? 'good' : standard.alignment === 'not-aligned' ? 'critical' : standard.alignment === 'partial' ? 'warning' : 'info'}>
                        {ALIGNMENT_LABEL[standard.alignment]}
                      </Chip>
                    </div>
                    <div className="mt-1 truncate font-mono text-[9.5px] text-cyan-300/60" title={standard.evidence}>{standard.evidence}</div>
                    <div className="mt-0.5 text-[9px] leading-relaxed text-white/35">{standard.basis} Last verified {relativeTime(standard.lastVerifiedAt)}.</div>
                  </div>
                ))}
              </div>
            </Block>

            <Block title="Vendor PQC Roadmap">
              <div className="space-y-1">
                {selected.roadmap.map((stage, index) => (
                  <div key={stage.key} className="rounded-lg border border-white/8 bg-black/25 px-2.5 py-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[8px] text-white/25">{index + 1}</span>
                      <span className="text-[10.5px] font-black text-white/80">{stage.label}</span>
                      {stage.assessed ? <Chip tone="good" glyph="✓">Assessed</Chip> : <Chip tone="info" glyph="?">Not assessed</Chip>}
                    </div>
                    <div className="mt-1 grid gap-1 sm:grid-cols-2">
                      <div className="text-[9.5px] text-white/45"><span className="text-amber-300/70">Vendor says:</span> {stage.vendorCommitment}{stage.vendorTargetDate ? ` (target ${dateFmt(stage.vendorTargetDate)})` : ''}</div>
                      <div className="text-[9.5px] text-white/45"><span className="text-cyan-300/70">QGuard measured:</span> {stage.qguardAssessment}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Block>

            <Block title="Contractual Obligations">
              <div className="space-y-1">
                {selected.obligations.map((obligation) => (
                  <div key={obligation.key} className="flex items-start justify-between gap-2 rounded-lg border border-white/8 bg-black/25 px-2.5 py-1.5">
                    <div className="min-w-0">
                      <div className="text-[10.5px] font-bold text-white/75">{obligation.label}</div>
                      <div className="text-[9px] leading-relaxed text-white/35">{obligation.basis}</div>
                    </div>
                    <Chip tone={obligation.state === 'covered' ? 'good' : obligation.state === 'missing' || obligation.state === 'expired' ? 'critical' : 'warning'}>
                      {OBLIGATION_LABEL[obligation.state]}
                    </Chip>
                  </div>
                ))}
              </div>
            </Block>

            <Block title="Migration Support">
              <div className="rounded-lg border border-white/8 bg-black/25 p-2.5">
                <Chip tone={selected.migrationSupport === 'full' ? 'good' : selected.migrationSupport === 'none' ? 'critical' : 'warning'}>
                  {MIGRATION_SUPPORT_LABEL[selected.migrationSupport]}
                </Chip>
                <ul className="mt-2 space-y-1">
                  {selected.migrationSupportDetail.map((line, index) => (
                    <li key={index} className="text-[10px] leading-relaxed text-white/50">· {line}</li>
                  ))}
                </ul>
              </div>
            </Block>

            <Block title="Vendor Risk">
              <div className="rounded-lg border border-white/8 bg-black/25 p-2.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[20px] font-black text-white">{selected.riskScore}</span>
                  <span className="text-[10px] text-white/40">/100</span>
                  <RiskChip value={selected.risk} />
                </div>
                <p className="mt-1.5 text-[10.5px] leading-relaxed text-white/50">{selected.riskExplanation}</p>
                <div className="mt-2 space-y-1">
                  {selected.riskFactors.map((factor) => (
                    <div key={factor.key} className="grid grid-cols-[minmax(0,1fr)_44px_36px] items-center gap-2">
                      <span className="truncate text-[9.5px] text-white/55" title={factor.evidence}>{factor.label}</span>
                      <span className="h-1.5 overflow-hidden rounded-full bg-white/8">
                        <span className="block h-full rounded-full bg-cyan-400/70" style={{ width: `${factor.score}%` }} />
                      </span>
                      <span className="text-right font-mono text-[9px] text-white/45">{factor.score}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Block>

            {/* Evidence request workflow */}
            <Block title="Evidence Requests" right={<span className="text-[9px] text-white/35">{vendorRequests.length} on file</span>}>
              {!data?.persistenceAvailable ? (
                <div className="rounded-lg border border-amber-500/25 bg-amber-500/[0.07] p-2.5 text-[10px] leading-relaxed text-white/55">
                  Requests cannot be stored until <span className="font-mono text-amber-200">supabase/external-trust-schema.sql</span> is applied. The workflow is disabled rather than simulated.
                </div>
              ) : (
                <>
                  <div className="flex flex-wrap items-end gap-2 rounded-lg border border-white/8 bg-black/25 p-2.5">
                    <label className="min-w-[190px] flex-1">
                      <span className="mb-1 block text-[8px] font-black uppercase tracking-widest text-cyan-300/60">Request</span>
                      <select value={requestType} onChange={(event) => setRequestType(event.target.value as EvidenceRequestType)}
                        className="h-8 w-full rounded-lg border border-white/10 bg-black/40 px-2 text-[10.5px] text-white/80 focus:border-cyan-400/50 focus:outline-none">
                        {REQUEST_TYPES.map((type) => <option key={type} value={type} className="bg-[#0b1120]">{EVIDENCE_REQUEST_LABEL[type]}</option>)}
                      </select>
                    </label>
                    <label>
                      <span className="mb-1 block text-[8px] font-black uppercase tracking-widest text-cyan-300/60">Due</span>
                      <input type="date" value={requestDue} onChange={(event) => setRequestDue(event.target.value)}
                        className="h-8 rounded-lg border border-white/10 bg-black/40 px-2 text-[10.5px] text-white/80 focus:border-cyan-400/50 focus:outline-none" />
                    </label>
                    <button type="button" disabled={busy} onClick={() => void submitRequest(selected)}
                      className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 text-[9px] font-black uppercase tracking-wider text-cyan-200 disabled:opacity-40">
                      {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Send className="h-3 w-3" />} Request Evidence
                    </button>
                  </div>

                  {vendorRequests.length > 0 && (
                    <div className="mt-2 space-y-1.5">
                      {vendorRequests.map((request) => {
                        const stageIndex = EVIDENCE_STAGE_ORDER.indexOf(request.stage as typeof EVIDENCE_STAGE_ORDER[number])
                        const next = stageIndex >= 0 && stageIndex < EVIDENCE_STAGE_ORDER.length - 1 ? EVIDENCE_STAGE_ORDER[stageIndex + 1] : null
                        return (
                          <div key={request.id} className={cn('rounded-lg border p-2.5', request.overdue ? 'border-red-400/35 bg-red-500/[0.07]' : 'border-white/8 bg-black/25')}>
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="text-[10.5px] font-bold text-white/80">{request.requestLabel}</span>
                              <div className="flex items-center gap-1.5">
                                {request.overdue && <Chip tone="critical" glyph="!">Overdue</Chip>}
                                <Chip tone={request.stage === 'accepted' ? 'good' : request.stage === 'rejected' ? 'critical' : 'info'}>{EVIDENCE_STAGE_LABEL[request.stage]}</Chip>
                              </div>
                            </div>
                            <div className="mt-1 flex flex-wrap gap-x-3 text-[9px] text-white/35">
                              <span>Owner {request.owner}</span>
                              <span>Requested {relativeTime(request.requestedAt)}</span>
                              <span>Due {dateFmt(request.dueAt)}</span>
                              {request.reviewer !== 'Unassigned' && <span>Reviewer {request.reviewer}</span>}
                            </div>
                            {(next || request.stage !== 'rejected') && (
                              <div className="mt-1.5 flex flex-wrap gap-1.5">
                                {next && (
                                  <button type="button" disabled={busy} onClick={() => void advanceRequest(request.id, next)}
                                    className="rounded border border-cyan-400/35 bg-cyan-500/10 px-2 py-1 text-[8.5px] font-black uppercase tracking-wider text-cyan-200 disabled:opacity-40">
                                    Advance → {EVIDENCE_STAGE_LABEL[next]}
                                  </button>
                                )}
                                {request.stage !== 'rejected' && request.stage !== 'accepted' && (
                                  <button type="button" disabled={busy} onClick={() => void advanceRequest(request.id, 'rejected')}
                                    className="rounded border border-red-400/35 bg-red-500/10 px-2 py-1 text-[8.5px] font-black uppercase tracking-wider text-red-200 disabled:opacity-40">
                                    Reject
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  )}
                </>
              )}
              <p className="mt-1.5 text-[9.5px] leading-relaxed text-white/35">{selected.evidenceBasis}</p>
            </Block>

            {selected.observedHosts.length > 0 && (
              <Block title="Observed Surfaces">
                <div className="flex flex-wrap gap-1">
                  {selected.observedHosts.map((host) => (
                    <span key={host} className="rounded border border-white/10 bg-black/25 px-2 py-1 font-mono text-[9.5px] text-white/55">{host}</span>
                  ))}
                </div>
              </Block>
            )}
          </>
        )}
      </Drawer>
    </div>
  )
}
