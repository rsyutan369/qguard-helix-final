'use client'
import { useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { AlertTriangle, BarChart3, ListOrdered, Network, Rocket, Radar } from 'lucide-react'
import { EmptyState, ErrorState, KpiStrip, PageHeader } from '../_components/external-trust/_shared'
import { WorkflowRail } from '@/components/workflow/WorkflowRail'
import { useEstateOverview } from '@/hooks/use-estate-intelligence'
import { FixPlan } from './FixPlan'
import { EstateMap, type MapLevel } from './EstateMap'
import { Campaigns } from './Campaigns'
import { Analytics } from './Analytics'
import './estate.css'

type View = 'plan' | 'map' | 'campaigns' | 'analytics'
const VIEWS: Array<{ key: View; label: string; icon: typeof ListOrdered }> = [
  { key: 'plan', label: 'Fix plan', icon: ListOrdered },
  { key: 'map', label: 'Relationship map', icon: Network },
  { key: 'campaigns', label: 'Campaigns', icon: Rocket },
  { key: 'analytics', label: 'Analytics', icon: BarChart3 },
]

export default function EstateIntelligence() {
  const { data, state, error, refresh, refreshing, live, lastVerifiedAt } = useEstateOverview()
  const [params, setParams] = useSearchParams()
  const view = (VIEWS.some((v) => v.key === params.get('view')) ? params.get('view') : 'plan') as View
  const fixId = params.get('fix')
  const level = (['estate', 'root-cause', 'neighbourhood'].includes(params.get('level') ?? '') ? params.get('level') : 'estate') as MapLevel
  const focus = params.get('focus')

  const update = useCallback((patch: Record<string, string | null>) => {
    setParams((current) => {
      const next = new URLSearchParams(current)
      for (const [key, value] of Object.entries(patch)) { if (value === null) next.delete(key); else next.set(key, value) }
      return next
    }, { replace: true })
  }, [setParams])

  if (state === 'error' && !data) {
    return <div className="p-3 lg:p-5"><ErrorState message={error || 'Unknown error'} onRetry={() => void refresh(true)} lastGoodAt={null} /></div>
  }

  const s = data?.summary
  const truncated = data?.coverage.filter((c) => c.truncated) ?? []

  return (
    <div className="qe min-h-screen space-y-4 p-3 lg:p-5">
      <WorkflowRail activeStage="planning" />
      <PageHeader
        title="Estate Remediation Intelligence"
        subtitle="Group recorded cryptographic exposures into fixes and track migration progress against validation evidence."
        icon={Radar}
        live={live}
        generatedAt={lastVerifiedAt}
        onRefresh={() => void refresh(true)}
        refreshing={refreshing}
        sophiaPrompt="Explain my top remediation fixes, why they are ranked that way and which campaign to start first."
      />

      {data && state === 'error' && (
        <div role="status" className="flex flex-wrap items-center gap-2 rounded-lg border border-amber-400/30 bg-amber-500/10 px-3 py-2 text-[13px] text-amber-200">
          <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span>The latest refresh failed. Showing the last successful estate snapshot.</span>
          <button type="button" className="min-h-8 px-2 font-semibold underline" onClick={() => void refresh(true)}>Retry</button>
        </div>
      )}

      {truncated.length > 0 && (
        <ul className="rounded-lg border border-amber-400/30 bg-amber-500/10 px-4 py-2 text-[13px] text-amber-200" aria-label="Incomplete data sources">
          {truncated.map((c) => <li key={c.table}>{c.total === null && c.loaded === 0
            ? `${c.table} is unavailable.`
            : `${c.table} loaded ${c.loaded.toLocaleString()} of ${c.total?.toLocaleString() ?? 'an unknown number of'} records.`}</li>)}
        </ul>
      )}

      {!data ? (
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6" aria-busy="true">
          {Array.from({ length: 6 }, (_, i) => <div key={i} className="h-[74px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />)}
        </div>
      ) : !data.hasData ? (
        <EmptyState icon={Radar} title="No scan evidence yet"
          detail="Estate intelligence groups real scan findings into fixes. Scan your endpoints or connect a collector agent, and certificates, keys and algorithms will appear here."
          cta={{ label: 'Open the PQC Scanner', href: '/dashboard/scanner' }} />
      ) : (
        <>
          <KpiStrip items={[
            { key: 'assets', label: 'Assets in fix scope', value: s!.affectedAssets.toLocaleString(), detail: 'including validated work', tone: s!.affectedAssets ? 'warning' : 'good' },
            { key: 'fixes', label: 'Fixes to resolve them', value: s!.fixes.toLocaleString(), detail: `top 5 cover ${s!.topFiveCoverage}% of affected assets`, tone: 'info', onClick: () => update({ view: 'plan' }) },
            { key: 'merged', label: 'Duplicates merged', value: s!.duplicatesMerged.toLocaleString(), detail: `${s!.uniqueComponents.toLocaleString()} component groups`, tone: 'neutral', title: 'Repeated observations of the same component type and separate records of the same certificate.' },
            { key: 'certs', label: 'Unique certificates', value: s!.uniqueCertificates.toLocaleString(), detail: `${s!.reusedCertificates.toLocaleString()} reused on several assets`, tone: 'neutral' },
            { key: 'open', label: 'Open work items', value: s!.openWorkItems.toLocaleString(), detail: `${s!.validatedWorkItems.toLocaleString()} validated`, tone: s!.openWorkItems ? 'critical' : 'neutral', onClick: () => update({ view: 'analytics' }) },
            { key: 'owners', label: 'In scope, no owner', value: s!.unownedAffectedAssets.toLocaleString(), detail: 'ownership missing from inventory', tone: s!.unownedAffectedAssets ? 'warning' : 'good', onClick: () => update({ view: 'analytics' }) },
          ]} />

          <details className="rounded-lg border border-white/12 bg-white/[0.035] px-3 py-2 text-[13px] text-slate-300">
            <summary className="cursor-pointer font-semibold focus-visible:outline focus-visible:outline-2">
              Evidence coverage · {(s!.unclassifiedObservations + s!.unclassifiedCertificates).toLocaleString()} need algorithm review
            </summary>
            <ul className="mt-2 space-y-1">
              <li>{s!.classifiedObservations.toLocaleString()} classified inventory observations</li>
              <li>{s!.contextualRows.toLocaleString()} policy, package, and diagnostic records</li>
              {s!.unclassifiedObservations > 0 && <li>{(s!.unclassifiedObservations - s!.missingAlgorithms).toLocaleString()} with an unsupported algorithm · {s!.missingAlgorithms.toLocaleString()} with no algorithm recorded</li>}
              {s!.unclassifiedCertificates > 0 && <li>{s!.unclassifiedCertificates.toLocaleString()} certificates need key algorithm evidence</li>}
              {s!.unlinkedEvidenceRows > 0 && <li>{s!.unlinkedEvidenceRows.toLocaleString()} observations could not be linked to an asset loaded in this snapshot</li>}
            </ul>
            <Link to="/dashboard/assets" className="mt-2 inline-flex min-h-9 items-center font-semibold underline">Review Assets &amp; CBOM</Link>
          </details>

          <div className="qe-tabs" role="tablist" aria-label="Estate views">
            {VIEWS.map(({ key, label, icon: Icon }) => (
              <button key={key} type="button" role="tab" id={`qe-tab-${key}`} aria-controls={`qe-panel-${key}`} aria-selected={view === key} className="qe-tab" onClick={() => update({ view: key })}>
                <Icon aria-hidden="true" />{label}
              </button>
            ))}
          </div>

          <section id={`qe-panel-${view}`} role="tabpanel" aria-labelledby={`qe-tab-${view}`} className={`min-w-0 rounded-xl border border-white/10 bg-[var(--qg-card-bg,transparent)]${view === 'map' ? '' : ' overflow-hidden'}`}>
            {view === 'plan' && (
              <FixPlan
                clusters={data.clusters}
                revision={data.revision}
                selectedId={fixId}
                onSelect={(id) => update({ fix: id })}
                onOpenMap={(id) => update({ view: 'map', level: 'neighbourhood', focus: `fix:${id}` })}
                onOpenCampaign={(id) => update({ view: 'campaigns', fix: id })}
              />
            )}
            {view === 'map' && (
              <EstateMap
                overview={data}
                level={level}
                focus={focus}
                onNavigate={(next, target) => update(target ? { level: next, focus: target } : { level: next })}
                onPlanCampaign={(id) => update({ view: 'campaigns', fix: id })}
              />
            )}
            {view === 'campaigns' && <Campaigns clusters={data.clusters} revision={data.revision} fixId={fixId} setFixId={(id) => update({ fix: id })} onQueued={() => void refresh(true)} />}
            {view === 'analytics' && <Analytics overview={data} />}
          </section>
        </>
      )}
    </div>
  )
}
