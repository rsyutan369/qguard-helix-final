'use client'
import { useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
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
  const { data, state, error, refresh } = useEstateOverview()
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
        subtitle="Every quantum-vulnerable finding across your estate, merged by fingerprint and grouped into the fixes that resolve it, with maps, campaigns and evidence-based progress."
        icon={Radar}
        live={state === 'ready'}
        generatedAt={data?.generatedAt}
        onRefresh={() => void refresh(true)}
        refreshing={state === 'loading'}
        sophiaPrompt="Explain my top remediation fixes, why they are ranked that way and which campaign to start first."
      />

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
            { key: 'assets', label: 'Assets affected', value: `${s!.affectedAssets.toLocaleString()}`, detail: `of ${s!.assets.toLocaleString()} assets in inventory`, tone: s!.affectedAssets ? 'warning' : 'good' },
            { key: 'fixes', label: 'Fixes to resolve them', value: s!.fixes.toLocaleString(), detail: `top 5 cover ${s!.topFiveCoverage}% of affected assets`, tone: 'info', onClick: () => update({ view: 'plan' }) },
            { key: 'merged', label: 'Duplicates merged', value: s!.duplicatesMerged.toLocaleString(), detail: `${s!.classifiedObservations.toLocaleString()} findings → ${s!.uniqueComponents.toLocaleString()} components`, tone: 'neutral', title: 'Repeated findings of the same component, and the same certificate recorded on several assets, are counted once.' },
            { key: 'certs', label: 'Unique certificates', value: s!.uniqueCertificates.toLocaleString(), detail: `${s!.reusedCertificates.toLocaleString()} reused on several assets`, tone: 'neutral' },
            { key: 'open', label: 'Open work items', value: s!.openWorkItems.toLocaleString(), detail: `${s!.validatedWorkItems.toLocaleString()} validated by rescan`, tone: s!.openWorkItems ? 'critical' : 'good', onClick: () => update({ view: 'analytics' }) },
            { key: 'owners', label: 'Affected, no owner', value: s!.unownedAffectedAssets.toLocaleString(), detail: 'no one to route the fix to', tone: s!.unownedAffectedAssets ? 'warning' : 'good', onClick: () => update({ view: 'analytics' }) },
          ]} />

          {(truncated.length > 0 || s!.unclassifiedObservations > 0) && (
            <div role="note" className="flex items-start gap-2 rounded-lg border border-amber-400/30 bg-amber-500/10 px-3 py-2 text-[12px] text-amber-200">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                {truncated.map((c) => `${c.table}: ${c.loaded.toLocaleString()} of ${c.total?.toLocaleString() ?? 'more'} rows loaded (newest first). `).join('')}
                {s!.unclassifiedObservations > 0 && `${s!.unclassifiedObservations.toLocaleString()} inventory row(s) name an algorithm the engine does not recognise; they are excluded from fixes, not counted as safe.`}
              </span>
            </div>
          )}

          <div className="qe-tabs" role="tablist" aria-label="Estate views">
            {VIEWS.map(({ key, label, icon: Icon }) => (
              <button key={key} type="button" role="tab" id={`qe-tab-${key}`} aria-controls={`qe-panel-${key}`} aria-selected={view === key} className="qe-tab" onClick={() => update({ view: key })}>
                <Icon aria-hidden="true" />{label}
              </button>
            ))}
          </div>

          <section id={`qe-panel-${view}`} role="tabpanel" aria-labelledby={`qe-tab-${view}`} className="overflow-hidden rounded-xl border border-white/10 bg-[var(--qg-card-bg,transparent)]">
            {view === 'plan' && (
              <FixPlan
                clusters={data.clusters}
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
                setLevel={(next) => update({ level: next })}
                focus={focus}
                setFocus={(next) => update({ focus: next })}
                onPlanCampaign={(id) => update({ view: 'campaigns', fix: id })}
              />
            )}
            {view === 'campaigns' && <Campaigns clusters={data.clusters} fixId={fixId} setFixId={(id) => update({ fix: id })} />}
            {view === 'analytics' && <Analytics overview={data} />}
          </section>
        </>
      )}
    </div>
  )
}
