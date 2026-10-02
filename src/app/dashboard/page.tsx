'use client'

import {
  Shield, AlertTriangle, Activity, RefreshCw, ChevronRight, GitBranch,
  ScrollText, Briefcase, Boxes, Radar, Bell, History, Sparkles, FileDown, Scale, Radio,
} from 'lucide-react'
import { useDashboard } from '@/hooks/use-dashboard'
import { useAuth } from '@/contexts/auth-context'
import { isOwnerEmail } from '@/lib/admin-access'
import { ExposureWorkflowGraph } from '@/components/exposure/ExposureWorkflowGraph'
import { ESTATE_GROUPINGS, ESTATE_LENSES } from '@/lib/dashboard/estate-workflow'
import SecurityEventsPanel from './security_events_panel/SecurityEventsPanel'
import ExecutiveSummary from './_components/executive/ExecutiveSummary'
import KpiGrid from './_components/executive/KpiGrid'
import MigrationPipeline from './_components/executive/MigrationPipeline'
import ComplianceStrip from './_components/executive/ComplianceStrip'
import BusinessImpact from './_components/executive/BusinessImpact'
import AssetInventory from './_components/executive/AssetInventory'
import ThreatTimeline from './_components/executive/ThreatTimeline'
import RuntimeTelemetry from './_components/executive/RuntimeTelemetry'
import ThreatIntel from './_components/executive/ThreatIntel'
import AiRecommendations from './_components/executive/AiRecommendations'
import SharedResponsibilityStrip from './_components/executive/SharedResponsibilityStrip'
import { SectionLabel, relativeTime } from './_components/executive/primitives'

function firstName(user: ReturnType<typeof useAuth>['user']): string | null {
  const meta = (user?.user_metadata || {}) as Record<string, unknown>
  const full = (meta.full_name || meta.name || '') as string
  if (full) return full.trim().split(/\s+/)[0]
  if (user?.email) return user.email.split('@')[0]
  return null
}

function plural(count: number, noun: string): string {
  return `${count.toLocaleString()} ${noun}${count === 1 ? '' : 's'}`
}

export default function Dashboard() {
  const { user } = useAuth()
  const {
    summary, executive, events, eventsOmitted, estateWorkflow, recommendations, recommendationsTotal, health,
    summaryState, executiveState, eventsState, workflowState, recommendationsState,
    lastSyncAt, sseConnected, refreshAll,
  } = useDashboard()

  const execLoading = executiveState === 'loading' && !executive
  const workflowLoading = workflowState === 'loading' && !estateWorkflow
  const workflowFailed = workflowState === 'error' && !estateWorkflow
  const eventsLoading = eventsState === 'loading' && events.length === 0
  const recsLoading = recommendationsState === 'loading' && recommendations.length === 0
  const summaryLoading = summaryState === 'loading' && !summary
  const error = summaryState === 'error' && !summary && executiveState === 'error' && !executive

  /*
   * Two different questions, two indicators.
   *
   * The first pill is the CONNECTION: is this page receiving live updates.
   * It used to read "Live monitoring" whenever a websocket was open — a claim
   * about the ESTATE (that something is watching it) made from a fact about the
   * BROWSER (that it is subscribed to database changes). The second pill is
   * the estate claim, answered from what is actually enrolled.
   */
  const activity = health?.services?.migration === 'migrating'
    ? 'Migration running'
    : health?.services?.scanner === 'scanning'
      ? 'Scan running'
      : null
  const syncState = summaryState === 'offline' || executiveState === 'offline'
    ? 'offline'
    : health?.status === 'degraded'
      ? 'degraded'
      : sseConnected
        ? 'live'
        : 'polling'
  const runtime = executive?.runtime
  const coverage = !runtime
    ? null
    : runtime.measured
      ? { label: 'Runtime telemetry reporting', tone: 'good' as const }
      : runtime.agentsEnrolled
        ? { label: 'Collector enrolled · no events yet', tone: 'warning' as const }
        : { label: 'No runtime collector', tone: 'muted' as const }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center p-8">
        <div className="w-20 h-20 bg-red-500/10 border border-red-500/20 rounded-full flex items-center justify-center mb-6">
          <AlertTriangle className="w-10 h-10 text-red-500" />
        </div>
        <h2 className="text-2xl font-black text-white uppercase tracking-tighter mb-2">Command Center Disconnected</h2>
        <p className="text-white/40 max-w-md mb-8">Unable to establish a secure handshake with the backend telemetry services. Check your connection or session status.</p>
        <button
          onClick={refreshAll}
          className="px-8 py-3 bg-cyan-500/15 border border-cyan-400/40 text-cyan-200 text-xs font-black uppercase tracking-widest rounded-lg hover:bg-cyan-500/25 transition-all flex items-center gap-2"
        >
          <RefreshCw className="w-4 h-4" /> Reconnect Now
        </button>
      </div>
    )
  }

  const estate = estateWorkflow?.estate

  return (
    <div className="p-4 lg:p-7 space-y-6 animate-in fade-in duration-500">
      {/* Global header */}
      <header className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <div className="mb-1.5 flex items-center gap-3">
            <div className="rounded-lg border border-cyan-500/25 bg-cyan-500/10 p-2">
              <Shield className="h-5 w-5 text-cyan-300" />
            </div>
            <h1 className="text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
              Quantum Security <span className="text-cyan-300">Command Center</span>
            </h1>
          </div>
          <p className="text-[13px] font-medium text-white/45">Enterprise Post-Quantum Cryptographic Posture · Discover → Migrate → Govern</p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <span className="font-mono text-[10px] uppercase tracking-widest text-white/30">Synced {relativeTime(lastSyncAt)}</span>
          <div
            title={syncState === 'live' ? 'Receiving database changes in real time' : syncState === 'polling' ? 'Realtime channel not open — refreshing every 30s' : undefined}
            className={`flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-[10px] font-black uppercase tracking-widest transition-all ${
              syncState === 'live' ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-400'
                : syncState === 'degraded' ? 'border-amber-500/25 bg-amber-500/10 text-amber-400'
                : syncState === 'offline' ? 'border-red-500/25 bg-red-500/10 text-red-400'
                : 'border-cyan-500/25 bg-cyan-500/10 text-cyan-300'
            }`}
          >
            <Activity className={`h-3 w-3 ${syncState === 'live' ? 'animate-pulse' : ''}`} />
            {syncState === 'live' ? 'Live sync' : syncState === 'polling' ? 'Polling · 30s' : syncState}
          </div>
          {activity && (
            <div className="flex items-center gap-2 rounded-full border border-cyan-500/25 bg-cyan-500/10 px-3.5 py-1.5 text-[10px] font-black uppercase tracking-widest text-cyan-300">
              <Activity className="h-3 w-3 animate-pulse" /> {activity}
            </div>
          )}
          {coverage && (
            <a
              href="/dashboard/runtime-telemetry"
              className={`flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-[10px] font-black uppercase tracking-widest no-underline transition-colors ${
                coverage.tone === 'good' ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-400'
                  : coverage.tone === 'warning' ? 'border-amber-500/25 bg-amber-500/10 text-amber-400'
                  : 'border-white/10 bg-white/5 text-white/45 hover:text-white/70'
              }`}
            >
              <Radio className="h-3 w-3" /> {coverage.label}
            </a>
          )}
          <a
            href="/dashboard/quantum-readiness/reports"
            className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-[10px] font-black uppercase tracking-widest text-white/55 no-underline transition-all hover:border-cyan-400/30 hover:text-cyan-300"
            title="Export executive / technical / compliance / board report (PDF, Word, Excel, JSON)"
          >
            <FileDown className="h-4 w-4" /> Export Report
          </a>
          <button
            onClick={refreshAll}
            className="rounded-lg border border-white/10 bg-white/5 p-2 text-white/40 transition-all hover:border-cyan-400/30 hover:text-cyan-300"
            title="Refresh command center"
          >
            <RefreshCw className={`h-5 w-5 ${execLoading || summaryLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </header>

      {/* Executive AI Summary */}
      <ExecutiveSummary narrative={executive?.narrative} userName={firstName(user)} loading={execLoading} />

      {/* Enterprise KPI Cards */}
      <KpiGrid kpis={executive?.kpis} loading={execLoading} />

      {/* Shared Responsibility Overview — ownership-classified migration intelligence */}
      <div>
        <SectionLabel href="/dashboard/migration-intelligence">
          <Scale className="h-4 w-4 text-cyan-300" /> Shared Responsibility Migration Intelligence™
        </SectionLabel>
        <div className="mt-2"><SharedResponsibilityStrip /></div>
      </div>

      {/* Estate Exposure Workflow — the same renderer the Local and Dev scanner
          panels use, projecting the TENANT ESTATE: scan sessions, assets and
          their real relationships, the canonical CBOM, certificates, algorithms,
          the canonical open findings and the actions recorded against them. */}
      <div>
        <SectionLabel
          href="/dashboard/assets"
          meta={estate
            ? [
                `${estate.assessedAssets} of ${plural(estate.assets, 'asset')} assessed`,
                plural(estate.openFindings, 'open finding'),
                plural(estate.components, 'CBOM component'),
                plural(estate.certificates, 'certificate'),
                plural(estate.relationships, 'relationship'),
              ].join(' · ')
            : summary?.lastScanAt ? `Last scan ${relativeTime(summary.lastScanAt)}` : undefined}
        >
          <GitBranch className="h-4 w-4 text-cyan-300" /> Estate Exposure Workflow™
        </SectionLabel>
        <div className="mt-2">
          {workflowLoading ? (
            <div className="grid h-[520px] place-items-center rounded-2xl border border-white/[0.07] bg-[#080d1a]/80">
              <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-500">
                Building estate workflow…
              </p>
            </div>
          ) : workflowFailed ? (
            /* A failed read is NOT an empty estate. Saying "No estate evidence
               yet" here would tell a tenant with a full inventory that it has
               none. */
            <div className="grid h-[320px] place-items-center rounded-2xl border border-amber-400/25 bg-amber-400/[0.04] px-6 text-center">
              <div className="max-w-md space-y-2">
                <p className="text-sm font-bold text-amber-100">The estate workflow could not be built</p>
                <p className="text-[12.5px] leading-relaxed text-amber-100/70">
                  The server did not return the estate graph. Your inventory is unaffected — this view could not be drawn.
                  Retry, or open the Assets page for the same records.
                </p>
                <button
                  type="button"
                  onClick={refreshAll}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-amber-300/30 bg-amber-300/10 px-3 py-1.5 text-[11px] font-bold uppercase tracking-[0.14em] text-amber-100 transition-colors hover:border-amber-300/50"
                >
                  <RefreshCw className="h-3.5 w-3.5" /> Retry
                </button>
              </div>
            </div>
          ) : estateWorkflow && estate && estateWorkflow.nodes.length > 0 ? (
            <div className="space-y-2">
              {/* A degraded read is disclosed, never presented as the durable
                  estate. `persistence: 'memory'` means the database was
                  unreachable and the scanner's in-process results answered —
                  real scan output that will not survive a restart. */}
              {estate.persistence === 'memory' && (
                <div className="flex items-start gap-2.5 rounded-xl border border-amber-400/30 bg-amber-400/[0.07] px-3.5 py-2.5">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
                  <p className="text-[12px] leading-relaxed text-amber-100/85">
                    <span className="font-bold">Served from the local scan cache.</span> The database is unreachable, so
                    this estate is drawn from scan results held in the running server rather than your stored inventory.
                    The findings are real; they are not durable, and asset relationships — which live only in the
                    database — cannot be shown until it is reachable again.
                  </p>
                </div>
              )}
              <ExposureWorkflowGraph
                graph={estateWorkflow}
                findings={estateWorkflow.findingCorpus}
                lenses={ESTATE_LENSES}
                groupings={ESTATE_GROUPINGS}
                focusKind="asset"
                evidenceNote={
                  <>
                    Asset, finding, CBOM, certificate and scan-session nodes are records your tenant holds —{' '}
                    <strong className="font-bold">observed</strong>. Algorithm and remediation nodes are groupings this view
                    draws from those records — <strong className="font-bold">inferred</strong>, drawn dashed, and can be switched
                    off. An algorithm or remediation carries the severity of its <strong className="font-bold">own</strong> findings,
                    never that of the asset it sits on.
                  </>
                }
                inferredHint="Turn it off to see only the records the platform holds — no algorithm or remediation groupings."
                reconciliationNote={
                  <>
                    Plotted {estateWorkflow.reconciliation.findingsProjected.toLocaleString()} of{' '}
                    {plural(estate.openFindings, 'open finding')} (the Open Findings KPI) and{' '}
                    {estateWorkflow.reconciliation.componentsProjected.toLocaleString()} of {plural(estate.components, 'CBOM component')}{' '}
                    ({plural(estate.componentInstances, 'recorded instance')} — the Cryptographic Inventory KPI).
                    {estate.pqcConfirmations > 0 && ` ${plural(estate.pqcConfirmations, 'PQC-ready confirmation')} are carried by their CBOM components, not drawn as findings.`}
                    {estate.unlinkedFindings > 0 && ` ${plural(estate.unlinkedFindings, 'finding')} could not be linked to an inventoried asset.`}
                    {estate.rejectedAlgorithmLabels > 0 && ` ${plural(estate.rejectedAlgorithmLabels, 'recorded value')} named a finding rather than a primitive and produced no algorithm node.`}
                    {estate.nonActionRecommendations > 0 && ` ${plural(estate.nonActionRecommendations, 'recommendation')} read “no action required” and are not drawn as actions.`}
                  </>
                }
                provenance="Findings and components are the same canonical sets the KPI cards count; risk comes from the shared posture model the Assets and Quantum Readiness pages read."
              />
            </div>
          ) : (
            /* Empty state, not a fabricated graph. An estate with no scanned
               assets has no workflow to draw, and drawing one anyway would be
               the fabrication this module exists to avoid. */
            <div className="grid h-[520px] place-items-center rounded-2xl border border-white/[0.07] bg-[#080d1a]/80 px-6 text-center">
              <div className="max-w-md space-y-2">
                <p className="text-sm font-bold text-slate-200">No estate evidence yet</p>
                <p className="text-[12.5px] leading-relaxed text-slate-400">
                  The workflow is drawn from your own assets, scans, CBOM records and certificates. Run a PQC discovery
                  scan or connect an integration and every asset, relationship and finding it produces appears here.
                </p>
                <a
                  href="/dashboard/scanner"
                  className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-3 py-1.5 text-[11px] font-bold uppercase tracking-[0.14em] text-cyan-200 transition-colors hover:border-cyan-400/50"
                >
                  Run a discovery scan <ChevronRight className="h-3.5 w-3.5" />
                </a>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* AI Recommendations + Threat Timeline */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div>
          <SectionLabel href="/dashboard/quantum-risk-scoring"><Sparkles className="h-4 w-4 text-violet-300" /> AI Recommendations</SectionLabel>
          <div className="mt-2 h-[460px]">
            <AiRecommendations recommendations={recommendations} total={recommendationsTotal} loading={recsLoading} />
          </div>
        </div>
        <div>
          <SectionLabel href="/dashboard/audit-vault"><History className="h-4 w-4 text-cyan-300" /> Threat Timeline</SectionLabel>
          <div className="mt-2 h-[460px]">
            <ThreatTimeline events={events} loading={eventsLoading} live={sseConnected} pqcConfirmationsOmitted={eventsOmitted} />
          </div>
        </div>
      </div>

      {/* Migration Pipeline + Compliance */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div>
          <SectionLabel href="/dashboard/migration-planner"><GitBranch className="h-4 w-4 text-cyan-300" /> Migration Pipeline</SectionLabel>
          <div className="mt-2"><MigrationPipeline pipeline={executive?.pipeline} loading={execLoading} /></div>
        </div>
        <div>
          <SectionLabel href="/dashboard/compliance"><ScrollText className="h-4 w-4 text-cyan-300" /> Compliance</SectionLabel>
          <div className="mt-2"><ComplianceStrip compliance={executive?.compliance} loading={execLoading} /></div>
        </div>
      </div>

      {/* Business Impact + Asset Inventory */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div>
          {/* Revenue Intelligence is owner-only; for everyone else the link would bounce straight back here. */}
          <SectionLabel href={isOwnerEmail(user?.email) ? '/dashboard/revenue-intelligence' : undefined}><Briefcase className="h-4 w-4 text-cyan-300" /> Business Impact</SectionLabel>
          <div className="mt-2"><BusinessImpact data={executive?.businessImpact} loading={execLoading} /></div>
        </div>
        <div>
          <SectionLabel href="/dashboard/assets"><Boxes className="h-4 w-4 text-cyan-300" /> Asset Inventory</SectionLabel>
          <div className="mt-2"><AssetInventory inventory={executive?.assetInventory} loading={execLoading} /></div>
        </div>
      </div>

      {/* Live Runtime Telemetry */}
      <div>
        <SectionLabel href="/dashboard/runtime-telemetry"><Activity className="h-4 w-4 text-cyan-300" /> Live Runtime Telemetry</SectionLabel>
        <div className="mt-2"><RuntimeTelemetry runtime={executive?.runtime} sseConnected={sseConnected} loading={execLoading} /></div>
      </div>

      {/* Threat Intelligence + Security Events */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div>
          <SectionLabel href="/dashboard/quantum-readiness/risk-analysis"><Radar className="h-4 w-4 text-cyan-300" /> Threat Intelligence</SectionLabel>
          <div className="mt-2"><ThreatIntel intel={executive?.threatIntel} loading={execLoading} runtimeMeasured={executive?.runtime?.measured} /></div>
        </div>
        <div>
          <SectionLabel href="/dashboard/audit-vault"><Bell className="h-4 w-4 text-cyan-300" /> Security Events</SectionLabel>
          <div className="mt-2 h-[440px]">
            <SecurityEventsPanel events={events} loading={eventsLoading} live={sseConnected} />
          </div>
        </div>
      </div>

      {/* Footer — statements about THIS page's data only. Compliance or
          encryption claims about the platform ("FIPS 140-3 aligned",
          "end-to-end PQC encrypted") are not evidenced here and are not made. */}
      <footer className="flex flex-col items-center justify-between gap-4 border-t border-white/5 pt-6 md:flex-row">
        <div className="flex items-center gap-2 opacity-30">
          <img src="/NEW_LOGO.png" alt="Logo" className="h-5 w-5 grayscale" />
          <span className="text-[10px] font-black uppercase tracking-widest text-white">QGuard Helix</span>
        </div>
        <div className="flex flex-wrap justify-center gap-x-6 gap-y-1 text-[9px] font-bold uppercase tracking-widest text-white/25">
          <span>Every figure derives from your own scans and records</span>
          <span>Tenant-isolated reads</span>
          <span>{executive?.lastAssessmentAt ? `Last assessment ${relativeTime(executive.lastAssessmentAt)}` : 'No assessment yet'}</span>
        </div>
      </footer>
    </div>
  )
}
