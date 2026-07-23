'use client'

import { useState } from 'react'
import {
  Shield, AlertTriangle, Activity, RefreshCw, Globe, Eye, GitBranch,
  ScrollText, Briefcase, Boxes, Radar, Bell, History, Sparkles, FileDown, Scale,
} from 'lucide-react'
import { useDashboard, type ExposureNode } from '@/hooks/use-dashboard'
import { useAuth } from '@/contexts/auth-context'
import QuantumExposureMap, { NodeInspector } from './crypto_exposure_map/QuantumExposureMap'
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

export default function Dashboard() {
  const [selectedNode, setSelectedNode] = useState<ExposureNode | null>(null)
  const { user } = useAuth()
  const {
    summary, executive, events, exposureMap, recommendations, health,
    summaryState, executiveState, eventsState, mapState, recommendationsState,
    lastSyncAt, sseConnected, refreshAll,
  } = useDashboard()

  const execLoading = executiveState === 'loading' && !executive
  const mapLoading = mapState === 'loading' && exposureMap.nodes.length === 0
  const eventsLoading = eventsState === 'loading' && events.length === 0
  const recsLoading = recommendationsState === 'loading' && recommendations.length === 0
  const summaryLoading = summaryState === 'loading' && !summary
  const error = summaryState === 'error' && !summary && executiveState === 'error' && !executive

  const monitoringStatus = health?.services?.migration === 'migrating'
    ? 'migrating'
    : health?.services?.scanner === 'scanning'
      ? 'scanning'
      : summaryState === 'offline'
        ? 'offline'
        : health?.status === 'degraded'
          ? 'degraded'
          : sseConnected
            ? 'active'
            : summary?.monitoringStatus || 'active'

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

        <div className="flex flex-wrap items-center gap-3">
          <span className="font-mono text-[10px] uppercase tracking-widest text-white/30">Synced {relativeTime(lastSyncAt)}</span>
          <div className={`flex items-center gap-2 rounded-full border px-4 py-1.5 text-[10px] font-black uppercase tracking-widest transition-all ${
            monitoringStatus === 'active' ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-400'
              : monitoringStatus === 'scanning' || monitoringStatus === 'migrating' ? 'border-cyan-500/25 bg-cyan-500/10 text-cyan-300'
              : monitoringStatus === 'degraded' ? 'border-amber-500/25 bg-amber-500/10 text-amber-400'
              : monitoringStatus === 'offline' ? 'border-red-500/25 bg-red-500/10 text-red-400'
              : 'border-cyan-500/25 bg-cyan-500/10 text-cyan-300'
          }`}>
            <Activity className={`h-3 w-3 ${monitoringStatus === 'active' || monitoringStatus === 'scanning' ? 'animate-pulse' : ''}`} />
            {monitoringStatus === 'active' ? 'Live monitoring' : monitoringStatus}
          </div>
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

      {/* Enterprise Quantum Exposure Graph + Node Inspector */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <SectionLabel href="/dashboard/quantum-readiness/exposure-graph" meta={summary?.lastScanAt ? `Last scan ${relativeTime(summary.lastScanAt)}` : undefined}>
            <Globe className="h-4 w-4 text-cyan-300" /> Enterprise Quantum Exposure Graph™
          </SectionLabel>
          <div className="mt-2">
            <QuantumExposureMap
              data={exposureMap}
              loading={mapLoading}
              onRefresh={refreshAll}
              selectedNode={selectedNode}
              onSelectNode={setSelectedNode}
            />
          </div>
        </div>
        <div className="lg:col-span-1">
          <SectionLabel href={selectedNode?.id ? `/dashboard/assets?asset=${encodeURIComponent(selectedNode.id)}` : '/dashboard/assets'} meta="Telemetry analysis">
            <Eye className="h-4 w-4 text-cyan-300" /> Node Inspector
          </SectionLabel>
          <div className="mt-2 h-[520px]">
            <NodeInspector selectedNode={selectedNode} exposureMap={exposureMap} />
          </div>
        </div>
      </div>

      {/* AI Recommendations + Threat Timeline */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div>
          <SectionLabel href="/dashboard/quantum-risk-scoring"><Sparkles className="h-4 w-4 text-violet-300" /> AI Recommendations</SectionLabel>
          <div className="mt-2 h-[460px]">
            <AiRecommendations recommendations={recommendations} loading={recsLoading} />
          </div>
        </div>
        <div>
          <SectionLabel href="/dashboard/audit-vault"><History className="h-4 w-4 text-cyan-300" /> Threat Timeline</SectionLabel>
          <div className="mt-2 h-[460px]">
            <ThreatTimeline events={events} loading={eventsLoading} />
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
          <SectionLabel href="/dashboard/revenue-intelligence"><Briefcase className="h-4 w-4 text-cyan-300" /> Business Impact</SectionLabel>
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
          <SectionLabel href="/dashboard/vulnerabilities"><Radar className="h-4 w-4 text-cyan-300" /> Threat Intelligence</SectionLabel>
          <div className="mt-2"><ThreatIntel intel={executive?.threatIntel} loading={execLoading} /></div>
        </div>
        <div>
          <SectionLabel href="/dashboard/audit-vault"><Bell className="h-4 w-4 text-cyan-300" /> Security Events</SectionLabel>
          <div className="mt-2 h-[440px]">
            <SecurityEventsPanel events={events} loading={eventsLoading} />
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="flex flex-col items-center justify-between gap-4 border-t border-white/5 pt-6 md:flex-row">
        <div className="flex items-center gap-2 opacity-30">
          <img src="/NEW_LOGO.png" alt="Logo" className="h-5 w-5 grayscale" />
          <span className="text-[10px] font-black uppercase tracking-widest text-white">QGuard Helix Protocol v2.4</span>
        </div>
        <div className="flex gap-6 text-[9px] font-bold uppercase tracking-widest text-white/20">
          <span>End-to-End PQC Encrypted</span>
          <span>GDPR / NIST / FIPS 140-3 Aligned</span>
          <span>Tenant-Isolated</span>
        </div>
      </footer>
    </div>
  )
}
