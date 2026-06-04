'use client'

import { useState } from 'react'
import { 
  Shield, AlertTriangle, Zap, Search, Activity, 
  RefreshCw, Radio, Database, ShieldCheck, Globe, Bell, Eye
} from 'lucide-react'
import { useDashboard, type ExposureNode } from '@/hooks/use-dashboard'
import MetricCard from './metric_card/MetricCard'
import QuantumExposureMap, { NodeInspector } from './crypto_exposure_map/QuantumExposureMap'
import SecurityEventsPanel from './security_events_panel/SecurityEventsPanel'
import RecommendationsPanel from './recommendation_panel/RecommendationsPanel'
import TelemetryFeatures from './TelemetryFeatures'

const GLASS_PANEL_CLASSES = 'qg-executive-panel group relative overflow-hidden rounded-lg text-white';

export default function Dashboard() {
  const [selectedNode, setSelectedNode] = useState<ExposureNode | null>(null)
  const {
    summary,
    events,
    exposureMap,
    activities,
    recommendations,
    health,
    summaryState,
    eventsState,
    mapState,
    recommendationsState,
    lastSyncAt,
    sseConnected,
    refreshAll,
  } = useDashboard()

  const loading = summaryState === 'loading' && !summary
  const mapLoading = mapState === 'loading' && exposureMap.nodes.length === 0
  const eventsLoading = eventsState === 'loading' && events.length === 0
  const telemetryLoading = loading || eventsLoading || mapLoading
  const error = summaryState === 'error' && !summary ? 'Connection failure' : null

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

  const riskTrendText = summary?.riskTrend
    ? `${Math.abs(summary.riskTrend)} finding${Math.abs(summary.riskTrend) === 1 ? '' : 's'} ${summary.riskTrend > 0 ? 'reduced' : 'added'} since previous scan`
    : summary?.riskBand || 'Awaiting scan baseline'

  if (error && !summary) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center p-8">
        <div className="w-20 h-20 bg-red-500/10 border border-red-500/20 rounded-full flex items-center justify-center mb-6">
          <AlertTriangle className="w-10 h-10 text-red-500" />
        </div>
        <h2 className="text-2xl font-black text-white uppercase tracking-tighter mb-2">Security Nexus Disconnected</h2>
        <p className="text-white/40 max-w-md mb-8">Unable to establish a secure handshake with the backend telemetry services. Please check your connection or session status.</p>
        <button 
          onClick={refreshAll}
          className="px-8 py-3 bg-gold border border-gold text-black text-xs font-black uppercase tracking-widest rounded-lg hover:bg-gold/90 transition-all flex items-center gap-2"
        >
          <RefreshCw className="w-4 h-4" /> Reconnect Now
        </button>
      </div>
    )
  }

  const riskScoreColor = summary?.riskBand === 'Quantum Ready' ? 'text-green-500' : 
                         summary?.riskBand === 'Low Risk' ? 'text-gold' : 
                         summary?.riskBand === 'High Risk' ? 'text-orange-500' : 'text-red-500'

  return (
    <div className="p-4 lg:p-8 space-y-8 animate-in fade-in duration-700">
      {/* Header */}
      <header className="flex flex-col md:flex-row md:items-end justify-between gap-6">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 rounded bg-gold/10 border border-gold/20">
                <Shield className="w-6 h-6 text-gold" />
            </div>
            <h1 className="text-3xl font-black uppercase tracking-tight text-white leading-none">
              Quantum Risk <span className="text-gold">Intelligence</span>
            </h1>
          </div>
          <p className="text-white/50 text-sm font-medium">Enterprise Command Center • Post-Quantum Cryptographic Posture</p>
        </div>
        
        <div className="flex flex-wrap items-center gap-4">
          <div className={`px-4 py-2 border rounded-full text-[10px] font-black uppercase tracking-widest flex items-center gap-2 transition-all duration-500 ${
            monitoringStatus === 'active' ? 'bg-green-500/10 border-green-500/20 text-green-500' :
            monitoringStatus === 'degraded' ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-500' :
            monitoringStatus === 'offline' ? 'bg-red-500/10 border-red-500/20 text-red-500' :
            'bg-gold/10 border-gold/20 text-gold'
          }`}>
            <Activity className={`h-3 w-3 ${monitoringStatus === 'active' || monitoringStatus === 'scanning' ? 'animate-pulse' : ''}`} />
            Live Monitoring {monitoringStatus}
          </div>
          
          <button 
            onClick={refreshAll}
            className="p-2 bg-white/5 border border-white/10 rounded-lg text-white/40 hover:text-gold hover:border-gold/30 transition-all"
            title="Refresh Dashboard"
          >
            <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </header>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard 
          label="Quantum Risk Score"
          value={summary?.quantumRiskScore || 0}
          icon={ShieldCheck}
          color={riskScoreColor}
          trend={riskTrendText}
          loading={loading && !summary}
          delay={0.1}
          href="/dashboard/quantum-risk-scoring"
        />
        <MetricCard 
          label="Vulnerable Assets"
          value={summary?.vulnerableAssetsCount || 0}
          icon={AlertTriangle}
          color="text-red-500"
          trend={`${summary?.newVulnerableAssets || 0} discovered since last scan`}
          loading={loading && !summary}
          delay={0.2}
          href="/dashboard/vulnerabilities"
        />
        <MetricCard 
          label="Total CBOM Items"
          value={summary?.totalCbomItems || 0}
          icon={Search}
          color="text-blue-400"
          trend={`${summary?.totalAssets || 0} assets in authenticated scope`}
          loading={loading && !summary}
          delay={0.3}
          href="/dashboard/cbom"
        />
        <MetricCard 
          label="Active Migrations"
          value={summary?.activeMigrations || 0}
          icon={Zap}
          color="text-gold"
          trend={`${summary?.completedMigrations || 0} completed, ${summary?.failedMigrations || 0} need attention`}
          loading={loading && !summary}
          delay={0.4}
          href="/dashboard/live-migration"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-x-8 gap-y-4">
        {/* Row 1 Headers */}
        <div className="lg:col-span-2">
          <div className="flex justify-between items-center px-1">
            <a href="/dashboard/crypto-exposure" className="text-sm font-black uppercase tracking-[0.2em] text-white/80 flex items-center gap-2 no-underline hover:text-gold transition-colors">
              <Globe className="h-4 w-4 text-gold" />
              Quantum Exposure Map
            </a>
            {summary?.lastScanAt && (
              <div className="text-[10px] font-mono text-white/30 uppercase">
                Last Global Scan: {new Date(summary.lastScanAt).toLocaleString()}
              </div>
            )}
          </div>
        </div>
        <div className="lg:col-span-1">
          <div className="flex justify-between items-center px-1">
            <a href={selectedNode?.id ? `/dashboard/assets?asset=${encodeURIComponent(selectedNode.id)}` : '/dashboard/assets'} className="text-sm font-black uppercase tracking-[0.2em] text-white/80 flex items-center gap-2 no-underline hover:text-gold transition-colors">
              <Eye className="h-4 w-4 text-gold" />
              Node Inspector
            </a>
            <div className="text-[10px] font-mono text-white/30 uppercase">
              Telemetry Analysis
            </div>
          </div>
        </div>

        {/* Row 1 Cards */}
        <div className="lg:col-span-2">
          <QuantumExposureMap
            data={exposureMap}
            loading={mapLoading}
            onRefresh={refreshAll}
            selectedNode={selectedNode}
            onSelectNode={setSelectedNode}
          />
        </div>
        <div className="lg:col-span-1">
          <div className="h-[500px]">
            <NodeInspector selectedNode={selectedNode} />
          </div>
        </div>

        {/* Row 2 Headers (Empty header space for left columns to align with Security Events, keeping the grid balanced) */}
        <div className="lg:col-span-2">
          <div className="h-6" /> {/* Symmetrical vertical spacing */}
        </div>
        <div className="lg:col-span-1">
          <div className="h-6" /> {/* Symmetrical vertical spacing */}
        </div>

        {/* Row 2 Cards */}
        <div className="lg:col-span-2">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 h-full">
            <RecommendationsPanel recommendations={recommendations} loading={recommendationsState === 'loading' && recommendations.length === 0} />

            {/* Quick Actions / Status */}
            <div className={`p-6 ${GLASS_PANEL_CLASSES} h-full`}>
              <div className="absolute -right-4 -bottom-4 opacity-5">
                <Shield className="w-32 h-32 text-gold" />
              </div>
              <h2 className="text-sm font-black uppercase tracking-[0.2em] text-white/80 mb-4">System Integrity</h2>
              <div className="space-y-4 relative z-10">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-white/40 uppercase">Database</span>
                  <span className="text-[10px] font-black text-green-500 uppercase flex items-center gap-1.5">
                    <div className={`w-1.5 h-1.5 rounded-full ${health?.services?.supabase === 'healthy' ? 'bg-green-500' : 'bg-yellow-500'}`} /> {health?.services?.supabase || 'unknown'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-white/40 uppercase">Scanner</span>
                  <span className="text-[10px] font-black text-green-500 uppercase flex items-center gap-1.5">
                    <div className={`w-1.5 h-1.5 rounded-full ${health?.services?.scanner === 'scanning' ? 'bg-gold animate-pulse' : 'bg-green-500'}`} /> {health?.services?.scanner || 'unknown'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-white/40 uppercase">Migration</span>
                  <span className="text-[10px] font-black text-gold uppercase flex items-center gap-1.5">
                    {health?.services?.migration || 'unknown'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-white/40 uppercase">Realtime Stream</span>
                  <span className="text-[10px] font-black text-gold uppercase flex items-center gap-1.5">
                    {sseConnected ? 'SSE Connected' : health?.services?.realtime || 'syncing'}
                  </span>
                </div>
                <div className="pt-4 mt-4 border-t border-white/5">
                  <div className="grid grid-cols-2 gap-2">
                    <a href="/dashboard/compliance" className="inline-flex items-center justify-center gap-1.5 rounded border border-white/10 bg-white/5 px-2 py-2 text-[9px] font-black uppercase tracking-widest text-white/60 no-underline transition-colors hover:border-gold/35 hover:bg-gold/10 hover:text-gold">
                      <ShieldCheck className="h-3 w-3" /> Compliance
                    </a>
                    <a href="/dashboard/scanner" className="inline-flex items-center justify-center gap-1.5 rounded border border-white/10 bg-white/5 px-2 py-2 text-[9px] font-black uppercase tracking-widest text-white/60 no-underline transition-colors hover:border-gold/35 hover:bg-gold/10 hover:text-gold">
                      <Radio className="h-3 w-3" /> Scanner
                    </a>
                    <a href="/dashboard/runtime-telemetry" className="inline-flex items-center justify-center gap-1.5 rounded border border-white/10 bg-white/5 px-2 py-2 text-[9px] font-black uppercase tracking-widest text-white/60 no-underline transition-colors hover:border-gold/35 hover:bg-gold/10 hover:text-gold">
                      <Bell className="h-3 w-3" /> Telemetry
                    </a>
                    <a href="/dashboard/audit-vault" className="inline-flex items-center justify-center gap-1.5 rounded border border-white/10 bg-white/5 px-2 py-2 text-[9px] font-black uppercase tracking-widest text-white/60 no-underline transition-colors hover:border-gold/35 hover:bg-gold/10 hover:text-gold">
                      <Database className="h-3 w-3" /> Audit
                    </a>
                  </div>
                  <div className="mt-2 text-center text-[9px] font-mono text-white/25">
                    Last sync: {lastSyncAt ? new Date(lastSyncAt).toLocaleTimeString() : 'waiting for telemetry'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-1">
          {/* Security Events is exactly aligned height-wise and top-wise */}
          <div className="h-full min-h-[380px]">
            <SecurityEventsPanel events={events} loading={eventsLoading} />
          </div>
        </div>
      </div>
      
      {/* New Telemetry Features */}
      <section className="mt-8 animate-in fade-in duration-700 delay-500">
        <TelemetryFeatures
          summary={summary}
          events={events}
          exposureMap={exposureMap}
          activities={activities}
          recommendations={recommendations}
          health={health}
          lastSyncAt={lastSyncAt}
          sseConnected={sseConnected}
          loading={telemetryLoading}
        />
      </section>

      {/* Footer Branding */}
      <footer className="pt-8 border-t border-white/5 flex flex-col md:flex-row justify-between items-center gap-4">
        <div className="flex items-center gap-2 opacity-30">
            <img src="/NEW_LOGO.png" alt="Logo" className="w-5 h-5 grayscale" />
            <span className="text-[10px] font-black uppercase tracking-widest text-white">QGuard Helix Protocol v2.4</span>
        </div>
        <div className="flex gap-6 text-[9px] font-bold text-white/20 uppercase tracking-widest">
            <span>End-to-End PQC Encrypted</span>
            <span>GDPR / NIST / FIPS 140-3 Compliant</span>
        </div>
      </footer>
    </div>
  )
}
