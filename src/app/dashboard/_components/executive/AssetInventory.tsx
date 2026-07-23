'use client'

import { motion, useReducedMotion } from 'framer-motion'
import {
  Boxes, Server, AppWindow, Container, ShieldCheck, Cloud, Users, Database,
  KeyRound, Network, Layers, Cpu, Radio, Fingerprint, type LucideIcon,
} from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, cx, fmtNumber } from './primitives'

const ICONS: Record<string, LucideIcon> = {
  servers: Server, applications: AppWindow, containers: Container, certificates: ShieldCheck,
  cloud_accounts: Cloud, users: Users, databases: Database, secrets: KeyRound,
  clusters: Layers, kubernetes: Network, virtual_machines: Cpu, iot: Radio,
  identity_providers: Fingerprint, network_devices: Network,
}

export default function AssetInventory({ inventory, loading }: { inventory: ExecutiveSnapshot['assetInventory'] | undefined; loading: boolean }) {
  const reduce = useReducedMotion()
  if (loading && !inventory) {
    return <Panel><PanelHeader title="Asset Inventory" icon={Boxes} /><div className="h-56 animate-pulse rounded-lg bg-white/[0.03]" /></Panel>
  }
  const categories = inventory?.categories || []
  const populated = categories.filter((c) => c.count > 0)
  const shown = populated.length ? populated : categories.slice(0, 8)
  return (
    <Panel>
      <PanelHeader
        title="Asset Inventory" icon={Boxes} href="/dashboard/assets"
        right={<span className="text-[9px] font-black uppercase tracking-widest text-cyan-300">{fmtNumber(inventory?.total || 0)} total</span>}
      />
      {populated.length === 0 ? (
        <div className="flex h-40 flex-col items-center justify-center text-center">
          <Boxes className="mb-3 h-8 w-8 text-white/20" />
          <p className="text-xs font-bold text-white/45">No assets discovered</p>
          <p className="mt-1 text-[10px] text-white/25">Run a discovery scan or connect an integration to build inventory.</p>
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
          {shown.map((c, i) => {
            const Icon = ICONS[c.key] || Boxes
            return (
              <motion.a
                key={c.key}
                href="/dashboard/assets"
                initial={reduce ? false : { opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.03 }}
                className="group/cat flex items-center gap-2.5 rounded-lg border border-white/5 bg-white/[0.02] p-2.5 no-underline transition-colors hover:border-cyan-400/30"
              >
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                  <Icon className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[9px] font-bold uppercase tracking-wide text-white/45">{c.label}</div>
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-base font-black text-white">{fmtNumber(c.count)}</span>
                    {c.atRisk > 0 && <span className="text-[9px] font-black text-red-400">{fmtNumber(c.atRisk)} at risk</span>}
                  </div>
                </div>
              </motion.a>
            )
          })}
        </div>
      )}
    </Panel>
  )
}
