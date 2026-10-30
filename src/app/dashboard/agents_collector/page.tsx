'use client'

import AgentCollectorConsole from '@/components/agent-collector/AgentCollectorConsole'
import { QuantumField } from '@/components/quantum-scan/ui'

/**
 * Agents Collector — Discovery › PQC Scanner › Agents Collector.
 *
 * Deploying, binding and operating agent collectors, moved out of the PQC
 * Scanner's former Agents tab onto a page of its own. The plan gate is the
 * dashboard layout's (BASIC, see subscription-access.ts); the console owns the
 * page's single agent-scanner data connection and SSE stream.
 */
export default function AgentsCollectorPage() {
  return (
    <div className="relative min-h-full text-slate-200 antialiased">
      <QuantumField scoped />
      <div className="relative z-10 mx-auto max-w-[92rem] overflow-x-clip px-3 pb-16 pt-4 sm:px-5 sm:pt-6">
        <AgentCollectorConsole />
      </div>
    </div>
  )
}
