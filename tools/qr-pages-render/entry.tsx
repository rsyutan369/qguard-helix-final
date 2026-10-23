import { readFileSync } from 'node:fs'
import type { ComponentType } from 'react'
import { renderToString } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import Overview from '@/app/dashboard/quantum-readiness/page'
import ExposureGraph from '@/app/dashboard/quantum-readiness/exposure-graph/page'
import RiskAnalysis from '@/app/dashboard/quantum-readiness/risk-analysis/page'
import Remediation from '@/app/dashboard/quantum-readiness/remediation/page'
import ExecutiveAdvisor from '@/app/dashboard/quantum-readiness/ai-executive-advisor/page'
import MigrationAdvisor from '@/app/dashboard/quantum-readiness/ai-migration-advisor/page'
import HarvestNow from '@/app/dashboard/harvest-now/HarvestNow'
import Certification from '@/app/dashboard/quantum-certification/page'
import Reports from '@/app/dashboard/quantum-readiness/reports/page'

const PAGES: Array<{ path: string; Page: ComponentType; expect: string[] }> = [
  { path: '/dashboard/quantum-readiness', Page: Overview, expect: ['Quantum Readiness Assessment Engine', 'What Drives the Readiness Score', 'Not measured', '7 of 29 components'] },
  { path: '/dashboard/quantum-readiness/exposure-graph', Page: ExposureGraph, expect: ['Quantum Exposure Graph', 'Quantum Vulnerable'] },
  { path: '/dashboard/quantum-readiness/risk-analysis', Page: RiskAnalysis, expect: ['Quantum Risk Analysis', 'Quantum Readiness', 'Quantum Risk', 'Risk Heat Map'] },
  { path: '/dashboard/quantum-readiness/remediation', Page: Remediation, expect: ['Certification Readiness Score', 'Asset-Level Remediation Queue'] },
  { path: '/dashboard/quantum-readiness/ai-executive-advisor', Page: ExecutiveAdvisor, expect: ['AI Executive Advisor', 'Advisory Audit Trail'] },
  { path: '/dashboard/quantum-readiness/ai-migration-advisor', Page: MigrationAdvisor, expect: ['AI Migration Advisor', 'Hybrid In-Progress', '1 not yet assessed'] },
  { path: '/dashboard/harvest-now', Page: HarvestNow, expect: ['Harvest Now, Decrypt Later', 'CRQC Planning Horizon', 'Threat Actor Relevance', 'planning estimate'] },
  { path: '/dashboard/quantum-certification', Page: Certification, expect: ['Quantum Trust Certification', 'Attested Readiness'] },
  { path: '/dashboard/quantum-readiness/reports', Page: Reports, expect: ['Report Center', 'Report History', 'not available in this deployment'] },
]

// Strings that must never render: the defects this audit removed.
const FORBIDDEN = ['Next Escalation Cycle', 'schedule saved for this template', 'Live telemetry, metrics stream', 'Latest AI Recommendation']

;(globalThis as any).__LIVE_FIXTURES__ = JSON.parse(readFileSync(process.argv[2], 'utf8'))

let failures = 0
const consoleErrors: string[] = []
const originalError = console.error
console.error = (...args: unknown[]) => { consoleErrors.push(args.map(String).join(' ')); }

for (const mode of ['populated', 'empty', 'loading'] as const) {
  ;(globalThis as any).__LIVE_MODE__ = mode
  for (const { path, Page, expect } of PAGES) {
    consoleErrors.length = 0
    let html = ''
    let crash = ''
    try {
      html = renderToString(<MemoryRouter initialEntries={[path]}><Page /></MemoryRouter>)
    } catch (error) {
      crash = error instanceof Error ? `${error.message}\n${error.stack?.split('\n').slice(1, 4).join('\n')}` : String(error)
    }
    const text = html.replace(/<[^>]+>/g, ' ').replace(/&#x27;|&#39;/g, "'").replace(/&amp;/g, '&').replace(/\s+/g, ' ')
    const missing = mode === 'populated' ? expect.filter((e) => !text.includes(e)) : []
    const forbidden = FORBIDDEN.filter((f) => text.includes(f))
    const ok = !crash && !missing.length && !forbidden.length && consoleErrors.length === 0
    if (!ok) failures += 1
    process.stdout.write(`  ${ok ? 'PASS' : 'FAIL'}  [${mode}] ${path}  (${html.length} bytes)\n`)
    if (crash) process.stdout.write(`        crash: ${crash}\n`)
    if (missing.length) process.stdout.write(`        missing text: ${missing.join(' | ')}\n`)
    if (forbidden.length) process.stdout.write(`        forbidden text rendered: ${forbidden.join(' | ')}\n`)
    for (const e of consoleErrors.slice(0, 3)) process.stdout.write(`        console.error: ${e.slice(0, 300)}\n`)
  }
}
process.stdout.write(`\n${PAGES.length * 3} renders — ${failures} failed\n`)
process.exit(failures ? 1 : 0)
