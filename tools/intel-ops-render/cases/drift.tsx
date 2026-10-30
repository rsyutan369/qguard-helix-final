import DriftDetection from '@/app/dashboard/drift_detection/DriftDetection'
import { buildDriftIntelligence } from '@/lib/drift/drift-intelligence'
import { renderCases } from '../harness'
import { base } from '../fixtures/drift'

const populated = buildDriftIntelligence(base)
const noBaseline = buildDriftIntelligence({ ...base, scanSessions: [], scanResults: [] })
const unreadable = {
  ...populated,
  reads: [
    { key: 'pqc_scan_results', label: 'Scan findings', state: 'unavailable' as const, rows: 0, limit: 4000, detail: 'The query failed.' },
    { key: 'migration_jobs', label: 'Migration jobs', state: 'ok' as const, rows: 1, limit: 400, detail: '1 row(s) read.' },
  ],
}

renderCases({
  page: 'Cryptographic Drift Detection',
  path: '/dashboard/drift',
  Page: DriftDetection,
  forbidAlways: ['NaN', 'undefined', '[object Object]'],
  cases: [
    { name: 'loading', live: { drift: { payload: null, state: 'loading', transport: 'connecting' } }, expect: ['Connecting'] },
    { name: 'no-baseline', live: { drift: { payload: noBaseline } }, expect: ['Drift Detection', 'No Baseline to Compare Against'] },
    { name: 'hard-error', live: { drift: { payload: null, state: 'error', transport: 'polling', error: 'HTTP 500' } }, expect: ['Drift Assessment Unavailable'] },
    { name: 'populated-live', live: { drift: { payload: populated } }, expect: ['Live', 'What you are looking at', 'Recommended next step'], forbid: ['Live stream interrupted'] },
    { name: 'offline', live: { drift: { payload: populated, transport: 'offline' } }, expect: ['Offline', 'Connection lost'] },
    { name: 'findings-unreadable', live: { drift: { payload: unreadable } }, expect: ['Scan findings', 'could not be read', 'Refresh'] },
  ],
})
