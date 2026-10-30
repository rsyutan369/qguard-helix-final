import TelemetryCorrelation from '@/app/dashboard/telemetry-correlation/TelemetryCorrelation'
import { buildCorrelationIntelligence } from '@/lib/telemetry/correlation-intelligence'
import { renderCases } from '../harness'
import { base } from '../fixtures/correlation'

const populated = buildCorrelationIntelligence(base)
const nothing = buildCorrelationIntelligence({ ...base, scannerEvidence: [], runtimeEvents: [], cryptoInventory: [], scannerAgents: [], connectorAccounts: [], scanSessions: [] })
const unreadable = {
  ...populated,
  reads: [
    { key: 'scanner_evidence', label: 'Scanner evidence', state: 'unavailable' as const, rows: 0, limit: 3000, detail: 'The query failed.' },
    { key: 'runtime_crypto_events', label: 'Runtime telemetry', state: 'ok' as const, rows: 4, limit: 3000, detail: '4 row(s) read.' },
  ],
}

renderCases({
  page: 'Telemetry Correlation',
  path: '/dashboard/telemetry-correlation',
  Page: TelemetryCorrelation,
  forbidAlways: ['NaN', 'undefined', '[object Object]'],
  cases: [
    { name: 'loading', live: { correlation: { payload: null, state: 'loading', transport: 'connecting' } }, expect: ['Connecting'] },
    { name: 'hard-error', live: { correlation: { payload: null, state: 'error', transport: 'polling', error: 'HTTP 500' } }, expect: ['Telemetry Correlation Unavailable'] },
    { name: 'no-telemetry', live: { correlation: { payload: nothing } }, expect: ['No Telemetry Source Reporting'] },
    { name: 'populated-live', live: { correlation: { payload: populated } }, expect: ['Live', 'What you are looking at', 'Recommended next step'], forbid: ['Live stream interrupted'] },
    { name: 'polling', live: { correlation: { payload: populated, transport: 'polling' } }, expect: ['Polling', 'Live stream interrupted'] },
    { name: 'source-unreadable', live: { correlation: { payload: unreadable } }, expect: ['Evidence sources', 'could not be read', 'Refresh'] },
  ],
})
