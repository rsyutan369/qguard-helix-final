import RuntimeCryptoIntel from '@/app/dashboard/runtime-crypto-intel/RuntimeCryptoIntel'
import { buildRuntimeCryptoIntelligence } from '@/lib/runtime-crypto/runtime-intelligence'
import { renderCases } from '../harness'
import { inputs } from '../fixtures/runtime'

const populated = buildRuntimeCryptoIntelligence({ ...inputs, window: '30d' })
const noCollector = buildRuntimeCryptoIntelligence({ ...inputs, runtimeEvents: [], scannerAgents: [], connectorAccounts: [] })
const withReads = {
  ...populated,
  reads: [
    { key: 'runtime_crypto_events', label: 'Runtime telemetry', state: 'ok' as const, rows: 12, limit: 5000, detail: '12 row(s) read.' },
    { key: 'scanner_agents', label: 'Agent fleet', state: 'unavailable' as const, rows: 0, limit: 250, detail: 'The query failed.' },
  ],
}

renderCases({
  page: 'Runtime Cryptographic Intelligence',
  path: '/dashboard/runtime-crypto-intel',
  Page: RuntimeCryptoIntel,
  forbidAlways: ['NaN', 'undefined', '[object Object]'],
  cases: [
    { name: 'loading', live: { 'runtime-intel': { payload: null, state: 'loading', transport: 'connecting' } }, expect: ['Connecting'] },
    { name: 'hard-error', live: { 'runtime-intel': { payload: null, state: 'error', transport: 'polling', error: 'HTTP 500' } }, expect: ['Runtime Telemetry Unavailable'] },
    { name: 'no-collector', live: { 'runtime-intel': { payload: noCollector } }, expect: ['No Collector Configured'] },
    {
      name: 'populated-live',
      live: { 'runtime-intel': { payload: populated } },
      expect: ['Live', 'What you are looking at', 'Recommended next step'],
      forbid: ['Live stream interrupted', 'Connection lost'],
    },
    { name: 'offline', live: { 'runtime-intel': { payload: populated, transport: 'offline' } }, expect: ['Offline', 'Connection lost'] },
    { name: 'agents-unreadable', live: { 'runtime-intel': { payload: withReads } }, expect: ['Evidence sources', 'Agent fleet', 'could not be read'] },
  ],
})
