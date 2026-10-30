import QuantumRiskScoring from '@/app/dashboard/quantum-risk-scoring/QuantumRiskScoring'
import { buildQuantumRiskIntelligence } from '@/lib/quantum-risk/risk-intelligence'
import { renderCases } from '../harness'
import { NOW, portfolio, snapshot } from '../fixtures/quantum-risk'

const populated = {
  ...buildQuantumRiskIntelligence({ snapshot, assets: portfolio.assets, now: NOW }),
  reads: [
    { key: 'quantum_readiness', label: 'Quantum Readiness assessment', state: 'ok' as const, rows: 4, limit: null, detail: '4 asset(s) assessed.' },
    { key: 'asset_portfolio', label: 'Asset portfolio', state: 'ok' as const, rows: 4, limit: null, detail: '4 asset(s) read.' },
  ],
}
const empty = buildQuantumRiskIntelligence({ snapshot: { ...snapshot, hasData: false }, assets: [], now: NOW })

renderCases({
  page: 'Quantum Risk Scoring',
  path: '/dashboard/quantum-risk-scoring',
  Page: QuantumRiskScoring,
  forbidAlways: ['NaN', 'undefined', '[object Object]'],
  cases: [
    { name: 'loading', live: { 'quantum-risk': { payload: null, state: 'loading', transport: 'connecting' } }, expect: ['Connecting'] },
    { name: 'hard-error', live: { 'quantum-risk': { payload: null, state: 'error', transport: 'polling', error: 'HTTP 500' } }, expect: ['Quantum Risk Assessment Unavailable'] },
    { name: 'empty', live: { 'quantum-risk': { payload: empty } }, expect: ['No Cryptographic Assessment Yet'] },
    { name: 'populated-live', live: { 'quantum-risk': { payload: populated } }, expect: ['Live', 'What you are looking at', 'Recommended next step', 'Evidence sources', 'What Drives the Score'], forbid: ['Live stream interrupted', 'could not be read'] },
    { name: 'polling', live: { 'quantum-risk': { payload: populated, transport: 'polling' } }, expect: ['Polling', 'Live stream interrupted'] },
  ],
})
