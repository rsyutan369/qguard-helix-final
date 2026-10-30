import CryptoAgility from '@/app/dashboard/crypto-agility/CryptoAgility'
import { buildCryptoAgilityIntelligence } from '@/lib/crypto-agility/agility-intelligence'
import { renderCases } from '../harness'
import { inputs } from '../fixtures/agility'

const populated = buildCryptoAgilityIntelligence(inputs)
const empty = buildCryptoAgilityIntelligence({ ...inputs, assets: [], snapshot: { ...inputs.snapshot, hasData: false } })
const certsUnreadable = buildCryptoAgilityIntelligence({
  ...inputs,
  certificates: [],
  sourceHealth: [{ key: 'certificates', label: 'Certificates', state: 'unavailable', rows: 0, limit: 1500, detail: 'The query failed.' }],
})

renderCases({
  page: 'Crypto Agility Command Center',
  path: '/dashboard/crypto-agility',
  Page: CryptoAgility,
  forbidAlways: ['NaN', 'undefined', '[object Object]', 'Last evaluated'],
  cases: [
    { name: 'loading', live: { 'agility-update': { payload: null, state: 'loading', transport: 'connecting' } }, expect: ['Connecting'] },
    { name: 'hard-error', live: { 'agility-update': { payload: null, state: 'error', transport: 'polling', error: 'HTTP 500' } }, expect: ['Crypto Agility Data Unavailable'] },
    { name: 'empty', live: { 'agility-update': { payload: empty } }, expect: ['No Crypto Agility Assessment'] },
    {
      name: 'populated-live',
      live: { 'agility-update': { payload: populated } },
      expect: ['Live', 'What you are looking at', 'Recommended next step', populated.nextStep.label, 'Algorithm Transition Matrix', 'Approved target', 'Recorded Cryptographic Changes', 'Evaluated, not enforced', 'Evidence sources'],
      forbid: ['Live stream interrupted'],
    },
    { name: 'polling', live: { 'agility-update': { payload: populated, transport: 'polling' } }, expect: ['Polling', 'Live stream interrupted'] },
    { name: 'certificates-unreadable', live: { 'agility-update': { payload: certsUnreadable } }, expect: ['Refresh the assessment', 'could not be read', 'not measurements of zero'] },
  ],
})
