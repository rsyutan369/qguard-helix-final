import PqcOrchestration from '@/app/dashboard/pqc-orchestration/PqcOrchestration'
import { renderCases } from '../harness'
import { empty, populated, unreadable } from '../fixtures/orchestration'

// PQC Orchestration (flow view) over the REAL orchestration snapshot.
renderCases({
  page: 'PQC Orchestration',
  path: '/dashboard/pqc-orchestration',
  Page: PqcOrchestration,
  forbidAlways: ['NaN', 'undefined', '[object Object]', 'Global Orchestration Pipeline', 'Marketplace', 'Change freeze'],
  cases: [
    { name: 'loading', live: { orchestrator: { payload: null, state: 'loading', transport: 'connecting' } }, expect: ['Connecting'] },
    { name: 'hard-error', live: { orchestrator: { payload: null, state: 'error', transport: 'polling', error: 'HTTP 500' } }, expect: ['PQC Orchestration Unavailable', 'HTTP 500'] },
    { name: 'empty', live: { orchestrator: { payload: empty } }, expect: ['No Migration Work to Orchestrate Yet', 'Open Migration Planner'], forbid: ['Migration lifecycle'] },
    {
      name: 'populated-live',
      live: { orchestrator: { payload: populated } },
      expect: ['Live', 'What you are looking at', 'Recommended next step', 'Migration lifecycle', 'Discover', 'Approve', 'Validate', 'Monitor', 'Gate summary', 'cutover web-01', 'Evidence sources', '1 simulation(s) excluded'],
      forbid: ['[DRY RUN] web-01', 'Connection lost', 'Live stream interrupted'],
    },
    { name: 'polling', live: { orchestrator: { payload: populated, transport: 'polling' } }, expect: ['Polling', 'Live stream interrupted'] },
    { name: 'fleet-unreadable', live: { orchestrator: { payload: unreadable } }, expect: ['Agent fleet', 'could not be read', 'not measurements of zero'] },
  ],
})
