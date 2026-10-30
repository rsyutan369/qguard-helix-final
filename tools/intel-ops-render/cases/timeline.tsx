import MigrationTimeline from '@/app/dashboard/migration_timeline/MigrationTimeline'
import { renderCases } from '../harness'
import { empty, populated, unreadable } from '../fixtures/orchestration'

// Migration Timeline (time view) over the same orchestration snapshot.
renderCases({
  page: 'Migration Timeline',
  path: '/dashboard/migration-timeline',
  Page: MigrationTimeline,
  forbidAlways: ['NaN', 'undefined', '[object Object]', 'Digital Twin', 'Risk burn-down'],
  cases: [
    { name: 'loading', live: { orchestrator: { payload: null, state: 'loading', transport: 'connecting' } }, expect: ['Connecting'] },
    { name: 'hard-error', live: { orchestrator: { payload: null, state: 'error', transport: 'polling', error: 'HTTP 500' } }, expect: ['Migration Timeline Unavailable'] },
    { name: 'empty', live: { orchestrator: { payload: empty } }, expect: ['No Migration Work Recorded Yet'] },
    {
      name: 'populated-live',
      live: { orchestrator: { payload: populated } },
      expect: ['Live', 'What you are looking at', 'Recommended next step', 'Completed', 'Verified', 'Unverified completions', 'Evidence sources'],
      forbid: ['[DRY RUN] web-01', 'Live stream interrupted'],
    },
    { name: 'offline', live: { orchestrator: { payload: populated, transport: 'offline' } }, expect: ['Offline', 'Connection lost'] },
    { name: 'fleet-unreadable', live: { orchestrator: { payload: unreadable } }, expect: ['could not be read'] },
  ],
})
