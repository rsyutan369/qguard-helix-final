/**
 * Offline check for the account-preference vocabulary.
 *   npx tsx tools/preferences-check.ts
 */
import assert from 'node:assert/strict'
import {
  DASHBOARD_VIEWS,
  PROFILE_THEMES,
  dashboardViewPath,
  normalizeTheme,
  validatePreferencePatch,
} from '../src/lib/preferences'

// Themes: only Light and Dark exist; retired values read as Dark.
assert.deepEqual([...PROFILE_THEMES], ['dark', 'light'])
assert.equal(normalizeTheme('gold'), 'dark')
assert.equal(normalizeTheme('cyber'), 'dark')
assert.equal(normalizeTheme(undefined), 'dark')
assert.equal(normalizeTheme('light'), 'light')
assert.equal(validatePreferencePatch({ theme: 'light' }), null)
assert.ok(validatePreferencePatch({ theme: 'gold' as never }))
assert.ok(validatePreferencePatch({ theme: 'cyber' as never }))

// Patch validation rejects every malformed field and accepts a clean one.
assert.equal(validatePreferencePatch({ dashboardDensity: 'compact', defaultDashboardView: 'scanner', notificationPush: true, securityAlerts: false, telemetryOptIn: true }), null)
assert.ok(validatePreferencePatch({ dashboardDensity: 'huge' as never }))
assert.ok(validatePreferencePatch({ defaultDashboardView: 'admin' }))
assert.ok(validatePreferencePatch({ notificationPush: 'yes' as never }))
assert.ok(validatePreferencePatch({ securityAlerts: 1 as never }))
assert.ok(validatePreferencePatch({ telemetryOptIn: null as never }))

// Default views: every option resolves to a path under /dashboard.
for (const view of DASHBOARD_VIEWS) assert.ok(dashboardViewPath(view.value).startsWith('/dashboard'))
assert.equal(dashboardViewPath('overview'), '/dashboard')
assert.equal(dashboardViewPath('does-not-exist'), '/dashboard')

console.log('preferences-check: all assertions passed')
