/**
 * Account preference vocabulary shared by the browser and the API server.
 *
 * One list per setting, so the control a user sees, the value the server
 * accepts and the effect the app applies can never drift apart. This module is
 * isomorphic: no DOM, no Node-only imports.
 */

export type ProfileTheme = 'dark' | 'light'
export type DashboardDensity = 'compact' | 'comfortable' | 'expanded'

export const PROFILE_THEMES: readonly ProfileTheme[] = ['dark', 'light']
export const DEFAULT_THEME: ProfileTheme = 'dark'

/**
 * Rows written before the Gold and Cyber themes were retired still carry those
 * values. They are read as Dark and rewritten the next time the user saves.
 */
export function normalizeTheme(value: unknown): ProfileTheme {
  return value === 'light' ? 'light' : 'dark'
}

export const DASHBOARD_DENSITIES: readonly { value: DashboardDensity; label: string; hint: string }[] = [
  { value: 'compact', label: 'Compact', hint: 'More on screen, tighter spacing' },
  { value: 'comfortable', label: 'Comfortable', hint: 'Balanced default' },
  { value: 'expanded', label: 'Expanded', hint: 'Larger type and spacing' },
]

/** Root font size per density. Every rem-based size in the dashboard follows it. */
export const DENSITY_ROOT_FONT_PX: Record<DashboardDensity, number> = {
  compact: 15,
  comfortable: 16,
  expanded: 17,
}

export interface DashboardViewOption {
  value: string
  label: string
  path: string
}

/** Landing pages a user may choose. `overview` is the command center itself. */
export const DASHBOARD_VIEWS: readonly DashboardViewOption[] = [
  { value: 'overview', label: 'Overview (Command Center)', path: '/dashboard' },
  { value: 'quantum-readiness', label: 'Quantum Readiness Assessment', path: '/dashboard/quantum-readiness' },
  { value: 'quantum-risk-scoring', label: 'Quantum Risk Scoring', path: '/dashboard/quantum-risk-scoring' },
  { value: 'scanner', label: 'PQC Scanner', path: '/dashboard/scanner' },
  { value: 'assets', label: 'Assets & CBOM', path: '/dashboard/assets' },
  { value: 'migration-planner', label: 'Migration Planner', path: '/dashboard/migration-planner' },
]

export function dashboardViewPath(view: string | null | undefined): string {
  return DASHBOARD_VIEWS.find((option) => option.value === view)?.path ?? '/dashboard'
}

export interface UserPreferences {
  theme: ProfileTheme
  dashboardDensity: DashboardDensity
  defaultDashboardView: string
  notificationPush: boolean
  securityAlerts: boolean
  telemetryOptIn: boolean
  updatedAt: string | null
}

/** Why a preference patch is not acceptable, or null when it is. */
export function validatePreferencePatch(patch: Partial<UserPreferences>): string | null {
  if (patch.theme !== undefined && !PROFILE_THEMES.includes(patch.theme)) return 'Choose Light or Dark.'
  if (
    patch.dashboardDensity !== undefined &&
    !DASHBOARD_DENSITIES.some((option) => option.value === patch.dashboardDensity)
  ) {
    return 'Choose a valid dashboard density.'
  }
  if (
    patch.defaultDashboardView !== undefined &&
    !DASHBOARD_VIEWS.some((option) => option.value === patch.defaultDashboardView)
  ) {
    return 'Choose a valid default dashboard view.'
  }
  for (const key of ['notificationPush', 'securityAlerts', 'telemetryOptIn'] as const) {
    if (patch[key] !== undefined && typeof patch[key] !== 'boolean') return `${key} must be true or false.`
  }
  return null
}
