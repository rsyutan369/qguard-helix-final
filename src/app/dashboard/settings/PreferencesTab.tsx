import { useCallback, useMemo, useRef, useState } from 'react'
import type { KeyboardEvent, ReactNode } from 'react'
import {
  AlertTriangle,
  Bell,
  BellRing,
  Check,
  LayoutDashboard,
  Loader2,
  Moon,
  Palette,
  Radio,
  Sun,
  Undo2,
} from 'lucide-react'
import { useTheme } from '@/contexts/theme-context'
import { useUserPreferences } from '@/contexts/user-preferences-context'
import {
  DASHBOARD_DENSITIES,
  DASHBOARD_VIEWS,
  validatePreferencePatch,
  type ProfileTheme,
  type UserPreferences,
} from '@/lib/preferences'
import { SectionCard, Switch, ghostButtonClass, inputClass, labelClass, primaryButtonClass } from './_ui'

type EditableKey = Exclude<keyof UserPreferences, 'theme' | 'updatedAt'>
type Overrides = Partial<Pick<UserPreferences, EditableKey>>

interface PreferencesTabProps {
  preferences: UserPreferences
  onSave: (patch: Overrides) => Promise<unknown>
}

const THEMES: { key: ProfileTheme; label: string; description: string; icon: typeof Sun }[] = [
  { key: 'dark', label: 'Dark', description: 'Low-glare surfaces for SOC rooms and long sessions.', icon: Moon },
  { key: 'light', label: 'Light', description: 'Bright surfaces for well-lit offices and printing.', icon: Sun },
]

function SectionTitle({ icon: Icon, children, aside }: { icon: typeof Bell; children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 text-gold" />
        <h3 className="text-sm font-black uppercase tracking-[0.16em] text-white/70">{children}</h3>
      </div>
      {aside}
    </div>
  )
}

function StatusChip({ tone, children }: { tone: 'good' | 'warn' | 'muted'; children: ReactNode }) {
  const palette = tone === 'good'
    ? 'border-green-400/25 bg-green-400/10 text-green-300'
    : tone === 'warn'
      ? 'border-yellow-400/25 bg-yellow-400/10 text-yellow-200'
      : 'border-white/15 bg-white/5 text-white/45'
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[9px] font-black uppercase tracking-[0.12em] ${palette}`}>
      {children}
    </span>
  )
}

function ThemePreview({ variant }: { variant: ProfileTheme }) {
  const dark = variant === 'dark'
  const surface = dark ? '#0b1020' : '#f8fafc'
  const rail = dark ? '#070b16' : '#ffffff'
  const card = dark ? '#131a30' : '#ffffff'
  const line = dark ? '#243049' : '#cbd5e1'
  const accent = '#d4af37'
  return (
    <div className="flex h-24 overflow-hidden rounded-md border" style={{ background: surface, borderColor: line }} aria-hidden="true">
      <div className="flex w-1/5 flex-col gap-1.5 border-r p-2" style={{ background: rail, borderColor: line }}>
        <span className="h-1.5 w-full rounded-full" style={{ background: accent }} />
        <span className="h-1.5 w-3/4 rounded-full" style={{ background: line }} />
        <span className="h-1.5 w-2/3 rounded-full" style={{ background: line }} />
      </div>
      <div className="flex flex-1 flex-col gap-2 p-2.5">
        <span className="h-2 w-1/3 rounded-full" style={{ background: dark ? '#e2e8f0' : '#0f172a' }} />
        <div className="grid flex-1 grid-cols-3 gap-2">
          {[0, 1, 2].map((item) => (
            <div key={item} className="rounded border p-1.5" style={{ background: card, borderColor: line }}>
              <span className="block h-1.5 w-1/2 rounded-full" style={{ background: item === 0 ? accent : line }} />
              <span className="mt-1.5 block h-3 w-3/4 rounded" style={{ background: dark ? '#1e293b' : '#e2e8f0' }} />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function ThemePicker() {
  const { theme, setMode } = useTheme()
  const { saving, error } = useUserPreferences()
  const refs = useRef<Record<string, HTMLButtonElement | null>>({})

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const index = THEMES.findIndex((option) => option.key === theme)
    let next = index
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % THEMES.length
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index - 1 + THEMES.length) % THEMES.length
    else return
    event.preventDefault()
    setMode(THEMES[next].key)
    refs.current[THEMES[next].key]?.focus()
  }

  const status = error
    ? <StatusChip tone="warn">Not saved</StatusChip>
    : saving
      ? <span className="inline-flex items-center gap-1.5 text-[11px] font-bold text-white/45"><Loader2 className="h-3 w-3 animate-spin" />Saving…</span>
      : <span className="inline-flex items-center gap-1.5 text-[11px] font-bold text-green-300"><Check className="h-3 w-3" />Applied and saved to your account</span>

  return (
    <SectionCard>
      <SectionTitle icon={Palette} aside={<span role="status" aria-live="polite">{status}</span>}>Appearance</SectionTitle>
      <div role="radiogroup" aria-label="Theme" onKeyDown={onKeyDown} className="grid gap-3 sm:grid-cols-2">
        {THEMES.map((option) => {
          const selected = theme === option.key
          const Icon = option.icon
          return (
            <button
              key={option.key}
              ref={(node) => { refs.current[option.key] = node }}
              type="button"
              role="radio"
              aria-checked={selected}
              tabIndex={selected ? 0 : -1}
              onClick={() => setMode(option.key)}
              className={`group rounded-lg border p-3 text-left transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold/60 ${selected ? 'border-gold/60 bg-gold/[0.08] shadow-[0_0_24px_rgba(212,175,55,0.12)]' : 'border-white/10 bg-white/[0.025] hover:border-gold/30'}`}
            >
              <ThemePreview variant={option.key} />
              <div className="mt-3 flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 text-sm font-black text-white/90">
                    <Icon className="h-4 w-4 text-gold" />
                    {option.label}
                  </div>
                  <p className="mt-1 text-xs text-white/45">{option.description}</p>
                </div>
                <span className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full border transition ${selected ? 'border-gold bg-gold text-black' : 'border-white/20 text-transparent'}`}>
                  <Check className="h-3 w-3" />
                </span>
              </div>
            </button>
          )
        })}
      </div>
      <p className="mt-3 text-xs text-white/35">Your choice applies the moment you select it and follows you to every device you sign in on.</p>
    </SectionCard>
  )
}

export default function PreferencesTab({ preferences, onSave }: PreferencesTabProps) {
  const { push, saving } = useUserPreferences()
  const [overrides, setOverrides] = useState<Overrides>({})
  const [pushNote, setPushNote] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const effective = useMemo<UserPreferences>(() => ({ ...preferences, ...overrides }), [overrides, preferences])

  // Only keys that actually differ from what is saved count as unsaved edits,
  // so flipping a switch back clears the "unsaved changes" state.
  const changes = useMemo<Overrides>(() => {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(overrides) as EditableKey[]) {
      if (overrides[key] !== preferences[key]) out[key] = overrides[key]
    }
    return out as Overrides
  }, [overrides, preferences])
  const dirty = Object.keys(changes).length > 0
  const validationError = useMemo(() => validatePreferencePatch(changes), [changes])

  const set = useCallback(<K extends EditableKey>(key: K, value: UserPreferences[K]) => {
    setOverrides((prev) => ({ ...prev, [key]: value }))
  }, [])

  async function togglePush(next: boolean) {
    setPushNote(null)
    if (!next) {
      set('notificationPush', false)
      return
    }
    if (!push.supported) {
      setPushNote('This browser does not support notifications.')
      return
    }
    let permission = push.permission
    if (permission === 'default') permission = await push.requestPermission()
    if (permission === 'granted') {
      set('notificationPush', true)
    } else if (permission === 'denied') {
      setPushNote('Notifications are blocked for this site. Allow them in your browser’s site settings, then turn this on again.')
    } else {
      setPushNote('Permission was dismissed, so push notifications stay off.')
    }
  }

  function sendTest() {
    setPushNote(push.sendTest()
      ? 'Test notification sent. Look for it in your system notification area.'
      : 'The browser did not show the notification. Check that notifications are allowed for this site.')
  }

  async function submit() {
    if (validationError || !dirty) return
    setSubmitting(true)
    const submitted = changes
    try {
      await onSave(submitted)
      // Drop only what was saved. Edits made while the save was in flight stay.
      setOverrides((prev) => {
        const next: Record<string, unknown> = { ...prev }
        for (const key of Object.keys(submitted) as EditableKey[]) {
          if (next[key] === submitted[key]) delete next[key]
        }
        return next as Overrides
      })
    } catch {
      // The page banner shows the server's reason; the edits stay so the user can retry.
    } finally {
      setSubmitting(false)
    }
  }

  const pushStatus = !push.supported
    ? <StatusChip tone="muted">Not supported here</StatusChip>
    : push.permission === 'granted'
      ? <StatusChip tone="good">Allowed</StatusChip>
      : push.permission === 'denied'
        ? <StatusChip tone="warn">Blocked in browser</StatusChip>
        : <StatusChip tone="muted">Permission needed</StatusChip>

  return (
    <form
      onSubmit={(event) => { event.preventDefault(); void submit() }}
      className="space-y-5"
      aria-label="Account preferences"
    >
      <ThemePicker />

      <div className="grid gap-5 xl:grid-cols-2">
        <SectionCard>
          <SectionTitle icon={Bell}>Notifications</SectionTitle>

          <div className="rounded-lg border border-white/10 bg-white/[0.025] p-3">
            <div className="flex items-start justify-between gap-4">
              <div className="flex min-w-0 gap-3">
                <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-md border border-gold/20 bg-gold/[0.05] text-gold">
                  <BellRing className="h-4 w-4" />
                </span>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span id="pref-push-label" className="text-sm font-bold text-white/85">Browser push</span>
                    {pushStatus}
                  </div>
                  <div id="pref-push-desc" className="mt-0.5 text-xs text-white/40">Desktop alerts for security events that need attention.</div>
                </div>
              </div>
              <Switch
                checked={effective.notificationPush}
                onChange={(value) => { void togglePush(value) }}
                labelledBy="pref-push-label"
                describedBy="pref-push-desc"
                disabled={!push.supported || (push.permission === 'denied' && !effective.notificationPush)}
              />
            </div>
            {(pushNote || push.permission === 'granted') && (
              <div className="mt-3 flex flex-wrap items-center gap-3 pl-11">
                {pushNote && (
                  <div className="flex items-center gap-1.5 text-xs font-medium text-white/60" role="status">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-yellow-400" />
                    {pushNote}
                  </div>
                )}
                {push.permission === 'granted' && (
                  <button type="button" className={ghostButtonClass} onClick={sendTest}>
                    <BellRing className="h-3.5 w-3.5" />
                    Send test notification
                  </button>
                )}
              </div>
            )}
          </div>

          <div className="mt-3 flex items-center justify-between gap-4 rounded-lg border border-white/10 bg-white/[0.025] p-3">
            <div>
              <div id="pref-security-label" className="text-sm font-bold text-white/85">Security alerts</div>
              <div id="pref-security-desc" className="mt-0.5 text-xs text-white/40">
                MFA, session and suspicious-activity notices. Warning and critical events raise a push alert when browser push is on.
              </div>
            </div>
            <Switch
              checked={effective.securityAlerts}
              onChange={(value) => set('securityAlerts', value)}
              labelledBy="pref-security-label"
              describedBy="pref-security-desc"
            />
          </div>
        </SectionCard>

        <SectionCard>
          <SectionTitle icon={LayoutDashboard}>Workspace</SectionTitle>
          <div className="grid gap-4">
            <div>
              <span className={labelClass} id="pref-density-label">Dashboard density</span>
              <div role="radiogroup" aria-labelledby="pref-density-label" className="grid grid-cols-3 gap-2">
                {DASHBOARD_DENSITIES.map((option) => {
                  const selected = effective.dashboardDensity === option.value
                  return (
                    <button
                      key={option.value}
                      type="button"
                      role="radio"
                      aria-checked={selected}
                      onClick={() => set('dashboardDensity', option.value)}
                      className={`rounded-lg border px-3 py-2.5 text-left transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold/60 ${selected ? 'border-gold/55 bg-gold/[0.08]' : 'border-white/10 bg-white/[0.025] hover:border-gold/25'}`}
                    >
                      <span className="block text-xs font-black text-white/85">{option.label}</span>
                      <span className="mt-0.5 block text-[10px] leading-snug text-white/40">{option.hint}</span>
                    </button>
                  )
                })}
              </div>
            </div>

            <label>
              <span className={labelClass}>Default dashboard view</span>
              <select className={inputClass} value={effective.defaultDashboardView} onChange={(event) => set('defaultDashboardView', event.target.value)}>
                {DASHBOARD_VIEWS.map((view) => <option key={view.value} value={view.value}>{view.label}</option>)}
              </select>
              <span className="mt-1.5 block text-[11px] text-slate-500">Opens when you start a new session. Plan-restricted pages fall back to Overview.</span>
            </label>

            <div className="flex items-center justify-between gap-4 rounded-lg border border-white/10 bg-white/[0.025] p-3">
              <div>
                <div id="pref-telemetry-label" className="flex items-center gap-2 text-sm font-bold text-white/85">
                  <Radio className="h-3.5 w-3.5 text-gold" />
                  Live telemetry sync
                </div>
                <div id="pref-telemetry-desc" className="mt-0.5 text-xs text-white/40">
                  Streams profile telemetry and account activity to this page in real time. Off, they update only when you refresh.
                </div>
              </div>
              <Switch
                checked={effective.telemetryOptIn}
                onChange={(value) => set('telemetryOptIn', value)}
                labelledBy="pref-telemetry-label"
                describedBy="pref-telemetry-desc"
              />
            </div>
          </div>
        </SectionCard>
      </div>

      <div className="sticky bottom-4 z-20">
        {/* Right padding keeps the Save button clear of the floating Sophia launcher. */}
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border py-3 pl-4 pr-4 shadow-[0_12px_40px_rgba(0,0,0,0.35)] glass-panel lg:pr-24">
          <div className="flex items-center gap-2 text-xs" role="status" aria-live="polite">
            {validationError ? (
              <span className="inline-flex items-center gap-1.5 font-bold text-yellow-200"><AlertTriangle className="h-3.5 w-3.5" />{validationError}</span>
            ) : dirty ? (
              <span className="inline-flex items-center gap-1.5 font-bold text-gold"><span className="h-2 w-2 rounded-full bg-gold" />Unsaved changes</span>
            ) : (
              <span className="inline-flex items-center gap-1.5 font-bold text-green-300"><Check className="h-3.5 w-3.5" />All preferences saved</span>
            )}
          </div>
          <div className="flex gap-2">
            <button type="button" className={ghostButtonClass} disabled={!dirty || submitting} onClick={() => { setOverrides({}); setPushNote(null) }}>
              <Undo2 className="h-3.5 w-3.5" />
              Discard
            </button>
            <button type="submit" className={primaryButtonClass} disabled={!dirty || submitting || saving || Boolean(validationError)}>
              {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
              Save changes
            </button>
          </div>
        </div>
      </div>
    </form>
  )
}
