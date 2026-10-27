import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { useTheme, type ThemeMode } from '@/contexts/theme-context'
import { supabase } from '@/lib/supabase'
import {
  DENSITY_ROOT_FONT_PX,
  normalizeTheme,
  type UserPreferences,
} from '@/lib/preferences'

export type PushPermission = NotificationPermission | 'unsupported'

interface PushController {
  supported: boolean
  permission: PushPermission
  /** Asks the browser for permission. Must be called from a user gesture. */
  requestPermission: () => Promise<PushPermission>
  /** Raises a real browser notification so the user can confirm delivery. */
  sendTest: () => boolean
}

interface UserPreferencesContextValue {
  preferences: UserPreferences | null
  loading: boolean
  /** True while at least one change is being written to the server. */
  saving: boolean
  error: string | null
  clearError: () => void
  refresh: () => Promise<void>
  /**
   * Applies a patch immediately and persists it. Resolves with the server's
   * copy; rejects (after rolling the patch back) when the server refuses it.
   */
  updatePreferences: (patch: Partial<Omit<UserPreferences, 'updatedAt'>>) => Promise<UserPreferences>
  push: PushController
}

const UserPreferencesContext = createContext<UserPreferencesContextValue | undefined>(undefined)

type PatchKeys = keyof Omit<UserPreferences, 'updatedAt'>

function wait(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms))
}

function readPushPermission(): PushPermission {
  if (typeof window === 'undefined' || !('Notification' in window)) return 'unsupported'
  return Notification.permission
}

export function UserPreferencesProvider({ children }: { children: React.ReactNode }) {
  const { session, user } = useAuth()
  const { mode, setMode } = useTheme()
  const token = session?.access_token
  const userId = user?.id

  const [preferences, setPreferences] = useState<UserPreferences | null>(null)
  const [loading, setLoading] = useState(Boolean(userId))
  const [inflight, setInflight] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [permission, setPermission] = useState<PushPermission>(() => readPushPermission())

  // Last copy the server confirmed; the rollback target when a write fails.
  const confirmedRef = useRef<UserPreferences | null>(null)
  const queueRef = useRef<Promise<unknown>>(Promise.resolve())
  const inflightRef = useRef(0)
  // Bumped whenever a write starts or settles; lets a slow read notice it was overtaken.
  const writeEpochRef = useRef(0)
  const tokenRef = useRef(token)
  tokenRef.current = token

  const request = useCallback(async <T,>(init: RequestInit = {}): Promise<T> => {
    let lastError: Error | null = null
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const res = await fetch('/api/v1/profile/preferences', {
        ...init,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenRef.current}`,
        },
      })
      const json = await res.json().catch(() => ({}))
      if (res.ok) return json.data as T
      lastError = new Error(json?.error?.message || json?.message || `Request failed with HTTP ${res.status}`)
      const code = json?.error?.code || json?.code
      // The API is still booting; the profile hook retries this the same way.
      if (res.status === 503 && (code === 'NOT_READY' || code === 'API_LOAD_ERROR')) {
        await wait(350 + attempt * 150)
        continue
      }
      throw lastError
    }
    throw lastError || new Error('Request failed')
  }, [])

  const refresh = useCallback(async () => {
    if (!tokenRef.current) return
    const epochAtStart = writeEpochRef.current
    try {
      const data = await request<{ preferences: UserPreferences }>()
      // A write started or finished while this read was in flight, so the copy
      // is older than what the user just did. Applying it would undo that edit.
      if (writeEpochRef.current !== epochAtStart || inflightRef.current > 0) return
      confirmedRef.current = data.preferences
      setPreferences(data.preferences)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load preferences')
    } finally {
      setLoading(false)
    }
  }, [request])

  // Load on sign-in, reset on sign-out or account switch.
  useEffect(() => {
    confirmedRef.current = null
    setPreferences(null)
    setError(null)
    if (!userId || !token) {
      setLoading(false)
      return
    }
    setLoading(true)
    void refresh()
    // Token refreshes must not reload the row; only the account identity does.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId, Boolean(token)])

  // Cross-device sync: another session changed this row.
  useEffect(() => {
    if (!userId || !token) return
    const channel = supabase
      .channel(`user-preferences-${userId}`)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'user_preferences', filter: `user_id=eq.${userId}` }, () => {
        // Our own writes echo back here; ignore them while any are in flight.
        if (inflightRef.current === 0) void refresh()
      })
      .subscribe()
    return () => { void supabase.removeChannel(channel) }
  }, [refresh, token, userId])

  const updatePreferences = useCallback<UserPreferencesContextValue['updatePreferences']>((patch) => {
    const keys = Object.keys(patch) as PatchKeys[]
    setPreferences((prev) => (prev ? { ...prev, ...patch } : prev))
    inflightRef.current += 1
    writeEpochRef.current += 1
    setInflight(inflightRef.current)
    setError(null)

    const run = async (): Promise<UserPreferences> => {
      try {
        const data = await request<{ preferences: UserPreferences }>({ method: 'PUT', body: JSON.stringify(patch) })
        confirmedRef.current = data.preferences
        // Adopt the server's value for the keys we wrote, but keep any newer
        // optimistic edits still queued behind this one.
        setPreferences((prev) => {
          if (!prev) return data.preferences
          const next = { ...prev, updatedAt: data.preferences.updatedAt }
          for (const key of keys) (next as Record<string, unknown>)[key] = data.preferences[key]
          return next
        })
        return data.preferences
      } catch (err) {
        const confirmed = confirmedRef.current
        if (confirmed) {
          setPreferences((prev) => {
            if (!prev) return prev
            const next = { ...prev }
            for (const key of keys) (next as Record<string, unknown>)[key] = confirmed[key]
            return next
          })
        }
        const message = err instanceof Error ? err.message : 'Failed to save preferences'
        setError(message)
        throw err instanceof Error ? err : new Error(message)
      } finally {
        inflightRef.current -= 1
        writeEpochRef.current += 1
        setInflight(inflightRef.current)
      }
    }

    // Writes go out one at a time, in the order the user made them.
    const result = queueRef.current.then(run, run)
    queueRef.current = result.catch(() => undefined)
    return result
  }, [request])

  // --- Theme -----------------------------------------------------------------
  // The server copy is the source of truth across devices; ThemeProvider owns
  // the DOM. `reconciledMode` marks the last mode the two agreed on, so a change
  // the server caused is never written straight back to it.
  const serverTheme = preferences ? normalizeTheme(preferences.theme) : null
  const reconciledMode = useRef<ThemeMode | null>(null)

  useEffect(() => {
    if (!serverTheme) return
    reconciledMode.current = serverTheme
    if (mode !== serverTheme) setMode(serverTheme)
    // `mode` is deliberately not a dependency: this only reacts to the server.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serverTheme])

  useEffect(() => {
    if (!preferences || reconciledMode.current === null) return
    if (mode === reconciledMode.current) return
    reconciledMode.current = mode
    // "Follow system" has no server representation; it stays a device choice.
    if (mode === 'system' || mode === preferences.theme) return
    updatePreferences({ theme: mode }).catch(() => {
      // The rollback already restored the saved theme and set `error`.
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode])

  // --- Density -----------------------------------------------------------------
  const density = preferences?.dashboardDensity
  useEffect(() => {
    const root = document.documentElement
    if (!density) {
      delete root.dataset.density
      root.style.removeProperty('--qg-density-root-size')
      return
    }
    root.dataset.density = density
    root.style.setProperty('--qg-density-root-size', `${DENSITY_ROOT_FONT_PX[density]}px`)
    return () => {
      delete root.dataset.density
      root.style.removeProperty('--qg-density-root-size')
    }
  }, [density])

  // --- Push notifications ----------------------------------------------------
  useEffect(() => {
    if (permission === 'unsupported' || !navigator.permissions?.query) return
    let status: PermissionStatus | null = null
    const sync = () => setPermission(readPushPermission())
    navigator.permissions.query({ name: 'notifications' as PermissionName }).then((result) => {
      status = result
      result.addEventListener('change', sync)
    }).catch(() => undefined)
    return () => status?.removeEventListener('change', sync)
  }, [permission])

  const requestPermission = useCallback(async (): Promise<PushPermission> => {
    if (readPushPermission() === 'unsupported') return 'unsupported'
    const result = await Notification.requestPermission()
    setPermission(result)
    return result
  }, [])

  const sendTest = useCallback(() => {
    if (readPushPermission() !== 'granted') return false
    try {
      new Notification('QGuard Helix — notifications are working', {
        body: 'Security alerts will appear like this while push notifications are on.',
        icon: '/NEW_LOGO.png',
        tag: 'qguard-test',
      })
      return true
    } catch {
      return false
    }
  }, [])

  // Security alerts → browser notifications. Only events that need attention
  // (warning, critical) interrupt the user; routine events stay in the
  // Activity tab.
  const pushActive = Boolean(preferences?.notificationPush && preferences.securityAlerts && permission === 'granted')
  useEffect(() => {
    if (!pushActive || !userId) return
    const seen = new Set<string>()
    const channel = supabase
      .channel(`security-push-${userId}`)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'user_security_events', filter: `user_id=eq.${userId}` }, (payload) => {
        const row = payload.new as { id?: string; severity?: string; message?: string; event_type?: string }
        if (!row.id || seen.has(row.id)) return
        seen.add(row.id)
        if (row.severity !== 'warning' && row.severity !== 'critical') return
        try {
          new Notification(row.severity === 'critical' ? 'QGuard Helix — critical security alert' : 'QGuard Helix — security alert', {
            body: row.message || 'A security event needs your attention.',
            icon: '/NEW_LOGO.png',
            tag: row.id,
          })
        } catch { /* a blocked or unsupported notification must never break the app */ }
      })
      .subscribe()
    return () => { void supabase.removeChannel(channel) }
  }, [pushActive, userId])

  const push = useMemo<PushController>(() => ({
    supported: permission !== 'unsupported',
    permission,
    requestPermission,
    sendTest,
  }), [permission, requestPermission, sendTest])

  const value = useMemo<UserPreferencesContextValue>(() => ({
    preferences,
    loading,
    saving: inflight > 0,
    error,
    clearError: () => setError(null),
    refresh,
    updatePreferences,
    push,
  }), [error, inflight, loading, preferences, push, refresh, updatePreferences])

  return <UserPreferencesContext.Provider value={value}>{children}</UserPreferencesContext.Provider>
}

export function useUserPreferences() {
  const context = useContext(UserPreferencesContext)
  if (!context) throw new Error('useUserPreferences must be used within UserPreferencesProvider')
  return context
}
