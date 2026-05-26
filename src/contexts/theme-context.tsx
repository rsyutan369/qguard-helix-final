import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

export type ThemeMode = 'light' | 'dark' | 'system'
export type ResolvedTheme = 'light' | 'dark'

type ThemeContextValue = {
  mode: ThemeMode
  theme: ResolvedTheme
  isLight: boolean
  isDark: boolean
  setMode: (mode: ThemeMode) => void
  toggleTheme: () => void
}

const STORAGE_KEY = 'qguard-theme-mode-v1'
const DEFAULT_MODE: ThemeMode = 'dark'

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined)

function getSystemTheme(): ResolvedTheme {
  if (typeof window === 'undefined') return DEFAULT_MODE
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

function resolveTheme(mode: ThemeMode): ResolvedTheme {
  return mode === 'system' ? getSystemTheme() : mode
}

function getStoredMode(): ThemeMode {
  if (typeof window === 'undefined') return DEFAULT_MODE
  const stored = window.localStorage.getItem(STORAGE_KEY)
  return stored === 'light' || stored === 'dark' || stored === 'system' ? stored : DEFAULT_MODE
}

function applyTheme(mode: ThemeMode, resolved: ResolvedTheme) {
  if (typeof document === 'undefined') return

  const root = document.documentElement
  root.dataset.theme = resolved
  root.dataset.themeMode = mode
  root.style.colorScheme = resolved
  root.classList.toggle('light', resolved === 'light')
  root.classList.toggle('dark', resolved === 'dark')
  root.classList.toggle('qg-theme-light', resolved === 'light')
  root.classList.toggle('qg-theme-dark', resolved === 'dark')
  root.classList.add('qg-theme-ready')
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(() => getStoredMode())
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(() => getSystemTheme())

  const theme = mode === 'system' ? systemTheme : mode

  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: light)')
    const handleChange = () => setSystemTheme(media.matches ? 'light' : 'dark')

    handleChange()
    media.addEventListener('change', handleChange)
    return () => media.removeEventListener('change', handleChange)
  }, [])

  useEffect(() => {
    applyTheme(mode, theme)
    window.localStorage.setItem(STORAGE_KEY, mode)
  }, [mode, theme])

  const setMode = useCallback((nextMode: ThemeMode) => {
    setModeState(nextMode)
  }, [])

  const toggleTheme = useCallback(() => {
    setModeState((current) => {
      const resolved = current === 'system' ? getSystemTheme() : current
      return resolved === 'light' ? 'dark' : 'light'
    })
  }, [])

  const value = useMemo<ThemeContextValue>(() => ({
    mode,
    theme,
    isLight: theme === 'light',
    isDark: theme === 'dark',
    setMode,
    toggleTheme,
  }), [mode, setMode, theme, toggleTheme])

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider')
  }
  return context
}
