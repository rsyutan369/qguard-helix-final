import { MonitorCog, Moon, Sun } from 'lucide-react'
import { motion } from 'framer-motion'
import { useTheme } from '@/contexts/theme-context'
import { cn } from '@/lib/utils'

type ThemeToggleProps = {
  compact?: boolean
  showSystem?: boolean
  className?: string
}

export default function ThemeToggle({ compact = false, showSystem = true, className }: ThemeToggleProps) {
  const { mode, theme, setMode, toggleTheme } = useTheme()
  const isLight = theme === 'light'

  return (
    <div className={cn('qg-theme-toggle inline-flex items-center gap-2', compact && 'qg-theme-toggle--compact', className)}>
      <button
        type="button"
        onClick={toggleTheme}
        className="qg-theme-toggle__switch"
        aria-label={`Switch to ${isLight ? 'dark' : 'light'} mode`}
        title={`Switch to ${isLight ? 'dark' : 'light'} mode`}
      >
        <span className="qg-theme-toggle__track">
          <motion.span
            className="qg-theme-toggle__thumb"
            animate={{ x: isLight ? 28 : 2 }}
            transition={{ type: 'spring', stiffness: 420, damping: 30 }}
          >
            {isLight ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
          </motion.span>
          <Moon className="qg-theme-toggle__icon qg-theme-toggle__icon--moon h-3.5 w-3.5" />
          <Sun className="qg-theme-toggle__icon qg-theme-toggle__icon--sun h-3.5 w-3.5" />
        </span>
        {!compact && (
          <span className="qg-theme-toggle__label">
            {isLight ? 'Light' : 'Dark'}
          </span>
        )}
      </button>

      {showSystem && !compact && (
        <button
          type="button"
          onClick={() => setMode(mode === 'system' ? theme : 'system')}
          className={cn('qg-theme-toggle__system', mode === 'system' && 'qg-theme-toggle__system--active')}
          aria-pressed={mode === 'system'}
          title="Follow system theme"
        >
          <MonitorCog className="h-3.5 w-3.5" />
          <span>Auto</span>
        </button>
      )}
    </div>
  )
}
