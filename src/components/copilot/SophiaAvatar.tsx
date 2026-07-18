import { motion, AnimatePresence } from 'framer-motion';

/**
 * SophiaAvatar — Sophia's brand avatar with a live "thinking/speaking" state.
 *
 * When `active` (Sophia is answering), the avatar breathes, a cyan halo pulses,
 * a conic-gradient light sweeps the rim and a status dot pings — a premium,
 * enterprise-grade signal that she is working. When idle it settles to a calm,
 * static ring with a soft glow. Pure CSS/Framer, no external assets beyond the
 * PNG served from /Sophia_AVATAR.png.
 */
export function SophiaAvatar({
  active = false,
  size = 44,
  className = '',
}: {
  active?: boolean;
  size?: number;
  className?: string;
}) {
  return (
    <div className={`relative shrink-0 ${className}`} style={{ width: size, height: size }} aria-hidden={false}>
      <AnimatePresence>
        {active && (
          <>
            {/* Pulsing glow halo */}
            <motion.span
              key="halo"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: [0.35, 0.7, 0.35], scale: [1, 1.35, 1] }}
              exit={{ opacity: 0, scale: 0.8 }}
              transition={{ duration: 1.8, repeat: Infinity, ease: 'easeInOut' }}
              className="pointer-events-none absolute -inset-2 rounded-full bg-cyan-400/40 blur-md"
            />
            {/* Rotating conic light sweep around the rim */}
            <motion.span
              key="ring"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1, rotate: 360 }}
              exit={{ opacity: 0 }}
              transition={{ rotate: { duration: 2.6, repeat: Infinity, ease: 'linear' }, opacity: { duration: 0.3 } }}
              className="pointer-events-none absolute -inset-[3px] rounded-full"
              style={{
                background: 'conic-gradient(from 0deg, transparent 0deg, rgba(34,211,238,0.15) 90deg, #22d3ee 180deg, #3b82f6 240deg, transparent 320deg)',
                WebkitMask: 'radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 3px))',
                mask: 'radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 3px))',
              }}
            />
          </>
        )}
      </AnimatePresence>

      {/* Static rim glow — brighter/tighter while active, calm while idle */}
      <span
        className={`pointer-events-none absolute -inset-[1.5px] rounded-full transition-all duration-500 ${
          active ? 'shadow-[0_0_24px_rgba(34,211,238,0.55)]' : 'shadow-[0_0_12px_rgba(37,99,235,0.28)]'
        }`}
      />

      {/* Avatar image — gentle breathing while active */}
      <motion.div
        animate={active ? { scale: [1, 1.06, 1] } : { scale: 1 }}
        transition={active ? { duration: 1.6, repeat: Infinity, ease: 'easeInOut' } : { duration: 0.3 }}
        className={`relative h-full w-full overflow-hidden rounded-full border bg-slate-900 transition-colors duration-500 ${
          active ? 'border-cyan-300/70' : 'border-blue-400/40'
        }`}
      >
        <img
          src="/Sophia_AVATAR.png"
          alt="Sophia — AI Security Copilot"
          className="h-full w-full object-cover"
          draggable={false}
        />
        {/* Subtle sheen so the portrait reads as a premium glass token */}
        <span className="pointer-events-none absolute inset-0 rounded-full bg-gradient-to-tr from-transparent via-transparent to-white/10" />
      </motion.div>

      {/* Live status dot */}
      <span className="absolute -bottom-0.5 -right-0.5 flex" style={{ height: Math.max(9, size * 0.22), width: Math.max(9, size * 0.22) }}>
        {active && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400/70" />}
        <span
          className={`relative inline-flex h-full w-full rounded-full ring-2 ring-slate-950 transition-colors duration-500 ${
            active ? 'bg-cyan-400' : 'bg-emerald-400/80'
          }`}
        />
      </span>
    </div>
  );
}

export default SophiaAvatar;
