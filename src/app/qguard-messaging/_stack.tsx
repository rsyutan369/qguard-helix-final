/**
 * Tilted, explodable stack of glass planes, shared by the Secure Chat "device
 * privacy" layers and the Quantum Vault "key envelope".
 *
 * Planes carry only an icon and their number — text on a tilted plane is
 * unreadable — so callers pair the stack with a layer picker and a detail panel.
 * Planes are buttons, so the stack is usable by keyboard too. `explode` runs
 * from 0 (squeezed together) to 1 (fully apart).
 */
import { motion } from 'motion/react';
import type { LucideIcon } from 'lucide-react';
import { useCalm } from './_motion';

export type StackLayer = { icon: LucideIcon; title: string; tone: string };

export function ExplodedStack({
  layers,
  sel,
  onSelect,
  explode,
}: {
  layers: StackLayer[];
  sel: number;
  onSelect: (i: number) => void;
  explode: number;
}) {
  const calm = useCalm();
  const gap = 12 + explode * 36;
  return (
    <div style={{ perspective: 1100, height: 330 }} className="relative">
      <div style={{ position: 'absolute', left: '50%', top: '74%', transformStyle: 'preserve-3d', transform: 'rotateX(60deg) rotateZ(-35deg)' }}>
        {layers.map((l, i) => {
          const active = sel === i;
          return (
            <motion.button
              key={l.title}
              type="button"
              aria-pressed={active}
              aria-label={`Layer ${i + 1}: ${l.title}`}
              onClick={() => onSelect(i)}
              initial={false}
              animate={{ z: (layers.length - 1 - i) * gap }}
              transition={calm ? { duration: 0 } : { type: 'spring', stiffness: 110, damping: 16 }}
              className="qm-glass"
              style={{
                position: 'absolute',
                left: -90,
                top: -42,
                width: 180,
                height: 84,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 10,
                cursor: 'pointer',
                borderColor: active ? l.tone : 'rgba(148,163,184,.3)',
                boxShadow: active ? `0 0 34px ${l.tone}88, inset 0 0 22px ${l.tone}22` : undefined,
              }}
            >
              <l.icon className="h-7 w-7" style={{ color: l.tone }} aria-hidden />
              <span className="qm-mono" style={{ fontSize: 22, fontWeight: 800, color: l.tone }}>{String(i + 1).padStart(2, '0')}</span>
            </motion.button>
          );
        })}
      </div>
    </div>
  );
}
