/**
 * Resizable panel rows and a focus view for the Dashboard Scanner.
 *
 * Two ways to give a panel more room, both presentation-only — they never touch
 * the assessment a panel renders, so a resized or focused panel shows exactly
 * the numbers the inline one does:
 *
 *  - `ResizablePanelRow` lays panels side by side with a drag handle between
 *    each pair. Drag (or focus the handle and use the arrow keys) to widen one
 *    panel at its neighbour's expense; double-click a handle to reset. The split
 *    is remembered per viewer in localStorage, which is a convenience only: any
 *    read or write failure falls back to the default split.
 *  - A panel inside a row can open in a full-screen focus view. Panels opt in by
 *    rendering `<PanelFocusToggle />` in their header and may read
 *    `usePanelFocus().focused` to show more detail when there is room for it.
 *
 * Below the `lg` breakpoint panels stack in one column and the handles are not
 * rendered: there is no neighbour to trade width with.
 */
import React from 'react';
import { createPortal } from 'react-dom';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import { Maximize2, Minimize2, RotateCcw, X } from 'lucide-react';
import { cn } from '@/lib/utils';

/* ------------------------------------------------------------- utilities - */

const DESKTOP_QUERY = '(min-width: 1024px)';
/** Width of the drag gutter. Replaces the row's 1.25rem gap, so the at-rest layout is unchanged. */
const GUTTER_PX = 20;
const KEY_STEP = 2;
const KEY_STEP_LARGE = 10;
const STORAGE_PREFIX = 'qg.panel-layout.v1.';

function useMediaQuery(query: string): boolean {
  const get = () => (typeof window !== 'undefined' && typeof window.matchMedia === 'function' ? window.matchMedia(query).matches : false);
  const [matches, setMatches] = React.useState(get);
  React.useEffect(() => {
    if (typeof window.matchMedia !== 'function') return;
    const list = window.matchMedia(query);
    const onChange = () => setMatches(list.matches);
    onChange();
    list.addEventListener('change', onChange);
    return () => list.removeEventListener('change', onChange);
  }, [query]);
  return matches;
}

/**
 * Observed content width of an element, coalesced to one update per frame and
 * rounded to whole pixels so a drag does not re-render on sub-pixel noise.
 */
export function useElementWidth<T extends HTMLElement>(): [React.RefCallback<T>, number | null] {
  const [width, setWidth] = React.useState<number | null>(null);
  const observer = React.useRef<ResizeObserver | null>(null);
  const frame = React.useRef(0);
  const ref = React.useCallback((node: T | null) => {
    observer.current?.disconnect();
    cancelAnimationFrame(frame.current);
    if (!node || typeof ResizeObserver === 'undefined') return;
    const measure = () => {
      cancelAnimationFrame(frame.current);
      frame.current = requestAnimationFrame(() => setWidth(Math.round(node.getBoundingClientRect().width)));
    };
    observer.current = new ResizeObserver(measure);
    observer.current.observe(node);
    setWidth(Math.round(node.getBoundingClientRect().width));
  }, []);
  React.useEffect(
    () => () => {
      observer.current?.disconnect();
      cancelAnimationFrame(frame.current);
    },
    [],
  );
  return [ref, width];
}

/** Width (px) at which an Encryption Score block switches to three columns — `@[27rem]` in its markup. */
const SCORE_THREE_COLUMN_PX = 432;

/**
 * Encryption Score gauge diameter for the panel's current width: 268 px in the
 * default column (its historical size), growing as the panel is dragged wider
 * or focused, and shrinking only as far as the stacked layout needs on a narrow
 * panel. Shared by the Dashboard Scanner and the Public Quantum Exposure
 * Assessment so the two surfaces size one gauge one way.
 */
export function scoreGaugeSize(width: number | null, focused: boolean): number {
  if (width === null) return 268;
  if (width < SCORE_THREE_COLUMN_PX) return Math.max(200, Math.min(268, width - 40));
  const grown = 268 + (width - 560) * 0.45;
  const size = Math.min(Math.max(grown, 250), focused ? 460 : 400);
  return Math.round(size / 2) * 2;
}

/** Turns relative weights into percentages that sum to 100. */
function normalise(weights: number[]): number[] {
  const total = weights.reduce((sum, weight) => sum + weight, 0) || 1;
  return weights.map((weight) => (weight / total) * 100);
}

function readStoredSizes(key: string, count: number, mins: number[]): number[] | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_PREFIX + key);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length !== count) return null;
    if (!parsed.every((value, index) => typeof value === 'number' && Number.isFinite(value) && value >= mins[index] - 0.01)) {
      return null;
    }
    const sum = (parsed as number[]).reduce((total, value) => total + value, 0);
    return Math.abs(sum - 100) < 0.5 ? (parsed as number[]) : null;
  } catch {
    return null;
  }
}

function writeStoredSizes(key: string, sizes: number[] | null) {
  try {
    if (sizes) window.localStorage.setItem(STORAGE_PREFIX + key, JSON.stringify(sizes.map((size) => Math.round(size * 100) / 100)));
    else window.localStorage.removeItem(STORAGE_PREFIX + key);
  } catch {
    /* Storage unavailable (private window, blocked site data): the layout still works, it is just not remembered. */
  }
}

function templateFor(sizes: number[]): string {
  return sizes.map((size) => `minmax(0, ${size.toFixed(3)}fr)`).join(` ${GUTTER_PX}px `);
}

const sameSizes = (a: number[], b: number[]) => a.every((value, index) => Math.abs(value - b[index]) < 0.05);

/* ----------------------------------------------------------- focus context - */

interface PanelFocusValue {
  /** True for the copy of the panel rendered inside the focus view. */
  focused: boolean;
  title: string;
  open: () => void;
  close: () => void;
}

const PanelFocusContext = React.createContext<PanelFocusValue | null>(null);

/** `focused` is false outside a resizable row, so panels can read it unconditionally. */
export function usePanelFocus(): { focused: boolean } {
  return { focused: React.useContext(PanelFocusContext)?.focused ?? false };
}

/**
 * The header button that opens a panel in the focus view, or closes it from
 * inside. Renders nothing for a panel that is not inside a resizable row.
 */
export function PanelFocusToggle({ className }: { className?: string }) {
  const context = React.useContext(PanelFocusContext);
  if (!context) return null;
  const { focused, title, open, close } = context;
  const label = focused ? `Exit focus view for ${title}` : `Expand ${title} to focus view`;
  const Icon = focused ? Minimize2 : Maximize2;
  return (
    <button
      type="button"
      onClick={focused ? close : open}
      aria-label={label}
      title={focused ? 'Exit focus view (Esc)' : 'Expand to focus view'}
      className={cn(
        '-my-1.5 grid h-[34px] w-[34px] shrink-0 place-items-center rounded-lg border border-white/[0.07] bg-white/[0.03] text-slate-400',
        'transition-colors hover:border-cyan-400/30 hover:bg-cyan-400/[0.08] hover:text-cyan-300',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50',
        className,
      )}
    >
      <Icon className="h-3.5 w-3.5" />
    </button>
  );
}

/* ------------------------------------------------------------- focus view - */

/**
 * The focus view's ground. On the dashboard it re-applies the dashboard's theme
 * scope classes, because the light-theme layer in index.css is scoped to them
 * and <body> sits outside both.
 */
const DASHBOARD_FOCUS_SURFACE = 'qg-dashboard-main dashboard-theme-scope';

function FocusView({
  open,
  title,
  onClose,
  surfaceClassName,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  surfaceClassName: string;
  children: React.ReactNode;
}) {
  const reduce = useReducedMotion();
  const dialogRef = React.useRef<HTMLDivElement>(null);
  const titleId = React.useId();

  React.useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const focusTimer = window.setTimeout(() => dialogRef.current?.focus(), 0);

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key !== 'Tab' || !dialogRef.current) return;
      // Keep keyboard focus inside the dialog while it is open.
      const focusable = Array.from(
        dialogRef.current.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => element.offsetParent !== null);
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialogRef.current)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener('keydown', onKeyDown, true);
    return () => {
      window.clearTimeout(focusTimer);
      window.removeEventListener('keydown', onKeyDown, true);
      document.body.style.overflow = previousOverflow;
      previouslyFocused?.focus?.();
    };
  }, [open, onClose]);

  /* Portalled to <body>: the page's <Reveal> wrappers leave a transform on
     their element, which would make `position: fixed` resolve against the panel
     instead of the viewport (see Modal in ./ui). */
  return createPortal(
    <AnimatePresence>
      {open && (
        <motion.div
          key="focus-view"
          className={cn('fixed inset-0 z-[95] flex flex-col', surfaceClassName)}
          initial={reduce ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={reduce ? { opacity: 0, transition: { duration: 0 } } : { opacity: 0 }}
          transition={{ duration: 0.18 }}
        >
          <div
            ref={dialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            tabIndex={-1}
            className="flex min-h-0 flex-1 flex-col focus:outline-none"
          >
            <div className="flex shrink-0 items-center justify-between gap-3 border-b border-white/[0.07] px-4 py-3 sm:px-6">
              <div className="flex min-w-0 items-center gap-2.5">
                <span className="rounded-md border border-cyan-400/25 bg-cyan-400/[0.08] px-2 py-0.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-cyan-300">
                  Focus view
                </span>
                <h2 id={titleId} className="truncate text-[13px] font-bold uppercase tracking-[0.08em] text-white">
                  {title}
                </h2>
              </div>
              <div className="flex shrink-0 items-center gap-3">
                <span className="hidden font-mono text-[10px] text-slate-500 sm:inline">
                  Press <kbd className="rounded border border-white/[0.12] bg-white/[0.04] px-1.5 py-0.5 text-slate-300">Esc</kbd> to return
                </span>
                <button
                  type="button"
                  onClick={onClose}
                  aria-label={`Close focus view for ${title}`}
                  className="grid h-[34px] w-[34px] place-items-center rounded-lg text-slate-400 transition-colors hover:bg-white/[0.07] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
              <motion.div
                initial={reduce ? false : { opacity: 0, scale: 0.985, y: 10 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
                className="mx-auto w-full max-w-[1680px] p-4 sm:p-6"
              >
                {children}
              </motion.div>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  );
}

/* ------------------------------------------------------------------ row --- */

export interface ResizablePane {
  id: string;
  /** Used for the focus view title and the drag handles' accessible names. */
  title: string;
  /** Relative width at rest, e.g. 1.35 / 0.85 / 1 — the same weights the old `fr` columns used. */
  defaultSize: number;
  /** Narrowest the pane may be dragged, as a percentage of the row. */
  minSize?: number;
  /** The panel, rendered inline and — when focused — again inside the focus view. */
  render: () => React.ReactNode;
}

export function ResizablePanelRow({
  storageKey,
  panes,
  className,
  focusSurfaceClassName = DASHBOARD_FOCUS_SURFACE,
}: {
  /** Distinct per row; the remembered split is stored under it. */
  storageKey: string;
  panes: ResizablePane[];
  className?: string;
  /** Ground for the focus view. Defaults to the dashboard's themed ground; a page outside the dashboard passes its own. */
  focusSurfaceClassName?: string;
}) {
  const desktop = useMediaQuery(DESKTOP_QUERY);
  const containerRef = React.useRef<HTMLDivElement>(null);
  const readoutRef = React.useRef<HTMLSpanElement>(null);

  const defaults = React.useMemo(() => normalise(panes.map((pane) => pane.defaultSize)), [panes]);
  const mins = React.useMemo(() => panes.map((pane) => pane.minSize ?? 18), [panes]);

  const [sizes, setSizes] = React.useState<number[]>(() => readStoredSizes(storageKey, panes.length, mins) ?? defaults);
  const liveSizes = React.useRef(sizes);
  liveSizes.current = sizes;

  const [dragging, setDragging] = React.useState<number | null>(null);
  const [focusedPane, setFocusedPane] = React.useState<string | null>(null);

  const customised = !sameSizes(sizes, defaults);

  const commit = React.useCallback(
    (next: number[]) => {
      setSizes(next);
      writeStoredSizes(storageKey, sameSizes(next, defaults) ? null : next);
    },
    [storageKey, defaults],
  );

  /** Moves the boundary after pane `index` so that pane becomes `target` percent wide. */
  const resizeAt = React.useCallback(
    (base: number[], index: number, target: number): number[] => {
      const pair = base[index] + base[index + 1];
      const left = Math.min(Math.max(target, mins[index]), pair - mins[index + 1]);
      const next = [...base];
      next[index] = left;
      next[index + 1] = pair - left;
      return next;
    },
    [mins],
  );

  const readoutText = React.useCallback(
    (values: number[], index: number) =>
      `${panes[index].title} ${Math.round(values[index])}% · ${panes[index + 1].title} ${Math.round(values[index + 1])}%`,
    [panes],
  );

  const onPointerDown = (index: number) => (event: React.PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0 || !containerRef.current) return;
    event.preventDefault();
    const handle = event.currentTarget;
    handle.setPointerCapture(event.pointerId);
    handle.focus({ preventScroll: true });

    const container = containerRef.current;
    const available = container.getBoundingClientRect().width - GUTTER_PX * (panes.length - 1);
    const startX = event.clientX;
    const start = [...liveSizes.current];
    let current = start;
    let frame = 0;

    const previousCursor = document.body.style.cursor;
    const previousSelect = document.body.style.userSelect;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    setDragging(index);

    /* The drag writes the grid template straight to the DOM and commits to
       React state once, on release — re-rendering every panel on every pointer
       move made the handle trail the cursor. */
    const onMove = (moveEvent: PointerEvent) => {
      const delta = ((moveEvent.clientX - startX) / Math.max(available, 1)) * 100;
      current = resizeAt(start, index, start[index] + delta);
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        container.style.gridTemplateColumns = templateFor(current);
        if (readoutRef.current) readoutRef.current.textContent = readoutText(current, index);
      });
    };
    const finish = () => {
      cancelAnimationFrame(frame);
      handle.removeEventListener('pointermove', onMove);
      handle.removeEventListener('pointerup', finish);
      handle.removeEventListener('pointercancel', finish);
      document.body.style.cursor = previousCursor;
      document.body.style.userSelect = previousSelect;
      setDragging(null);
      commit(current);
    };
    handle.addEventListener('pointermove', onMove);
    handle.addEventListener('pointerup', finish);
    handle.addEventListener('pointercancel', finish);
  };

  const onKeyDown = (index: number) => (event: React.KeyboardEvent<HTMLDivElement>) => {
    const base = liveSizes.current;
    const step = event.shiftKey ? KEY_STEP_LARGE : KEY_STEP;
    let next: number[] | null = null;
    if (event.key === 'ArrowLeft') next = resizeAt(base, index, base[index] - step);
    else if (event.key === 'ArrowRight') next = resizeAt(base, index, base[index] + step);
    else if (event.key === 'Home') next = resizeAt(base, index, mins[index]);
    else if (event.key === 'End') next = resizeAt(base, index, Number.POSITIVE_INFINITY);
    else if (event.key === 'Enter') next = defaults;
    if (!next) return;
    event.preventDefault();
    commit(next);
  };

  const closeFocus = React.useCallback(() => setFocusedPane(null), []);
  const focused = panes.find((pane) => pane.id === focusedPane) ?? null;

  const contexts = React.useMemo(
    () =>
      new Map(
        panes.map((pane) => [
          pane.id,
          {
            inline: { focused: false, title: pane.title, open: () => setFocusedPane(pane.id), close: closeFocus },
            focus: { focused: true, title: pane.title, open: () => setFocusedPane(pane.id), close: closeFocus },
          },
        ]),
      ),
    [panes, closeFocus],
  );

  const children: React.ReactNode[] = [];
  panes.forEach((pane, index) => {
    children.push(
      <div key={pane.id} id={`${storageKey}-${pane.id}`} className="min-w-0">
        <PanelFocusContext.Provider value={contexts.get(pane.id)!.inline}>{pane.render()}</PanelFocusContext.Provider>
      </div>,
    );
    if (index < panes.length - 1 && desktop) {
      const active = dragging === index;
      children.push(
        <div
          key={`${pane.id}-handle`}
          role="separator"
          aria-orientation="vertical"
          aria-label={`Resize ${pane.title} and ${panes[index + 1].title}`}
          aria-controls={`${storageKey}-${pane.id} ${storageKey}-${panes[index + 1].id}`}
          aria-valuenow={Math.round(sizes[index])}
          aria-valuemin={Math.round(mins[index])}
          aria-valuemax={Math.round(sizes[index] + sizes[index + 1] - mins[index + 1])}
          aria-valuetext={readoutText(sizes, index)}
          tabIndex={0}
          title="Drag to resize · double-click to reset"
          onPointerDown={onPointerDown(index)}
          onDoubleClick={() => commit(defaults)}
          onKeyDown={onKeyDown(index)}
          className="group/handle relative flex cursor-col-resize touch-none select-none items-center justify-center focus-visible:outline-none"
        >
          {/* Track: a hairline at rest, lit while hovered, focused or dragged. */}
          <span
            className={cn(
              'absolute inset-y-3 left-1/2 w-px -translate-x-1/2 rounded-full transition-colors duration-150',
              active
                ? 'bg-cyan-400/70'
                : 'bg-transparent group-hover/handle:bg-cyan-400/35 group-focus-visible/handle:bg-cyan-400/60',
            )}
          />
          {/* Grip. */}
          <span
            className={cn(
              'relative z-10 flex h-12 w-[7px] flex-col items-center justify-center gap-[3px] rounded-full border transition-all duration-150',
              active
                ? 'h-16 border-cyan-400/60 bg-cyan-400/20 shadow-[0_0_18px_-2px_rgba(34,211,238,0.55)]'
                : 'border-white/[0.09] bg-white/[0.04] group-hover/handle:h-14 group-hover/handle:border-cyan-400/40 group-hover/handle:bg-cyan-400/10 group-focus-visible/handle:border-cyan-400/60 group-focus-visible/handle:ring-2 group-focus-visible/handle:ring-cyan-400/40',
            )}
          >
            {[0, 1, 2].map((dot) => (
              <span
                key={dot}
                className={cn(
                  'h-[3px] w-[3px] rounded-full transition-colors',
                  active ? 'bg-cyan-300' : 'bg-slate-500 group-hover/handle:bg-cyan-300',
                )}
              />
            ))}
          </span>
          {active && (
            <span className="pointer-events-none absolute -top-1 left-1/2 z-20 -translate-x-1/2 -translate-y-full whitespace-nowrap rounded-md border border-cyan-400/25 bg-[#080d1a]/95 px-2.5 py-1 font-mono text-[10px] font-semibold text-cyan-200 shadow-[0_12px_30px_-10px_rgba(0,0,0,0.8)]">
              <span ref={readoutRef}>{readoutText(sizes, index)}</span>
            </span>
          )}
        </div>,
      );
    }
  });

  return (
    <div className={cn('relative', className)}>
      {desktop && customised && (
        <button
          type="button"
          onClick={() => commit(defaults)}
          className="absolute -top-[18px] right-0 z-10 inline-flex items-center gap-1 rounded font-mono text-[9.5px] font-bold uppercase tracking-[0.14em] text-slate-500 transition-colors hover:text-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50"
        >
          <RotateCcw className="h-3 w-3" /> Reset layout
        </button>
      )}
      <div
        ref={containerRef}
        className={cn('grid', desktop ? 'gap-0' : 'grid-cols-[minmax(0,1fr)] gap-5')}
        style={desktop ? { gridTemplateColumns: templateFor(sizes) } : undefined}
      >
        {children}
      </div>

      <FocusView
        open={focused !== null}
        title={focused?.title ?? ''}
        onClose={closeFocus}
        surfaceClassName={focusSurfaceClassName}
      >
        {focused && (
          <PanelFocusContext.Provider value={contexts.get(focused.id)!.focus}>{focused.render()}</PanelFocusContext.Provider>
        )}
      </FocusView>
    </div>
  );
}
