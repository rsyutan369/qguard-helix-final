/**
 * Shared marketing-page atmosphere: the bowl-glow background, scroll-linked
 * heading reveals, image zoom-out and Lenis smooth scrolling, matching the
 * homepage (src/pages/landing-motion.ts).
 *
 * Render it once inside a page root that carries the `qh-sky` class. It never
 * changes the page's DOM: heading reveals are drawn with the CSS Custom
 * Highlight API over the existing text nodes, so React keeps full ownership of
 * the markup. Browsers without that API simply show the headings as they are.
 * With `prefers-reduced-motion` only a single still glow frame is painted.
 */
import { useLayoutEffect, useRef } from 'react';
import Lenis from 'lenis';
import 'lenis/dist/lenis.css';
import {
  BOWL_HIDDEN,
  HERO_REVEAL_MS,
  INTRO_DELAY_MS,
  INTRO_MS,
  bowlAt,
  clamp01,
  createBowlPainter,
  mix,
  smoothstep,
} from '@/pages/landing-motion';
import './sky-theme.css';

/** Reveal stages a letter passes through before it reaches its own colour. */
const STAGES = 5;
const SPREAD = 0.35;
/** How far past the last clear section the glow can still be seen (px). */
const GLOW_TAIL = 260;

type Mark = { node: Text; offset: number };
type HeadingGroup = {
  element: HTMLElement;
  marks: Mark[];
  length: number;
  dark: boolean;
  onLoad: boolean;
  progress: number;
};

type HighlightRegistry = Map<string, { add(range: Range): void; clear(): void }>;

function highlightRegistry(): HighlightRegistry | null {
  const registry = (CSS as unknown as { highlights?: HighlightRegistry }).highlights;
  const HighlightCtor = (window as unknown as { Highlight?: new () => { add(range: Range): void; clear(): void } }).Highlight;
  if (!registry || !HighlightCtor) return null;
  for (const tone of ['l', 'd']) {
    for (let stage = 0; stage < STAGES; stage += 1) {
      const name = `sky-${tone}${stage}`;
      if (!registry.has(name)) registry.set(name, new HighlightCtor());
    }
  }
  return registry;
}

function collectMarks(element: HTMLElement): Mark[] {
  const marks: Mark[] = [];
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const text = node.nodeValue ?? '';
    for (let offset = 0; offset < text.length; offset += 1) {
      if (text[offset].trim() !== '') marks.push({ node: node as Text, offset });
    }
  }
  return marks;
}

function collectHeadings(root: HTMLElement): HeadingGroup[] {
  const firstH1 = root.querySelector('main h1');
  return Array.from(root.querySelectorAll<HTMLElement>('main h1, main h2'))
    .filter((element) => !element.closest('[aria-live], [data-sky-static]'))
    .map((element) => {
      const marks = collectMarks(element);
      return {
        element,
        marks,
        length: element.textContent?.length ?? 0,
        dark: element.closest('.qguard-dark-stage') !== null,
        onLoad: element === firstH1,
        progress: -1,
      };
    })
    .filter((group) => group.marks.length > 0);
}

function stageOf(t: number) {
  if (t <= 0) return 0;
  if (t < 0.35) return 1;
  if (t < 0.55) return 2;
  if (t < 0.8) return 3;
  if (t < 1) return 4;
  return STAGES;
}

/** Rebuilds every highlight range from the groups' current progress. */
function paintHeadings(registry: HighlightRegistry, groups: HeadingGroup[]) {
  registry.forEach((highlight, name) => {
    if (name.startsWith('sky-')) highlight.clear();
  });

  groups.forEach((group) => {
    if (group.progress >= 1) return;
    const count = group.marks.length;
    let runStart = 0;
    let runStage = -1;

    const flush = (end: number) => {
      if (runStage < 0 || runStage >= STAGES || end <= runStart) return;
      const first = group.marks[runStart];
      const last = group.marks[end - 1];
      if (!first.node.isConnected || !last.node.isConnected) return;
      try {
        const range = new Range();
        range.setStart(first.node, first.offset);
        range.setEnd(last.node, last.offset + 1);
        registry.get(`sky-${group.dark ? 'd' : 'l'}${runStage}`)?.add(range);
      } catch {
        // The text changed underneath us; the next frame re-collects it.
      }
    };

    for (let i = 0; i < count; i += 1) {
      const stage = stageOf(clamp01((group.progress * (1 + SPREAD) - i / count) / SPREAD));
      if (stage !== runStage) {
        flush(i);
        runStart = i;
        runStage = stage;
      }
    }
    flush(count);
  });
}

/** Marks the sections that sit on the glow and returns where the glow ends. */
function measureClearZone(root: HTMLElement) {
  const main = root.querySelector<HTMLElement>('main');
  if (!main) return 0;
  const sections = Array.from(main.querySelectorAll<HTMLElement>('section')).filter(
    (section) => section.parentElement?.closest('section') === null,
  );
  let end = 0;
  let open = true;
  sections.forEach((section, index) => {
    const clear = open && (index === 0 || section.classList.contains('qguard-dark-stage'));
    if (clear) {
      end = section.offsetTop + section.offsetHeight;
      section.setAttribute('data-sky', index === 0 ? 'hero' : 'clear');
    } else {
      open = false;
      section.removeAttribute('data-sky');
    }
  });
  if (end === 0) end = window.innerHeight;
  main.style.setProperty('--sky-end', `${Math.round(end)}px`);
  return main.offsetTop + end;
}

function useSkyMotion(canvasRef: React.RefObject<HTMLCanvasElement | null>, routeKey: string) {
  useLayoutEffect(() => {
    const canvas = canvasRef.current;
    const root = canvas?.closest<HTMLElement>('.qh-sky');
    if (!canvas || !root) return;

    const paintBowl = createBowlPainter(canvas);
    const aspect = () => window.innerWidth / Math.max(1, window.innerHeight);
    let glowEnd = measureClearZone(root);

    const main = root.querySelector<HTMLElement>('main');
    const resize = new ResizeObserver(() => {
      glowEnd = measureClearZone(root);
    });
    if (main) resize.observe(main);

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      const rest = bowlAt(0);
      paintBowl(rest.tip, rest.half, rest.soft, aspect());
      return () => resize.disconnect();
    }

    const registry = highlightRegistry();
    let groups = registry ? collectHeadings(root) : [];
    groups.forEach((group) => {
      group.progress = 0;
    });
    if (registry) paintHeadings(registry, groups);

    const lenis = new Lenis({
      autoRaf: false,
      lerp: 0.1,
      anchors: { offset: -80 },
      prevent: (node) =>
        node.closest('[data-lenis-prevent], [role="dialog"], .overflow-y-auto, .overflow-auto, .overflow-y-scroll') !== null,
    });

    const start = performance.now();
    const current = { ...BOWL_HIDDEN };
    let frame = 0;
    let lastCollect = start;

    const tick = (time: number) => {
      frame = requestAnimationFrame(tick);
      lenis.raf(time);

      const viewport = window.innerHeight;
      const elapsed = time - start;

      if (window.scrollY < glowEnd + GLOW_TAIL) {
        const target = bowlAt(window.scrollY / viewport);
        const intro = smoothstep((elapsed - INTRO_DELAY_MS) / INTRO_MS);
        if (intro < 1) {
          current.tip = mix(BOWL_HIDDEN.tip, target.tip, intro);
          current.half = mix(BOWL_HIDDEN.half, target.half, intro);
          current.soft = mix(BOWL_HIDDEN.soft, target.soft, intro);
        } else {
          current.tip += (target.tip - current.tip) * 0.12;
          current.half += (target.half - current.half) * 0.12;
          current.soft += (target.soft - current.soft) * 0.12;
        }
        paintBowl(
          current.tip + Math.sin(time * 0.00033 + 1.3) * 0.02,
          current.half + Math.sin(time * 0.0005) * 0.015,
          current.soft,
          aspect(),
        );
      }

      if (registry) {
        // Headings can mount late or change text (tabs, carousels): re-read them.
        if (time - lastCollect > 1200) {
          lastCollect = time;
          const previous = new Map(groups.map((group) => [group.element, group]));
          groups = collectHeadings(root).map((group) => {
            const known = previous.get(group.element);
            // Anything that appears or changes after load is shown as it is.
            group.progress = known && known.length === group.length ? known.progress : 1;
            return group;
          });
        }

        let changed = false;
        groups.forEach((group) => {
          if (group.progress >= 1) return;
          let next: number;
          if (group.onLoad) {
            next = clamp01(elapsed / HERO_REVEAL_MS);
          } else {
            const top = group.element.getBoundingClientRect().top;
            next = clamp01((0.92 - top / viewport) / 0.45);
            // Once shown, a heading stays shown when scrolling back up.
            if (next < group.progress) next = group.progress;
          }
          if (Math.abs(next - group.progress) > 0.002 || (next >= 1 && group.progress < 1)) {
            group.progress = next;
            changed = true;
          }
        });
        if (changed) paintHeadings(registry, groups);
      }

      root.querySelectorAll<HTMLElement>('main img[class*="object-cover"]').forEach((media) => {
        const frameElement = media.parentElement;
        if (!frameElement || media.closest('[data-sky-static]')) return;
        const rect = frameElement.getBoundingClientRect();
        if (rect.bottom < 0 || rect.top > viewport) return;
        if (getComputedStyle(frameElement).overflow === 'visible') return;
        media.style.scale = (1.08 - 0.08 * clamp01(1 - rect.top / viewport)).toFixed(4);
      });
    };
    frame = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(frame);
      resize.disconnect();
      lenis.destroy();
      if (registry) paintHeadings(registry, []);
      root.querySelectorAll<HTMLElement>('main img[class*="object-cover"]').forEach((media) => {
        media.style.scale = '';
      });
    };
  }, [canvasRef, routeKey]);
}

export function SkyAtmosphere({ routeKey }: { routeKey: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useSkyMotion(canvasRef, routeKey);

  return (
    <div className="sky-atmo" aria-hidden="true">
      <canvas ref={canvasRef} width={96} height={60} />
    </div>
  );
}

/** The small cyan dot on a primary button that grows into an arrow on hover. */
export function SkyButtonDot() {
  return (
    <span className="sky-btn__dot" aria-hidden="true">
      <svg viewBox="0 0 12 12" fill="none">
        <path d="M4.5 2.5 8 6l-3.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}
