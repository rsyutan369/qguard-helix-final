/**
 * Homepage scroll motion: the bowl-glow atmosphere, scroll-linked letter
 * reveals, fade-ups, image zoom-out and Lenis smooth scrolling.
 *
 * Everything here is presentation only. With `prefers-reduced-motion` the page
 * stays fully static: one glow frame is painted and nothing else runs.
 */
import { useEffect, useLayoutEffect, useRef, type RefObject } from 'react';
import Lenis from 'lenis';
import 'lenis/dist/lenis.css';

type Rgb = readonly [number, number, number];

const WHITE: Rgb = [255, 255, 255];
const BOWL_RIM: Rgb = [0xd2, 0xda, 0xff];
const BOWL_CORE: Rgb = [0x8f, 0xd5, 0xf1];

const LIGHT_TONE = { ghost: WHITE, accent: [0x3f, 0x7c, 0xff] as Rgb };
const DARK_TONE = { ghost: [0x5c, 0x6f, 0x92] as Rgb, accent: [0x8f, 0xe6, 0xf4] as Rgb };

/** Bowl shape per scroll position, in screens scrolled (q = scrollY / innerHeight). */
const BOWL_KEYS = {
  q: [0, 0.03, 0.08, 0.18, 0.4, 0.66, 0.87, 1.15, 1.43, 1.8],
  tip: [0.3, 0.45, 0.65, 0.8, 0.95, 1.05, 1.05, 1.1, 1.3, 2.4],
  half: [0.34, 0.38, 0.38, 0.38, 0.38, 0.46, 0.66, 0.9, 1.6, 3.0],
  soft: [0.22, 0.26, 0.22, 0.22, 0.19, 0.16, 0.13, 0.1, 0.1, 0.1],
};
const BOWL_ROUND = 0.25;
const BOWL_POINTS = 48;
export const BOWL_HIDDEN = { tip: -0.3, half: 0.3, soft: 0.1 };
export const INTRO_DELAY_MS = 250;
export const INTRO_MS = 1050;
export const HERO_REVEAL_MS = 1250;

/** Elements that fade up the first time they enter the viewport. */
const REVEAL_SELECTOR = [
  '.lp-eyebrow',
  '.lp-lede',
  '.lp-hero__body > *',
  '.lp-hero__actions',
  '.lp-note',
  '.lp-instrument',
  '.lp-standards li',
  '.lp-figure',
  '.lp-reasons > li',
  '.lp-stage',
  '.lp-actions > li',
  '.lp-timeline',
  '.lp-timeline__detail',
  '.lp-impact > div',
  '.lp-process__tab',
  '.lp-process__detail',
  '.lp-caps > li',
  '.lp-qa__rows',
  '.lp-qa__console',
  '.lp-points > div',
  '.lp-sandbox > *',
  '.lp-phase',
  '.lp-roadmap__detail',
  '.lp-tabs',
  '.lp-feature',
  '.lp-usecases__list',
  '.lp-usecases__detail',
  '.lp-toggle',
  '.lp-plan',
  '.lp-faq__cats',
  '.lp-faq__item',
  '.lp-cta',
  '.site-footer__grid > *',
  // Opt-in for pages that reuse this motion with their own markup (login, register).
  '[data-lp-reveal]',
].join(',');

const ZOOM_SELECTOR = '.lp-figure img, .lp-feature__media img, .lp-stage video';

export const clamp01 = (value: number) => Math.min(1, Math.max(0, value));
export const smoothstep = (value: number) => {
  const t = clamp01(value);
  return t * t * (3 - 2 * t);
};
export const mix = (a: number, b: number, t: number) => a + (b - a) * t;
const mixRgb = (a: Rgb, b: Rgb, t: number): Rgb => [mix(a[0], b[0], t), mix(a[1], b[1], t), mix(a[2], b[2], t)];

function parseRgb(value: string): Rgb {
  const parts = value.match(/[\d.]+/g);
  if (!parts || parts.length < 3) return [11, 29, 58];
  return [Number(parts[0]), Number(parts[1]), Number(parts[2])];
}

export function bowlAt(q: number) {
  const keys = BOWL_KEYS.q;
  const last = keys.length - 1;
  if (q <= keys[0]) return { tip: BOWL_KEYS.tip[0], half: BOWL_KEYS.half[0], soft: BOWL_KEYS.soft[0] };
  if (q >= keys[last]) return { tip: BOWL_KEYS.tip[last], half: BOWL_KEYS.half[last], soft: BOWL_KEYS.soft[last] };
  let i = 0;
  while (q > keys[i + 1]) i += 1;
  const t = (q - keys[i]) / (keys[i + 1] - keys[i]);
  return {
    tip: mix(BOWL_KEYS.tip[i], BOWL_KEYS.tip[i + 1], t),
    half: mix(BOWL_KEYS.half[i], BOWL_KEYS.half[i + 1], t),
    soft: mix(BOWL_KEYS.soft[i], BOWL_KEYS.soft[i + 1], t),
  };
}

/** Paints the bowl into a tiny canvas; CSS stretches it, so upscaling keeps it soft. */
export function createBowlPainter(canvas: HTMLCanvasElement) {
  const context = canvas.getContext('2d');
  const width = canvas.width;
  const height = canvas.height;
  const image = context?.createImageData(width, height) ?? null;
  const edgeX = new Float32Array(BOWL_POINTS);
  const edgeY = new Float32Array(BOWL_POINTS);

  return (tip: number, half: number, soft: number, aspect: number) => {
    if (!context || !image) return;
    const safeTip = Math.max(tip, 0.001);

    for (let i = 0; i < BOWL_POINTS; i += 1) {
      const yy = -0.3 + ((tip + 0.3) * i) / (BOWL_POINTS - 1);
      edgeX[i] = half * aspect * Math.pow(Math.max(0, 1 - yy / safeTip), 0.72);
      edgeY[i] = yy;
    }

    const data = image.data;
    for (let y = 0; y < height; y += 1) {
      const py = (y + 0.5) / height;
      for (let x = 0; x < width; x += 1) {
        const px = Math.abs((x + 0.5) / width - 0.5) * aspect;

        let nearest = Infinity;
        for (let i = 0; i < BOWL_POINTS - 1; i += 1) {
          const ax = edgeX[i];
          const ay = edgeY[i];
          const bx = edgeX[i + 1] - ax;
          const by = edgeY[i + 1] - ay;
          const lengthSq = bx * bx + by * by;
          const t = lengthSq > 0 ? clamp01(((px - ax) * bx + (py - ay) * by) / lengthSq) : 0;
          const dx = px - (ax + bx * t);
          const dy = py - (ay + by * t);
          const distSq = dx * dx + dy * dy;
          if (distSq < nearest) nearest = distSq;
        }

        const inside = py < tip && px < half * aspect * Math.pow(Math.max(0, 1 - py / safeTip), 0.72);
        const signed = (inside ? -1 : 1) * Math.sqrt(nearest) - BOWL_ROUND;
        const fill = 1 - smoothstep((signed + soft) / (2 * soft));
        const color =
          fill < 0.38
            ? mixRgb(WHITE, BOWL_RIM, smoothstep(fill / 0.38))
            : mixRgb(BOWL_RIM, BOWL_CORE, smoothstep((fill - 0.38) / 0.62));

        const offset = (y * width + x) * 4;
        data[offset] = color[0];
        data[offset + 1] = color[1];
        data[offset + 2] = color[2];
        data[offset + 3] = 255;
      }
    }

    context.putImageData(image, 0, 0);
  };
}

type LetterGroup = {
  element: HTMLElement;
  chars: HTMLElement[];
  finals: Rgb[];
  tone: typeof LIGHT_TONE;
  spread: number;
  onLoad: boolean;
  painted: number;
};

function collectLetterGroups(root: HTMLElement): LetterGroup[] {
  return Array.from(root.querySelectorAll<HTMLElement>('[data-letters]')).map((element) => {
    const chars = Array.from(element.querySelectorAll<HTMLElement>('.lp-ch'));
    return {
      element,
      chars,
      finals: chars.map((char) => parseRgb(getComputedStyle(char).color)),
      tone: element.closest('.lp-section--dark, .lp-dark') ? DARK_TONE : LIGHT_TONE,
      spread: 0.35,
      onLoad: element.dataset.letters === 'load',
      painted: -1,
    };
  });
}

/** Each letter goes invisible, then a blurred ghost, then the accent, then its final colour. */
function paintLetters(group: LetterGroup, progress: number) {
  if (Math.abs(progress - group.painted) < 0.002) return;
  group.painted = progress;
  const count = group.chars.length;

  for (let i = 0; i < count; i += 1) {
    const style = group.chars[i].style;
    const t = clamp01((progress * (1 + group.spread) - i / count) / group.spread);

    if (t >= 1) {
      if (style.opacity !== '') {
        style.opacity = '';
        style.color = '';
        style.filter = '';
      }
      continue;
    }

    let color: Rgb = group.tone.ghost;
    let opacity = 1;
    let blur = 0;
    if (t < 0.35) {
      const local = t / 0.35;
      opacity = local;
      blur = mix(8, 1.5, local);
    } else if (t < 0.7) {
      const local = (t - 0.35) / 0.35;
      color = mixRgb(group.tone.ghost, group.tone.accent, local);
      blur = mix(1.5, 0, local);
    } else {
      color = mixRgb(group.tone.accent, group.finals[i], (t - 0.7) / 0.3);
    }

    style.opacity = opacity.toFixed(3);
    style.color = `rgb(${color[0] | 0},${color[1] | 0},${color[2] | 0})`;
    style.filter = blur > 0.05 ? `blur(${blur.toFixed(2)}px)` : '';
  }
}

function clearLetters(groups: LetterGroup[]) {
  groups.forEach((group) =>
    group.chars.forEach((char) => {
      char.style.opacity = '';
      char.style.color = '';
      char.style.filter = '';
    }),
  );
}

/**
 * Fade-ups: every match of `selector` under `root` starts hidden and rises in
 * the first time it enters the viewport, staggered among its siblings. Marked
 * here (not in markup) so content without motion is never left hidden.
 * Returns the cleanup.
 */
function armReveals(root: HTMLElement, selector: string) {
  const targets = Array.from(root.querySelectorAll<HTMLElement>(selector));
  const siblingIndex = new Map<Element, number>();
  targets.forEach((target) => {
    const parent = target.parentElement;
    const index = parent ? siblingIndex.get(parent) ?? 0 : 0;
    if (parent) siblingIndex.set(parent, index + 1);
    target.style.setProperty('--lp-delay', `${Math.min(index, 5) * 60}ms`);
    target.setAttribute('data-reveal', '');
  });
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.setAttribute('data-in', '');
        observer.unobserve(entry.target);
      });
    },
    { rootMargin: '0px 0px -8% 0px', threshold: 0.05 },
  );
  targets.forEach((target) => observer.observe(target));

  return () => {
    observer.disconnect();
    targets.forEach((target) => {
      target.removeAttribute('data-reveal');
      target.removeAttribute('data-in');
      target.style.removeProperty('--lp-delay');
    });
  };
}

/**
 * The homepage motion for an app surface that scrolls inside an element
 * rather than the window (the dashboard's <main>): bowl glow driven by that
 * element's scroll, letter reveals (`data-letters`), fade-ups
 * (`[data-lp-reveal]`), a scroll-progress value (`--qh-scroll` on the
 * scroller) and Lenis smooth scrolling scoped to the scroller.
 *
 * Nested scroll areas, canvases and anything marked `data-lenis-prevent`
 * scroll natively. `maxScreens` caps how far the glow floods, so long pages
 * keep a calm background. Reduced motion paints one glow frame and nothing else.
 */
export function useScrollerMotion({
  enabled,
  scroller,
  canvas,
  maxScreens = 1.15,
  routeKey,
}: {
  enabled: boolean;
  scroller: HTMLElement | null;
  canvas: HTMLCanvasElement | null;
  maxScreens?: number;
  /** Re-arms reveals, letters and the glow intro when the page inside the scroller changes. */
  routeKey?: string;
}) {
  useLayoutEffect(() => {
    if (!enabled || !scroller) return;

    const paintBowl = canvas ? createBowlPainter(canvas) : null;
    const aspect = () => scroller.clientWidth / Math.max(1, scroller.clientHeight);

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      const rest = bowlAt(0);
      paintBowl?.(rest.tip, rest.half, rest.soft, aspect());
      scroller.style.setProperty('--qh-scroll', '0');
      return;
    }

    scroller.setAttribute('data-motion', '');
    const disarmReveals = armReveals(scroller, '[data-lp-reveal]');
    const groups = collectLetterGroups(scroller);
    groups.forEach((group) => paintLetters(group, 0));

    const lenis = new Lenis({
      wrapper: scroller,
      content: scroller,
      eventsTarget: scroller,
      autoRaf: false,
      lerp: 0.12,
      // Dimensions straight from the scroller, so headers and overlays inside it count.
      __experimental__naiveDimensions: true,
      allowNestedScroll: true,
      prevent: (node) => {
        if (node instanceof HTMLCanvasElement) return true;
        const nested = node.closest('[data-lenis-prevent], [class*="overflow-y-auto"], [class*="overflow-auto"], [class*="overflow-y-scroll"]');
        return nested !== null && nested !== scroller && scroller.contains(nested);
      },
    });

    const start = performance.now();
    const current = { ...BOWL_HIDDEN };
    let frame = 0;
    let lastProgress = -1;

    const tick = (time: number) => {
      frame = requestAnimationFrame(tick);
      lenis.raf(time);

      const viewport = scroller.clientHeight || window.innerHeight;
      const top = scroller.scrollTop;
      const elapsed = time - start;

      if (paintBowl) {
        const target = bowlAt(Math.min(maxScreens, top / viewport));
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

      const max = scroller.scrollHeight - viewport;
      const progress = max > 0 ? clamp01(top / max) : 0;
      if (Math.abs(progress - lastProgress) > 0.001) {
        lastProgress = progress;
        scroller.style.setProperty('--qh-scroll', progress.toFixed(4));
        // The last items can sit inside the observer's bottom margin even at
        // full scroll; at the bottom, nothing may stay hidden.
        if (progress > 0.995) {
          scroller.querySelectorAll('[data-reveal]:not([data-in])').forEach((el) => el.setAttribute('data-in', ''));
        }
      }

      const scrollerTop = scroller.getBoundingClientRect().top;
      groups.forEach((group) => {
        if (group.onLoad) {
          paintLetters(group, clamp01(elapsed / HERO_REVEAL_MS));
          return;
        }
        const offset = group.element.getBoundingClientRect().top - scrollerTop;
        if (offset > viewport * 1.2 && group.painted === 0) return;
        paintLetters(group, clamp01((0.92 - offset / viewport) / 0.45));
      });
    };
    frame = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(frame);
      disarmReveals();
      lenis.destroy();
      clearLetters(groups);
      scroller.removeAttribute('data-motion');
      scroller.style.removeProperty('--qh-scroll');
    };
    // routeKey is a re-arm trigger only; it is not read inside the effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, scroller, canvas, maxScreens, routeKey]);
}

/**
 * Runs the homepage motion for the page rooted at `rootRef`.
 * `scrollLocked` pauses smooth scrolling while a modal is open.
 */
export function useLandingMotion(
  rootRef: RefObject<HTMLElement | null>,
  canvasRef: RefObject<HTMLCanvasElement | null>,
  scrollLocked: boolean,
  {
    allowNestedScroll = false,
    animate = true,
    smoothAnchors = true,
    routeKey,
  }: { allowNestedScroll?: boolean; animate?: boolean; smoothAnchors?: boolean; routeKey?: string } = {},
) {
  const lenisRef = useRef<Lenis | null>(null);

  useLayoutEffect(() => {
    const root = rootRef.current;
    const canvas = canvasRef.current;
    if (!root || !canvas) return;

    const paintBowl = createBowlPainter(canvas);
    const aspect = () => window.innerWidth / Math.max(1, window.innerHeight);

    if (!animate || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      const rest = bowlAt(0);
      paintBowl(rest.tip, rest.half, rest.soft, aspect());
      return;
    }

    root.setAttribute('data-motion', '');
    const disarmReveals = armReveals(root, REVEAL_SELECTOR);

    const groups = collectLetterGroups(root);
    groups.forEach((group) => paintLetters(group, 0));

    const lenis = new Lenis({
      autoRaf: false,
      lerp: 0.1,
      anchors: smoothAnchors ? { offset: -88 } : false,
      allowNestedScroll,
      prevent: (node) => node.closest('.qh-nav__panel, .lp-modal, .lp-console__log, [data-lenis-prevent]') !== null,
    });
    lenisRef.current = lenis;

    const start = performance.now();
    const current = { ...BOWL_HIDDEN };
    const cover = root.querySelector<HTMLElement>('.lp-section--dark, [data-lp-glow-cover]');
    let frame = 0;

    const tick = (time: number) => {
      frame = requestAnimationFrame(tick);
      lenis.raf(time);

      const viewport = window.innerHeight;
      const elapsed = time - start;

      // The glow is only visible behind the opening sections.
      const glowVisible = !cover || cover.getBoundingClientRect().top > 0;
      if (glowVisible) {
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

      groups.forEach((group) => {
        if (group.onLoad) {
          paintLetters(group, clamp01(elapsed / HERO_REVEAL_MS));
          return;
        }
        const top = group.element.getBoundingClientRect().top;
        if (top > viewport * 1.2 && group.painted === 0) return;
        paintLetters(group, clamp01((0.92 - top / viewport) / 0.45));
      });

      root.querySelectorAll<HTMLElement>(ZOOM_SELECTOR).forEach((media) => {
        const rect = (media.parentElement ?? media).getBoundingClientRect();
        if (rect.bottom < 0 || rect.top > viewport) return;
        const scale = 1.08 - 0.08 * clamp01(1 - rect.top / viewport);
        media.style.transform = `scale(${scale.toFixed(4)})`;
      });
    };
    frame = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(frame);
      disarmReveals();
      lenis.destroy();
      lenisRef.current = null;
      clearLetters(groups);
      root.removeAttribute('data-motion');
      root.querySelectorAll<HTMLElement>(ZOOM_SELECTOR).forEach((media) => {
        media.style.transform = '';
      });
    };
  }, [rootRef, canvasRef, allowNestedScroll, animate, smoothAnchors, routeKey]);

  useEffect(() => {
    const lenis = lenisRef.current;
    if (!lenis) return;
    if (scrollLocked) lenis.stop();
    else lenis.start();
  }, [scrollLocked, animate, routeKey]);
}
