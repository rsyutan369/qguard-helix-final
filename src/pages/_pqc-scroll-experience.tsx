import { useEffect, useRef, type ReactNode } from 'react';
import './pqc-scroll-experience.css';

const clamp = (value: number) => Math.min(1, Math.max(0, value));

/** Page-local native-scroll choreography. Geometry reads precede style writes. */
export function PqcScrollExperience({ children }: { children: ReactNode }) {
  const rootRef = useRef<HTMLDivElement>(null);
  const progressRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    const preference = matchMedia('(prefers-reduced-motion: reduce)');
    const hero = root.querySelector<HTMLElement>('.pqc-solutions-hero');
    const chapters = Array.from(root.querySelectorAll<HTMLElement>('.pqc-story-chapter'));
    const images = Array.from(root.querySelectorAll<HTMLImageElement>('section:not(.pqc-solutions-hero) img'));
    let frame = 0;
    const paint = () => {
      frame = 0;
      const vh = window.innerHeight;
      const mobile = window.innerWidth < 768;
      const reduced = preference.matches;
      const scrollable = document.documentElement.scrollHeight - vh;
      const progress = scrollable > 0 ? clamp(window.scrollY / scrollable) : 0;
      const heroRect = hero?.getBoundingClientRect();
      const chapterRects = chapters.map(element => element.getBoundingClientRect());
      const imageRects = images.map(element => element.getBoundingClientRect());
      progressRef.current?.style.setProperty('transform', `scaleX(${progress})`);
      if (hero && heroRect) {
        const exit = reduced ? 0 : clamp(-heroRect.top / heroRect.height);
        hero.style.setProperty('--pqc-hero-depth', `${exit * (mobile ? 10 : 48)}px`);
        hero.style.setProperty('--pqc-stage-scale', String(1 - exit * (mobile ? .015 : .055)));
      }
      chapters.forEach((element, index) => {
        const rect = chapterRects[index];
        if (rect.bottom < -100 || rect.top > vh + 100) return;
        const progress = clamp((vh * .7 - rect.top) / (rect.height + vh * .2));
        element.style.setProperty('--pqc-chapter-progress', reduced ? '1' : progress.toFixed(4));
      });
      images.forEach((element, index) => {
        const rect = imageRects[index];
        if (!reduced && (rect.bottom < -100 || rect.top > vh + 100)) return;
        const travel = clamp((vh - rect.top) / (vh + rect.height)) * 2 - 1;
        const amplitude = mobile ? 5 : Math.min(18, rect.height * .045);
        element.style.setProperty('--pqc-image-y', `${reduced ? 0 : travel * amplitude}px`);
        element.style.setProperty('--pqc-image-scale', reduced ? '1' : mobile ? '1.05' : '1.08');
      });
    };
    const schedule = () => { if (!frame) frame = requestAnimationFrame(paint); };
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule, { passive: true });
    root.addEventListener('load', schedule, true);
    preference.addEventListener('change', schedule);
    const observer = new ResizeObserver(schedule);
    observer.observe(root);
    schedule();
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
      root.removeEventListener('load', schedule, true);
      preference.removeEventListener('change', schedule);
      observer.disconnect();
    };
  }, []);

  return (
    <div ref={rootRef} className="pqc-scroll-experience">
      <div className="pqc-reading-progress" aria-hidden="true"><div ref={progressRef} /></div>
      {children}
    </div>
  );
}
