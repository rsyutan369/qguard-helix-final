import { useEffect, useRef, useState, type CSSProperties, type MouseEvent } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import { ArrowLeft, ArrowRight, ArrowUpRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { DarkButton } from './_solution-shared';
import type { ModuleEntry } from './_features-sections';
import './features-book-hero.css';

const PAPERS = ['#193448', '#dce1df', '#245056', '#323e4b', '#e5e0d5'];
const CHAPTER_LABELS: Record<string, string> = { assess: 'Assess', plan: 'Plan', execute: 'Execute', identity: 'Identity', ecosystem: 'Ecosystem', ai: 'AI Copilot' };
const unit = (value: unknown, suffix: string) => typeof value === 'number' ? `${value}${suffix}` : String(value || `0${suffix}`);

export function FeaturesBookHero({ modules }: { modules: ModuleEntry[] }) {
  const navigate = useNavigate();
  const [active, setActive] = useState(Math.min(7, modules.length - 1));
  const reduce = useReducedMotion();
  const links = useRef<Array<HTMLAnchorElement | null>>([]);
  const shelfRef = useRef<HTMLDivElement>(null);
  const activeCoverRef = useRef<HTMLAnchorElement | null>(null);
  const coverHitRef = useRef<HTMLAnchorElement>(null);
  const drag = useRef({ down: false, moved: false, start: 0, index: 0 });
  const selected = modules[active];
  const chapters = [...new Set(modules.map(module => module.chapter))];

  useEffect(() => {
    // A flat sibling link avoids browser hit-testing gaps on the edge-on 3D parent.
    let frame = 0, until = 0;
    const measure = () => {
      const shelf = shelfRef.current, cover = activeCoverRef.current, hit = coverHitRef.current;
      if (shelf && cover && hit) {
        const bounds = shelf.getBoundingClientRect(), face = cover.getBoundingClientRect();
        hit.style.left = `${face.left - bounds.left}px`;
        hit.style.top = `${face.top - bounds.top}px`;
        hit.style.width = `${face.width}px`;
        hit.style.height = `${face.height}px`;
      }
      frame = performance.now() < until ? requestAnimationFrame(measure) : 0;
    };
    const refresh = () => {
      until = performance.now() + (reduce ? 80 : 850);
      if (!frame) frame = requestAnimationFrame(measure);
    };
    const observer = new ResizeObserver(refresh);
    if (shelfRef.current) observer.observe(shelfRef.current);
    refresh();
    return () => { cancelAnimationFrame(frame); observer.disconnect(); };
  }, [active, reduce]);

  useEffect(() => {
    const shelf = shelfRef.current;
    if (!shelf) return;
    let accumulated = 0, previous = 0;
    const wheel = (event: WheelEvent) => {
      if (Math.abs(event.deltaX) <= Math.abs(event.deltaY)) return;
      event.preventDefault();
      if (event.timeStamp - previous > 180) accumulated = 0;
      previous = event.timeStamp;
      accumulated += event.deltaX;
      if (Math.abs(accumulated) > 45) {
        const direction = Math.sign(accumulated);
        setActive(index => Math.max(0, Math.min(modules.length - 1, index + direction)));
        accumulated = 0;
      }
    };
    shelf.addEventListener('wheel', wheel, { passive: false });
    return () => shelf.removeEventListener('wheel', wheel);
  }, [modules.length]);

  useEffect(() => {
    // SolutionLayout resets pathname navigation. Restore a real incoming feature anchor afterward.
    const id = window.location.hash.slice(1);
    const index = modules.findIndex(module => module.id === id);
    if (index < 0) return;
    setActive(index);
    const frame = requestAnimationFrame(() => document.getElementById(id)?.scrollIntoView({ block: 'start' }));
    return () => cancelAnimationFrame(frame);
  }, [modules]);

  const select = (index: number, focus = false) => {
    const next = Math.max(0, Math.min(modules.length - 1, index));
    setActive(next);
    if (focus) requestAnimationFrame(() => links.current[next]?.focus({ preventScroll: true }));
  };
  const follow = (event: MouseEvent<HTMLAnchorElement>, index: number) => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) return;
    const target = document.getElementById(modules[index].id);
    if (target) {
      event.preventDefault();
      // Lenis also handles anchor clicks on document. Let this handler own the
      // jump so it cannot restart scrolling from its pre-navigation position.
      event.stopPropagation();
      setActive(index);
      navigate({ hash: `#${modules[index].id}` }, { preventScrollReset: true });
      target.setAttribute('tabindex', '-1');
      target.focus({ preventScroll: true });
      // Explicitly scroll even when the clicked book already matches the URL hash.
      const longJump = Math.abs(target.getBoundingClientRect().top) > window.innerHeight * 2;
      target.scrollIntoView({ behavior: reduce || longJump ? 'auto' : 'smooth', block: 'start' });
    }
  };

  return (
    <section id="top" className="feature-library-hero" aria-labelledby="feature-library-title">
      <div className="feature-library-intro">
        <div className="feature-library-kicker"><span /> QGuard Helix / Platform Library <span>{modules.length} features</span></div>
        <h1 id="feature-library-title">Discover. Migrate. Govern.<br /><span>Advance your post-quantum readiness.</span></h1>
      </div>
      <nav className="feature-library-chapters" aria-label="Preview a feature chapter">
        {chapters.map(chapter => <button type="button" key={chapter} aria-pressed={selected.chapter === chapter}
          onClick={() => select(modules.findIndex(module => module.chapter === chapter))}>{CHAPTER_LABELS[chapter]}</button>)}
      </nav>
      <div ref={shelfRef} className="feature-book-shelf" role="group" aria-label="Feature books. Use arrow keys to preview; Enter opens the focused feature."
        onKeyDown={event => {
          if (event.key === 'ArrowRight' || event.key === 'ArrowLeft' || event.key === 'Home' || event.key === 'End') {
            event.preventDefault();
            select(event.key === 'Home' ? 0 : event.key === 'End' ? modules.length - 1 : active + (event.key === 'ArrowRight' ? 1 : -1), true);
          }
        }}
        onPointerDown={event => {
          if (event.button !== 0) return;
          drag.current = { down: true, moved: false, start: event.clientX, index: active };
        }}
        onPointerMove={event => {
          const state = drag.current;
          if (!state.down) return;
          const dx = event.clientX - state.start;
          if (Math.abs(dx) > 7) {
            state.moved = true;
            if (!event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.setPointerCapture(event.pointerId);
            select(Math.round(state.index - dx / 54));
          }
        }}
        onPointerUp={event => {
          drag.current.down = false;
          if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
        }}
        onPointerCancel={() => { drag.current.down = false; drag.current.moved = false; }}
        onLostPointerCapture={() => { drag.current.down = false; }}
        onClickCapture={event => { if (drag.current.moved) { event.preventDefault(); event.stopPropagation(); drag.current.moved = false; } }}
      >
        <div className="feature-book-stage">
        <div className="feature-book-ground" aria-hidden="true" />
        {modules.map((module, index) => {
          const distance = index - active;
          const open = distance === 0;
          const Icon = module.icon;
          const light = index % PAPERS.length === 1 || index % PAPERS.length === 4;
          return (
            <motion.div key={module.id}
              title={`Open ${module.title}`}
              className={`feature-book${open ? ' is-open' : ''}${light ? ' is-light' : ''}`}
              style={{ '--book-paper': PAPERS[index % PAPERS.length], '--book-accent': module.accent, zIndex: 30 - Math.abs(distance) } as CSSProperties}
              initial={false} animate={{ x: distance * 53 + (distance < 0 ? -80 : distance > 0 ? 80 : 0), y: open ? -9 : 0, z: open ? 42 : 0, rotateY: open ? -90 : 0, rotateZ: open ? -4 : 0 }}
              transformTemplate={({ x, y, z, rotateY, rotateZ }) => `translate3d(${unit(x, 'px')},${unit(y, 'px')},${unit(z, 'px')}) rotateZ(${unit(rotateZ, 'deg')}) rotateY(${unit(rotateY, 'deg')})`}
              whileHover={reduce || open ? undefined : { y: -8 }}
              transition={{ duration: reduce ? 0 : .65, ease: [.2, .8, .2, 1] }}
              onFocus={() => { if (!drag.current.down && !open) select(index, true); }}
            >
              <a className="feature-book-spine" href={`#${module.id}`} aria-label={`Explore ${module.title}`}
                aria-hidden={open} tabIndex={open ? -1 : 0} draggable={false}
                ref={element => { if (!open) links.current[index] = element; }}
                onClick={event => follow(event, index)}>
                <span className="feature-spine-number">{String(index + 1).padStart(2, '0')}</span>
                <Icon className="feature-spine-icon" size={20} />
                <span className="feature-spine-title">{module.title}</span>
                <span className="feature-spine-brand">QH</span>
              </a>
              <a className="feature-book-cover" href={`#${module.id}`} aria-label={`Explore ${module.title}`}
                aria-hidden={!open} tabIndex={open ? 0 : -1} draggable={false}
                ref={element => { if (open) { links.current[index] = element; activeCoverRef.current = element; } }}
                onClick={event => follow(event, index)}>
                <div className="feature-cover-brand">QGUARD HELIX <span>{String(index + 1).padStart(2, '0')}</span></div>
                <div className="feature-cover-title"><span>{CHAPTER_LABELS[module.chapter]}</span><strong>{module.title}</strong></div>
                <img src={module.image} alt="" draggable={false} />
                <div className="feature-cover-foot"><Icon size={18} /><span>PLATFORM CAPABILITIES</span><ArrowUpRight size={15} /></div>
              </a>
            </motion.div>
          );
        })}
        </div>
        <a ref={coverHitRef} className="feature-book-cover-hit" href={`#${selected.id}`}
          title={`Open ${selected.title}`} aria-hidden="true" tabIndex={-1} draggable={false}
          onClick={event => follow(event, active)} />
      </div>
      <div className="feature-library-caption">
        <button type="button" aria-label="Preview previous feature" disabled={active === 0} onClick={() => select(active - 1)}><ArrowLeft size={18} /></button>
        <div className="feature-caption-center" aria-live="polite" aria-atomic="true">
          <div className="feature-caption-mask"><AnimatePresence mode="wait" initial={false}>
            <motion.a key={selected.id} href={`#${selected.id}`} onClick={event => follow(event, active)}
              initial={reduce ? false : { y: '110%' }} animate={{ y: 0 }} exit={reduce ? undefined : { y: '-110%' }}
              transition={{ duration: reduce ? 0 : .25, ease: [.2, .8, .2, 1] }}>{selected.title}<ArrowUpRight size={18} /></motion.a>
          </AnimatePresence></div>
          <span>{selected.eyebrow} · {String(active + 1).padStart(2, '0')} / {modules.length}</span>
        </div>
        <button type="button" aria-label="Preview next feature" disabled={active === modules.length - 1} onClick={() => select(active + 1)}><ArrowRight size={18} /></button>
      </div>
      <div className="feature-library-message">
        <p>Quantum computers won't simply introduce a new cyber threat—they will redefine cryptographic security. QGuard Helix gives your organization complete visibility into every cryptographic dependency, measures quantum exposure with evidence-backed intelligence, prioritizes the highest-risk migrations, safely validates every change before production, and continuously proves your quantum readiness through a single enterprise platform.</p>
        <strong>Discover. Assess. Migrate. Validate. Prove.</strong>
        <div className="feature-library-actions"><DarkButton to="/public-scan">Start a free assessment</DarkButton><a href="#modules">Explore the platform <ArrowRight size={16} /></a></div>
      </div>
    </section>
  );
}
