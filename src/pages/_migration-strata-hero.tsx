import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router-dom';
import { Activity, ArrowRight, ArrowUpRight, CheckCheck, GitBranch, Layers3, Menu, Network, Pause, Play, RefreshCcw, ScanSearch, ShieldCheck, X } from 'lucide-react';
import './migration-strata-hero.css';

const ASSETS = '/migration-hero/strata/';
const STAGES = [
  { label: 'Discover', icon: ScanSearch }, { label: 'Map', icon: Network },
  { label: 'Plan', icon: Layers3 }, { label: 'Orchestrate', icon: GitBranch },
  { label: 'Cutover', icon: ShieldCheck }, { label: 'Monitor', icon: Activity },
] as const;
const PATHS = {
  plan: { title: 'The planning path', body: 'Let inventory and dependencies shape each wave. Rehearse compatibility before execution.' },
  recovery: { title: 'The recovery path', body: 'Validate the change at each checkpoint. Keep rollback and recovery in the migration plan.' },
} as const;
const motionQuery = '(prefers-reduced-motion: reduce)';
function subscribeMotion(onChange: () => void) {
  const query = window.matchMedia(motionQuery);
  query.addEventListener('change', onChange);
  return () => query.removeEventListener('change', onChange);
}
const readMotion = () => window.matchMedia(motionQuery).matches;
const serverMotion = () => true;

export function MigrationStrataHero() {
  const root = useRef<HTMLElement>(null);
  const video = useRef<HTMLVideoElement>(null);
  const menuButton = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLElement>(null);
  const entered = useRef(false);
  const depth = useRef(0);
  const reduced = useSyncExternalStore(subscribeMotion, readMotion, serverMotion);
  const [paused, setPaused] = useState(false);
  const [inView, setInView] = useState(true);
  const [hidden, setHidden] = useState(false);
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [path, setPath] = useState<'plan' | 'recovery'>('plan');
  const running = !reduced && !paused && inView && !hidden;

  useEffect(() => {
    const element = root.current;
    if (!element) return;
    const observer = new IntersectionObserver(([entry]) => setInView(entry.isIntersecting));
    const visibility = () => setHidden(document.hidden);
    observer.observe(element);
    document.addEventListener('visibilitychange', visibility);
    visibility();
    return () => { observer.disconnect(); document.removeEventListener('visibilitychange', visibility); };
  }, []);

  useEffect(() => {
    const element = video.current;
    if (!element) return;
    const sync = () => {
      if (!running) { element.pause(); return; }
      element.muted = true;
      void element.play().catch(() => { /* The inspected local poster remains visible if playback is unavailable. */ });
    };
    element.addEventListener('canplay', sync);
    sync();
    return () => { element.pause(); element.removeEventListener('canplay', sync); };
  }, [running]);

  useEffect(() => {
    const element = root.current;
    if (!element || entered.current) return;
    entered.current = true;
    if (reduced) return;
    const start = Number(document.timeline.currentTime ?? 0);
    const animations: Animation[] = [];
    element.querySelectorAll<HTMLElement>('[data-ms-enter]').forEach(item => {
      const delay = Number(item.dataset.msEnter) * 1000;
      const line = item.dataset.msLine === 'true';
      const animation = item.animate([
        { opacity: 0, transform: line ? 'translateY(110%)' : 'translateY(18px)' },
        { opacity: 1, transform: 'translateY(0)' },
      ], { duration: line ? 780 : 660, delay, easing: 'cubic-bezier(.22,1,.36,1)', fill: 'both' });
      animation.startTime = start;
      animations.push(animation);
    });
    const header = element.closest('.qguard-home')?.querySelector('header');
    const headerItems = header?.querySelectorAll<HTMLElement>('nav a, header > div > a');
    headerItems?.forEach((item, index) => {
      const animation = item.animate([{ opacity: 0, transform: 'translateY(10px)' }, { opacity: 1, transform: 'translateY(0)' }], { duration: 600, delay: index * 45, easing: 'cubic-bezier(.22,1,.36,1)', fill: 'both' });
      animation.startTime = start;
      animations.push(animation);
    });
    return () => animations.forEach(animation => animation.cancel());
  }, [reduced]);

  useEffect(() => {
    const element = root.current;
    if (!element) return;
    if (reduced) {
      depth.current = 0;
      element.style.setProperty('--ms-media-y', '0px');
      element.style.setProperty('--ms-media-scale', '1');
      return;
    }
    if (paused) return;
    let frame = 0, measure = true, target = depth.current;
    const paint = () => {
      frame = 0;
      if (measure) {
        const bounds = element.getBoundingClientRect();
        target = Math.min(1, Math.max(0, -bounds.top / Math.max(1, bounds.height)));
        measure = false;
      }
      const mobile = window.innerWidth < 768;
      depth.current += (target - depth.current) * (mobile ? .3 : .18);
      element.style.setProperty('--ms-media-y', `${-depth.current * (mobile ? 12 : 28)}px`);
      element.style.setProperty('--ms-media-scale', String(1 + depth.current * .03));
      if (Math.abs(target - depth.current) > .0005) frame = requestAnimationFrame(paint);
    };
    const schedule = () => { measure = true; if (!frame) frame = requestAnimationFrame(paint); };
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule);
    schedule();
    return () => { cancelAnimationFrame(frame); window.removeEventListener('scroll', schedule); window.removeEventListener('resize', schedule); };
  }, [reduced, paused]);

  useEffect(() => {
    if (!menuOpen) return;
    menu.current?.querySelector<HTMLAnchorElement>('a')?.focus({ preventScroll: true });
    const keyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault(); setMenuOpen(false); menuButton.current?.focus();
    };
    const outside = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!menu.current?.contains(target) && !menuButton.current?.contains(target)) setMenuOpen(false);
    };
    const resize = () => { if (window.innerWidth >= 1024) setMenuOpen(false); };
    document.addEventListener('keydown', keyDown);
    document.addEventListener('pointerdown', outside);
    window.addEventListener('resize', resize);
    return () => { document.removeEventListener('keydown', keyDown); document.removeEventListener('pointerdown', outside); window.removeEventListener('resize', resize); };
  }, [menuOpen]);

  return (
    <section ref={root} className="migration-strata-hero qguard-dark-stage" aria-labelledby="migration-strata-title" data-running={running} data-path={path}>
      <div className="ms-grid" aria-hidden="true" />
      <div className="ms-shell">
        <div className="ms-main">
          <div className="ms-copy">
            <p className="ms-kicker" data-ms-enter=".08"><span /> Post-Quantum Migration Platform</p>
            <h1 id="migration-strata-title">
              {['See every asset.', 'Plan every wave.', 'Migrate with control.'].map((line, index) => <span className="ms-title-mask" key={line}><span data-ms-enter={.18 + index * .12} data-ms-line="true">{line}</span></span>)}
            </h1>
            <p className="ms-summary" data-ms-enter=".52">Discover your cryptographic estate, rehearse migration waves, and move to PQC with validation and rollback controls.</p>
            <div className="ms-actions" data-ms-enter=".66">
              <Link className="ms-primary" to="/checkout?plan=Pro&cycle=yearly">Choose Pro <ArrowUpRight size={16} /></Link>
              <a className="ms-secondary" href="#lifecycle">Explore lifecycle <ArrowRight size={16} /></a>
            </div>
            <dl className="ms-capability-proof" data-ms-enter=".78">
              <div><dt>CBOM</dt><dd>Map your estate</dd></div>
              <div><dt>Sandbox</dt><dd>Rehearse changes</dd></div>
              <div><dt>Rollback</dt><dd>Plan recovery</dd></div>
            </dl>
          </div>

          <figure className="ms-visual" aria-label="Illustrative layered migration workflow">
            <div className="ms-art-reveal" data-ms-enter=".12">
              <div className="ms-art-mask"><div className="ms-media-depth">
                <img src={ASSETS + 'glass-layers.webp'} width={1200} height={1200} alt="Four floating glass layers representing cryptographic inventory, dependencies, migration waves and validation" className="ms-poster" fetchPriority="high" />
                <video ref={video} className={ready && !failed && !reduced ? 'ms-film is-ready' : 'ms-film'} src={reduced ? undefined : ASSETS + 'glass-layers.mp4'} poster={ASSETS + 'glass-layers.webp'} muted loop playsInline preload={reduced ? 'none' : 'metadata'} aria-hidden="true" onLoadedData={() => { setReady(true); setFailed(false); }} onError={() => { setFailed(true); setReady(false); }} />
              </div></div>
            </div>
            <svg className="ms-paths" viewBox="0 0 680 600" preserveAspectRatio="none" aria-hidden="true">
              <path className="ms-beam ms-beam--plan" d="M232 134C302 134 273 210 343 230S427 256 427 290" />
              <path className="ms-beam ms-beam--recovery" d="M534 407C615 407 620 516 514 526H257C160 526 161 444 239 444" />
              <path className="ms-return-arrow" d="m228 434 12 10-12 10" />
            </svg>
            <button type="button" className="ms-float-card ms-card--plan" data-ms-enter=".58" aria-pressed={path === 'plan'} aria-controls="ms-path-detail" onClick={() => setPath('plan')}>
              <span className="ms-card-icon"><Network size={25} strokeWidth={1.4} /></span>
              <span><small>Migration planning</small><strong>Dependency-aware waves.<br />Rehearsed before rollout.</strong></span><ArrowUpRight className="ms-card-arrow" size={14} />
            </button>
            <button type="button" className="ms-float-card ms-card--recovery" data-ms-enter=".72" aria-pressed={path === 'recovery'} aria-controls="ms-path-detail" onClick={() => setPath('recovery')}>
              <span className="ms-card-icon"><RefreshCcw size={25} strokeWidth={1.4} /></span>
              <span><small>Validation &amp; recovery</small><strong>Validate every cutover.<br />Keep rollback in reach.</strong></span><ArrowUpRight className="ms-card-arrow" size={14} />
            </button>
            <figcaption className="ms-visual-footer"><span>Illustrative migration layers</span><button type="button" className="ms-motion-toggle" onClick={() => setPaused(value => !value)} disabled={reduced} aria-label={reduced ? 'Hero animation disabled by reduced-motion preference' : paused ? 'Play migration animation' : 'Pause migration animation'} aria-pressed={paused || reduced}>{running ? <Pause size={12} /> : <Play size={12} />}{reduced ? 'Reduced motion' : paused ? 'Play motion' : 'Pause motion'}</button></figcaption>
          </figure>
        </div>

        <div className="ms-journey" data-ms-enter=".82">
          <div id="ms-path-detail" className="ms-path-detail" role="status" aria-live="polite" aria-atomic="true"><span>{path === 'plan' ? <GitBranch size={15} /> : <CheckCheck size={15} />}{PATHS[path].title}</span><p>{PATHS[path].body}</p><a href="#capabilities">Inside the platform <ArrowUpRight size={14} /></a></div>
          <ol className="ms-process" aria-label="Migration lifecycle">
            {STAGES.map((stage, index) => { const Icon = stage.icon; return <li key={stage.label}><a href="#lifecycle" className={(path === 'plan' && index === 2) || (path === 'recovery' && index === 4) ? 'is-highlighted' : ''}><Icon size={17} strokeWidth={1.4} /><span>{stage.label}</span></a>{index < STAGES.length - 1 && <ArrowRight className="ms-step-arrow" size={13} aria-hidden="true" />}</li>; })}
          </ol>
        </div>
      </div>

      {typeof document !== 'undefined' && createPortal(<>
        <button ref={menuButton} type="button" className="ms-mobile-toggle" aria-label={menuOpen ? 'Close migration menu' : 'Open migration menu'} aria-expanded={menuOpen} aria-controls="ms-mobile-menu" onClick={() => setMenuOpen(value => !value)}>{menuOpen ? <X size={20} /> : <Menu size={20} />}</button>
        {menuOpen && <nav ref={menu} id="ms-mobile-menu" className="ms-mobile-menu" aria-label="Migration navigation">
          {[['Overview', '#top'], ['Lifecycle', '#lifecycle'], ['Capabilities', '#capabilities'], ['Included', '#included']].map(([label, href]) => <a key={href} href={href} onClick={() => setMenuOpen(false)}>{label}<ArrowUpRight size={15} /></a>)}
          <div><Link to="/login" onClick={() => setMenuOpen(false)}>Sign in</Link><Link className="ms-menu-primary" to="/checkout?plan=Pro&cycle=yearly" onClick={() => setMenuOpen(false)}>Choose Pro <ArrowUpRight size={14} /></Link></div>
        </nav>}
      </>, document.body)}
    </section>
  );
}
