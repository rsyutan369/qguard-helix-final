import { useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore } from 'react';
import { motion } from 'motion/react';
import { ArrowRight, ArrowUpRight, FileCheck2, Fingerprint, KeyRound, Pause, Play, ShieldCheck, SlidersHorizontal, X } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { TrustSceneApi, TrustSceneState } from './_governance-trust-scene';
import './governance-trust-hero.css';

const DOMAINS = [
  { label: 'Key management', short: 'Keys', icon: KeyRound, title: 'Every key has a lifecycle.', body: 'Connect inventory, ownership, rotation and post-quantum readiness through QKMS.', detail: 'Inventory / Rotation / Readiness' },
  { label: 'Crypto policy', short: 'Policies', icon: SlidersHorizontal, title: 'Policy follows the asset.', body: 'Define cryptographic policy centrally. Surface drift and keep decisions traceable across the estate.', detail: 'Policy / Enforcement / Drift' },
  { label: 'Continuous trust', short: 'Trust', icon: Fingerprint, title: 'Trust requires evidence.', body: 'Connect identity, device and certificate relationships to the findings that support each trust decision.', detail: 'Identity / Devices / Certificates' },
  { label: 'Audit evidence', short: 'Evidence', icon: FileCheck2, title: 'A finding becomes a proof trail.', body: 'Link control mappings to supporting evidence and preserve governance history in the audit vault.', detail: 'Controls / Evidence / Audit vault' },
] as const;

// Subscribe directly so OS preference changes also update an already-open hero.
const motionPreference = '(prefers-reduced-motion: reduce)';
function subscribeMotionPreference(onChange: () => void) {
  const query = window.matchMedia(motionPreference);
  query.addEventListener('change', onChange);
  return () => query.removeEventListener('change', onChange);
}
const readMotionPreference = () => window.matchMedia(motionPreference).matches;
const serverMotionPreference = () => true;

export function GovernanceTrustHero() {
  const root = useRef<HTMLElement>(null);
  const host = useRef<HTMLDivElement>(null);
  const scene = useRef<TrustSceneApi | null>(null);
  const reduced = useSyncExternalStore(subscribeMotionPreference, readMotionPreference, serverMotionPreference);
  const [paused, setPaused] = useState(false);
  const [active, setActive] = useState(0);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const detailCard = useRef<HTMLDivElement>(null);
  const detailTrigger = useRef<HTMLElement | null>(null);
  const state = useRef<TrustSceneState>({ active: 0, running: false, reduced: true, progress: 0, pointerX: 0, pointerY: 0 });
  const running = !reduced && !paused;

  function showFeature(index: number, trigger: HTMLElement) {
    detailTrigger.current = trigger;
    setActive(index);
    setDetailsOpen(true);
  }

  function closeDetails() {
    setDetailsOpen(false);
    detailTrigger.current?.focus({ preventScroll: true });
  }

  useLayoutEffect(() => {
    const card = detailCard.current;
    if (!detailsOpen || !card) return;
    let frame = 0;
    const position = () => {
      frame = 0;
      const bounds = card.getBoundingClientRect();
      const previousShift = Number.parseFloat(card.style.getPropertyValue('--gth-popover-shift')) || 0;
      const naturalTop = bounds.top - previousShift;
      const maxTop = Math.max(80, window.innerHeight - bounds.height - 16);
      const top = Math.min(maxTop, Math.max(80, naturalTop));
      card.style.setProperty('--gth-popover-shift', `${top - naturalTop}px`);
    };
    const schedule = () => { if (!frame) frame = requestAnimationFrame(position); };
    position();
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule);
    return () => { cancelAnimationFrame(frame); window.removeEventListener('scroll', schedule); window.removeEventListener('resize', schedule); };
  }, [detailsOpen, active]);

  useEffect(() => {
    if (!detailsOpen) return;
    detailCard.current?.focus({ preventScroll: true });
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      setDetailsOpen(false);
      detailTrigger.current?.focus({ preventScroll: true });
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [detailsOpen, active]);

  useEffect(() => {
    state.current.active = active;
    state.current.running = running;
    state.current.reduced = reduced;
    scene.current?.invalidate();
  }, [active, running, reduced]);

  useEffect(() => {
    const element = host.current;
    if (!element) return;
    let disposed = false;
    void import('./_governance-trust-scene').then(({ mountTrustScene }) => {
      if (disposed) return;
      scene.current = mountTrustScene(element, () => state.current);
    }).catch(() => { element.dataset.renderer = 'fallback'; });
    return () => { disposed = true; scene.current?.dispose(); scene.current = null; };
  }, []);

  useEffect(() => {
    const element = root.current;
    if (!element) return;
    let frame = 0;
    const update = () => {
      frame = 0;
      if (!state.current.running) return;
      const rect = element.getBoundingClientRect();
      state.current.progress = Math.min(1, Math.max(0, -rect.top / Math.max(1, rect.height * .7)));
    };
    const schedule = () => { if (!frame) frame = requestAnimationFrame(update); };
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule, { passive: true });
    schedule();
    return () => { cancelAnimationFrame(frame); window.removeEventListener('scroll', schedule); window.removeEventListener('resize', schedule); };
  }, [running]);

  const selected = DOMAINS[active];
  const SelectedIcon = selected.icon;
  const entrance = (delay: number) => ({
    initial: reduced ? false as const : { opacity: 0, y: 18 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: .72, delay, ease: [.22, 1, .36, 1] as [number, number, number, number] },
  });

  return (
    <section ref={root} className="governance-trust-hero qguard-dark-stage" aria-labelledby="governance-trust-title" data-motion={running ? 'running' : 'paused'}>
      <div className="gth-horizon" aria-hidden="true" />
      <div className="gth-shell">
        <div className="gth-composition">
          <div className="gth-copy">
            <motion.p className="gth-kicker" {...entrance(.08)}><span /> Quantum Trust &amp; Governance</motion.p>
            <h1 id="governance-trust-title">
              {['Govern trust.', 'Prove it.'].map((line, index) => (
                <span className="gth-line" key={line}><motion.span {...entrance(.16 + index * .1)}>{line}</motion.span></span>
              ))}
            </h1>
            <motion.p className="gth-description" {...entrance(.4)}>
              Unify key management, cryptographic policy and audit evidence. Make every trust decision traceable.
            </motion.p>
            <motion.div className="gth-actions" {...entrance(.52)}>
              <Link className="gth-primary" to="/checkout?plan=Elite&cycle=yearly">Choose Elite <ArrowUpRight size={18} /></Link>
              <a className="gth-secondary" href="#capabilities">Explore capabilities <ArrowRight size={17} /></a>
            </motion.div>
            <motion.div className="gth-assurance" {...entrance(.64)}><ShieldCheck size={16} /><span>One estate. One accountable trust fabric.</span></motion.div>
          </div>

          <motion.div className="gth-architecture" {...entrance(.25)}>
            <div className="gth-diagram-heading"><span>The enterprise trust anchor</span><span className="gth-diagram-type">Conceptual architecture</span></div>
            <div
              className="gth-scene"
              role="group"
              aria-label="Interactive trust architecture. Select a feature node or its label for details."
              tabIndex={-1}
              onClick={event => {
                const index = scene.current?.pick(event.clientX, event.clientY);
                if (index !== null && index !== undefined) showFeature(index, event.currentTarget);
              }}
              onPointerMove={event => {
                const index = scene.current?.pick(event.clientX, event.clientY);
                event.currentTarget.dataset.nodeHover = String(index !== null && index !== undefined);
                if (!running || event.pointerType !== 'mouse') return;
                const rect = event.currentTarget.getBoundingClientRect();
                state.current.pointerX = (event.clientX - rect.left) / rect.width - .5;
                state.current.pointerY = (event.clientY - rect.top) / rect.height - .5;
              }}
              onPointerLeave={event => { state.current.pointerX = 0; state.current.pointerY = 0; event.currentTarget.dataset.nodeHover = 'false'; }}
            >
              <div className="gth-scene-grid" aria-hidden="true" />
              <div ref={host} className="gth-renderer" data-renderer="loading" aria-hidden="true">
                <img className="gth-fallback" src="/governance/trust-fabric-fallback.svg" alt="" width={800} height={640} />
              </div>
              {DOMAINS.map((domain, index) => {
                const Icon = domain.icon;
                return <button key={domain.short} type="button" className={'gth-node-label gth-node-label--' + ['keys', 'policies', 'trust', 'evidence'][index]} data-active={active === index} aria-label={'View ' + domain.label.toLowerCase() + ' details'} aria-expanded={detailsOpen && active === index} aria-controls="gth-feature-popover" onClick={event => { event.stopPropagation(); showFeature(index, event.currentTarget); }}><Icon size={12} />{['Key lifecycle', 'Crypto policy', 'Trust validation', 'Audit evidence'][index]}<ArrowUpRight size={11} /></button>;
              })}
              <div className="gth-anchor-label" aria-hidden="true"><span>QKMS</span>TRUST ANCHOR</div>
              {detailsOpen && (
                <div ref={detailCard} id="gth-feature-popover" className="gth-feature-popover" role="dialog" aria-modal="false" aria-labelledby="gth-feature-title" tabIndex={-1} onClick={event => event.stopPropagation()} onPointerMove={event => event.stopPropagation()}>
                  <div className="gth-popover-heading"><span><SelectedIcon size={16} /><strong id="gth-feature-title">{selected.label}</strong></span><button type="button" aria-label="Close feature details" onClick={closeDetails}><X size={16} /></button></div>
                  <p>{selected.body}</p>
                  <small>{selected.detail}</small>
                </div>
              )}
            </div>
            <div className="gth-scene-footer">
              <span><span className="gth-trace-key" /> Connected by evidence</span>
              <button className="gth-motion-toggle" type="button" onClick={() => setPaused(value => !value)} aria-label={reduced ? 'Hero animation disabled by reduced-motion preference' : running ? 'Pause hero animation' : 'Play hero animation'} aria-pressed={paused || reduced} disabled={reduced}>
                {running ? <Pause size={12} /> : <Play size={12} />} {reduced ? 'Reduced motion' : running ? 'Pause motion' : 'Play motion'}
              </button>
            </div>
          </motion.div>
        </div>

        <div className="gth-explorer">
          <div className="gth-domain-controls" role="group" aria-label="Explore governance capabilities">
            {DOMAINS.map((domain, index) => {
              const Icon = domain.icon;
              return <button key={domain.short} type="button" className="gth-domain" aria-pressed={active === index} aria-controls="gth-domain-detail" onClick={() => setActive(index)}><Icon size={18} /><span>{domain.label}<small>{domain.detail}</small></span><ArrowUpRight size={14} className="gth-domain-arrow" /></button>;
            })}
          </div>
          <div id="gth-domain-detail" className="gth-domain-detail" aria-live="polite" aria-atomic="true">
            <span className="gth-detail-title"><SelectedIcon size={15} />{selected.title}</span>
            <p>{selected.body}</p>
            <a href="#capabilities" aria-label={'Explore ' + selected.label.toLowerCase() + ' capabilities'}>Explore <ArrowRight size={14} /></a>
          </div>
        </div>
      </div>
    </section>
  );
}
