import { useEffect, useRef, useState } from 'react';
import { Pause, Play, ChevronLeft, ChevronRight } from 'lucide-react';
import './pqc-scanner-hero.css';

export type HeroMapping = { problem: string; module: string };
const IMAGES = ['/Digital_certificates.png', '/ownership.png', '/monitoring.png', '/Scanner.png', '/Encryption_key.png', '/migration_wizard.png'];
const hash = (a: number, b: number, c: number) => {
  let h = (Math.imul(a, 374761393) + Math.imul(b, 668265263) + Math.imul(c, 2147483647)) | 0;
  h = Math.imul(h ^ (h >>> 13), 1274126177);
  return ((h ^ (h >>> 16)) >>> 0) / 4294967296;
};

/** Decorative problem-to-capability illustration, never a live scan or tenant result. */
export function PqcScannerHero({ mappings }: { mappings: HeroMapping[] }) {
  const stageRef = useRef<HTMLDivElement>(null);
  const cardsRef = useRef<Array<HTMLDivElement | null>>([]);
  const codesRef = useRef<Array<HTMLDivElement | null>>([]);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const engineRef = useRef({ offset: 0, velocity: 0, dragging: false, hover: false, paused: false, x: 0, time: 0, nudge: 0 });
  const [paused, setPaused] = useState(false);

  useEffect(() => { engineRef.current.paused = paused; }, [paused]);

  useEffect(() => {
    const stage = stageRef.current;
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!stage || !canvas || !ctx || !mappings.length) return;
    const engine = engineRef.current;
    const media = matchMedia('(prefers-reduced-motion: reduce)');
    let reduced = media.matches;
    let visible = true;
    let width = 0, height = 0, cw = 0, ch = 0, gap = 0;
    let frame = 0, last = 0, paintedOffset = Number.NaN;
    const resize = () => {
      const previousSpan = cw + gap;
      width = stage.clientWidth;
      height = stage.clientHeight;
      const style = getComputedStyle(stage);
      cw = parseFloat(style.getPropertyValue('--card-width'));
      ch = parseFloat(style.getPropertyValue('--card-height'));
      gap = width < 768 ? 24 : 52;
      engine.offset = previousSpan ? engine.offset * (cw + gap) / previousSpan : width / 2 - cw * .62;
      const dpr = Math.min(devicePixelRatio || 1, 2);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(canvas.width / width, 0, 0, canvas.height / height, 0, 0);
      paintedOffset = Number.NaN;
    };
    const observer = new ResizeObserver(resize);
    observer.observe(stage);
    const intersection = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; });
    intersection.observe(stage);
    const motionChange = () => { reduced = media.matches; engine.velocity = 0; };
    media.addEventListener('change', motionChange);
    const wheel = (event: WheelEvent) => {
      if (Math.abs(event.deltaX) <= Math.abs(event.deltaY)) return;
      event.preventDefault();
      engine.nudge -= event.deltaX;
    };
    stage.addEventListener('wheel', wheel, { passive: false });
    let previousScroll = window.scrollY;
    const scrub = () => {
      const delta = window.scrollY - previousScroll;
      previousScroll = window.scrollY;
      if (visible && !engine.dragging && !engine.paused && !reduced) {
        engine.nudge -= delta * .65;
      }
    };
    window.addEventListener('scroll', scrub, { passive: true });
    resize();
    const palette = ['#7c3aed', '#8b5cf6', '#a78bfa', '#06b6d4', '#67e8f9', '#ddd6fe', '#f5f3ff'];
    const draw = (now: number) => {
      const dt = last ? Math.min((now - last) / 1000, .04) : 0;
      last = now;
      if (visible && !document.hidden) {
        const active = !engine.paused && !reduced;
        if (!engine.dragging) {
          const target = active ? -width * .055 * (engine.hover ? .35 : 1) : 0;
          engine.velocity += (target - engine.velocity) * (1 - Math.exp(-2.2 * dt));
          if (!active) engine.velocity = 0;
          engine.offset += engine.velocity * dt;
        }
        engine.offset += engine.nudge;
        engine.nudge = 0;
        const span = cw + gap;
        const period = span * mappings.length;
        engine.offset = ((engine.offset % period) + period) % period;
        if (!active && paintedOffset === engine.offset) {
          frame = requestAnimationFrame(draw);
          return;
        }
        paintedOffset = engine.offset;
        ctx.clearRect(0, 0, width, height);
        const line = width / 2;
        mappings.forEach((_, i) => {
          const x = ((engine.offset + i * span + span) % period) - span;
          const cut = Math.max(0, Math.min(cw, line - x));
          const card = cardsRef.current[i], code = codesRef.current[i];
          if (!card || !code) return;
          card.style.transform = code.style.transform = `translate3d(${x}px,0,0)`;
          card.style.clipPath = `inset(0 0 0 ${cut}px)`;
          code.style.clipPath = `inset(0 ${cw - cut}px 0 0)`;
          if (cut <= 0 || cut >= cw) return;
          const radius = Math.min(cw * .3, 160);
          const glow = ctx.createLinearGradient(line, 0, line + radius, 0);
          glow.addColorStop(0, 'rgba(139,92,246,.36)');
          glow.addColorStop(1, 'rgba(6,182,212,0)');
          ctx.fillStyle = glow;
          ctx.fillRect(line, 70, Math.min(radius, x + cw - line), ch);
          const tick = active && !engine.dragging ? Math.floor(now * .008) : 0;
          for (let gx = Math.ceil(cut / 4); gx * 4 < Math.min(cw, cut + radius); gx++) {
            const sx = x + gx * 4;
            const probability = Math.pow(1 - (sx - line) / radius, 1.7);
            for (let row = -3; row < ch / 4 + 3; row++) {
              const outside = row < 0 || row * 4 > ch;
              if (hash(gx, row, i) > probability * (outside ? .12 : .88) || hash(gx, row, tick + 97) < .2) continue;
              const h = hash(row, gx, i + 31);
              ctx.fillStyle = palette[sx - line < 10 ? 4 + Math.floor(h * 3) : Math.floor(h * 7)];
              const size = 1 + h * 1.8;
              ctx.fillRect(sx, 70 + row * 4, size, size);
            }
          }
        });
      }
      frame = requestAnimationFrame(draw);
    };
    frame = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      intersection.disconnect();
      media.removeEventListener('change', motionChange);
      stage.removeEventListener('wheel', wheel);
      window.removeEventListener('scroll', scrub);
    };
  }, [mappings]);

  return (
    <div className="pqc-scanner" role="region" aria-label="Six problems and their QGuard Helix solutions">
      <div className="pqc-scanner-heading">
        <span>PROBLEM_LEDGER // SIX PROBLEMS, ONE PLATFORM</span>
        <span className="pqc-scanner-traced"><i /> ALL TRACED</span>
      </div>
      <div className="pqc-scanner-stage" ref={stageRef}
        onPointerEnter={() => { engineRef.current.hover = true; }}
        onPointerLeave={() => { engineRef.current.hover = false; }}
        onPointerDown={event => {
          if (event.button !== 0) return;
          event.currentTarget.setPointerCapture(event.pointerId);
          Object.assign(engineRef.current, { dragging: true, x: event.clientX, time: event.timeStamp, velocity: 0 });
        }}
        onPointerMove={event => {
          const e = engineRef.current;
          if (!e.dragging) return;
          const dx = event.clientX - e.x;
          e.offset += dx;
          e.velocity = dx / Math.max(8, event.timeStamp - e.time) * 800 + e.velocity * .2;
          e.x = event.clientX; e.time = event.timeStamp;
        }}
        onPointerUp={event => {
          engineRef.current.dragging = false;
          if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
        }}
        onPointerCancel={() => { engineRef.current.dragging = false; engineRef.current.velocity = 0; }}
        onLostPointerCapture={() => { engineRef.current.dragging = false; }}
      >
        <div className="pqc-scanner-codes" aria-hidden="true">
          {mappings.map((row, i) => (
            <div className="pqc-scanner-code" key={row.problem} ref={el => { codesRef.current[i] = el; }}>
              <span className="pqc-code-label">QGUARD HELIX / CAPABILITY MAP</span>
              <pre>{`<workflow>\n  <problem>\n    ${row.problem}\n  </problem>\n\n  <capability>\n    ${row.module}\n  </capability>\n\n  <checkpoints>\n    Visibility\n    Ownership\n    Dependencies\n    Risk\n    Migration Gate\n  </checkpoints>\n</workflow>`}</pre>
            </div>
          ))}
        </div>
        <div className="pqc-scanner-cards" aria-hidden="true">
          {mappings.map((row, i) => (
            <div className="pqc-scanner-card" key={row.problem} ref={el => { cardsRef.current[i] = el; }}>
              <img src={IMAGES[i % IMAGES.length]} alt="" draggable={false} />
              <div className="pqc-card-wash" />
              <div className="pqc-card-brand"><span className="pqc-card-symbol">Q</span> QGUARD HELIX <span>PQC SOLUTIONS</span></div>
              <div className="pqc-card-content"><span>THE PROBLEM</span><h2>{row.problem}</h2><div className="pqc-card-rule" /><span>THE CAPABILITY</span><p>{row.module}</p></div>
              <div className="pqc-card-foot">DISCOVER → ASSESS → PLAN → MIGRATE</div>
            </div>
          ))}
        </div>
        <canvas ref={canvasRef} className="pqc-scanner-fx" aria-hidden="true" />
        <div className="pqc-scanner-line" aria-hidden="true"><i /><b /></div>
        <div className="pqc-scanner-badge" aria-hidden="true"><span>Six problems. One platform.</span><strong>QGUARD <i>HELIX</i></strong></div>
      </div>
      <ul className="sr-only">{mappings.map(row => <li key={row.problem}>{row.problem}: {row.module}</li>)}</ul>
      <div className="pqc-scanner-footer">
        <span>Visibility → Ownership → Dependencies → Risk → Migration Gate</span>
        <div className="pqc-scanner-controls">
          <button type="button" aria-label="Previous solution" onClick={() => { engineRef.current.nudge += 280; }}><ChevronLeft size={15} /></button>
          <button type="button" aria-label={paused ? 'Play hero animation' : 'Pause hero animation'} aria-pressed={paused} onClick={() => setPaused(value => !value)}>{paused ? <Play size={13} /> : <Pause size={13} />}</button>
          <button type="button" aria-label="Next solution" onClick={() => { engineRef.current.nudge -= 280; }}><ChevronRight size={15} /></button>
        </div>
      </div>
    </div>
  );
}
