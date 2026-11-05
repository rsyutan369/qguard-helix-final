import { useRef, useState } from 'react';
import { motion, useReducedMotion, useScroll, useTransform } from 'motion/react';
import { Activity, Box, Crosshair, Database, Network } from 'lucide-react';

const SOURCES = [
  {
    name: 'Inventory',
    icon: Database,
    title: 'Locate vulnerable algorithms.',
    evidence: 'Discovered algorithms, keys, and certificates tied to their assets.',
    decision: 'Identify which assets to assess first and where to fill inventory gaps.',
    route: 'M25 45 H92 Q113 45 132 63 L202 126 H354',
    y: 45,
  },
  {
    name: 'Runtime telemetry',
    icon: Activity,
    title: 'Check what is in use.',
    evidence: 'Runtime observations where telemetry is available, such as negotiated TLS parameters.',
    decision: 'Prioritize changes using observed behavior and investigate gaps in coverage.',
    route: 'M25 126 H354',
    y: 126,
  },
  {
    name: 'Trust relationships',
    icon: Network,
    title: 'See what depends on it.',
    evidence: 'Certificate chains and other observed relationships between cryptographic assets.',
    decision: 'Review which services could be affected before changing a shared dependency.',
    route: 'M25 207 H92 Q113 207 132 189 L202 126 H354',
    y: 207,
  },
];

export function HeroLens() {
  const figure = useRef<HTMLElement>(null);
  const reduced = useReducedMotion();
  const { scrollYProgress } = useScroll({ target: figure, offset: ['start 16%', 'end start'] });
  const y = useTransform(scrollYProgress, [0, 1], [0, 20]);
  const rotateX = useTransform(scrollYProgress, [0, 1], [0, 6]);
  const rotateY = useTransform(scrollYProgress, [0, 1], [0, -9]);

  return (
    <figure className="qa-hero-figure" ref={figure}>
      <div className="qa-hero-stage">
        <motion.div className="qa-hero-scene" style={reduced ? undefined : { y, rotateX, rotateY }}>
          <img
            src="/readiness-assessment/assessment-lens.webp"
            srcSet="/readiness-assessment/assessment-lens-small.webp 768w, /readiness-assessment/assessment-lens.webp 1440w"
            sizes="(max-width: 720px) calc(100vw - 40px), (max-width: 1240px) 52vw, 645px"
            alt="A precision-machined optical instrument focuses several beams on a glass cube, illustrating how assessment evidence converges."
            width={1440}
            height={960}
            fetchPriority="high"
          />
          <div className="qa-hero-orbit" aria-hidden="true"><i /><i /></div>
        </motion.div>
        <span className="qa-viewfinder" aria-hidden="true"><i /><i /><i /><i /></span>
        <span className="qa-figure-label"><Crosshair size={14} aria-hidden="true" /> Assessment lens <small>Concept illustration</small></span>
      </div>
    </figure>
  );
}

export function EvidenceLens() {
  const [selected, setSelected] = useState(0);
  const source = SOURCES[selected];

  return (
    <div className="qa-lens">
      <div className="qa-lens-content">
        <fieldset className="qa-lens-options">
          <legend>Evidence source</legend>
          <div>
            {SOURCES.map(({ name, icon: Icon }, index) => (
              <label key={name}>
                <input type="radio" name="qa-evidence-source" checked={selected === index} onChange={() => setSelected(index)} />
                <span><Icon size={17} aria-hidden="true" /> {name}</span>
              </label>
            ))}
          </div>
        </fieldset>
        <div className="qa-lens-detail" aria-live="polite" aria-atomic="true">
          <h3>{source.title}</h3>
          <dl>
            <div><dt>What you inspect</dt><dd>{source.evidence}</dd></div>
            <div><dt>What it helps you decide</dt><dd>{source.decision}</dd></div>
          </dl>
        </div>
      </div>
      <div className="qa-lens-visual" aria-hidden="true">
        <div className="qa-lens-graphic">
          <svg viewBox="0 0 380 252" fill="none">
            {SOURCES.map(({ name, route, y }) => (
              <g className="qa-lens-wire" key={name}>
                <path d={route} />
                <circle cx="25" cy={y} r="5" />
              </g>
            ))}
            <path key={source.name} className="qa-lens-trace" d={source.route} pathLength="1" />
            <circle className="qa-lens-node" cx="25" cy={source.y} r="5" />
            <circle className="qa-lens-node" cx="354" cy="126" r="5" />
          </svg>
          <div className="qa-lens-prism">
            <span /><span /><span><Box size={35} strokeWidth={1.25} /></span>
          </div>
        </div>
        <div className="qa-lens-legend"><span>{source.name}</span><span>Assessment evidence</span></div>
      </div>
    </div>
  );
}
