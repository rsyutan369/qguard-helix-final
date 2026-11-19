import { useEffect, useRef, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Activity, ArrowDown, ArrowRight, ArrowUpRight, Award, BrainCircuit, Check,
  EyeOff, FileText, Fingerprint, Gauge, GitBranch, Layers3, LockKeyhole, Menu,
  Network, Radar, ScanSearch, ShieldAlert, ShieldCheck, Sparkles, Wrench, X,
} from 'lucide-react';
import { EvidenceLens, HeroLens } from './_lenses';
import { SkyAtmosphere } from '@/components/sky/SkyAtmosphere';
import './assessment.css';

const DASHBOARD = '/dashboard/quantum-readiness';
const ART = '/readiness-assessment';
const NAV = [
  { label: 'Overview', href: '#top' },
  { label: 'Scoring', href: '#scoring' },
  { label: 'Modules', href: '#modules' },
  { label: 'Standards', href: '#standards' },
];

const STANDARDS = [
  { algorithm: 'ML-KEM', purpose: 'Key establishment', standard: 'FIPS 203', url: 'https://csrc.nist.gov/pubs/fips/203/final' },
  { algorithm: 'ML-DSA', purpose: 'Digital signatures', standard: 'FIPS 204', url: 'https://csrc.nist.gov/pubs/fips/204/final' },
  { algorithm: 'SLH-DSA', purpose: 'Stateless hash-based signatures', standard: 'FIPS 205', url: 'https://csrc.nist.gov/pubs/fips/205/final' },
];

const LIFECYCLE = [
  { icon: ScanSearch, title: 'Discover', body: 'Inventory algorithms, keys, and certificates.' },
  { icon: Gauge, title: 'Assess', body: 'Identify exposure and review the evidence behind each finding.' },
  { icon: GitBranch, title: 'Plan', body: 'Group changes by risk, dependency, and rollout order.' },
  { icon: Wrench, title: 'Migrate', body: 'Roll out changes with a recovery path.' },
  { icon: ShieldCheck, title: 'Validate', body: 'Check the resulting configuration against readiness criteria.' },
  { icon: Activity, title: 'Monitor', body: 'Watch for drift after cutover.' },
  { icon: FileText, title: 'Govern', body: 'Record decisions and retain supporting evidence.' },
];

const MODULES = [
  { icon: Network, title: 'Quantum Exposure Graph', body: 'Trace cryptographic dependencies and see what a change could affect.', to: `${DASHBOARD}/exposure-graph` },
  { icon: ShieldAlert, title: 'Quantum Risk Analysis', body: 'Review affected assets and the evidence behind risk findings.', to: `${DASHBOARD}/risk-analysis` },
  { icon: Wrench, title: 'Quantum Remediation Engine', body: 'Turn findings into asset-level remediation steps.', to: `${DASHBOARD}/remediation` },
  { icon: Sparkles, title: 'AI Executive Advisor', body: 'Translate findings into priorities that leadership can review.', to: `${DASHBOARD}/ai-executive-advisor` },
  { icon: EyeOff, title: 'Harvest Now, Decrypt Later', body: 'Prioritize sensitive data by exposure and confidentiality lifetime.', to: '/dashboard/harvest-now' },
  { icon: Award, title: 'Quantum Trust Certification', body: 'Review the evidence needed to issue a readiness certificate.', to: '/dashboard/quantum-certification' },
  { icon: FileText, title: 'Report Center', body: 'Package assessment findings and supporting evidence for review.', to: `${DASHBOARD}/reports` },
];

function AssessmentHeader() {
  const [expanded, setExpanded] = useState(false);
  const toggle = useRef<HTMLButtonElement>(null);
  const nav = useRef<HTMLElement>(null);

  useEffect(() => {
    if (expanded) nav.current?.querySelector<HTMLAnchorElement>("a")?.focus();
  }, [expanded]);

  return (
    <header
      className="qa-header"
      onKeyDown={(event) => {
        if (event.key === 'Escape' && expanded) {
          setExpanded(false);
          toggle.current?.focus();
        }
      }}
    >
      <div className="qa-container qa-nav">
        <Link to="/" className="qa-brand" aria-label="Qguard Helix home">
          <img src="/NEW_LOGO.png" alt="" width="35" height="35" />
          <span>Qguard Helix<small>ASSESSMENT ENGINE</small></span>
        </Link>
        <nav ref={nav} id="qa-navigation" className="qa-nav-links" aria-label="Assessment" data-expanded={expanded}>
          {NAV.map(({ label, href }) => (
            <a
              key={href}
              href={href}
              onClick={() => {
                setExpanded(false);
                document.getElementById(href.slice(1))?.focus({ preventScroll: true });
              }}
            >
              {label}
            </a>
          ))}
          <Link to="/public-scan" onClick={() => setExpanded(false)}>Free scan <ArrowUpRight size={14} aria-hidden="true" /></Link>
        </nav>
        <Link className="qa-button qa-button--nav" to="/login">Launch app <ArrowUpRight size={15} aria-hidden="true" /></Link>
        <button
          ref={toggle}
          className="qa-menu"
          type="button"
          aria-label={expanded ? 'Close assessment navigation' : 'Open assessment navigation'}
          aria-expanded={expanded}
          aria-controls="qa-navigation"
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
        </button>
      </div>
    </header>
  );
}

export default function QuantumReadinessAssessmentPage() {
  const { hash } = useLocation();
  useEffect(() => {
    const previous = document.title;
    document.title = 'Quantum Readiness Assessment | Qguard Helix';
    return () => { document.title = previous; };
  }, []);
  useEffect(() => {
    if (hash) {
      document.getElementById(hash.slice(1))?.scrollIntoView();
    } else {
      window.scrollTo({ top: 0 });
    }
  }, [hash]);

  return (
    <div className="qguard-home qguard-home--light qh-sky qa-page">
      <SkyAtmosphere routeKey="quantum-readiness-assessment" />
      <a className="qa-skip" href="#qa-main">Skip to assessment content</a>
      <AssessmentHeader />
      <main id="qa-main" tabIndex={-1}>
        <section id="top" tabIndex={-1} className="qa-hero" aria-labelledby="qa-title">
          <div className="qa-container qa-hero-grid">
            <div className="qa-hero-copy">
              <span className="qa-kicker"><Radar size={16} aria-hidden="true" /> Quantum Readiness Assessment</span>
              <h1 id="qa-title">See quantum risk.<br /><span>Plan what changes.</span></h1>
              <p className="qa-lede">Find where your organization relies on quantum-vulnerable cryptography, trace the evidence behind each finding, and decide what to migrate first.</p>
              <div className="qa-actions">
                <Link className="qa-button qa-button--primary" to={DASHBOARD}>Open assessment <ArrowUpRight aria-hidden="true" /></Link>
                <a className="qa-button qa-button--secondary" href="#scoring">Explore scoring <ArrowDown aria-hidden="true" /></a>
              </div>
              <p className="qa-hero-note"><Fingerprint size={16} aria-hidden="true" /> Built for security, infrastructure, and risk teams</p>
            </div>
            <HeroLens />
          </div>
          <div className="qa-container qa-reference-strip" aria-label="NIST post-quantum standards">
            <span className="qa-reference-title"><ShieldCheck size={19} aria-hidden="true" /> NIST PQC standards</span>
            {STANDARDS.map(({ algorithm, standard }) => (
              <a key={algorithm} href="#standards"><span>{algorithm}</span><small>{standard}</small></a>
            ))}
          </div>
        </section>

        <section className="qa-section" aria-labelledby="qa-exposure-title">
          <div className="qa-container qa-exposure">
            <figure className="qa-editorial-figure">
              <img src={`${ART}/archived-traffic.webp`} width={1200} height={800} loading="lazy" decoding="async" alt="A branch of a fiber-optic signal is diverted into a separate archive layer." />
              <figcaption><EyeOff size={15} aria-hidden="true" /> Illustration of encrypted traffic being captured</figcaption>
            </figure>
            <div>
              <span className="qa-kicker"><LockKeyhole size={16} aria-hidden="true" /> Harvest now, decrypt later</span>
              <h2 id="qa-exposure-title">How long does your data need to stay secret?</h2>
              <p>Attackers can store encrypted traffic today and attempt to decrypt it later. Data that needs to stay confidential for years deserves an early look, especially when its protection relies on RSA or elliptic-curve cryptography.</p>
              <ul className="qa-checks">
                <li><Check aria-hidden="true" /> Identify where vulnerable algorithms protect sensitive data.</li>
                <li><Check aria-hidden="true" /> Compare confidentiality requirements with migration lead time.</li>
              </ul>
              <Link className="qa-text-link" to="/dashboard/harvest-now">Explore HNDL exposure <ArrowRight aria-hidden="true" /></Link>
            </div>
          </div>
        </section>

        <section id="scoring" tabIndex={-1} className="qa-section qa-scoring" aria-labelledby="qa-scoring-title">
          <div className="qa-container">
            <div className="qa-section-head">
              <h2 id="qa-scoring-title">See what goes into a readiness score.</h2>
              <p>Choose an evidence source to see what it contributes to the assessment and which decision it helps you make.</p>
            </div>
            <EvidenceLens />
            <dl className="qa-indicators" aria-label="Assessment indicators">
              <div><dt>Quantum readiness</dt><dd>Overall posture from available evidence.</dd></div>
              <div><dt>Quantum risk</dt><dd>Exposure from vulnerable cryptography and affected assets.</dd></div>
              <div><dt>HNDL risk</dt><dd>Exposure of data that must stay confidential over time.</dd></div>
              <div><dt>PQC adoption</dt><dd>Extent of post-quantum cryptography in assessed assets.</dd></div>
              <div><dt>Assets assessed</dt><dd>Coverage across inventoried assets.</dd></div>
              <div><dt>Keys discovered</dt><dd>Keys identified in the assessment inventory.</dd></div>
            </dl>
          </div>
        </section>

        <section className="qa-section qa-lifecycle" aria-labelledby="qa-lifecycle-title">
          <div className="qa-container">
            <div className="qa-section-head">
              <h2 id="qa-lifecycle-title">From first scan to verified change.</h2>
              <p>Start with an inventory. Use the evidence to plan the rollout, validate the change, and monitor what happens next.</p>
            </div>
            <ol className="qa-stages">
              {LIFECYCLE.map(({ icon: Icon, title, body }) => (
                <li key={title}><Icon aria-hidden="true" /><h3>{title}</h3><p>{body}</p></li>
              ))}
            </ol>
          </div>
        </section>

        <section id="modules" tabIndex={-1} className="qa-section qa-modules" aria-labelledby="qa-modules-title">
          <div className="qa-container">
            <div className="qa-section-head">
              <h2 id="qa-modules-title">Turn findings into a migration plan.</h2>
              <p>Start in the assessment dashboard, then follow the evidence into the tools your team needs.</p>
            </div>
            <article className="qa-spotlight">
              <div>
                <span className="qa-kicker"><BrainCircuit size={17} aria-hidden="true" /> AI Migration Advisor</span>
                <h3>Sequence the rollout.</h3>
                <p>Group migrations into waves, inspect dependencies, and review validation and rollback steps before making changes.</p>
                <Link className="qa-text-link" to={`${DASHBOARD}/ai-migration-advisor`}>Open Migration Advisor <ArrowRight aria-hidden="true" /></Link>
              </div>
              <img src={`${ART}/migration-waves.webp`} width={1200} height={800} loading="lazy" decoding="async" alt="A single optical route connects four ascending circuit layers, illustrating staged migration." />
            </article>
            <div className="qa-module-grid">
              {MODULES.map(({ icon: Icon, title, body, to }) => (
                <Link key={to} className="qa-module" to={to}>
                  <Icon className="qa-module-icon" aria-hidden="true" />
                  <div><h3>{title}</h3><p>{body}</p></div>
                  <ArrowUpRight className="qa-module-arrow" aria-hidden="true" />
                </Link>
              ))}
            </div>
          </div>
        </section>

        <section id="standards" tabIndex={-1} className="qa-section qa-standards" aria-labelledby="qa-standards-title">
          <div className="qa-container qa-standards-grid">
            <div>
              <span className="qa-kicker"><Layers3 size={16} aria-hidden="true" /> Cryptographic reference</span>
              <h2 id="qa-standards-title">The standards behind the assessment.</h2>
              <p>NIST defines distinct post-quantum standards for key establishment and digital signatures. Review algorithm adoption alongside the protocol, configuration, and deployment evidence.</p>
            </div>
            <ul className="qa-standard-list">
              {STANDARDS.map(({ algorithm, purpose, standard, url }) => (
                <li key={standard}>
                  <a href={url}>
                    <span><strong>{algorithm}</strong><small>{purpose}</small></span>
                    <span className="qa-standard-id">{standard} <ArrowUpRight size={17} aria-hidden="true" /></span>
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="qa-close" aria-labelledby="qa-close-title">
          <div className="qa-container qa-close-grid">
            <div>
              <h2 id="qa-close-title">Start with what you can verify.</h2>
              <p>Open your workspace to review assessment evidence, or start with a free scan of a public endpoint.</p>
            </div>
            <div className="qa-actions">
              <Link className="qa-button qa-button--primary" to={DASHBOARD}>Open assessment <ArrowUpRight aria-hidden="true" /></Link>
              <Link className="qa-button qa-button--secondary" to="/public-scan">Run a free scan <ArrowRight aria-hidden="true" /></Link>
            </div>
          </div>
        </section>
      </main>
      <footer className="qa-footer">
        <div className="qa-container">
          <Link to="/">Qguard Helix</Link>
          <nav aria-label="Company">
            <Link to="/docs">Documentation</Link><Link to="/contact">Contact</Link><Link to="/privacy">Privacy</Link><Link to="/terms">Terms</Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}
