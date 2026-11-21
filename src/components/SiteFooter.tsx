import type { ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { LEGAL_PAGES } from '@/lib/site-identity';
import './site-footer.css';

const websiteOnly = import.meta.env.VITE_SITE_EDITION === 'public';

const footerGroups = [
  {
    title: 'Product',
    links: [
      { label: 'Platform Features', path: '/qguard-helix-features' },
      { label: 'Quantum Messaging', path: '/qguard-messaging' },
      { label: 'Secure Chat', path: '/qguard-messaging/secure-chat' },
      { label: 'Quantum Vault', path: '/qguard-messaging/quantum-vault' },
      { label: 'Readiness Assessment', path: '/quantum-readiness-assessment' },
      { label: 'Pricing', path: '/#pricing' },
      ...(!websiteOnly ? [{ label: 'Downloads', path: '/downloads' }] : []),
    ],
  },
  {
    title: 'Solutions',
    links: [
      { label: 'PQC Solutions', path: '/pqc-solutions' },
      { label: 'Migration Platform', path: '/post-quantum-migration-platform' },
      { label: 'Trust & Governance', path: '/quantum-trust-governance-center' },
      { label: 'Use Cases', path: '/#use-cases' },
      { label: 'Migration Roadmap', path: '/#roadmap' },
    ],
  },
  {
    title: 'Resources',
    links: [
      { label: 'Documentation', path: '/docs' },
      { label: 'PQC Checklist', path: '/resources/pqc-checklist' },
      { label: 'Quantum Simulation', path: '/resources/quantum-simulation' },
      { label: 'Free Public Scan', path: '/public-scan' },
      ...(!websiteOnly ? [
        { label: 'Verify a Certificate', path: '/verify-certificate' },
        { label: 'Verify a Report', path: '/verify-report' },
      ] : []),
    ],
  },
  { title: 'Legal', links: LEGAL_PAGES },
];

export function SiteFooter({ children }: { children?: ReactNode }) {
  const { pathname } = useLocation();

  return (
    <footer className="site-footer">
      <div className="site-footer__wrap">
        <div className="site-footer__grid">
          <div className="site-footer__identity">
            <a href="/" className="site-footer__brand">
              <img src="/NEW_LOGO.png" width="44" height="44" alt="" loading="lazy" />
              <span>Qguard Helix</span>
            </a>
            <p className="site-footer__tagline"><em>Quantum Cyber Defense &amp; Post-Quantum Security Platform</em></p>
            <p className="site-footer__description">Securing today's digital infrastructure while preparing organizations for the quantum era.</p>
            {children}
          </div>
          <nav className="site-footer__links" aria-label="Footer navigation">
            {footerGroups.map(({ title, links }) => (
              <div key={title}>
                <h2>{title}</h2>
                <ul>
                  {links.map(({ label, path }) => (
                    <li key={path}>
                      <a href={path} aria-current={pathname === path ? 'page' : undefined}>
                        {label}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
        </div>
        <p className="site-footer__copyright">
          © {new Date().getUTCFullYear()} Qguard Helix. All rights reserved.
        </p>
      </div>
    </footer>
  );
}
