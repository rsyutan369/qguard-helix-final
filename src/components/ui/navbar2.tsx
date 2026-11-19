import { useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  Activity,
  ArrowRight,
  BookOpen,
  Calendar,
  CalendarCheck,
  CheckCircle2,
  ChevronDown,
  Database,
  FileCheck,
  HelpCircle,
  KeyRound,
  Lock,
  Mail,
  Menu,
  MessageSquareLock,
  RefreshCcw,
  Search,
  ShieldCheck,
  Sparkles,
  Terminal,
  Users,
  X,
  type LucideIcon
} from 'lucide-react';

type MegaLink = {
  title: string;
  description: string;
  href: string;
  icon: LucideIcon;
  badge?: string;
};

type MegaColumn = {
  eyebrow: string;
  links: MegaLink[];
};

type MegaMenu = {
  columns: MegaColumn[];
  footerLinks?: { label: string; href: string }[];
  preview: { src: string; alt: string; eyebrow: string; caption: string; cta: string; href: string };
};

type MenuKey = 'Platform' | 'Solutions' | 'Resources';

const MEGA_MENUS: Record<MenuKey, MegaMenu> = {
  Platform: {
    columns: [
      {
        eyebrow: 'Migration Lifecycle',
        links: [
          {
            title: 'Post-Quantum Migration Process',
            description: 'A phased workflow for discovery, assessment, migration, validation, and monitoring.',
            href: '#migration-process',
            icon: RefreshCcw
          },
          {
            title: 'Removing the RoadBlocks',
            description: 'Practical answers for PQC readiness, crypto inventory gaps, vendors, VPNs, and TLS risk.',
            href: '#mitigation-roadblocks-section',
            icon: Lock
          },
          {
            title: 'Quantum Risk Assessment Sandbox',
            description: 'Interactive classification of RSA, ECC, symmetric crypto, and NIST PQC primitives.',
            href: '#simulator',
            icon: Terminal
          },
          {
            title: 'Post Quantum Roadmap',
            description: 'A 2026-2029 plan for inventory, prioritization, pilots, migration, and assurance.',
            href: '#roadmap',
            icon: Calendar
          }
        ]
      },
      {
        eyebrow: 'Platform Sections',
        links: [
          {
            title: 'Core Platform Capabilities',
            description: 'Runtime crypto visibility, risk scoring, orchestration, governance, and crypto-agility.',
            href: '#core-capabilities-section',
            icon: Activity
          },
          {
            title: 'Qguard Helix - Advance Features',
            description: 'Unified operational surface for HNDL, runtime visibility, trust fabric, crypto agility, migration, sandboxing, rollback, and vaulting.',
            href: '#command-center',
            icon: Database
          },
          {
            title: 'Quantum Encryption Services Use Cases',
            description: 'Applied encryption, QRNG, authentication, tokenization, and secure communication patterns.',
            href: '#use-cases',
            icon: KeyRound,
            badge: 'Coming soon'
          }
        ]
      }
    ],
    footerLinks: [
      { label: 'NIST PQC strategy', href: '#nist-strategy' },
      { label: 'Pricing', href: '#pricing' }
    ],
    preview: {
      src: '/nav/platform.webp',
      alt: 'Illuminated migration path crossing a cryptographic data field',
      eyebrow: 'Qguard Helix Platform',
      caption: 'Plan, execute and validate every stage from DISCOVER to GOVERN.',
      cta: 'Explore the process',
      href: '#migration-process'
    }
  },
  Solutions: {
    columns: [
      {
        eyebrow: 'Solution Suites',
        links: [
          {
            title: 'QGuard Helix Features',
            description: 'The full platform showcase — all fifteen modules, what each one does, and the business value it delivers.',
            href: '/qguard-helix-features',
            icon: Sparkles
          },
          {
            title: 'PQC Solutions',
            description: 'The six problems that stall every PQC migration — hidden trust, shadow crypto, unmanaged keys — solved in one platform.',
            href: '/pqc-solutions',
            icon: CheckCircle2
          },
          {
            title: 'Post-Quantum Migration Platform',
            description: 'Discover your crypto estate, then plan, orchestrate, and validate PQC migration with rollback-safe controls.',
            href: '/post-quantum-migration-platform',
            icon: RefreshCcw
          },
          {
            title: 'Quantum Trust & Governance Center',
            description: 'Enterprise governance, full QKMS, and evidence mapping for SOC 2, PCI DSS and NIST across your estate.',
            href: '/quantum-trust-governance-center',
            icon: ShieldCheck
          }
        ]
      },
      {
        eyebrow: 'Assess & Secure',
        links: [
          {
            title: 'Public Quantum Exposure Assessment',
            description: 'Free, no-signup scan of your Internet-facing TLS, certificates and post-quantum readiness.',
            href: '/public-scan',
            icon: Search,
            badge: 'Free'
          },
          {
            title: 'Quantum Readiness & Assessment',
            description: 'Score quantum risk, model exposure, and generate executive readiness reports.',
            href: '/quantum-readiness-assessment',
            icon: Search
          },
          {
            title: 'Qguard Messaging',
            description: 'End-to-end encrypted Secure Chat and an on-device Quantum Vault, built on NIST post-quantum cryptography.',
            href: '/qguard-messaging',
            icon: MessageSquareLock
          }
        ]
      }
    ],
    footerLinks: [
      { label: 'Compare plans', href: '#pricing' },
      { label: 'Talk to the team', href: '/contact' }
    ],
    preview: {
      src: '/nav/solutions.webp',
      alt: 'Global network of connected endpoints across a digital globe',
      eyebrow: 'Enterprise Solutions',
      caption: 'Find quantum-vulnerable TLS and certificates on your public estate.',
      cta: 'Run a free scan',
      href: '/public-scan'
    }
  },
  Resources: {
    columns: [
      {
        eyebrow: 'Resource Library',
        links: [
          {
            title: 'Qguard Helix PQC Checklist',
            description: 'Download the CPM readiness checklist for cryptographic visibility, governance, and post-quantum migration planning.',
            href: '/resources/pqc-checklist',
            icon: FileCheck
          },
          {
            title: 'Documentation Center',
            description: 'Review platform guides, module walkthroughs, API references, and operational workflows.',
            href: '/docs',
            icon: BookOpen
          }
        ]
      },
      {
        eyebrow: 'Support',
        links: [
          {
            title: 'Frequently Asked Questions',
            description: 'Answers on Q-Day timelines, PQC readiness, deployment, and how the platform works.',
            href: '#faq',
            icon: HelpCircle
          },
          {
            title: 'Contact Qguard Helix',
            description: 'Reach the team about deployments, partnerships, and migration programs.',
            href: '/contact',
            icon: Mail
          }
        ]
      }
    ],
    footerLinks: [
      { label: 'Privacy Policy', href: '/privacy' },
      { label: 'Terms of Service', href: '/terms' }
    ],
    preview: {
      src: '/nav/resources.webp',
      alt: 'Layered library of guides, videos, documentation and downloads',
      eyebrow: 'Resource Library',
      caption: 'Start with a readiness checklist for your cryptographic estate.',
      cta: 'Get the checklist',
      href: '/resources/pqc-checklist'
    }
  }
};

type NavItem = { kind: 'menu'; label: MenuKey } | { kind: 'link'; label: string; href: string };

const NAV_ITEMS: NavItem[] = [
  { kind: 'menu', label: 'Platform' },
  { kind: 'menu', label: 'Solutions' },
  { kind: 'menu', label: 'Resources' },
  { kind: 'link', label: 'Free Scan', href: '/public-scan' },
  { kind: 'link', label: 'Pricing', href: '#pricing' },
  { kind: 'link', label: 'Company', href: '#faq' }
];

const EASE = [0.22, 1, 0.36, 1] as const;

interface Navbar2Props {
  /** Opens the homepage Request Demo modal. The demo CTA is hidden when omitted. */
  onRequestDemo?: () => void;
}

export default function Navbar2({ onRequestDemo }: Navbar2Props) {
  const [openMenu, setOpenMenu] = useState<MenuKey | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [mobileSection, setMobileSection] = useState<MenuKey | null>(null);
  const [scrolled, setScrolled] = useState(false);
  const navRef = useRef<HTMLElement | null>(null);

  const closeAll = () => {
    setOpenMenu(null);
    setMobileOpen(false);
    setMobileSection(null);
  };

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 24);
      // Desktop mega menus overlay the page; scrolling away dismisses them.
      setOpenMenu(null);
    };

    setScrolled(window.scrollY > 24);
    window.addEventListener('scroll', handleScroll, { passive: true });

    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    if (!openMenu && !mobileOpen) {
      return;
    }

    const handleOutsidePointer = (event: MouseEvent | TouchEvent) => {
      const target = event.target;

      if (target instanceof Node && !navRef.current?.contains(target)) {
        closeAll();
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        closeAll();
      }
    };

    document.addEventListener('mousedown', handleOutsidePointer);
    document.addEventListener('touchstart', handleOutsidePointer, { passive: true });
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('mousedown', handleOutsidePointer);
      document.removeEventListener('touchstart', handleOutsidePointer);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [openMenu, mobileOpen]);

  useEffect(() => {
    window.addEventListener('hashchange', closeAll);
    window.addEventListener('popstate', closeAll);

    return () => {
      window.removeEventListener('hashchange', closeAll);
      window.removeEventListener('popstate', closeAll);
    };
  }, []);

  useEffect(() => {
    // Warm the preview artwork so a mega panel never opens on an empty card.
    Object.values(MEGA_MENUS).forEach(({ preview }) => {
      const image = new Image();
      image.src = preview.src;
    });
  }, []);

  const activeMenu = openMenu ? MEGA_MENUS[openMenu] : null;

  const requestDemo = () => {
    closeAll();
    onRequestDemo?.();
  };

  return (
    <header
      ref={navRef}
      className={`qh-nav fixed inset-x-0 top-0 z-50 px-3 sm:px-5 ${scrolled ? 'qh-nav--scrolled' : ''}`}
    >
      <div className={`qh-nav__shell mx-auto max-w-[96rem] overflow-hidden ${openMenu || mobileOpen ? 'qh-nav__shell--open' : ''}`}>
        {/* Top row */}
        <div className="flex h-[4.5rem] items-center justify-between gap-4 pl-3 pr-3 sm:pl-4 sm:pr-4">
          <a href="#hero" onClick={closeAll} className="homepage-nav__brand group flex min-w-0 items-center gap-3 no-underline">
            <img
              src="/NEW_LOGO.png"
              alt="Qguard Helix logo"
              className="homepage-nav__logo qh-nav__logo h-14 w-auto shrink-0 object-contain"
            />
            <span className="hidden min-w-0 flex-col leading-none sm:flex">
              <span className="homepage-nav__wordmark whitespace-nowrap text-lg font-black tracking-[0.03em] transition-colors group-hover:text-cyan-600">
                Qguard Helix
              </span>
              <span className="homepage-logo-subtitle homepage-nav__tagline mt-1 whitespace-nowrap bg-gradient-to-r from-cyan-500 via-slate-600 to-violet-600 bg-clip-text font-mono text-[10px] font-black uppercase tracking-[0.32em] text-transparent">
                Quantum Cyber Defense
              </span>
            </span>
          </a>

          {/* Desktop nav */}
          <nav className="hidden items-center gap-0.5 xl:flex 2xl:gap-1" aria-label="Primary">
            {NAV_ITEMS.map((item) => {
              if (item.kind === 'link') {
                return (
                  <a key={item.label} href={item.href} onClick={closeAll} className="qh-nav__trigger no-underline">
                    {item.label}
                  </a>
                );
              }

              const isOpen = openMenu === item.label;

              return (
                <button
                  key={item.label}
                  type="button"
                  aria-expanded={isOpen}
                  aria-controls="homepage-mega-menu"
                  onClick={() => setOpenMenu((current) => (current === item.label ? null : item.label))}
                  className={`qh-nav__trigger ${isOpen ? 'qh-nav__trigger--open' : ''}`}
                >
                  {item.label}
                  <ChevronDown className={`h-4 w-4 transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`} />
                </button>
              );
            })}
          </nav>

          {/* Right actions */}
          <div className="hidden shrink-0 items-center gap-2 xl:flex 2xl:gap-3">
            <div className="qh-nav__status hidden 2xl:inline-flex">
              <span>Status:</span>
              <i />
              <strong>Active</strong>
            </div>
            <a href="/login" className="qh-nav__btn qh-nav__btn--secondary no-underline">
              <Users className="hidden h-4 w-4 2xl:block" />
              Login / Register
            </a>
            {onRequestDemo && (
              <button type="button" onClick={requestDemo} className="qh-nav__btn qh-nav__btn--primary">
                Request Demo
                <ArrowRight className="h-4 w-4" />
              </button>
            )}
          </div>

          {/* Mobile trigger */}
          <div className="flex items-center gap-2 xl:hidden">
            <a href="/login" className="qh-nav__btn qh-nav__btn--secondary qh-nav__btn--compact no-underline">
              Login
            </a>
            <button
              type="button"
              onClick={() => {
                setOpenMenu(null);
                setMobileOpen((open) => !open);
              }}
              aria-expanded={mobileOpen}
              aria-controls="homepage-mobile-menu"
              aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
              className="qh-nav__icon-btn"
            >
              {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
          </div>
        </div>

        {/* Desktop mega panel — shared across Platform / Solutions / Resources */}
        <AnimatePresence initial={false}>
          {activeMenu && openMenu && (
            <motion.div
              id="homepage-mega-menu"
              role="region"
              aria-label={`${openMenu} menu`}
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.35, ease: EASE }}
              className="hidden overflow-hidden xl:block"
            >
              <motion.div
                key={openMenu}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25, ease: EASE }}
                className="qh-nav__panel grid max-h-[calc(100vh-7.5rem)] grid-cols-[minmax(0,1fr)_minmax(0,1fr)_18.5rem] gap-8 overflow-y-auto px-6 pb-6 pt-5"
              >
                {activeMenu.columns.map((column, columnIndex) => (
                  <div key={column.eyebrow} className="flex min-w-0 flex-col">
                    <span className="qh-nav__eyebrow">{column.eyebrow}</span>
                    <ul className="mt-3 flex flex-col gap-1">
                      {column.links.map((link) => (
                        <li key={link.title}>
                          <a href={link.href} onClick={closeAll} className="qh-nav__item no-underline">
                            <span className="qh-nav__item-icon">
                              <link.icon className="h-4 w-4" />
                            </span>
                            <span className="min-w-0">
                              <span className="qh-nav__item-title">
                                {link.title}
                                {link.badge && <span className="qh-nav__badge">{link.badge}</span>}
                              </span>
                              <span className="qh-nav__item-desc">{link.description}</span>
                            </span>
                          </a>
                        </li>
                      ))}
                    </ul>

                    {/* Footer links sit under the last column */}
                    {columnIndex === activeMenu.columns.length - 1 && activeMenu.footerLinks && (
                      <div className="qh-nav__footer mt-auto">
                        {activeMenu.footerLinks.map((footerLink) => (
                          <a key={footerLink.label} href={footerLink.href} onClick={closeAll} className="no-underline">
                            {footerLink.label}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                ))}

                {/* Preview card */}
                <a href={activeMenu.preview.href} onClick={closeAll} className="qh-nav__preview group no-underline">
                  <img
                    src={activeMenu.preview.src}
                    alt={activeMenu.preview.alt}
                    decoding="async"
                    className="absolute inset-0 h-full w-full object-cover object-center transition-transform duration-700 group-hover:scale-[1.05]"
                  />
                  <span className="qh-nav__preview-eyebrow">
                    <i />
                    {activeMenu.preview.eyebrow}
                  </span>
                  <span className="qh-nav__preview-copy">
                    <span className="qh-nav__preview-caption">{activeMenu.preview.caption}</span>
                    <span className="qh-nav__preview-cta">
                      {activeMenu.preview.cta}
                      <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
                    </span>
                  </span>
                </a>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Mobile panel */}
        <AnimatePresence initial={false}>
          {mobileOpen && (
            <motion.div
              id="homepage-mobile-menu"
              key="mobile-panel"
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3, ease: EASE }}
              className="overflow-hidden xl:hidden"
            >
              <nav className="qh-nav__panel flex max-h-[calc(100dvh-7.5rem)] flex-col gap-1 overflow-y-auto px-3 pb-5 pt-3" aria-label="Mobile">
                {NAV_ITEMS.map((item) => {
                  if (item.kind === 'link') {
                    return (
                      <a key={item.label} href={item.href} onClick={closeAll} className="qh-nav__mobile-row no-underline">
                        {item.label}
                      </a>
                    );
                  }

                  const isOpen = mobileSection === item.label;

                  return (
                    <div key={item.label}>
                      <button
                        type="button"
                        aria-expanded={isOpen}
                        onClick={() => setMobileSection((current) => (current === item.label ? null : item.label))}
                        className={`qh-nav__mobile-row ${isOpen ? 'qh-nav__mobile-row--open' : ''}`}
                      >
                        {item.label}
                        <ChevronDown className={`h-4 w-4 transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`} />
                      </button>
                      <AnimatePresence initial={false}>
                        {isOpen && (
                          <motion.ul
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.25, ease: EASE }}
                            className="qh-nav__mobile-sub overflow-hidden"
                          >
                            {MEGA_MENUS[item.label].columns.flatMap((column) =>
                              column.links.map((link) => (
                                <li key={link.title}>
                                  <a href={link.href} onClick={closeAll} className="qh-nav__mobile-link no-underline">
                                    <link.icon className="h-4 w-4 shrink-0" />
                                    <span className="min-w-0 flex-1">{link.title}</span>
                                    {link.badge && <span className="qh-nav__badge">{link.badge}</span>}
                                  </a>
                                </li>
                              ))
                            )}
                          </motion.ul>
                        )}
                      </AnimatePresence>
                    </div>
                  );
                })}

                <div className="qh-nav__mobile-actions">
                  <a href="/login" onClick={closeAll} className="qh-nav__btn qh-nav__btn--secondary justify-center no-underline">
                    <Users className="h-4 w-4" />
                    Login / Register
                  </a>
                  {onRequestDemo && (
                    <button type="button" onClick={requestDemo} className="qh-nav__btn qh-nav__btn--primary justify-center">
                      <CalendarCheck className="h-4 w-4" />
                      Request Demo
                    </button>
                  )}
                </div>
              </nav>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </header>
  );
}
