/**
 * Shared frame for /login, /register and /reset-password in the homepage look: the same
 * tokens, type, bowl-glow atmosphere, letter reveal and scroll fade-ups as
 * "/" (see src/pages/landing.css and landing-motion.ts), plus a scroll-linked
 * lifecycle rail. Presentation only — all authentication stays in
 * auth-context and Supabase.
 */
import React, { useEffect, useLayoutEffect, useRef, useState, type InputHTMLAttributes, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, ArrowLeft, Eye, EyeOff, Fingerprint, KeyRound, Server, ShieldCheck, type LucideIcon } from "lucide-react";
import { useTheme, type ThemeMode } from "@/contexts/theme-context";
import { Chars } from "@/pages/landing-chars";
import { useLandingMotion } from "@/pages/landing-motion";
import "@/pages/landing.css";
import "./auth-landing.css";

export type AuthMode = "login" | "register" | "reset";

const STORY: Record<AuthMode, { eyebrow: string; before: string; mark: string; after: string; lede: string }> = {
  login: {
    eyebrow: "Secure identity gateway",
    before: "Welcome back to your ",
    mark: "quantum-safe",
    after: " command center.",
    lede: "Pick up where your team left off: cryptographic inventory, migration plans, live telemetry and compliance evidence for your organisation.",
  },
  register: {
    eyebrow: "Create your workspace",
    before: "Start your ",
    mark: "post-quantum",
    after: " migration today.",
    lede: "Discover every cryptographic asset you run, see which ones a quantum computer could break, and plan the move to ML-KEM and ML-DSA with evidence at every step.",
  },
  reset: {
    eyebrow: "Credential recovery",
    before: "Regain access to your ",
    mark: "quantum-safe",
    after: " workspace.",
    lede: "Recovery links are single-use and short-lived. Once you set a new password, every session on every device is signed out, so the old credentials stop working everywhere.",
  },
};

type RailStep = readonly [string, string];

const LIFECYCLE: readonly RailStep[] = [
  ["Discover", "Inventory certificates, keys, protocols and libraries across your estate."],
  ["Assess", "See which assets are quantum-vulnerable and why, ranked by exposure."],
  ["Plan", "Sequence migrations by risk, dependency and business impact."],
  ["Migrate", "Execute changes with validation checkpoints and rollback."],
  ["Validate", "Prove each asset is PQC-ready before it is marked complete."],
  ["Monitor", "Watch cryptographic posture and drift in real time."],
  ["Govern", "Map every finding to policy and audit-ready evidence."],
];

const RECOVERY: readonly RailStep[] = [
  ["Request", "Enter your account email. We answer the same way whether or not it exists."],
  ["Verify", "Open the single-use link we email you. It expires shortly after it is sent."],
  ["Reset", "Choose a new password of 8 to 128 characters."],
  ["Revoke", "Every existing session is signed out on every device."],
  ["Return", "Sign in again with your new password."],
];

const RAIL: Record<AuthMode, { label: string; steps: readonly RailStep[] }> = {
  login: { label: "One platform, the whole migration lifecycle", steps: LIFECYCLE },
  register: { label: "One platform, the whole migration lifecycle", steps: LIFECYCLE },
  reset: { label: "How password recovery works", steps: RECOVERY },
};

const PROTECTIONS: { icon: LucideIcon; title: string; body: string }[] = [
  { icon: Server, title: "Tenant isolation", body: "Your assets, scans and evidence are kept separate from every other organisation." },
  { icon: KeyRound, title: "Server-side authorization", body: "Privileged actions are checked on the server, never trusted from the browser." },
  { icon: Fingerprint, title: "Standards-based guidance", body: "Recommendations follow NIST FIPS 203, 204 and 205: ML-KEM, ML-DSA and SLH-DSA." },
];

/*
 * The auth pages always render light, like the homepage, and give the user's
 * own theme back when they leave. Moving between /login and /register
 * unmounts one page and mounts the other, so the restore is deferred one tick
 * and cancelled if the next page is another auth page — otherwise the second
 * page would remember "light" as the user's choice.
 */
let pendingRestore: number | null = null;
let savedMode: ThemeMode | null = null;

function useAuthLightTheme() {
  const { mode, setMode } = useTheme();
  const modeRef = useRef(mode);

  useLayoutEffect(() => {
    if (pendingRestore !== null) {
      window.clearTimeout(pendingRestore);
      pendingRestore = null;
    } else {
      savedMode = modeRef.current;
    }
    setMode("light");
    return () => {
      pendingRestore = window.setTimeout(() => {
        pendingRestore = null;
        if (savedMode) setMode(savedMode);
        savedMode = null;
      }, 0);
    };
  }, [setMode]);
}

/** Fills the lifecycle rail as the list scrolls through the viewport. */
function useRailProgress(listRef: React.RefObject<HTMLOListElement | null>) {
  useEffect(() => {
    const list = listRef.current;
    if (!list) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      list.style.setProperty("--auth-rail", "1");
      list.querySelectorAll("li").forEach((item) => item.setAttribute("data-lit", ""));
      return;
    }

    let frame = 0;
    const update = () => {
      frame = 0;
      const rect = list.getBoundingClientRect();
      const viewport = window.innerHeight;
      const progress = Math.min(1, Math.max(0, (viewport * 0.72 - rect.top) / Math.max(1, rect.height)));
      list.style.setProperty("--auth-rail", progress.toFixed(4));
      const items = list.querySelectorAll<HTMLElement>("li");
      items.forEach((item, index) => {
        if (progress >= (index + 0.35) / items.length) item.setAttribute("data-lit", "");
        else item.removeAttribute("data-lit");
      });
    };
    const schedule = () => {
      if (!frame) frame = requestAnimationFrame(update);
    };

    update();
    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule);
    return () => {
      if (frame) cancelAnimationFrame(frame);
      window.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
    };
  }, [listRef]);
}

export function AuthShell({ mode, nextQuery, children }: { mode: AuthMode; nextQuery: string; children: ReactNode }) {
  const rootRef = useRef<HTMLDivElement>(null);
  const glowRef = useRef<HTMLCanvasElement>(null);
  const railRef = useRef<HTMLOListElement>(null);
  const story = STORY[mode];
  const rail = RAIL[mode];
  const title = `${story.before}${story.mark}${story.after}`;

  useAuthLightTheme();
  useLandingMotion(rootRef, glowRef, false);
  useRailProgress(railRef);

  const swap =
    mode === "login"
      ? { prompt: "New to Qguard Helix?", label: "Create account", to: `/register${nextQuery}` }
      : mode === "reset"
        ? { prompt: "Remembered it?", label: "Sign in", to: `/login${nextQuery}` }
        : { prompt: "Already have an account?", label: "Sign in", to: `/login${nextQuery}` };

  return (
    <div className="lp lp-auth" ref={rootRef}>
      <div className="lp-atmo" aria-hidden="true">
        <canvas ref={glowRef} width={96} height={60} />
      </div>

      <header className="lp-auth__nav">
        <div className="lp-auth__nav-shell">
          <Link to="/" className="lp-auth__brand" aria-label="Qguard Helix home">
            <img src="/NEW_LOGO.png" alt="" className="lp-auth__logo" />
            <span className="lp-auth__brand-copy">
              <strong>Qguard Helix</strong>
              <span>Quantum Cyber Defense</span>
            </span>
          </Link>
          <nav className="lp-auth__nav-actions" aria-label="Account">
            <Link to="/" className="lp-auth__nav-link">
              <ArrowLeft aria-hidden="true" />
              <span>Home</span>
            </Link>
            <span className="lp-auth__nav-prompt">{swap.prompt}</span>
            <Link to={swap.to} viewTransition className="lp-btn lp-btn--secondary lp-btn--sm">
              {swap.label}
            </Link>
          </nav>
        </div>
      </header>

      <main className="lp-auth__main">
        <div className="lp-wrap lp-auth__grid">
          <section className="lp-auth__story" aria-labelledby="auth-title">
            <p className="lp-eyebrow">{story.eyebrow}</p>
            <h1 id="auth-title" className="lp-auth__title" data-letters="load" aria-label={title}>
              <Chars text={story.before} />
              <span className="lp-auth__mark">
                <Chars text={story.mark} />
              </span>
              <Chars text={story.after} />
            </h1>
            <p className="lp-lede">{story.lede}</p>

            <div className="lp-auth__lifecycle">
              <p className="lp-label" data-lp-reveal>
                {rail.label}
              </p>
              <ol className="lp-auth__rail" ref={railRef}>
                {rail.steps.map(([name, body], index) => (
                  <li key={name} data-lp-reveal>
                    <span className="lp-auth__rail-num">{String(index + 1).padStart(2, "0")}</span>
                    <div>
                      <strong>{name}</strong>
                      <p>{body}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </div>

            <div className="lp-dark lp-auth__protect" data-lp-reveal>
              <p className="lp-label">How your workspace is protected</p>
              <ul>
                {PROTECTIONS.map(({ icon: Icon, title: heading, body }) => (
                  <li key={heading}>
                    <Icon aria-hidden="true" />
                    <div>
                      <strong>{heading}</strong>
                      <p>{body}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </section>

          <aside className="lp-auth__aside">{children}</aside>
        </div>
      </main>
    </div>
  );
}

/** The sign-in / sign-up card, with a soft light that follows the pointer. */
export function AuthCard({ kicker, heading, sub, children }: { kicker: string; heading: string; sub: string; children: ReactNode }) {
  const handlePointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    if (event.pointerType !== "mouse") return;
    const rect = event.currentTarget.getBoundingClientRect();
    event.currentTarget.style.setProperty("--lp-auth-x", `${event.clientX - rect.left}px`);
    event.currentTarget.style.setProperty("--lp-auth-y", `${event.clientY - rect.top}px`);
  };

  return (
    <div className="lp-auth__card" onPointerMove={handlePointerMove}>
      <div className="lp-auth__card-beam" aria-hidden="true" />
      <p className="lp-auth__kicker">
        <i aria-hidden="true" />
        {kicker}
      </p>
      <h2 className="lp-auth__card-title">{heading}</h2>
      <p className="lp-auth__card-sub">{sub}</p>
      {children}
    </div>
  );
}

type FieldProps = Omit<InputHTMLAttributes<HTMLInputElement>, "id"> & {
  id: string;
  label: string;
  icon: LucideIcon;
  revealable?: boolean;
  hint?: ReactNode;
  aside?: ReactNode;
};

export function AuthField({ id, label, icon: Icon, revealable, hint, aside, type, ...input }: FieldProps) {
  const [visible, setVisible] = useState(false);
  const inputType = revealable ? (visible ? "text" : "password") : type;

  return (
    <div className="lp-auth__field">
      <div className="lp-auth__field-head">
        <label htmlFor={id}>{label}</label>
        {aside}
      </div>
      <div className="lp-auth__control">
        <Icon className="lp-auth__control-icon" aria-hidden="true" />
        <input id={id} type={inputType} {...input} />
        {revealable && (
          <button
            type="button"
            className="lp-auth__reveal"
            onClick={() => setVisible((value) => !value)}
            aria-label={visible ? "Hide password" : "Show password"}
            aria-pressed={visible}
          >
            {visible ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
          </button>
        )}
        <span className="lp-auth__control-line" aria-hidden="true" />
      </div>
      {hint}
    </div>
  );
}

export function AuthAlert({ tone, children }: { tone: "error" | "success"; children: ReactNode }) {
  const Icon = tone === "error" ? AlertTriangle : ShieldCheck;
  return (
    <div className={`lp-auth__alert lp-auth__alert--${tone}`} role={tone === "error" ? "alert" : "status"}>
      <Icon aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

export function AuthDivider() {
  return (
    <div className="lp-auth__divider" role="separator">
      <span>or</span>
    </div>
  );
}

export function GoogleButton({ label, disabled, onClick }: { label: string; disabled: boolean; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} disabled={disabled} className="lp-btn lp-btn--secondary lp-btn--block lp-auth__google">
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.84z" fill="#FBBC05" />
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
      </svg>
      {label}
    </button>
  );
}
