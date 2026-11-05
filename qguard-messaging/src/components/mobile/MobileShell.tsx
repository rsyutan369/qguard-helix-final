import { useEffect, useState, type ReactNode } from "react";
import {
  Activity,
  CreditCard,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LayoutGrid,
  LockKeyhole,
  LogOut,
  MessageSquare,
  Phone,
  MonitorSmartphone,
  Moon,
  QrCode,
  Settings,
  ShieldCheck,
  Sun,
  X,
} from "lucide-react";
import type { MessagingModule, Page } from "@/lib/types";
import type { QGuardLiveStatus } from "@/lib/live-sse";
import { liveStatusLabel } from "@/lib/live-sse";
import { APP_VERSION } from "@/lib/app-update";

const iconMap = {
  dashboard: LayoutDashboard,
  chat: MessageSquare,
  calls: Phone,
  vault: LockKeyhole,
  keys: KeyRound,
  devices: MonitorSmartphone,
  verification: QrCode,
  audit: Activity,
  quantum: Gauge,
  subscription: CreditCard,
  settings: Settings,
};

/** The five primary destinations pinned to the floating bottom rail. */
const PRIMARY_TABS: { route: Page; label: string }[] = [
  { route: "dashboard", label: "Home" },
  { route: "chat", label: "Chats" },
  { route: "vault", label: "Vault" },
  { route: "quantum", label: "Security" },
  { route: "settings", label: "Settings" },
];

/**
 * Modernist page kicker — the tracked micro-caps line that sits above the
 * display title, naming the module's scope. Condensed from the same subtitles
 * App.tsx already carries, so it states what the page actually is rather than
 * inventing a claim. Rendered only under the Android skin.
 */
const PAGE_KICKER: Record<string, string> = {
  dashboard: "Overview · Hybrid E2EE",
  chat: "End-to-end encrypted · ML-KEM + X25519",
  calls: "Voice & video · Quantum-encrypted",
  keys: "Identity · Prekeys · Rotation",
  devices: "Trust state per device",
  verification: "Safety numbers · Fingerprints",
  audit: "Tamper-evident local events",
  admin: "Organisation security posture",
  subscription: "Plan · Billing · Activation",
};

/** Pages named in the masthead itself, with no separate page head. */
const TITLE_IN_MASTHEAD = new Set<Page>(["vault", "quantum", "settings"]);

/** Compact realtime readout. Wording matches liveStatusLabel's meaning. */
function liveTone(state: QGuardLiveStatus["state"]): { label: string; className: string } {
  switch (state) {
    case "live":
      return { label: "Live", className: "qg-tone-ok" };
    case "connecting":
      return { label: "Linking", className: "qg-tone-info" };
    case "fallback":
      return { label: "Polling", className: "qg-tone-warn" };
    default:
      return { label: "Offline", className: "qg-tone-alert" };
  }
}

interface MobileShellProps {
  activePage: Page;
  title: string;
  modules: MessagingModule[];
  unreadMessages: number;
  /** Files shared with this account waiting for Accept / Decline (Vault tab badge). */
  sharedFilesWaiting?: number;
  liveStatus: QGuardLiveStatus;
  theme: "light" | "dark";
  onToggleTheme: () => void;
  onNavigate: (page: Page) => void;
  onSignOut: () => void;
  children: ReactNode;
}

/**
 * Phone app chrome: a glass instrument header, the page content, and a floating
 * navigation rail whose single indicator slides between destinations.
 *
 * Secondary modules (keys, devices, verification, audit, subscription) open from
 * the grid button as a bottom sheet. Both themes are first-class — every colour
 * comes from the Cold Fusion token layer in styles/mobile.css.
 */
export default function MobileShell({
  activePage,
  title,
  modules,
  unreadMessages,
  sharedFilesWaiting = 0,
  liveStatus,
  theme,
  onToggleTheme,
  onNavigate,
  onSignOut,
  children,
}: MobileShellProps) {
  const [sheetOpen, setSheetOpen] = useState(false);
  const enabledRoutes = new Set(modules.map((item) => item.route));
  const tabs = PRIMARY_TABS.filter((tab) => enabledRoutes.has(tab.route) || tab.route === "dashboard");
  const sheetModules = modules.filter(
    (item) => item.module_id !== "admin" && item.route !== "admin",
  );

  const activeIndex = tabs.findIndex((tab) => tab.route === activePage);
  const live = liveTone(liveStatus.state);
  const isChat = activePage === "chat";
  // Pages whose title replaces the QGUARD wordmark and the page head, so the
  // name is not repeated (QGUARD / kicker / title) three times over.
  const titleInMasthead = TITLE_IN_MASTHEAD.has(activePage);

  // Close the sheet on hardware/gesture back so it never traps the user.
  useEffect(() => {
    if (!sheetOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSheetOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [sheetOpen]);

  const navigate = (page: Page) => {
    setSheetOpen(false);
    onNavigate(page);
  };

  return (
    <div className="mobile-shell qg-stage relative flex h-[100dvh] w-screen flex-col overflow-hidden">
      {/* Ambient light. Sits behind the whole shell and drifts slowly; the grid
          and gradients come from .qg-stage. */}
      <div className="pointer-events-none absolute inset-0 -z-10 overflow-hidden" aria-hidden>
        <span
          className="qg-orb"
          style={{
            width: 300,
            height: 300,
            top: -110,
            left: -90,
            background: "radial-gradient(circle, var(--qg-flux), transparent 68%)",
            opacity: 0.32,
          }}
        />
        <span
          className="qg-orb"
          style={{
            width: 280,
            height: 280,
            bottom: -110,
            right: -80,
            background: "radial-gradient(circle, var(--qg-helix), transparent 68%)",
            opacity: 0.3,
            animationDelay: "-7s",
          }}
        />
      </div>

      {/* Header */}
      <header className="z-30 shrink-0">

        {/* ---- Modernist masthead (Android skin only) ----
            An ink block behind a lit lattice, crossed once by an accent scan
            bar, carrying the wordmark, the live tally and the two controls.
            `.qgm-only` is display:none in every build that does not set the
            skin attribute, so the Cold Fusion header below is untouched. */}
        <div className="qgm-masthead qgm-only mobile-safe-top px-5 pb-3.5">
          {/* pt-2.5 rather than a hairline gap: the wordmark is set at 800/1.0,
              so its caps paint slightly above their line box and would graze
              the status bar on a device reporting a small top inset. */}
          <div className="relative flex items-center gap-2.5 pt-2.5">
            {isChat ? (
              // Chat folds the page identity into the masthead so the thread
              // gets the height the separate page head used to take.
              <>
                <span className="qgm-chatmark" aria-hidden>
                  <ShieldCheck size={15} strokeWidth={2.2} />
                </span>
                <h1 className="qgm-wordmark truncate">{title}</h1>
              </>
            ) : titleInMasthead ? (
              // These pages name themselves in the masthead instead of
              // repeating "QGUARD" above a separate page head.
              <>
                <h1 className="qgm-wordmark truncate">{title}</h1>
                <span className="qgm-tally" aria-hidden />
              </>
            ) : (
              <>
                <span className="qgm-wordmark">QGUARD</span>
                <span className="qgm-tally" aria-hidden />
              </>
            )}
            <span className="ml-auto flex shrink-0 items-center gap-2">
              <span
                className="qgm-kicker flex items-center gap-1.5"
                style={{ opacity: 0.75 }}
                title={liveStatusLabel(liveStatus.state)}
              >
                <span className="qg-live-dot" />
                {live.label}
              </span>
              <button
                type="button"
                onClick={onToggleTheme}
                className="qg-focusable"
                aria-label={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
                style={{
                  border: "1px solid color-mix(in srgb, var(--m-on-slab) 40%, transparent)",
                  color: "var(--m-on-slab)",
                  background: "transparent",
                  height: 30,
                  width: 30,
                  display: "grid",
                  placeItems: "center",
                }}
              >
                {theme === "light" ? <Moon size={15} /> : <Sun size={15} />}
              </button>
              <button
                type="button"
                onClick={() => setSheetOpen(true)}
                className="qg-focusable"
                aria-label="Open all security modules"
                style={{
                  border: "1px solid color-mix(in srgb, var(--m-on-slab) 40%, transparent)",
                  color: "var(--m-on-slab)",
                  background: "transparent",
                  height: 30,
                  width: 30,
                  display: "grid",
                  placeItems: "center",
                }}
              >
                <LayoutGrid size={15} />
              </button>
            </span>
          </div>
          {isChat ? (
            <div className="qgm-chatsuite relative mt-2" aria-label="End-to-end encrypted with hybrid ML-KEM and X25519 key exchange">
              <span className="qgm-chatsuite-lead">End-to-end encrypted</span>
              <span className="qgm-chatchip" data-accent="true">ML-KEM</span>
              <span className="qgm-chatplus" aria-hidden>+</span>
              <span className="qgm-chatchip">X25519</span>
            </div>
          ) : (
            <div className="qgm-kicker relative mt-1.5">Quantum-safe chat &amp; vault</div>
          )}
        </div>

        {/* ---- Modernist page identity (Android skin only) ----
            Not on the home screen: it opens straight onto its greeting and
            cards, without an "Overview · Dashboard" heading. */}
        {!isChat && !titleInMasthead && activePage !== "dashboard" && (
          <div className="qgm-pagehead qgm-only px-5 pb-3.5 pt-2.5">
            <div className="qgm-pagekicker truncate">{PAGE_KICKER[activePage] ?? "Secure workspace"}</div>
            <h1 className="qgm-pagetitle mt-1.5 truncate">{title}</h1>
          </div>
        )}

        {/* ---- Cold Fusion header (desktop + narrow windows) ---- */}
        <div
          className="qgm-not mobile-safe-top qg-glass px-4 pb-3"
          style={{ borderBottom: "1px solid var(--qg-hairline)" }}
        >
        <div className="flex items-center gap-3 pt-2.5">
          <div
            className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full"
            style={{ boxShadow: "var(--qg-glow)" }}
          >
            <img src="/brand/qguard-messaging-badge.webp" alt="" className="h-full w-full object-contain" />
          </div>

          <div className="min-w-0 flex-1">
            <h1 className="qg-display truncate text-[16px] leading-tight">{title}</h1>
            <div className="mt-0.5 flex items-center gap-1.5">
              <span
                className={`qg-pill ${live.className}`}
                style={{ padding: "2px 7px", fontSize: 9.5 }}
                title={liveStatusLabel(liveStatus.state)}
              >
                <span className="qg-live-dot" />
                {live.label}
              </span>
              <span className="qg-eyebrow truncate" style={{ fontSize: 9.5 }}>
                Hybrid E2EE
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={onToggleTheme}
            className="qg-icon-btn qg-focusable"
            aria-label={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
          >
            {/* The two icons cross-fade and counter-rotate so the switch reads as
                one object turning over, not two icons swapping. */}
            <span className="relative block h-4 w-4">
              <Moon
                size={16}
                className="absolute inset-0 transition-all duration-500"
                style={{
                  opacity: theme === "light" ? 1 : 0,
                  transform: theme === "light" ? "rotate(0deg) scale(1)" : "rotate(-90deg) scale(0.5)",
                }}
              />
              <Sun
                size={16}
                className="absolute inset-0 transition-all duration-500"
                style={{
                  opacity: theme === "light" ? 0 : 1,
                  transform: theme === "light" ? "rotate(90deg) scale(0.5)" : "rotate(0deg) scale(1)",
                }}
              />
            </span>
          </button>

          <button
            type="button"
            onClick={() => setSheetOpen(true)}
            className="qg-icon-btn qg-focusable"
            aria-label="Open all security modules"
          >
            <LayoutGrid size={16} />
          </button>
        </div>
        </div>
      </header>

      {/* Content. overflow-x-hidden is the backstop against horizontal page
          panning: wide tables must scroll inside their own cards, never pan the
          whole page (each page also caps its root grid track). */}
      <main className="qg-scroll min-h-0 flex-1 overflow-x-hidden overflow-y-auto overscroll-contain p-3.5 pb-28">
        {children}
      </main>

      {/* Floating navigation rail */}
      <nav className="mobile-safe-bottom pointer-events-none fixed inset-x-0 bottom-0 z-30 flex justify-center px-4 pb-3">
        <div className="qg-nav pointer-events-auto">
          {activeIndex >= 0 && (
            <span
              className="qg-nav-pill"
              aria-hidden
              style={{
                width: `calc((100% - 12px) / ${tabs.length})`,
                transform: `translateX(${activeIndex * 100}%)`,
              }}
            />
          )}
          {tabs.map((tab) => {
            const Icon = iconMap[tab.route as keyof typeof iconMap] ?? LayoutDashboard;
            const active = activePage === tab.route;
            return (
              <button
                key={tab.route}
                type="button"
                onClick={() => navigate(tab.route)}
                className="qg-nav-item qg-focusable"
                data-active={active}
                aria-current={active ? "page" : undefined}
              >
                <Icon size={19} strokeWidth={active ? 2.4 : 2} />
                <span>{tab.label}</span>
                {tab.route === "chat" && unreadMessages > 0 && (
                  <span className="qg-badge">{unreadMessages > 99 ? "99+" : unreadMessages}</span>
                )}
                {tab.route === "vault" && sharedFilesWaiting > 0 && (
                  <span className="qg-badge" title={`${sharedFilesWaiting} shared file${sharedFilesWaiting === 1 ? "" : "s"} waiting`}>
                    {sharedFilesWaiting > 99 ? "99+" : sharedFilesWaiting}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </nav>

      {/* All-modules sheet */}
      {sheetOpen && (
        <div className="fixed inset-0 z-40 flex items-end justify-center" role="dialog" aria-modal="true" aria-label="Security modules">
          <button
            type="button"
            aria-label="Close module list"
            className="qg-scrim"
            onClick={() => setSheetOpen(false)}
          />
          <div className="qg-sheet mobile-safe-bottom px-5 pb-7 pt-3">
            <div className="mx-auto mb-4 qg-grabber" />
            <div className="mb-4 flex items-center justify-between gap-3">
              <div className="min-w-0">
                <h2 className="qg-display text-[15px]">Security modules</h2>
                <p className="qg-eyebrow mt-1 truncate">QGuard Messaging v{APP_VERSION}</p>
              </div>
              <button
                type="button"
                onClick={() => setSheetOpen(false)}
                className="qg-icon-btn qg-focusable"
                aria-label="Close"
              >
                <X size={16} />
              </button>
            </div>

            <div className="grid grid-cols-3 gap-2.5">
              {sheetModules.map((item, index) => {
                const Icon = iconMap[item.icon as keyof typeof iconMap] ?? LayoutDashboard;
                const active = activePage === item.route;
                return (
                  <button
                    key={item.module_id}
                    type="button"
                    onClick={() => navigate(item.route)}
                    // Selection is exposed as an attribute as well as an inline
                    // style so a skin can restate it: the Cold Fusion gradient
                    // below resolves to a pale fill under a one-hue palette,
                    // which would leave a white glyph on a light chip.
                    data-module-active={active || undefined}
                    className="qg-card qg-card-press qg-focusable qg-rise flex flex-col items-center gap-2 p-3 text-center"
                    style={{
                      ["--qg-i" as string]: index,
                      borderColor: active ? "var(--qg-helix)" : undefined,
                      borderRadius: 16,
                    }}
                  >
                    <span
                      className="flex h-10 w-10 items-center justify-center rounded-xl"
                      style={
                        active
                          ? {
                              background: "linear-gradient(140deg, var(--qg-flux), var(--qg-helix))",
                              color: "#fff",
                              boxShadow: "var(--qg-glow)",
                            }
                          : {
                              background: "var(--qg-panel-soft)",
                              border: "1px solid var(--qg-hairline)",
                              color: "var(--qg-helix)",
                            }
                      }
                    >
                      <Icon size={18} />
                    </span>
                    <span
                      className="qg-display text-[11px] leading-tight"
                      style={{ color: active ? "var(--qg-helix)" : "var(--qg-text-2)" }}
                    >
                      {item.label}
                    </span>
                  </button>
                );
              })}
            </div>

            <div
              className="mt-5 flex items-center gap-2 rounded-2xl p-3"
              style={{ background: "var(--qg-plasma-wash)", border: "1px solid var(--qg-hairline)" }}
            >
              <ShieldCheck size={15} style={{ color: "var(--qg-plasma)", flex: "none" }} />
              <p className="text-[11.5px] leading-snug" style={{ color: "var(--qg-text-2)" }}>
                Keys never leave this device unencrypted.
              </p>
            </div>

            <button
              type="button"
              onClick={onSignOut}
              className="qg-btn qg-btn-quiet qg-focusable mt-3"
              style={{ color: "var(--qg-alert)", borderColor: "var(--qg-alert)" }}
            >
              <LogOut size={15} />
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
