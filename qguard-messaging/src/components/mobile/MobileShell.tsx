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
      <header
        className="mobile-safe-top qg-glass z-30 shrink-0 px-4 pb-3"
        style={{ borderBottom: "1px solid var(--qg-hairline)" }}
      >
        <div className="flex items-center gap-3 pt-2.5">
          <div
            className="flex h-10 w-10 shrink-0 items-center justify-center overflow-hidden rounded-[13px] p-1.5"
            style={{
              border: "1px solid var(--qg-hairline)",
              background: "var(--qg-panel-soft)",
              boxShadow: "var(--qg-glow)",
            }}
          >
            <img src="/NEW_LOGO.png" alt="" className="h-full w-full object-contain" />
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
