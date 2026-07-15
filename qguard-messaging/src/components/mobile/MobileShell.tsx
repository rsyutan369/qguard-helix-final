import { useState, type ReactNode } from "react";
import {
  Activity,
  CreditCard,
  Gauge,
  Grip,
  KeyRound,
  LayoutDashboard,
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

/** The five primary destinations pinned to the floating bottom bar. */
const PRIMARY_TABS: { route: Page; label: string }[] = [
  { route: "dashboard", label: "Home" },
  { route: "chat", label: "Chats" },
  { route: "vault", label: "Vault" },
  { route: "quantum", label: "Security" },
  { route: "settings", label: "Settings" },
];

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
 * Phone-sized app chrome: a compact glass header, the page content, and a
 * floating rounded bottom navigation bar (Home / Chats / Vault / Security /
 * Settings). Secondary modules (keys, devices, verification, audit) open from
 * the grid button in the header. Mirrors the light, purple-accented design
 * language of the QGuard Android reference mocks.
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

  const navigate = (page: Page) => {
    setSheetOpen(false);
    onNavigate(page);
  };

  return (
    <div className="mobile-shell flex h-[100dvh] w-screen flex-col overflow-hidden bg-canvas">
      {/* Header */}
      <header className="mobile-safe-top z-30 shrink-0 border-b border-line bg-white/80 px-4 pb-2.5 backdrop-blur-xl">
        <div className="flex items-center gap-3 pt-2.5">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center overflow-hidden rounded-xl border border-violet-100 bg-white p-1 shadow-tight">
            <img src="/NEW_LOGO.png" alt="QGuard" className="h-full w-full object-contain" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h1 className="truncate text-[15px] font-bold text-ink-950">{title}</h1>
              <span
                className={`h-2 w-2 shrink-0 rounded-full ${
                  liveStatus.state === "live" ? "bg-emerald-500" : liveStatus.state === "connecting" ? "bg-amber-500" : "bg-ink-400"
                }`}
                title={`Realtime: ${liveStatus.state}`}
              />
            </div>
            <div className="flex items-center gap-1 text-[11px] font-semibold text-emerald-600">
              <ShieldCheck size={11} />
              Quantum-safe · E2EE
            </div>
          </div>
          <button
            type="button"
            onClick={onToggleTheme}
            className="icon-button"
            title={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
          >
            {theme === "light" ? <Moon size={16} /> : <Sun size={16} />}
          </button>
          <button
            type="button"
            onClick={() => setSheetOpen(true)}
            className="icon-button"
            title="All security modules"
          >
            <Grip size={16} />
          </button>
        </div>
      </header>

      {/* Content. overflow-x-hidden is the backstop against horizontal page
          panning: wide tables must scroll inside their own cards, never pan
          the whole page (each page also caps its root grid track). */}
      <main className="min-h-0 flex-1 overflow-x-hidden overflow-y-auto overscroll-contain p-3 pb-24">{children}</main>

      {/* Floating bottom navigation */}
      <nav className="mobile-safe-bottom pointer-events-none fixed inset-x-0 bottom-0 z-30 flex justify-center px-4 pb-3">
        <div className="pointer-events-auto flex w-full max-w-md items-center justify-between rounded-2xl border border-line bg-white/90 px-2 py-1.5 shadow-soft backdrop-blur-xl">
          {tabs.map((tab) => {
            const Icon = iconMap[tab.route as keyof typeof iconMap] ?? LayoutDashboard;
            const active = activePage === tab.route;
            return (
              <button
                key={tab.route}
                type="button"
                onClick={() => navigate(tab.route)}
                className={`relative flex min-w-[56px] flex-col items-center gap-0.5 rounded-xl px-2 py-1.5 text-[10px] font-bold transition ${
                  active
                    ? "bg-gradient-to-br from-violet-600 to-violet-500 text-white shadow-tight"
                    : "text-ink-500 active:bg-violet-50"
                }`}
              >
                <Icon size={19} />
                <span>{tab.label}</span>
                {tab.route === "chat" && unreadMessages > 0 && (
                  <span className="absolute -top-1 right-1.5 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-rose-500 px-1 text-[9px] font-bold leading-none text-white ring-2 ring-white">
                    {unreadMessages > 99 ? "99+" : unreadMessages}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </nav>

      {/* All-modules sheet */}
      {sheetOpen && (
        <div className="fixed inset-0 z-40 flex items-end justify-center" role="dialog" aria-modal="true">
          <button
            type="button"
            aria-label="Close module list"
            className="absolute inset-0 bg-ink-950/40 backdrop-blur-sm"
            onClick={() => setSheetOpen(false)}
          />
          <div className="mobile-safe-bottom relative w-full max-w-md rounded-t-3xl border border-line bg-white p-5 pb-8 shadow-soft">
            <div className="mx-auto mb-4 h-1 w-10 rounded-full bg-line" />
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-ink-950">Security Modules</h2>
                <p className="text-[11px] font-medium text-ink-400">QGuard Messaging v{APP_VERSION}</p>
              </div>
              <button type="button" onClick={() => setSheetOpen(false)} className="icon-button" title="Close">
                <X size={16} />
              </button>
            </div>
            <div className="grid grid-cols-3 gap-2.5">
              {sheetModules.map((item) => {
                const Icon = iconMap[item.icon as keyof typeof iconMap] ?? LayoutDashboard;
                const active = activePage === item.route;
                return (
                  <button
                    key={item.module_id}
                    type="button"
                    onClick={() => navigate(item.route)}
                    className={`flex flex-col items-center gap-2 rounded-2xl border p-3 text-center text-[11px] font-semibold transition ${
                      active
                        ? "border-violet-200 bg-violet-50 text-violet-700"
                        : "border-line bg-canvas text-ink-600 active:bg-violet-50"
                    }`}
                  >
                    <span
                      className={`flex h-10 w-10 items-center justify-center rounded-xl ${
                        active ? "bg-gradient-to-br from-violet-600 to-violet-500 text-white" : "bg-white text-violet-600 shadow-tight"
                      }`}
                    >
                      <Icon size={18} />
                    </span>
                    <span className="leading-tight">{item.label}</span>
                  </button>
                );
              })}
            </div>
            <button
              type="button"
              onClick={onSignOut}
              className="mt-5 flex w-full items-center justify-center gap-2 rounded-xl border border-rose-100 bg-rose-50 px-4 py-2.5 text-sm font-bold text-rose-600 active:bg-rose-100"
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
