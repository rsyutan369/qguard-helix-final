import { useState } from "react";
import {
  Activity,
  CreditCard,
  Gauge,
  Info,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  MessageSquare,
  Phone,
  MonitorSmartphone,
  QrCode,
  Settings,
  ShieldCheck,
} from "lucide-react";
import type { DashboardSnapshot, MessagingModule, Page } from "@/lib/types";
import { APP_VERSION } from "@/lib/app-update";
import { AboutModal } from "@/components/AboutModal";

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

interface SidebarProps {
  activePage: Page;
  modules: MessagingModule[];
  snapshot: DashboardSnapshot;
  unreadMessages?: number;
  /** Missed calls not yet looked at. */
  missedCalls?: number;
  /** Files shared with this account waiting for Accept / Decline. */
  sharedFilesWaiting?: number;
  onNavigate: (page: Page) => void;
}

export default function Sidebar({ activePage, modules, snapshot, unreadMessages = 0, missedCalls = 0, sharedFilesWaiting = 0, onNavigate }: SidebarProps) {
  const visibleModules = modules.filter((item) => item.module_id !== "admin" && item.route !== "admin");
  const [aboutOpen, setAboutOpen] = useState(false);

  return (
    <aside className="flex h-screen w-[232px] flex-col border-r border-line bg-white/75 px-3 py-5 backdrop-blur-xl">
      <div className="mb-7 flex shrink-0 items-center gap-3 px-2">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full">
          <img src="/brand/qguard-messaging-badge.webp" alt="QGuard Messaging" className="h-full w-full object-contain drop-shadow-[0_4px_10px_rgba(59,130,246,0.45)]" />
        </div>
        <div>
          <div className="text-sm font-bold tracking-wide text-violet-600">QGUARD</div>
          <div className="text-[11px] font-medium text-ink-400">Quantum Messaging</div>
        </div>
      </div>

      <div className="-mr-1 min-h-0 flex-1 overflow-y-auto pr-1">
        <nav className="space-y-1">
          {visibleModules.length === 0 && (
            <div className="rounded-lg border border-amber-100 bg-amber-50 p-3 text-xs font-semibold text-amber-700">
              No dashboard modules are enabled for this account.
            </div>
          )}
          {visibleModules.map((item) => {
            const Icon = iconMap[item.icon as keyof typeof iconMap] ?? LayoutDashboard;
            const active = activePage === item.route;
            return (
              <button
                key={item.module_id}
                type="button"
                data-tour={`nav-${item.route}`}
                onClick={() => onNavigate(item.route)}
                className={`focus-ring flex h-10 w-full items-center gap-3 rounded-lg px-3 text-sm font-semibold transition ${
                  active
                    ? "bg-violet-50 text-violet-600"
                    : "text-ink-600 hover:bg-canvas hover:text-ink-950"
                }`}
              >
                <Icon size={18} />
                <span>{item.label}</span>
                {item.route === "chat" && unreadMessages > 0 && (
                  <span
                    className="ml-auto flex h-5 min-w-[20px] items-center justify-center rounded-full bg-violet-600 px-1.5 text-[11px] font-bold leading-none text-white"
                    title={`${unreadMessages} unread encrypted message${unreadMessages === 1 ? "" : "s"}`}
                  >
                    {unreadMessages > 99 ? "99+" : unreadMessages}
                  </span>
                )}
                {item.route === "calls" && missedCalls > 0 && (
                  <span
                    className="ml-auto flex h-5 min-w-[20px] items-center justify-center rounded-full bg-rose-500 px-1.5 text-[11px] font-bold leading-none text-white"
                    title={`${missedCalls} missed call${missedCalls === 1 ? "" : "s"}`}
                  >
                    {missedCalls > 99 ? "99+" : missedCalls}
                  </span>
                )}
                {item.route === "vault" && sharedFilesWaiting > 0 && (
                  <span
                    className="ml-auto flex h-5 min-w-[20px] items-center justify-center rounded-full bg-cyan-600 px-1.5 text-[11px] font-bold leading-none text-white"
                    title={`${sharedFilesWaiting} shared file${sharedFilesWaiting === 1 ? "" : "s"} waiting for you`}
                  >
                    {sharedFilesWaiting > 99 ? "99+" : sharedFilesWaiting}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-security-card mt-6 rounded-lg border p-3 shadow-tight backdrop-blur">
          <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
            <ShieldCheck size={16} />
            {snapshot.e2ee_status}
          </div>
          <div className="text-xs leading-5">
            PQC: {snapshot.pqc_status} - HNDL: {snapshot.hndl_status}
          </div>
        </div>
      </div>

      {/* Version + About — pinned to the bottom of the navigation rail. */}
      <div className="mt-4 shrink-0 border-t border-line pt-3">
        <button
          type="button"
          data-tour="about"
          onClick={() => setAboutOpen(true)}
          title="About QGuard Messaging"
          className="focus-ring group flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left transition hover:bg-canvas"
        >
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-line bg-white text-ink-500 transition group-hover:border-violet-100 group-hover:text-violet-600">
            <Info size={15} />
          </span>
          <span className="min-w-0">
            <span className="block text-xs font-semibold text-ink-700 group-hover:text-ink-950">About QGuard</span>
            <span className="block text-[11px] font-medium tabular-nums text-ink-400">Version {APP_VERSION}</span>
          </span>
        </button>
      </div>

      <AboutModal open={aboutOpen} version={APP_VERSION} onClose={() => setAboutOpen(false)} />
    </aside>
  );
}
