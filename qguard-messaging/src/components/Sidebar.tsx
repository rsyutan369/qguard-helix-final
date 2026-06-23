import {
  Activity,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  MessageSquare,
  MonitorSmartphone,
  QrCode,
  Settings,
  ShieldCheck,
} from "lucide-react";
import type { DashboardSnapshot, MessagingModule, Page } from "@/lib/types";

const iconMap = {
  dashboard: LayoutDashboard,
  chat: MessageSquare,
  vault: LockKeyhole,
  keys: KeyRound,
  devices: MonitorSmartphone,
  verification: QrCode,
  audit: Activity,
  quantum: Gauge,
  settings: Settings,
};

interface SidebarProps {
  activePage: Page;
  modules: MessagingModule[];
  snapshot: DashboardSnapshot;
  onNavigate: (page: Page) => void;
}

export default function Sidebar({ activePage, modules, snapshot, onNavigate }: SidebarProps) {
  const visibleModules = modules.filter((item) => item.module_id !== "admin" && item.route !== "admin");

  return (
    <aside className="h-screen w-[232px] border-r border-line bg-white/75 px-3 py-5 backdrop-blur-xl">
      <div className="mb-7 flex items-center gap-3 px-2">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-violet-100 bg-violet-50 text-violet-600">
          <ShieldCheck size={22} />
        </div>
        <div>
          <div className="text-sm font-bold tracking-wide text-violet-600">QGUARD</div>
          <div className="text-[11px] font-medium text-ink-400">Quantum Messaging</div>
        </div>
      </div>

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
    </aside>
  );
}
