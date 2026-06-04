import { Bell, CircleHelp, LogOut, Moon, Search, Sun } from "lucide-react";
import type { User } from "@supabase/supabase-js";
import { useMemo, useState } from "react";
import type { QGuardLiveEvent, QGuardLiveStatus } from "@/lib/live-sse";
import type { ThemeMode } from "@/lib/use-theme";

interface TopBarProps {
  title: string;
  subtitle: string;
  user: User;
  theme: ThemeMode;
  liveStatus: QGuardLiveStatus;
  lastLiveEvent: QGuardLiveEvent | null;
  onToggleTheme: () => void;
  onSignOut: () => void;
}

function initials(user: User): string {
  const name = String(user.user_metadata?.full_name ?? user.email ?? "User");
  return name
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "U";
}

export default function TopBar({ title, subtitle, user, theme, liveStatus, lastLiveEvent, onToggleTheme, onSignOut }: TopBarProps) {
  const [panel, setPanel] = useState<"search" | "notifications" | "help" | null>(null);
  const [search, setSearch] = useState("");
  const liveTone = liveStatus.state === "live"
    ? "bg-emerald-50 text-emerald-600"
    : liveStatus.state === "connecting"
      ? "bg-cyan-50 text-cyan-700"
      : liveStatus.state === "fallback"
        ? "bg-amber-50 text-amber-700"
        : "bg-rose-50 text-rose-600";
  const searchSummary = useMemo(() => {
    const clean = search.trim().toLowerCase();
    if (!clean) return "Type to filter the current secure workspace context.";
    return `Search queued for "${clean}". Workspace-wide encrypted content remains client-local.`;
  }, [search]);

  return (
    <header className="relative flex h-[76px] items-center justify-between border-b border-line bg-white/75 px-7 backdrop-blur-xl">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-ink-950">{title}</h1>
        <p className="mt-1 text-sm text-ink-600">{subtitle}</p>
      </div>
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => setPanel(panel === "search" ? null : "search")}
          className="flex h-10 w-[260px] items-center gap-2 rounded-lg border border-line bg-canvas px-3 text-left text-sm text-ink-400 transition hover:border-cyan-200 hover:bg-white"
        >
          <Search size={17} />
          <span>Search secure workspace</span>
        </button>
        <span className={`status-pill ${liveTone}`} title={liveStatus.detail}>
          {liveStatus.state}
        </span>
        <button className="icon-button" title="Notifications" onClick={() => setPanel(panel === "notifications" ? null : "notifications")}>
          <Bell size={18} />
        </button>
        <button className="icon-button" title="Security help" onClick={() => setPanel(panel === "help" ? null : "help")}>
          <CircleHelp size={18} />
        </button>
        <button className="icon-button" title="Toggle theme" onClick={onToggleTheme}>
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <button className="icon-button" title="Sign out" onClick={onSignOut}>
          <LogOut size={18} />
        </button>
        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-violet-600 text-sm font-bold text-white">
          {initials(user)}
        </div>
      </div>
      {panel && (
        <div className="absolute right-7 top-[66px] z-20 w-[360px] rounded-lg border border-line bg-white/90 p-4 shadow-soft backdrop-blur-xl">
          {panel === "search" && (
            <div>
              <div className="text-sm font-bold text-ink-950">Workspace Search</div>
              <input
                value={search}
                onChange={(event) => setSearch(event.currentTarget.value)}
                className="mt-3 w-full rounded-lg border border-line bg-canvas px-3 py-2 text-sm outline-none focus:border-cyan-300"
                autoFocus
              />
              <div className="mt-3 text-xs leading-5 text-ink-600">{searchSummary}</div>
            </div>
          )}
          {panel === "notifications" && (
            <div>
              <div className="text-sm font-bold text-ink-950">Live Activity</div>
              <div className="mt-3 rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">
                {lastLiveEvent ? lastLiveEvent.detail : liveStatus.detail}
              </div>
              {lastLiveEvent && <div className="mt-2 font-mono text-[11px] text-ink-400">{lastLiveEvent.raw.trim()}</div>}
            </div>
          )}
          {panel === "help" && (
            <div>
              <div className="text-sm font-bold text-ink-950">Security Help</div>
              <div className="mt-3 grid gap-2 text-xs leading-5 text-ink-600">
                <div>All production actions are routed through Supabase APIs or local Tauri crypto commands.</div>
                <div>Live status reflects SSE-formatted backend events with fallback polling.</div>
                <div>Plaintext and private keys stay on this client.</div>
              </div>
            </div>
          )}
        </div>
      )}
    </header>
  );
}
