import {
  Atom,
  ChevronRight,
  LockKeyhole,
  MessageSquarePlus,
  MonitorSmartphone,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react";
import type { QGuardLiveStatus } from "@/lib/live-sse";
import type { DashboardData, TrustedDevice } from "@/lib/types";
import { UserAvatar } from "@/components/UserAvatar";
import { ONE_TIME_PREKEY_MIN, SIGNED_PREKEY_MIN } from "@/lib/security-score";

interface MobileDashboardProps {
  data: DashboardData;
  liveStatus: QGuardLiveStatus;
  onNavigate: (page: string) => void;
}

function greeting(): string {
  const hour = new Date().getHours();
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}

function firstName(data: DashboardData): string {
  const name = data.profile?.name?.trim() || data.profile?.username?.trim();
  if (name) return name.split(/\s+/)[0];
  const email = data.profile?.email ?? "";
  return email ? email.split("@")[0] : "there";
}

function relativeTime(value: string | null | undefined): string {
  if (!value) return "—";
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function statusTone(value: string): string {
  if (/failed|critical|no devices|needs device|not ready|missing|below|awaiting/i.test(value)) return "text-rose-600";
  if (/review|warning|partial|needs verification|replenish/i.test(value)) return "text-amber-600";
  return "text-emerald-600";
}

function isTrustedDevice(device: TrustedDevice): boolean {
  return device.trust_state === "ThisDevice" || device.trust_state === "Trusted";
}

function hasSendablePrekeys(device: TrustedDevice): boolean {
  return Boolean(
    isTrustedDevice(device)
    && device.identity_signature
    && device.x25519_identity_public.length > 0
    && device.mlkem_identity_public.length > 0
    && device.signed_prekey
    && device.signed_prekey.x25519_public.length > 0
    && device.signed_prekey.mlkem_public.length > 0,
  );
}

/** One colorful stat tile — gradient icon chip + value + label, tappable. */
function StatTile({
  icon: Icon,
  gradient,
  value,
  label,
  onClick,
}: {
  icon: typeof ShieldCheck;
  gradient: string;
  value: string;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex flex-col items-start gap-3 rounded-2xl border border-line bg-white p-3.5 text-left shadow-tight transition active:scale-[0.98]"
    >
      <span className={`flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br ${gradient} text-white shadow-tight`}>
        <Icon size={20} />
      </span>
      <span className="min-w-0">
        <span className="block truncate text-[15px] font-bold leading-tight text-ink-950">{value}</span>
        <span className="mt-0.5 block truncate text-[11px] font-semibold text-ink-400">{label}</span>
      </span>
    </button>
  );
}

/**
 * Pure-Android home screen: a single vertical scroll of floating cards. The
 * gradient "Quantum Security" hero answers "am I protected right now?" at a
 * glance; colorful stat tiles jump into each module; the Recent Chats, Security
 * Overview, and My Devices sections stack below. No horizontal panes — every
 * section is full-width and the whole page scrolls down like a native app.
 */
export default function MobileDashboard({ data, onNavigate }: MobileDashboardProps) {
  const { snapshot, devices, conversations, report, keyInventory } = data;
  const myId = data.profile?.id;
  const activeDevices = devices.filter((device) => device.user_id === myId && device.trust_state !== "Revoked");
  const trustedDevices = activeDevices.filter(isTrustedDevice);
  const recentConversations = conversations
    .filter((conversation) => !conversation.archived_at && !conversation.hidden_at && !conversation.deleted_at)
    .slice(0, 4);

  const score = snapshot.quantum_safe_score;
  const scoreCaption = score >= 100
    ? "Fully protected"
    : score >= 90
      ? "Excellent protection"
      : score >= 70
        ? "Review warnings"
        : "Action needed";

  const securityRows: [string, string][] = [
    ["End-to-end encryption", snapshot.e2ee_status],
    ["Quantum protection", snapshot.pqc_status],
    ["Forward secrecy", report.forward_secrecy],
    ["Signed prekeys", keyInventory.active_signed_prekeys >= SIGNED_PREKEY_MIN ? `${keyInventory.active_signed_prekeys} active` : "Awaiting"],
    ["One-time prekeys", `${keyInventory.available_one_time_prekeys} ready`],
    ["Harvest-now resistance", snapshot.hndl_status],
  ];

  const tiles = [
    { icon: ShieldCheck, gradient: "from-emerald-500 to-teal-500", value: snapshot.e2ee_status, label: "E2E encryption", route: "quantum" },
    { icon: Atom, gradient: "from-violet-600 to-indigo-500", value: snapshot.pqc_status, label: "Quantum secure", route: "quantum" },
    { icon: MonitorSmartphone, gradient: "from-cyan-500 to-sky-500", value: `${trustedDevices.length}/${activeDevices.length || 0}`, label: "Trusted devices", route: "devices" },
    { icon: LockKeyhole, gradient: "from-fuchsia-500 to-pink-500", value: snapshot.vault_storage, label: "Quantum Vault", route: "vault" },
  ];

  return (
    <div className="flex flex-col gap-5 pb-2">
      {/* Greeting */}
      <div className="px-0.5">
        <div className="text-[13px] font-semibold text-ink-400">{greeting()},</div>
        <div className="text-2xl font-bold capitalize tracking-tight text-ink-950">{firstName(data)}</div>
      </div>

      {/* Hero — Quantum Security posture (signature element) */}
      <button
        type="button"
        onClick={() => onNavigate("quantum")}
        className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-violet-700 via-violet-600 to-indigo-600 p-5 text-left text-white shadow-soft transition active:scale-[0.99]"
      >
        <div className="pointer-events-none absolute -right-10 -top-12 h-40 w-40 rounded-full bg-white/15 blur-2xl" />
        <div className="pointer-events-none absolute -bottom-16 -left-8 h-44 w-44 rounded-full bg-indigo-400/25 blur-2xl" />
        <div className="relative">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.18em] text-violet-200">
                <ShieldCheck size={13} />
                Quantum Security
              </div>
              <div className="mt-2 flex items-end gap-1.5">
                <span className="text-5xl font-bold leading-none tracking-tight">{score}</span>
                <span className="mb-1 text-lg font-bold text-violet-200">%</span>
              </div>
              <div className="mt-1 text-sm font-semibold text-violet-100">{scoreCaption}</div>
            </div>
            <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white/15 ring-1 ring-white/25 backdrop-blur-sm">
              <ShieldCheck size={24} />
            </span>
          </div>

          {/* Score progress */}
          <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-white/20">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyan-300 to-emerald-300 transition-all"
              style={{ width: `${Math.max(4, Math.min(100, score))}%` }}
            />
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            <span className="rounded-full bg-white/15 px-2.5 py-1 text-[11px] font-semibold text-white ring-1 ring-white/15">{report.pqc_algorithm}</span>
            <span className="rounded-full bg-white/15 px-2.5 py-1 text-[11px] font-semibold text-white ring-1 ring-white/15">AES-256-GCM</span>
          </div>
        </div>
      </button>

      {/* Stat tiles */}
      <div className="grid grid-cols-2 gap-3">
        {tiles.map((tile) => (
          <StatTile
            key={tile.label}
            icon={tile.icon}
            gradient={tile.gradient}
            value={tile.value}
            label={tile.label}
            onClick={() => onNavigate(tile.route)}
          />
        ))}
      </div>

      {/* Recent chats */}
      <section className="rounded-2xl border border-line bg-white p-4 shadow-tight">
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-[15px] font-bold text-ink-950">Recent chats</h2>
          <button type="button" onClick={() => onNavigate("chat")} className="text-xs font-bold text-violet-600">
            View all
          </button>
        </div>
        {recentConversations.length === 0 ? (
          <div className="py-6 text-center text-sm text-ink-500">
            No conversations yet. Start a private, quantum-safe chat.
          </div>
        ) : (
          <div className="-mx-1">
            {recentConversations.map((conversation) => {
              const peerId = conversation.member_user_ids.find((id) => id !== myId) ?? null;
              return (
                <button
                  key={conversation.id}
                  type="button"
                  onClick={() => onNavigate("chat")}
                  className="flex w-full items-center gap-3 rounded-xl px-1 py-2.5 text-left transition active:bg-canvas"
                >
                  <UserAvatar userId={peerId} name={conversation.title} size={42} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate text-sm font-bold text-ink-950">{conversation.title}</span>
                      <LockKeyhole size={11} className="shrink-0 text-emerald-500" />
                    </div>
                    <div className="truncate text-xs text-ink-500">{conversation.last_activity}</div>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <span className="text-[11px] text-ink-400">{relativeTime(conversation.updated_at)}</span>
                    {conversation.unread_count > 0 && (
                      <span className="flex h-5 min-w-[20px] items-center justify-center rounded-full bg-violet-600 px-1.5 text-[11px] font-bold text-white">
                        {conversation.unread_count > 99 ? "99+" : conversation.unread_count}
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        )}
        <button
          type="button"
          onClick={() => onNavigate("chat")}
          className="mt-3 flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-violet-600 to-violet-500 py-3 text-sm font-bold text-white shadow-tight active:opacity-90"
        >
          <MessageSquarePlus size={16} />
          New secure chat
        </button>
      </section>

      {/* Security overview */}
      <section className="rounded-2xl border border-line bg-white p-4 shadow-tight">
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-[15px] font-bold text-ink-950">Security overview</h2>
          <button type="button" onClick={() => onNavigate("quantum")} className="text-xs font-bold text-violet-600">
            Details
          </button>
        </div>
        <div className="divide-y divide-line">
          {securityRows.map(([label, value]) => (
            <div key={label} className="flex items-center justify-between gap-3 py-2.5">
              <span className="flex min-w-0 items-center gap-2 text-sm text-ink-600">
                <ShieldCheck size={14} className={`shrink-0 ${statusTone(value)}`} />
                <span className="truncate">{label}</span>
              </span>
              <span className={`shrink-0 text-right text-xs font-bold ${statusTone(value)}`}>{value}</span>
            </div>
          ))}
        </div>
        {report.warnings.length > 0 && (
          <div className="mt-3 space-y-2 rounded-xl bg-amber-50 p-3">
            {report.warnings.slice(0, 2).map((warning) => (
              <div key={warning} className="flex gap-2 text-xs font-medium text-amber-700">
                <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                <span>{warning}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* My devices */}
      <section className="rounded-2xl border border-line bg-white p-4 shadow-tight">
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-[15px] font-bold text-ink-950">My devices</h2>
          <button type="button" onClick={() => onNavigate("devices")} className="text-xs font-bold text-violet-600">
            Manage
          </button>
        </div>
        {activeDevices.length === 0 ? (
          <div className="py-5 text-center text-sm text-ink-500">No trusted devices registered yet.</div>
        ) : (
          <div className="-mx-1">
            {activeDevices.slice(0, 3).map((device) => {
              const sendable = hasSendablePrekeys(device);
              return (
                <div key={device.device_id} className="flex items-center gap-3 rounded-xl px-1 py-2.5">
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-canvas text-violet-600">
                    <MonitorSmartphone size={19} />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-bold text-ink-950">{device.label}</div>
                    <div className="truncate text-xs text-ink-400">{device.pqc_status} · {relativeTime(device.last_seen_at)}</div>
                  </div>
                  <span className={`shrink-0 rounded-full px-2.5 py-1 text-[11px] font-bold ${sendable ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-600"}`}>
                    {device.trust_state === "ThisDevice" ? "This device" : sendable ? "Ready" : "Sync"}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Footer wordmark — a quiet close to the scroll */}
      <div className="flex items-center justify-center gap-1.5 pb-1 pt-1 text-[11px] font-semibold text-ink-400">
        <Users size={12} />
        Protected by QGuard post-quantum cryptography
        <ChevronRight size={12} className="opacity-0" />
      </div>
    </div>
  );
}
