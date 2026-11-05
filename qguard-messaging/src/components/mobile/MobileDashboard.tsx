import { ChevronRight, LockKeyhole, MessageSquarePlus, MonitorSmartphone, ShieldCheck } from "lucide-react";
import type { QGuardLiveStatus } from "@/lib/live-sse";
import type { DashboardData, TrustedDevice } from "@/lib/types";
import { UserAvatar } from "@/components/UserAvatar";
import HelixReactor, { TONE_VAR } from "@/components/mobile/HelixReactor";
import { buildCryptoPosture, completeLayerCount, scoreVerdict, toReactorRings } from "@/lib/mobile-posture";
import { displayableEmail } from "@/lib/account-identity";
import { dashboardHub, hubCardLabel, unreadMessageCount, type HubArea, type HubEntry } from "@/lib/dashboard-hub";

interface MobileDashboardProps {
  data: DashboardData;
  liveStatus: QGuardLiveStatus;
  onNavigate: (page: string) => void;
  /**
   * Open a protected area from its card. The app locks the area first, so the
   * PIN, password or pattern is asked every time. Falls back to `onNavigate`.
   */
  onOpenArea?: (area: HubArea) => void;
  /** Missed calls not yet looked at (badge on the Calls card). */
  missedCalls?: number;
  /** Files shared with this account waiting for Accept / Decline (badge on the Quantum Vault card). */
  sharedFilesWaiting?: number;
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
  const email = displayableEmail(data.profile?.email) ?? "";
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

/** Section wrapper — carries the staggered entrance and consistent spacing. */
function Section({
  index,
  title,
  action,
  children,
}: {
  index: number;
  title: string;
  action?: { label: string; onClick: () => void };
  children: React.ReactNode;
}) {
  return (
    <section className="qg-card qg-rise p-4" style={{ ["--qg-i" as string]: index }}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="qg-display text-[14.5px]">{title}</h2>
        {action && (
          <button
            type="button"
            onClick={action.onClick}
            className="qg-focusable qg-mono text-[11px] font-semibold"
            style={{ color: "var(--qg-helix)" }}
          >
            {action.label}
          </button>
        )}
      </div>
      {children}
    </section>
  );
}

/**
 * Entry card for a protected area. Each one leads to a page behind a
 * workspace lock (Secure Chat or Quantum Vault), so the lock mark is shown on
 * every card: opening it asks for the PIN, password or pattern whenever that
 * workspace is locked.
 */
function HubCard({ entry, index, onClick }: { entry: HubEntry; index: number; onClick: () => void }) {
  const { icon: Icon, title, caption, unlocks, badge } = entry;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={hubCardLabel(entry)}
      className="qg-card qg-card-press qg-focusable qg-rise flex min-h-[118px] flex-col items-start justify-between gap-3 p-3.5 text-left"
      style={{ ["--qg-i" as string]: index }}
    >
      <span className="flex w-full items-start justify-between gap-2">
        <span className="qg-tile-chip" style={{ color: "var(--qg-helix)" }}>
          <Icon size={18} />
        </span>
        <span className="flex items-center gap-1.5">
          {badge ? (
            <span
              className="qg-mono flex h-[18px] min-w-[18px] items-center justify-center rounded-full px-1.5 text-[10px] font-bold text-white"
              style={{ background: "var(--qg-helix)" }}
            >
              {badge > 99 ? "99+" : badge}
            </span>
          ) : null}
          <LockKeyhole size={12} style={{ color: "var(--qg-text-3)" }} aria-hidden />
        </span>
      </span>
      <span className="min-w-0 self-stretch">
        <span className="qg-display block truncate text-[15px] leading-tight">{title}</span>
        <span className="mt-1 block text-[11.5px] leading-snug" style={{ color: "var(--qg-text-3)" }}>
          {caption}
        </span>
      </span>
    </button>
  );
}

/**
 * Phone home screen.
 *
 * The Helix Reactor answers "am I protected right now?" in one glance: its
 * headline, arcs and legend all read the same buildCryptoPosture()
 * measurement, and the layer-by-layer detail is one tap away on the Security
 * page. Below it, four cards lead to the protected areas (Secure Chat, Calls,
 * Quantum Vault, Contacts), each behind its workspace lock.
 */
export default function MobileDashboard({ data, liveStatus, onNavigate, onOpenArea, missedCalls = 0, sharedFilesWaiting = 0 }: MobileDashboardProps) {
  const { snapshot, devices, conversations, report } = data;
  const myId = data.profile?.id;
  const activeDevices = devices.filter((device) => device.user_id === myId && device.trust_state !== "Revoked");
  const visibleConversations = conversations.filter(
    (conversation) => !conversation.archived_at && !conversation.hidden_at && !conversation.deleted_at,
  );
  const recentConversations = visibleConversations.slice(0, 4);
  // Same count as the Chats badge in the bottom navigation.
  const unread = unreadMessageCount(conversations);

  const posture = buildCryptoPosture(data);
  const layers = posture.layers;
  const rings = toReactorRings(layers);
  const score = snapshot.quantum_safe_score;
  // Layers whose measured readiness is complete. Same source as the arcs, so
  // the Modernist core block can never disagree with the gauge beside it — and
  // the verdict is derived from them too, so the headline cannot claim "fully
  // protected" over a layer that is measurably incomplete.
  const completeLayers = completeLayerCount(layers);
  const verdict = scoreVerdict(score, layers);

  // Each card opens a protected area: Calls and Contacts sit behind the
  // Secure Chat lock, the vault behind its own. The app locks the area before
  // opening it, so every tap asks for the PIN, password or pattern.
  const hub = dashboardHub(unread, missedCalls, sharedFilesWaiting);

  return (
    <div className="flex flex-col gap-3.5 pb-2">
      {/* Greeting */}
      <div className="qg-rise px-0.5" style={{ ["--qg-i" as string]: 0 }}>
        <div className="qg-eyebrow">{greeting()}</div>
        <div className="qg-display mt-1 text-[26px] capitalize leading-none">{firstName(data)}</div>
      </div>

      {/* Hero — the Helix Reactor */}
      <button
        type="button"
        onClick={() => onNavigate("quantum")}
        className="qg-card qg-card-press qg-focusable qg-rise qgm-core overflow-hidden p-5 text-left"
        style={{ ["--qg-i" as string]: 1 }}
      >
        {/* ---- Modernist quantum-core block (Android skin only) ----
            Same measurement as the gauge below it: the headline, the meter
            width and the layer count all read from buildCryptoPosture() and
            snapshot.quantum_safe_score, so nothing here can contradict an arc. */}
        <div className="qgm-only" style={{ display: "flex", gap: 14, alignItems: "flex-start" }}>
          <span className="qgm-core-mark" aria-hidden>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
              <ellipse cx="12" cy="12" rx="10" ry="4.2" />
              <ellipse cx="12" cy="12" rx="10" ry="4.2" transform="rotate(60 12 12)" />
              <ellipse cx="12" cy="12" rx="10" ry="4.2" transform="rotate(120 12 12)" />
              <circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none" />
            </svg>
          </span>
          <span style={{ flex: 1, minWidth: 0 }}>
            <span className="qg-eyebrow" style={{ display: "block", color: "var(--m-a800)" }}>
              Quantum core
            </span>
            <span className="qg-display mt-1.5 block text-[19px] leading-tight">
              {score}% · {verdict.label}
            </span>
            <span className="qgm-meter mt-2 block">
              <span style={{ width: `${Math.max(0, Math.min(100, score))}%` }} />
            </span>
            {/* The verdict is already the second half of the headline, so no
                pill repeats it here. */}
            <span className="mt-2 block text-[11px] leading-snug" style={{ color: "var(--m-n800)" }}>
              {/* Name the population the layers were measured over. A bare
                  "n of 4" with no denominator is what let a wrong measurement
                  sit unchallenged next to a 100% headline. */}
              {completeLayers} of {layers.length} cryptographic layers fully active
              {posture.enrolledDevices > 0
                ? ` across ${posture.enrolledDevices} enrolled ${posture.enrolledDevices === 1 ? "device" : "devices"}.`
                : "."}
            </span>
          </span>
        </div>

        <div className="qgm-not flex items-center justify-between gap-3">
          <div className="qg-eyebrow">Quantum posture</div>
          <span className={`qg-pill qg-tone-${verdict.tone}`}>{verdict.label}</span>
        </div>

        <div className="mt-3 flex justify-center">
          <HelixReactor rings={rings} live={liveStatus.state === "live"} size={224}>
            {/* Score and scale sit on one baseline so they clear the innermost
                ring — a stacked caption here collides with the arc. */}
            {/* Sized so the whole readout clears the innermost ring — a longer
                unit label here runs straight through the arc. */}
            <span className="flex items-baseline justify-center">
              <span className="qg-num text-[46px] leading-none" style={{ color: "var(--qg-text)" }}>
                {score}
              </span>
              <span className="qg-num text-[17px] leading-none" style={{ color: "var(--qg-text-3)" }}>
                %
              </span>
            </span>
          </HelixReactor>
        </div>

        {/* Legend — names each ring so the gauge is readable, not mysterious. */}
        <div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1.5">
          {layers.map((layer) => (
            <div key={layer.id} className="flex items-center gap-1.5">
              {/* Same colour source as the matching arc. */}
              <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: TONE_VAR[layer.tone] }} />
              <span className="qg-mono truncate text-[10.5px]" style={{ color: "var(--qg-text-3)" }}>
                {layer.label}
              </span>
            </div>
          ))}
        </div>

        <div className="mt-3.5 flex flex-wrap gap-1.5">
          <span className="qg-pill qg-tone-mute">{report.pqc_algorithm}</span>
          <span className="qg-pill qg-tone-mute">AES-256-GCM</span>
        </div>
      </button>

      {/* Protected areas */}
      <div className="grid grid-cols-2 gap-3">
        {hub.map((card, index) => (
          <HubCard
            key={card.route}
            entry={card}
            index={2 + index}
            onClick={() => (onOpenArea ? onOpenArea(card.route) : onNavigate(card.route))}
          />
        ))}
      </div>

      {/* Recent chats */}
      <Section index={6} title="Recent chats" action={{ label: "View all", onClick: () => onNavigate("chat") }}>
        {recentConversations.length === 0 ? (
          <div className="py-5 text-center">
            <p className="text-[13px]" style={{ color: "var(--qg-text-2)" }}>
              No conversations yet.
            </p>
            <p className="mt-1 text-[11.5px]" style={{ color: "var(--qg-text-3)" }}>
              Start one and the keys are exchanged before the first word is sent.
            </p>
          </div>
        ) : (
          <div className="-mx-1 flex flex-col">
            {recentConversations.map((conversation, index) => {
              const peerId = conversation.member_user_ids.find((id) => id !== myId) ?? null;
              return (
                <button
                  key={conversation.id}
                  type="button"
                  onClick={() => onNavigate("chat")}
                  className="qg-focusable qg-slide flex w-full items-center gap-3 rounded-xl px-1 py-2.5 text-left"
                  style={{ ["--qg-i" as string]: index }}
                >
                  <UserAvatar userId={peerId} name={conversation.title} size={40} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="qg-display truncate text-[13.5px]">{conversation.title}</span>
                      <LockKeyhole size={10} style={{ color: "var(--qg-plasma)", flex: "none" }} />
                    </div>
                    <div className="truncate text-[11.5px]" style={{ color: "var(--qg-text-3)" }}>
                      {conversation.last_activity}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <span className="qg-mono text-[10px]" style={{ color: "var(--qg-text-3)" }}>
                      {relativeTime(conversation.updated_at)}
                    </span>
                    {conversation.unread_count > 0 && (
                      <span
                        className="qg-mono flex h-[18px] min-w-[18px] items-center justify-center rounded-full px-1.5 text-[10px] font-bold text-white"
                        style={{ background: "var(--qg-helix)" }}
                      >
                        {conversation.unread_count > 99 ? "99+" : conversation.unread_count}
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        )}

        <button type="button" onClick={() => onNavigate("chat")} className="qg-btn qg-focusable mt-3">
          <MessageSquarePlus size={16} />
          New secure chat
        </button>
      </Section>

      {/* Devices */}
      <Section index={7} title="My devices" action={{ label: "Manage", onClick: () => onNavigate("devices") }}>
        {activeDevices.length === 0 ? (
          <div className="py-5 text-center">
            <p className="text-[13px]" style={{ color: "var(--qg-text-2)" }}>
              No device registered yet.
            </p>
            <p className="mt-1 text-[11.5px]" style={{ color: "var(--qg-text-3)" }}>
              Register this device to publish its identity keys.
            </p>
          </div>
        ) : (
          <div className="flex flex-col">
            {activeDevices.slice(0, 3).map((device, index) => {
              const sendable = hasSendablePrekeys(device);
              const label = device.trust_state === "ThisDevice" ? "This device" : sendable ? "Ready" : "Syncing";
              return (
                <div
                  key={device.device_id}
                  className="qg-slide flex items-center gap-3 py-2.5"
                  style={{
                    ["--qg-i" as string]: index,
                    borderTop: index === 0 ? undefined : "1px solid var(--qg-hairline)",
                  }}
                >
                  <span className="qg-tile-chip" style={{ color: "var(--qg-helix)", height: 34, width: 34 }}>
                    <MonitorSmartphone size={16} />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="qg-display truncate text-[13px] leading-tight">{device.label}</div>
                    <div className="mt-0.5 truncate text-[11px]" style={{ color: "var(--qg-text-3)" }}>
                      {device.pqc_status} · {relativeTime(device.last_seen_at)}
                    </div>
                  </div>
                  <span className={`qg-pill ${sendable ? "qg-tone-ok" : "qg-tone-warn"}`} style={{ padding: "2px 8px" }}>
                    {label}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </Section>

      {/* Quiet close to the scroll */}
      <div
        className="qg-rise flex items-center justify-center gap-1.5 py-2"
        style={{ ["--qg-i" as string]: 8 }}
      >
        <ShieldCheck size={12} style={{ color: "var(--qg-plasma)" }} />
        <span className="qg-eyebrow" style={{ fontSize: 9.5 }}>
          Post-quantum protected
        </span>
        <ChevronRight size={12} className="opacity-0" />
      </div>
    </div>
  );
}
