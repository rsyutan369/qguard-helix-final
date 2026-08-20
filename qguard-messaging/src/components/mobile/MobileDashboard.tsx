import {
  ChevronRight,
  KeyRound,
  LockKeyhole,
  MessageSquarePlus,
  MonitorSmartphone,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { QGuardLiveStatus } from "@/lib/live-sse";
import type { DashboardData, TrustedDevice } from "@/lib/types";
import { UserAvatar } from "@/components/UserAvatar";
import HelixReactor, { TONE_VAR } from "@/components/mobile/HelixReactor";
import { buildCryptoStack, scoreVerdict, toReactorRings } from "@/lib/mobile-posture";

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

/** Navigational tile: a real number and where it takes you. */
function QuickTile({
  icon: Icon,
  value,
  label,
  index,
  onClick,
}: {
  icon: typeof ShieldCheck;
  value: string;
  label: string;
  index: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="qg-card qg-card-press qg-focusable qg-rise flex flex-col items-start gap-2.5 p-3.5 text-left"
      style={{ ["--qg-i" as string]: index }}
    >
      <span className="qg-tile-chip" style={{ color: "var(--qg-helix)" }}>
        <Icon size={17} />
      </span>
      <span className="min-w-0 self-stretch">
        <span className="qg-num block truncate text-[17px] leading-tight" style={{ color: "var(--qg-text)" }}>
          {value}
        </span>
        <span className="qg-eyebrow mt-1 block truncate">{label}</span>
      </span>
    </button>
  );
}

/**
 * Phone home screen.
 *
 * The Helix Reactor answers "am I protected right now?" in one glance, and the
 * numbered pipeline below it answers "which layer, and how do you know?" — both
 * rendered from the same buildCryptoStack() measurement, so an arc can never
 * contradict the row beside it.
 */
export default function MobileDashboard({ data, liveStatus, onNavigate }: MobileDashboardProps) {
  const { snapshot, devices, conversations, report, keyInventory } = data;
  const myId = data.profile?.id;
  const activeDevices = devices.filter((device) => device.user_id === myId && device.trust_state !== "Revoked");
  const trustedDevices = activeDevices.filter(isTrustedDevice);
  const visibleConversations = conversations.filter(
    (conversation) => !conversation.archived_at && !conversation.hidden_at && !conversation.deleted_at,
  );
  const recentConversations = visibleConversations.slice(0, 4);

  const layers = buildCryptoStack(data);
  const rings = toReactorRings(layers);
  const score = snapshot.quantum_safe_score;
  const verdict = scoreVerdict(score);

  const tiles = [
    { icon: MessageSquarePlus, value: `${visibleConversations.length}`, label: "Conversations", route: "chat" },
    { icon: MonitorSmartphone, value: `${trustedDevices.length}/${activeDevices.length}`, label: "Trusted devices", route: "devices" },
    { icon: LockKeyhole, value: snapshot.vault_storage, label: "Vault stored", route: "vault" },
    { icon: KeyRound, value: `${keyInventory.available_one_time_prekeys}`, label: "Keys ready", route: "keys" },
  ];

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
        className="qg-card qg-card-press qg-focusable qg-rise overflow-hidden p-5 text-left"
        style={{ ["--qg-i" as string]: 1 }}
      >
        <div className="flex items-center justify-between gap-3">
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

      {/* Quick access */}
      <div className="grid grid-cols-2 gap-3">
        {tiles.map((tile, index) => (
          <QuickTile
            key={tile.label}
            icon={tile.icon}
            value={tile.value}
            label={tile.label}
            index={2 + index}
            onClick={() => onNavigate(tile.route)}
          />
        ))}
      </div>

      {/* Cryptographic pipeline. Numbering is legitimate here: this IS the order
          the stack is exercised in when a message is sent. */}
      <Section index={6} title="Cryptographic pipeline" action={{ label: "Details", onClick: () => onNavigate("quantum") }}>
        <div className="flex flex-col">
          {layers.map((layer, index) => (
            <div
              key={layer.id}
              className="qg-slide flex items-center gap-3 py-2.5"
              style={{
                ["--qg-i" as string]: index,
                borderTop: index === 0 ? undefined : "1px solid var(--qg-hairline)",
              }}
            >
              <span className="qg-mono text-[11px] tabular-nums" style={{ color: "var(--qg-text-3)", flex: "none" }}>
                {String(layer.ordinal).padStart(2, "0")}
              </span>
              <div className="min-w-0 flex-1">
                <div className="qg-display text-[13px] leading-tight">{layer.label}</div>
                <div className="mt-0.5 truncate text-[11px]" style={{ color: "var(--qg-text-3)" }}>
                  {layer.caption}
                </div>
              </div>
              {/* The reactor arc already carries the proportion; the pill carries
                  the exact measurement. A third readout here would be noise. */}
              <span className={`qg-pill qg-tone-${layer.tone} shrink-0`} style={{ padding: "3px 9px" }}>
                {layer.detail}
              </span>
            </div>
          ))}
        </div>

        {report.warnings.length > 0 && (
          <div
            className="mt-3 flex flex-col gap-2 rounded-xl p-3"
            style={{ background: "var(--qg-warn-wash)", border: "1px solid var(--qg-hairline)" }}
          >
            {report.warnings.slice(0, 2).map((warning) => (
              <div key={warning} className="flex gap-2 text-[11.5px] leading-snug" style={{ color: "var(--qg-warn)" }}>
                <ShieldAlert size={14} className="mt-px shrink-0" />
                <span>{warning}</span>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* Recent chats */}
      <Section index={7} title="Recent chats" action={{ label: "View all", onClick: () => onNavigate("chat") }}>
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
      <Section index={8} title="My devices" action={{ label: "Manage", onClick: () => onNavigate("devices") }}>
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
        style={{ ["--qg-i" as string]: 9 }}
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
