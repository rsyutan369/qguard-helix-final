import { useEffect, useLayoutEffect, useMemo, useRef, useState, type FormEvent, type RefObject } from "react";
import { AlertTriangle, ArrowLeft, Check, CheckCheck, Clock3, Info, Send, ShieldCheck, Users } from "lucide-react";
import {
  formatOfflineTime, offlineError, offlineLinkState, offlinePeerName,
  type MeshMessage, type OfflinePeer,
} from "@/lib/offline";
import { safeInvoke } from "@/lib/tauri";
import { offlinePairingPlatform } from "./OfflinePairingDialog";
import { PeerPicture } from "./PeerPicture";
import "./mesh-conversation.css";

/** Bubble time: the clock time today, the date and time otherwise. */
export function meshBubbleTime(seconds: number, now = Date.now()): string {
  const date = new Date(seconds * 1000);
  const today = new Date(now).toDateString() === date.toDateString();
  return today
    ? date.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })
    : date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

/** Messages exchanged with one device, oldest first. */
export function meshThread(messages: MeshMessage[] | null, peer: string): MeshMessage[] {
  if (!messages) return [];
  const when = (message: MeshMessage) => message.direction === "incoming" ? message.receivedAt ?? message.createdAt : message.createdAt;
  return messages
    .map((message, index) => ({ message, index }))
    .filter(({ message }) => message.direction === "incoming" ? message.sender === peer : message.recipients.includes(peer))
    // The ledger is written in local order: it breaks ties inside one second.
    .sort((a, b) => when(a.message) - when(b.message) || a.index - b.index)
    .map(({ message }) => message);
}

/** What one outgoing message's delivery line says for this device. */
export function meshDeliveryState(message: MeshMessage, peer: string, linked: boolean): { label: string; tone: "delivered" | "sending" | "waiting" | "failed" } {
  if (message.deliveredTo.includes(peer)) return { label: "Delivered", tone: "delivered" };
  if (message.status === "expired") return { label: "Not delivered. The message expired.", tone: "failed" };
  if (message.relayedTo?.includes(peer)) return { label: "Relayed, awaiting delivery", tone: "waiting" };
  return linked ? { label: "Sending", tone: "sending" } : { label: "Waiting for connection", tone: "waiting" };
}

/** Smallest conversation height before the page scrolls instead (px). */
const MIN_CONVERSATION_HEIGHT = 320;
/** Clear space kept between the composer and a bottom navigation bar (px). */
export const COMPOSER_CLEARANCE = 12;

function scrollParent(element: HTMLElement): HTMLElement | null {
  for (let parent = element.parentElement; parent; parent = parent.parentElement) {
    const overflow = getComputedStyle(parent).overflowY;
    if (overflow === "auto" || overflow === "scroll") return parent;
  }
  return null;
}

/**
 * Where usable space ends, measured from the top of the scroll area: above its
 * bottom padding, and at least COMPOSER_CLEARANCE above any bottom navigation
 * bar that overlaps it (a floating rail, or one that sits over the content on
 * a given skin). `bars` are the bars' top edges in the same coordinates.
 */
export function meshUsableBottom(viewport: number, paddingBottom: number, bars: number[]): number {
  return bars.reduce((limit, bar) => Math.min(limit, bar - COMPOSER_CLEARANCE), viewport - paddingBottom);
}

/**
 * The height that lets the conversation fill what its scroll area still shows
 * below the content above it (shell header, offline banner, network notice)
 * and above the navigation. Viewport arithmetic cannot know those heights,
 * and guessing left the composer under the navigation bar on phones.
 */
export function meshConversationFit(metrics: {
  /** Where usable space ends (see meshUsableBottom). */
  bottom: number;
  /** Conversation top, measured from the top of the scroll content. */
  top: number;
  /** Content after the conversation (wrapper padding, trailing elements). */
  trailing: number;
}): number {
  const available = metrics.bottom - metrics.top - metrics.trailing;
  return Math.max(MIN_CONVERSATION_HEIGHT, Math.floor(available));
}

/** Keeps the conversation sized to the space it actually has, and the composer in view. */
function useFittedConversation(section: RefObject<HTMLElement | null>, composer: RefObject<HTMLElement | null>) {
  useLayoutEffect(() => {
    const element = section.current;
    const scroller = element && scrollParent(element);
    if (!element || !scroller) return;
    let frame = 0;
    let first = true;
    const fit = () => {
      frame = 0;
      const style = getComputedStyle(scroller);
      const paddingBottom = Number.parseFloat(style.paddingBottom) || 0;
      const box = scroller.getBoundingClientRect();
      const rect = element.getBoundingClientRect();
      const top = rect.top - box.top - scroller.clientTop + scroller.scrollTop;
      let contentBottom = rect.bottom;
      for (const child of Array.from(scroller.children)) contentBottom = Math.max(contentBottom, child.getBoundingClientRect().bottom);
      const origin = box.top + scroller.clientTop;
      const bars = Array.from(document.querySelectorAll<HTMLElement>("[data-qg-bottom-bar]"))
        .map((bar) => bar.getBoundingClientRect())
        .filter((bar) => bar.height > 0 && bar.top < box.bottom)
        .map((bar) => bar.top - origin);
      const bottom = meshUsableBottom(scroller.clientHeight, paddingBottom, bars);
      const height = meshConversationFit({ bottom, top, trailing: contentBottom - rect.bottom });
      if (element.style.getPropertyValue("--mesh-conversation-height") !== `${height}px`) {
        element.style.setProperty("--mesh-conversation-height", `${height}px`);
      }
      // When the space is too small (a large notice, an open keyboard), the
      // page scrolls: bring the composer above the navigation bar.
      const overflow = top + height - bottom;
      const typing = composer.current?.contains(document.activeElement) ?? false;
      if (overflow > 0 && (first || typing) && scroller.scrollTop < overflow) scroller.scrollTop = overflow;
      first = false;
    };
    const schedule = () => { if (!frame) frame = requestAnimationFrame(fit); };
    fit();
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(schedule);
    observer?.observe(scroller);
    for (const child of Array.from(scroller.children)) observer?.observe(child);
    window.addEventListener("resize", schedule);
    window.visualViewport?.addEventListener("resize", schedule);
    return () => {
      if (frame) cancelAnimationFrame(frame);
      observer?.disconnect();
      window.removeEventListener("resize", schedule);
      window.visualViewport?.removeEventListener("resize", schedule);
      element.style.removeProperty("--mesh-conversation-height");
    };
  }, [section, composer]);
}

/**
 * A continuous conversation with one trusted device over the persistent Mesh
 * channel. Everything shown is read from the sealed ledger and the channel
 * registry: a message is "Delivered" only once the other device's receipt is
 * stored, and the header reports the link the Rust core actually holds.
 */
export function MeshConversation({ peerId, peer, messages, running, onBack, onOpenMessage, onGroupMessage, onMeshRead }: {
  peerId: string; peer: OfflinePeer | undefined; messages: MeshMessage[] | null; running: boolean;
  onBack: () => void; onOpenMessage: (message: MeshMessage) => void; onGroupMessage: () => void;
  onMeshRead?: (messages: { id: string; sender: string }[]) => unknown;
}) {
  const thread = useMemo(() => meshThread(messages, peerId), [messages, peerId]);
  const [body, setBody] = useState("");
  const [emergency, setEmergency] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const pinned = useRef(true);
  const input = useRef<HTMLTextAreaElement>(null);
  const section = useRef<HTMLElement>(null);
  const composer = useRef<HTMLFormElement>(null);
  useFittedConversation(section, composer);
  const link = offlineLinkState(peer);
  const linked = peer?.link?.state === "connected";
  const platform = offlinePairingPlatform(peer?.platform);
  const canSend = Boolean(peer) && !peer?.blocked && !peer?.disconnected;

  // Incoming messages on screen have been read.
  const unread = useMemo(() => thread.filter((message) => message.direction === "incoming" && message.readAt == null)
    .map((message) => ({ id: message.id, sender: message.sender })), [thread]);
  const unreadKey = unread.map((entry) => entry.id).join(",");
  useEffect(() => {
    if (unread.length > 0) void onMeshRead?.(unread);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- keyed by the unread ids
  }, [unreadKey, onMeshRead]);

  // Follow new messages unless the user scrolled up to read older ones.
  useLayoutEffect(() => {
    const element = scroller.current;
    if (element && pinned.current) element.scrollTop = element.scrollHeight;
  }, [thread.length, thread[thread.length - 1]?.id]);

  async function send(event: FormEvent) {
    event.preventDefault();
    const text = body.trim();
    if (!text || sending || !canSend) return;
    setSending(true);
    setError(null);
    try {
      await safeInvoke<string>("offline_mesh_send", { recipients: [peerId], body: text, group: null, emergency, ttlSeconds: 86_400 });
      setBody("");
      setEmergency(false);
      pinned.current = true;
    } catch (failure) {
      setError(offlineError(failure));
    } finally {
      setSending(false);
      input.current?.focus();
    }
  }

  return <section ref={section} className="mesh-conversation" aria-label={`Conversation with ${offlinePeerName(peer, `Device ${peerId.slice(0, 8)}`)}`}>
    <header className="mesh-conversation-header">
      <button type="button" className="mesh-conversation-icon focus-ring" aria-label="Back" onClick={onBack}><ArrowLeft size={20} aria-hidden /></button>
      <span className="mesh-conversation-avatar" aria-hidden>
        <PeerPicture fingerprint={peer?.trusted ? peerId : undefined} digest={peer?.avatar} fallback={<platform.icon size={20} />} />
      </span>
      <div className="mesh-conversation-identity">
        <h2>{offlinePeerName(peer, `Device ${peerId.slice(0, 8)}`)}</h2>
        <p role="status" data-tone={link.tone}>
          <span className="mesh-conversation-dot" aria-hidden /> {link.label}{link.detail ? ` · ${link.detail}` : ""}
        </p>
      </div>
      <button type="button" className="mesh-conversation-icon focus-ring" aria-label="Send to several devices" title="Send to several devices" onClick={onGroupMessage}><Users size={19} aria-hidden /></button>
    </header>

    <div className="mesh-conversation-thread" ref={scroller} tabIndex={0}
      onScroll={(event) => {
        const element = event.currentTarget;
        pinned.current = element.scrollHeight - element.scrollTop - element.clientHeight < 72;
      }}>
      <p className="mesh-conversation-notice"><ShieldCheck size={14} aria-hidden /> Messages travel only between your two devices, sealed with ML-KEM-768 + X25519 and AES-256-GCM, and signed with ML-DSA-65 + Ed25519.</p>
      {messages === null && <p className="mesh-conversation-empty" role="status">Reading the sealed message ledger…</p>}
      {messages !== null && thread.length === 0 && <p className="mesh-conversation-empty">No messages with this device yet. {linked ? "The channel is open: say hello." : "A message you write now is sent as soon as the devices connect."}</p>}
      <ol>
        {thread.map((message) => {
          const mine = message.direction === "outgoing";
          const delivery = mine ? meshDeliveryState(message, peerId, linked) : null;
          const time = mine ? message.createdAt : message.receivedAt ?? message.createdAt;
          return <li key={`${message.direction}:${message.id}`} data-mine={mine} data-emergency={message.emergency || undefined}>
            <div className="mesh-conversation-bubble">
              {message.emergency && <p className="mesh-conversation-flag"><AlertTriangle size={13} aria-hidden /> Emergency</p>}
              {message.group && <p className="mesh-conversation-group">{message.group}</p>}
              <p className="mesh-conversation-body">{message.body}</p>
              <p className="mesh-conversation-meta">
                <time dateTime={new Date(time * 1000).toISOString()} title={formatOfflineTime(time)}>{meshBubbleTime(time)}</time>
                {delivery && <span data-tone={delivery.tone}>
                  {delivery.tone === "delivered" ? <CheckCheck size={14} aria-hidden /> : delivery.tone === "sending" ? <Check size={14} aria-hidden /> : delivery.tone === "failed" ? <AlertTriangle size={13} aria-hidden /> : <Clock3 size={13} aria-hidden />}
                  {delivery.label}
                </span>}
                <button type="button" className="mesh-conversation-details focus-ring" aria-label="Message details" onClick={() => onOpenMessage(message)}><Info size={14} aria-hidden /></button>
              </p>
            </div>
          </li>;
        })}
      </ol>
    </div>

    {error && <p role="alert" className="mesh-conversation-error">{error}</p>}
    {!running && <p role="status" className="mesh-conversation-error">Local networking is stopped. Messages are kept in the encrypted queue until you start discovery.</p>}
    {peer?.disconnected && <p role="status" className="mesh-conversation-error">You disconnected this device. Reconnect it from Trusted devices to send.</p>}
    <form ref={composer} className="mesh-conversation-composer" onSubmit={send}>
      <label className="mesh-conversation-emergency">
        <input type="checkbox" checked={emergency} onChange={(event) => setEmergency(event.target.checked)} />
        <AlertTriangle size={15} aria-hidden /><span className="sr-only">Mark as emergency</span>
      </label>
      <textarea ref={input} rows={1} value={body} maxLength={2048} placeholder="Message" aria-label="Message"
        disabled={!canSend}
        onChange={(event) => setBody(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
            event.preventDefault();
            event.currentTarget.form?.requestSubmit();
          }
        }} />
      <button type="submit" className="mesh-conversation-send focus-ring" disabled={!canSend || sending || !body.trim()} aria-label="Send message">
        <Send size={18} aria-hidden />
      </button>
    </form>
  </section>;
}
