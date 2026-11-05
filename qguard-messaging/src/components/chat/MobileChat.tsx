import { useEffect, useRef, type ReactNode } from "react";
import { BellOff, Archive, ArrowLeft, EyeOff, Info, Loader2, Lock, MoreVertical, Pencil, X } from "lucide-react";

/*
 * Phone chrome for Secure Chat, in the shape people know from Signal and
 * Telegram: a full-width conversation list (name and time on one line, the
 * last activity and an unread count on the next), one compose button instead
 * of a row of four, and every secondary action in a bottom sheet instead of
 * squeezed into a header. Desktop keeps its own layout; these render only when
 * the page is in its mobile layout.
 */

/** A bottom sheet over the page and the navigation bar. */
export function MobileSheet(props: { title: string; subtitle?: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") props.onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [props.onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center" role="dialog" aria-modal="true" aria-label={props.title}>
      <button type="button" aria-label="Close" className="qg-scrim" onClick={props.onClose} />
      <div className="qg-sheet mobile-safe-bottom px-2 pb-4 pt-3">
        <div className="mx-auto mb-3 qg-grabber" />
        <div className="mb-1 flex items-center gap-3 px-3">
          <div className="min-w-0 flex-1">
            <h2 className="qg-display truncate text-[15px]">{props.title}</h2>
            {props.subtitle && <p className="mt-0.5 truncate text-xs text-ink-500">{props.subtitle}</p>}
          </div>
          <button type="button" onClick={props.onClose} className="qg-icon-btn qg-focusable" aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="mt-1">{props.children}</div>
      </div>
    </div>
  );
}

/** One row in a sheet: icon, label, and a line saying what it does. */
export function SheetAction(props: {
  icon: ReactNode;
  label: string;
  detail?: string;
  danger?: boolean;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      disabled={props.disabled}
      className={`flex min-h-[56px] w-full items-center gap-3.5 rounded-xl px-3 py-2.5 text-left transition active:bg-canvas disabled:cursor-not-allowed disabled:opacity-50 ${props.danger ? "text-rose-600" : "text-ink-950"}`}
    >
      <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${props.danger ? "bg-rose-50" : "bg-canvas text-ink-700"}`}>
        {props.icon}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-[15px] font-semibold leading-tight">{props.label}</span>
        {props.detail && <span className="mt-0.5 block text-xs leading-snug text-ink-500">{props.detail}</span>}
      </span>
    </button>
  );
}

const LONG_PRESS_MS = 450;
const MOVE_TOLERANCE_PX = 10;

/**
 * A conversation in the list. Tap opens it; a long press (or the platform's
 * context-menu gesture) opens its actions, as in Signal and Telegram.
 */
export function MobileConversationRow(props: {
  avatar: ReactNode;
  title: string;
  preview: string;
  time: string;
  unread: number;
  archived: boolean;
  hidden: boolean;
  /** Muted (Notifications & Sounds): no sound or alert for new messages. */
  muted?: boolean;
  busy: boolean;
  onOpen: () => void;
  onActions: () => void;
}) {
  const timer = useRef<number | undefined>(undefined);
  const start = useRef<{ x: number; y: number } | null>(null);
  const longPressed = useRef(false);

  const cancel = () => {
    if (timer.current !== undefined) window.clearTimeout(timer.current);
    timer.current = undefined;
    start.current = null;
  };
  useEffect(() => cancel, []);

  const openActions = () => {
    longPressed.current = true;
    cancel();
    navigator.vibrate?.(12);
    props.onActions();
  };

  return (
    <li>
      <button
        type="button"
        onPointerDown={(event) => {
          longPressed.current = false;
          start.current = { x: event.clientX, y: event.clientY };
          timer.current = window.setTimeout(openActions, LONG_PRESS_MS);
        }}
        onPointerMove={(event) => {
          const origin = start.current;
          if (origin && Math.hypot(event.clientX - origin.x, event.clientY - origin.y) > MOVE_TOLERANCE_PX) cancel();
        }}
        onPointerUp={cancel}
        onPointerLeave={cancel}
        onPointerCancel={cancel}
        onContextMenu={(event) => {
          event.preventDefault();
          if (!longPressed.current) openActions();
        }}
        onClick={() => {
          if (longPressed.current) {
            longPressed.current = false;
            return;
          }
          props.onOpen();
        }}
        aria-label={`${props.title}${props.unread > 0 ? `, ${props.unread} unread` : ""}. Long press for actions.`}
        className="flex w-full select-none items-center gap-3 px-4 text-left transition active:bg-canvas"
        style={{ WebkitTouchCallout: "none" }}
      >
        {props.avatar}
        <span className="flex min-w-0 flex-1 flex-col justify-center border-b border-line py-3">
          <span className="flex items-baseline gap-2">
            <span className="min-w-0 flex-1 truncate text-[15px] font-semibold text-ink-950">{props.title}</span>
            {props.time && (
              <span className={`shrink-0 text-[11px] ${props.unread > 0 ? "font-bold text-violet-600" : "text-ink-500"}`}>{props.time}</span>
            )}
          </span>
          <span className="mt-0.5 flex items-center gap-1.5">
            {props.archived && <Archive size={12} className="shrink-0 text-ink-400" aria-label="Archived" />}
            {props.hidden && <EyeOff size={12} className="shrink-0 text-ink-400" aria-label="Hidden" />}
            {props.muted && <BellOff size={12} className="shrink-0 text-ink-400" aria-label="Muted" />}
            <span className="min-w-0 flex-1 truncate text-[13px] text-ink-600">{props.preview}</span>
            {props.busy ? (
              <Loader2 size={14} className="shrink-0 animate-spin text-ink-500" />
            ) : props.unread > 0 ? (
              <span className="flex h-5 min-w-[20px] shrink-0 items-center justify-center rounded-full bg-violet-600 px-1.5 text-[11px] font-bold text-white">
                {props.unread > 99 ? "99+" : props.unread}
              </span>
            ) : null}
          </span>
        </span>
      </button>
    </li>
  );
}

/**
 * A contact in the phone's Contacts tab. Tap opens its actions (chat,
 * restrict, block, delete) in a sheet, the way Signal and Telegram show a
 * contact; the state is spelled out under the name rather than as a bare chip.
 */
export function MobileContactRow(props: {
  avatar: ReactNode;
  name: string;
  detail: string;
  state: "added" | "restricted" | "blocked" | "removed";
  busy: boolean;
  onOpen: () => void;
}) {
  const badge = props.state === "blocked"
    ? { label: "Blocked", className: "bg-rose-50 text-rose-600" }
    : props.state === "restricted"
      ? { label: "Restricted", className: "bg-amber-50 text-amber-700" }
      : null;
  return (
    <li>
      <button
        type="button"
        onClick={props.onOpen}
        aria-label={`${props.name}${badge ? `, ${badge.label.toLowerCase()}` : ""}. Open contact actions.`}
        className="flex w-full items-center gap-3 px-4 text-left transition active:bg-canvas"
      >
        {props.avatar}
        <span className="flex min-w-0 flex-1 items-center gap-2 border-b border-line py-3">
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[15px] font-semibold text-ink-950">{props.name}</span>
            <span className="mt-0.5 block truncate text-[13px] text-ink-600">{props.detail}</span>
          </span>
          {props.busy ? (
            <Loader2 size={16} className="shrink-0 animate-spin text-ink-500" />
          ) : badge && (
            <span className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-bold ${badge.className}`}>{badge.label}</span>
          )}
        </span>
      </button>
    </li>
  );
}

/** Folder-style filter tabs (Chats / Contacts / Archived / Hidden) that scroll instead of truncating. */
export function MobileFilterTabs<T extends string>(props: {
  tabs: Array<{ id: T; label: string; count: number; locked: boolean }>;
  active: T;
  onSelect: (id: T) => void;
}) {
  return (
    <div role="tablist" aria-label="Conversation folders" className="flex gap-1.5 overflow-x-auto px-4 py-2.5">
      {props.tabs.map((tab) => {
        const selected = tab.id === props.active;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={selected}
            onClick={() => props.onSelect(tab.id)}
            className={`flex h-9 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full px-3.5 text-[13px] font-semibold transition ${selected ? "conversation-segment-active" : "border border-line text-ink-600"}`}
          >
            {tab.locked && <Lock size={12} aria-label="Locked" />}
            {tab.label}
            {tab.count > 0 && <span className="text-[11px] font-bold opacity-70">{tab.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

/**
 * The open conversation's header: back, who it is, the protection line under
 * the name, a call button, and everything else behind one options button. A
 * status that is not plain "ready" gets its own line underneath, never a chip
 * squeezed between the icons.
 */
export function MobileThreadHeader(props: {
  avatar: ReactNode;
  title: string;
  badge?: ReactNode;
  call?: ReactNode;
  onBack: () => void;
  onOptions?: () => void;
  notice?: string | null;
}) {
  return (
    <>
      <div className="flex items-center gap-1 border-b border-line px-1.5 py-1.5">
        <button
          type="button"
          onClick={props.onBack}
          className="flex h-11 w-11 shrink-0 items-center justify-center text-ink-700"
          aria-label="Back to conversations"
        >
          <ArrowLeft size={20} />
        </button>
        {props.avatar}
        <div className="min-w-0 flex-1 pl-1.5">
          <h2 className="truncate text-[15px] font-semibold leading-tight text-ink-950">{props.title}</h2>
          {props.badge}
        </div>
        {props.call}
        {props.onOptions && (
          <button
            type="button"
            onClick={props.onOptions}
            className="flex h-11 w-10 shrink-0 items-center justify-center text-ink-700"
            aria-label="Conversation options"
            title="Conversation options"
          >
            <MoreVertical size={20} />
          </button>
        )}
      </div>
      {props.notice && (
        <div className="flex items-start gap-2 border-b border-line bg-canvas px-4 py-2 text-xs font-semibold text-ink-600" role="status">
          <Info size={14} className="mt-px shrink-0" />
          <span className="min-w-0">{props.notice}</span>
        </div>
      )}
    </>
  );
}

/** The one compose button, above the navigation bar. */
export function MobileComposeButton(props: { onClick: () => void; label?: string; icon?: ReactNode }) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      aria-label={props.label ?? "New chat, group or channel"}
      title={props.label ?? "New chat, group or channel"}
      className="fixed right-5 z-30 flex h-14 w-14 items-center justify-center rounded-2xl bg-violet-600 text-white shadow-lg transition active:scale-95"
      style={{ bottom: "calc(env(safe-area-inset-bottom, 0px) + 92px)" }}
    >
      {props.icon ?? <Pencil size={22} />}
    </button>
  );
}
