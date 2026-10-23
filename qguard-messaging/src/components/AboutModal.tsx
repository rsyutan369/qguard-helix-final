import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  Atom,
  CheckCircle2,
  DownloadCloud,
  Fingerprint,
  KeyRound,
  Loader2,
  Lock,
  RefreshCcw,
  ShieldCheck,
  X,
} from "lucide-react";
import type { Update } from "@tauri-apps/plugin-updater";
import { isAndroidRuntime, isTauriRuntime } from "@/lib/tauri";
import { checkForAppUpdate, downloadAndInstallUpdate, relaunchApp } from "@/lib/app-update";

interface AboutModalProps {
  open: boolean;
  version: string;
  onClose: () => void;
}

type UpdateState =
  | { kind: "checking" }
  | { kind: "current" }
  | { kind: "available"; update: Update; version: string }
  | { kind: "downloading"; version: string; percent: number | null }
  | { kind: "ready"; version: string }
  | { kind: "error" }
  | { kind: "desktop-only" }
  | { kind: "android" };

const CRYPTO_BADGES: { icon: typeof KeyRound; label: string; standard: string }[] = [
  { icon: Atom, label: "ML-KEM-1024", standard: "FIPS 203" },
  { icon: Fingerprint, label: "ML-DSA-65", standard: "FIPS 204" },
  { icon: Lock, label: "AES-256-GCM", standard: "Envelope" },
];

const CURRENT_YEAR = new Date().getFullYear();

export function AboutModal({ open, version, onClose }: AboutModalProps) {
  const [state, setState] = useState<UpdateState>({ kind: "checking" });
  const updateRef = useRef<Update | null>(null);

  // Silent update check each time the dialog opens: a user reaching for "About"
  // wants a definitive answer to "am I on the latest version?". Outside the
  // desktop runtime we cannot check, so we say so instead of implying currency.
  useEffect(() => {
    if (!open) return;
    updateRef.current = null;

    if (!isTauriRuntime()) {
      setState({ kind: "desktop-only" });
      return;
    }

    // Android updates ship as signed APK / Play releases — the in-app updater
    // plugin isn't registered on mobile, so don't imply a self-update path.
    if (isAndroidRuntime()) {
      setState({ kind: "android" });
      return;
    }

    let cancelled = false;
    setState({ kind: "checking" });
    // Don't spin forever if the update endpoint is unreachable (e.g. a fresh
    // install whose endpoint isn't serving yet) — surface a clear message.
    const timeout = window.setTimeout(() => {
      if (!cancelled) setState({ kind: "error" });
    }, 8000);
    (async () => {
      try {
        const update = await checkForAppUpdate();
        if (cancelled) return;
        window.clearTimeout(timeout);
        if (update) {
          updateRef.current = update;
          setState({ kind: "available", update, version: update.version });
        } else {
          setState({ kind: "current" });
        }
      } catch {
        window.clearTimeout(timeout);
        if (!cancelled) setState({ kind: "error" });
      }
    })();
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [open]);

  // Close on Escape while open.
  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const install = async () => {
    const update = updateRef.current;
    if (!update) return;
    setState({ kind: "downloading", version: update.version, percent: null });
    try {
      await downloadAndInstallUpdate(update, ({ percent }) => {
        setState({ kind: "downloading", version: update.version, percent });
      });
      setState({ kind: "ready", version: update.version });
    } catch {
      setState({ kind: "error" });
    }
  };

  const restart = async () => {
    try {
      await relaunchApp();
    } catch {
      setState({ kind: "error" });
    }
  };

  // Portal to <body>: the sidebar that owns this modal's state has
  // `backdrop-filter` (backdrop-blur), which makes it a containing block for
  // `position: fixed` descendants — rendering the overlay inline would trap it
  // inside the 232px sidebar and clip it top and bottom. The portal lets the
  // overlay cover the real viewport.
  return createPortal(
    <div
      className="tour-fade fixed inset-0 z-[80] flex items-center justify-center bg-slate-900/55 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="about-title"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="tour-card flex max-h-[calc(100vh-2rem)] w-[min(92vw,480px)] flex-col overflow-hidden rounded-2xl border border-line bg-white shadow-soft">
        {/* Brand header — pinned so the logo, title and close stay visible even
            when the details scroll on a short window. */}
        <div className="relative shrink-0 overflow-hidden bg-gradient-to-br from-violet-700 via-violet-600 to-blue-700 p-6 text-white">
          <div className="pointer-events-none absolute -right-14 -top-16 h-48 w-48 rounded-full bg-white/10 blur-3xl" />
          <div className="pointer-events-none absolute -bottom-20 -left-10 h-48 w-48 rounded-full bg-blue-400/20 blur-3xl" />

          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="focus-ring absolute right-3 top-3 z-10 rounded-lg p-1.5 text-white/70 transition hover:bg-white/15 hover:text-white"
          >
            <X size={18} />
          </button>

          <div className="relative flex items-center gap-4">
            <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-full shadow-lg ring-1 ring-white/40">
              <img src="/brand/qguard-messaging-badge.webp" alt="QGuard Messaging" className="h-full w-full object-contain" />
            </div>
            <div className="min-w-0">
              <div className="text-[10px] font-semibold uppercase tracking-[0.26em] text-violet-200">
                Secure · Intelligent · Quantum-Ready
              </div>
              <h2 id="about-title" className="mt-1 text-xl font-bold leading-tight tracking-tight">
                Qguard Helix
              </h2>
              <div className="text-sm font-semibold text-violet-100">Messaging &amp; Quantum Vault</div>
            </div>
          </div>

          <div className="relative mt-4 inline-flex items-center gap-1.5 rounded-full bg-white/10 px-3 py-1 text-[11px] font-semibold text-violet-50 ring-1 ring-white/15">
            <ShieldCheck size={13} /> End-to-End Quantum Encrypted
          </div>
        </div>

        {/* Body — scrolls inside the height-capped card so nothing is ever clipped. */}
        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto p-6">
          <p className="text-sm leading-6 text-ink-600">
            <span className="font-semibold text-ink-900">Qguard Helix Messaging &amp; Quantum Vault</span> —
            end-to-end quantum-encrypted collaboration with a strictly on-device file vault, built on
            NIST-standardized post-quantum cryptography.
          </p>

          {/* Version + update status */}
          <div className="overflow-hidden rounded-xl border border-line bg-ink-50">
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-xs font-semibold uppercase tracking-wide text-ink-500">Installed version</span>
              <span className="rounded-md bg-violet-50 px-2.5 py-1 font-mono text-sm font-bold text-violet-600">
                v{version}
              </span>
            </div>
            <div className="border-t border-line px-4 py-3">
              <UpdateStatus state={state} onInstall={() => void install()} onRestart={() => void restart()} />
            </div>
          </div>

          {/* Cryptographic assurance */}
          <div>
            <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-ink-400">
              Cryptographic stack
            </div>
            <div className="flex flex-wrap gap-2">
              {CRYPTO_BADGES.map(({ icon: Icon, label, standard }) => (
                <span
                  key={label}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-white px-2.5 py-1.5 text-[11px] font-semibold text-ink-700"
                >
                  <Icon size={13} className="text-cyan-600" />
                  {label}
                  <span className="text-ink-400">· {standard}</span>
                </span>
              ))}
            </div>
          </div>

          {/* Meta footer */}
          <div className="flex items-center justify-between border-t border-line pt-4 text-[11px] text-ink-400">
            <span>© {CURRENT_YEAR} QGuard Helix</span>
            <span className="font-mono">com.qguard.messaging</span>
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}

function UpdateStatus({
  state,
  onInstall,
  onRestart,
}: {
  state: UpdateState;
  onInstall: () => void;
  onRestart: () => void;
}) {
  switch (state.kind) {
    case "checking":
      return (
        <div className="flex items-center gap-2 text-sm font-medium text-ink-500">
          <Loader2 size={16} className="animate-spin" /> Checking for updates…
        </div>
      );
    case "current":
      return (
        <div className="flex items-center gap-2 text-sm font-semibold text-emerald-600">
          <CheckCircle2 size={16} /> You&apos;re on the latest version
        </div>
      );
    case "available":
      return (
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2 text-sm font-semibold text-cyan-600">
            <DownloadCloud size={16} className="shrink-0" />
            <span className="truncate">Update available — v{state.version}</span>
          </div>
          <button
            type="button"
            onClick={onInstall}
            className="shrink-0 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-bold text-white transition hover:bg-cyan-700"
          >
            Update now
          </button>
        </div>
      );
    case "downloading":
      return (
        <div className="flex items-center gap-2 text-sm font-semibold text-ink-700">
          <Loader2 size={16} className="animate-spin text-cyan-600" />
          Downloading v{state.version}
          {state.percent !== null ? ` — ${state.percent}%` : "…"}
        </div>
      );
    case "ready":
      return (
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2 text-sm font-semibold text-emerald-600">
            <CheckCircle2 size={16} className="shrink-0" />
            <span className="truncate">v{state.version} installed</span>
          </div>
          <button
            type="button"
            onClick={onRestart}
            className="flex shrink-0 items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-bold text-white transition hover:bg-emerald-700"
          >
            <RefreshCcw size={13} /> Restart
          </button>
        </div>
      );
    case "desktop-only":
      return (
        <div className="text-sm font-medium text-ink-500">
          Update status is available in the installed desktop app.
        </div>
      );
    case "android":
      return (
        <div className="text-sm font-medium text-ink-500">
          Updates are delivered through signed app releases. Install the latest
          version from your app store or provided APK.
        </div>
      );
    case "error":
      return (
        <div className="text-sm font-medium text-ink-500">
          Couldn&apos;t check for updates. You may be offline — try again later.
        </div>
      );
  }
}
