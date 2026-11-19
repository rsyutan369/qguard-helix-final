import { useState, type ReactNode } from "react";
import { CreditCard, LogOut, Settings as SettingsIcon, TriangleAlert } from "lucide-react";

/**
 * Full-screen paywall shell (Qguard_Wiki/Android_Paywall_Guidelines).
 *
 * Mounted INSTEAD of the app shell whenever the authenticated account has no
 * access-granting subscription: premium modules (chat, vault, calls, keys,
 * devices, audit, dashboard) are never even mounted — only the Subscription
 * page (pricing + purchase + restore) and Settings/Profile remain reachable,
 * plus sign-out. The realtime subscription stream swaps this shell out
 * automatically the moment a verified payment activates the account.
 */
export function PaywallGate(props: {
  /** True when the account HAD a subscription that no longer grants access. */
  expired: boolean;
  subscriptionPage: ReactNode;
  settingsPage: ReactNode;
  onSignOut: () => void;
}) {
  const [tab, setTab] = useState<"subscription" | "settings">("subscription");

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-canvas">
      <header className="flex items-center justify-between border-b border-line bg-white/75 px-5 py-3 backdrop-blur-xl">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-full">
            <img src="/brand/qguard-messaging-badge.webp" alt="QGuard Messaging" className="h-full w-full object-contain drop-shadow-[0_4px_10px_rgba(59,130,246,0.45)]" />
          </div>
          <div>
            <div className="text-sm font-bold tracking-wide text-violet-600">QGUARD HELIX</div>
            <div className="text-[11px] font-medium text-ink-400">Quantum Messaging</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center rounded-full bg-canvas p-0.5 ring-1 ring-line">
            <button
              type="button"
              onClick={() => setTab("subscription")}
              className={`flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-bold transition ${tab === "subscription" ? "bg-violet-600 text-white" : "text-ink-500 hover:text-ink-800"}`}
            >
              <CreditCard size={13} /> Subscription
            </button>
            <button
              type="button"
              onClick={() => setTab("settings")}
              className={`flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-bold transition ${tab === "settings" ? "bg-violet-600 text-white" : "text-ink-500 hover:text-ink-800"}`}
            >
              <SettingsIcon size={13} /> Settings
            </button>
          </div>
          <button
            type="button"
            onClick={props.onSignOut}
            title="Sign out"
            className="flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-600 hover:bg-canvas"
          >
            <LogOut size={13} /> Sign out
          </button>
        </div>
      </header>

      {props.expired && (
        <div className="flex items-center justify-center gap-2 border-b border-amber-200 bg-amber-50 px-4 py-2 text-xs font-semibold text-amber-800">
          <TriangleAlert size={14} />
          Your subscription has ended — secure messaging, calls, and the vault are locked until it is renewed.
        </div>
      )}

      <main className="min-h-0 flex-1 overflow-y-auto p-5">
        {tab === "subscription" ? props.subscriptionPage : props.settingsPage}
      </main>
    </div>
  );
}
