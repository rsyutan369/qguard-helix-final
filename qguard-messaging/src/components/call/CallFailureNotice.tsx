import { useEffect, useState } from "react";
import { AlertTriangle, X } from "lucide-react";

/**
 * Why a call ended badly.
 *
 * A failed call used to vanish without a word: the reducer moved to `ended`,
 * the in-call overlay unmounted, and the reason it carried went nowhere. The
 * user was left to guess whether they had dialled the wrong person, whether the
 * app was broken, or whether the network was at fault — and an administrator
 * had nothing to act on either.
 *
 * The message is deliberately specific (see `describeCallConnectFailure`): a
 * connect failure with no relay configured says exactly that, because it is a
 * workspace configuration problem, not a user error.
 */
export function CallFailureNotice({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  const [visible, setVisible] = useState(true);

  // Auto-dismiss, but slowly — long enough to read a configuration message in
  // full, since that is the one someone needs to relay to their admin.
  useEffect(() => {
    setVisible(true);
    const timer = window.setTimeout(() => {
      setVisible(false);
      onDismiss();
    }, 14_000);
    return () => window.clearTimeout(timer);
  }, [message, onDismiss]);

  if (!visible) return null;

  return (
    <div
      role="alert"
      className="fixed bottom-6 left-1/2 z-[120] w-[min(32rem,calc(100vw-2rem))] -translate-x-1/2"
    >
      <div className="flex items-start gap-3 rounded-xl border border-amber-400/40 bg-slate-900/95 p-4 shadow-2xl backdrop-blur">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold text-white">Call ended</div>
          <p className="mt-1 text-sm leading-relaxed text-slate-300">{message}</p>
        </div>
        <button
          type="button"
          aria-label="Dismiss"
          onClick={() => { setVisible(false); onDismiss(); }}
          className="rounded-md p-1 text-slate-400 transition hover:bg-white/10 hover:text-white"
        >
          <X className="h-4 w-4" aria-hidden />
        </button>
      </div>
    </div>
  );
}
