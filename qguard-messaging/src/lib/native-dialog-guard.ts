// Native dialog guard
// ---------------------------------------------------------------------------
// Tracks native OS dialogs (file open/save pickers) that the APP itself opens.
//
// On WebView2 (Tauri on Windows) opening such a dialog makes the WebView report
// `document.visibilityState === "hidden"` (and a window `blur`) even though the
// user has NOT actually left the app — the dialog is a child of our own window.
// The Zero-Trust workspace auto-lock (see `use-workspace-lock.ts`) treats those
// transient events as "user left", calls `lockAll()`, and tears the Quantum
// Vault / Secure Chat page down mid-operation — so the lock gate pops up the
// instant the user opens the encrypt / attach file picker.
//
// The only component that can reliably tell "I opened this dialog" from "the
// user switched away" is the app itself. So every app-initiated native dialog
// registers here for its lifetime, and auto-lock skips while one is open.
//
// Safety: every acquisition is guaranteed to release (promise `finally`, window
// `focus`, or a generous timeout) so the guard always self-heals and auto-lock
// can never get stuck disabled.

let activeDialogs = 0;

/** True while any app-initiated native OS dialog is open. */
export function isNativeDialogOpen(): boolean {
  return activeDialogs > 0;
}

/**
 * Low-level acquire. Returns an idempotent release. A small trailing delay
 * keeps the guard held just past dialog close so the closing
 * visibility/focus/blur event settles before auto-lock is re-armed.
 */
function acquire(): () => void {
  activeDialogs += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    window.setTimeout(() => {
      activeDialogs = Math.max(0, activeDialogs - 1);
    }, 750);
  };
}

/**
 * Wrap a promise-based native dialog (Tauri `open` / `save`). The guard is held
 * for the dialog's exact lifetime; `finally` guarantees release, so it can
 * never leak even if the dialog throws or is cancelled.
 */
export async function withNativeDialog<T>(run: () => Promise<T>): Promise<T> {
  const release = acquire();
  try {
    return await run();
  } finally {
    release();
  }
}

/**
 * Guard an HTML `<input type="file">` picker. There is no promise — the picker
 * closes on select OR cancel, and the window regains focus either way — so the
 * guard is held until focus returns, with a generous safety timeout so it
 * always self-heals if `focus` never fires.
 */
export function guardNativeFileInput(safetyMs = 300_000): void {
  const release = acquire();
  const safety = window.setTimeout(finish, safetyMs);

  function finish() {
    window.clearTimeout(safety);
    window.removeEventListener("focus", onFocus);
    release();
  }

  function onFocus() {
    // Defer slightly so the trailing visibility/blur event settles first.
    window.setTimeout(finish, 50);
  }

  window.addEventListener("focus", onFocus, { once: true });
}
