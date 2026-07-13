import { useEffect, useState } from "react";
import { ChevronRight, FileLock2, LockKeyhole, ShieldCheck, Video } from "lucide-react";

const DONE_KEY = "qguard_mobile_onboarding_done";

const SLIDES = [
  {
    icon: LockKeyhole,
    title: "Quantum-Safe Messaging",
    body: "Every message is end-to-end encrypted with hybrid post-quantum cryptography — X25519 + ML-KEM (FIPS 203) with AES-256-GCM.",
    accent: "from-violet-600 via-violet-500 to-indigo-500",
  },
  {
    icon: Video,
    title: "Encrypted Calls",
    body: "Voice and video calls negotiate quantum-safe media keys and verify peer identity with Ed25519 + ML-DSA dual signatures before a single frame is sent.",
    accent: "from-indigo-500 via-violet-500 to-fuchsia-500",
  },
  {
    icon: FileLock2,
    title: "Quantum Vault",
    body: "A local-only encrypted vault for photos, videos and documents. Your files never leave this device unencrypted — you hold the recovery key.",
    accent: "from-fuchsia-500 via-violet-500 to-violet-600",
  },
];

/** True until the user finishes (or skips) the first-run tour on this device. */
export function isMobileOnboardingPending(): boolean {
  try {
    return localStorage.getItem(DONE_KEY) !== "1";
  } catch {
    return false;
  }
}

interface MobileOnboardingProps {
  onDone: () => void;
}

/**
 * First-run experience for the Android build: a short branded splash followed
 * by a swipeable 3-slide tour (messaging, calls, vault) in the light,
 * purple-gradient visual language of the QGuard Android design reference.
 */
export default function MobileOnboarding({ onDone }: MobileOnboardingProps) {
  const [phase, setPhase] = useState<"splash" | "slides">("splash");
  const [index, setIndex] = useState(0);

  useEffect(() => {
    const t = window.setTimeout(() => setPhase("slides"), 1400);
    return () => window.clearTimeout(t);
  }, []);

  const finish = () => {
    try {
      localStorage.setItem(DONE_KEY, "1");
    } catch {
      // Storage unavailable — the tour will simply show again next launch.
    }
    onDone();
  };

  if (phase === "splash") {
    return (
      <div className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-gradient-to-b from-violet-50 via-white to-violet-100">
        <div className="flex h-24 w-24 animate-pulse items-center justify-center rounded-3xl border border-violet-100 bg-white p-3 shadow-soft">
          <img src="/NEW_LOGO.png" alt="QGuard" className="h-full w-full object-contain" />
        </div>
        <div className="mt-6 text-xl font-bold tracking-wide text-ink-950">QGUARD</div>
        <div className="mt-1 text-xs font-semibold uppercase tracking-[0.3em] text-violet-500">Messaging</div>
        <div className="mt-8 flex items-center gap-2 text-[11px] font-semibold text-emerald-600">
          <ShieldCheck size={13} />
          Quantum Safe · Privacy First
        </div>
      </div>
    );
  }

  const slide = SLIDES[index];
  const Icon = slide.icon;
  const last = index === SLIDES.length - 1;

  return (
    <div className="mobile-safe-top mobile-safe-bottom fixed inset-0 z-50 flex flex-col bg-gradient-to-b from-violet-50 via-white to-violet-100 px-6 pb-8 pt-6">
      <div className="flex justify-end">
        <button type="button" onClick={finish} className="rounded-full px-4 py-1.5 text-sm font-bold text-ink-500 active:bg-white">
          Skip
        </button>
      </div>

      <div className="flex flex-1 flex-col items-center justify-center text-center">
        <div className={`relative flex h-56 w-56 items-center justify-center rounded-[2.5rem] bg-gradient-to-br ${slide.accent} shadow-soft`}>
          <div className="pointer-events-none absolute -left-4 -top-4 h-20 w-20 rounded-full bg-white/20 blur-2xl" />
          <div className="pointer-events-none absolute -bottom-6 -right-2 h-24 w-24 rounded-full bg-white/15 blur-2xl" />
          <div className="flex h-24 w-24 items-center justify-center rounded-3xl bg-white/15 backdrop-blur-sm ring-1 ring-white/30">
            <Icon size={44} className="text-white" />
          </div>
        </div>

        <h2 className="mt-10 text-2xl font-bold leading-tight text-ink-950">{slide.title}</h2>
        <p className="mt-3 max-w-xs text-sm leading-6 text-ink-600">{slide.body}</p>
      </div>

      <div className="mb-6 flex justify-center gap-2">
        {SLIDES.map((_, i) => (
          <span
            key={i}
            className={`h-2 rounded-full transition-all ${i === index ? "w-6 bg-violet-600" : "w-2 bg-violet-200"}`}
          />
        ))}
      </div>

      <button
        type="button"
        onClick={() => (last ? finish() : setIndex((i) => i + 1))}
        className="flex w-full items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-violet-600 to-violet-500 px-6 py-3.5 text-sm font-bold text-white shadow-soft active:opacity-90"
      >
        {last ? "Get started" : "Continue"}
        <ChevronRight size={16} />
      </button>
    </div>
  );
}
