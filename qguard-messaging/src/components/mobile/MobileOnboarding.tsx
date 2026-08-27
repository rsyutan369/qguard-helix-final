import { useEffect, useRef, useState } from "react";
import { ArrowRight, FileLock2, LockKeyhole, ShieldCheck, Video } from "lucide-react";
import HelixReactor from "@/components/mobile/HelixReactor";

const DONE_KEY = "qguard_mobile_onboarding_done";

/**
 * Each slide re-tints the reactor by overriding the accent tokens on a wrapper —
 * the same brand object turns a different colour rather than three unrelated
 * illustrations competing for attention.
 *
 * Slides 2 and 3 read their hue through `--qg-onb-*` with the Cold Fusion
 * literal as the fallback, so the Android Modernist skin — which has exactly
 * one hue — can collapse all three slides onto the accent without this file
 * needing a second render path.
 */
const SLIDES = [
  {
    icon: LockKeyhole,
    eyebrow: "Messaging",
    title: "Private now, private later",
    body: "Messages are encrypted on this device with a hybrid of X25519 and ML-KEM (FIPS 203). Traffic captured today still cannot be read once quantum computers arrive.",
    chips: ["ML-KEM-1024", "AES-256-GCM"],
    accent: "var(--qg-helix)",
    accentBright: "var(--qg-helix-bright)",
  },
  {
    icon: Video,
    eyebrow: "Calls",
    title: "Know who picked up",
    body: "Voice and video negotiate quantum-safe media keys, then verify the other device with Ed25519 and ML-DSA signatures — before the first frame is sent.",
    chips: ["ML-DSA-65", "SRTP E2EE"],
    accent: "var(--qg-onb-calls, #8b5cf6)",
    accentBright: "var(--qg-onb-calls-bright, #c4b5fd)",
  },
  {
    icon: FileLock2,
    eyebrow: "Vault",
    title: "Files that stay on your device",
    body: "The Quantum Vault encrypts photos, videos and documents locally. Nothing leaves unencrypted, and you hold the only recovery key.",
    chips: ["Zero-knowledge", "Local-first"],
    accent: "var(--qg-onb-vault, #0e9f86)",
    accentBright: "var(--qg-onb-vault-bright, #2de1c2)",
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
 * First-run experience for the Android build: a branded reactor splash followed
 * by a three-slide tour, swipeable or tappable. Both themes are supported; all
 * motion collapses under prefers-reduced-motion.
 */
export default function MobileOnboarding({ onDone }: MobileOnboardingProps) {
  const [phase, setPhase] = useState<"splash" | "slides">("splash");
  const [index, setIndex] = useState(0);
  const touchStartX = useRef<number | null>(null);

  useEffect(() => {
    const t = window.setTimeout(() => setPhase("slides"), 1600);
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

  const go = (next: number) => {
    if (next < 0 || next >= SLIDES.length) return;
    setIndex(next);
  };

  if (phase === "splash") {
    return (
      <div className="qg-stage mobile-safe-top mobile-safe-bottom fixed inset-0 z-50 flex flex-col items-center justify-center overflow-hidden px-6">
        <HelixReactor variant="mark" live size={250}>
          <div
            className="flex h-[92px] w-[92px] items-center justify-center rounded-[26px] p-3.5"
            style={{
              background: "var(--qg-panel)",
              border: "1px solid var(--qg-hairline)",
              boxShadow: "var(--qg-glow)",
            }}
          >
            <img src="/NEW_LOGO.png" alt="" className="h-full w-full object-contain" />
          </div>
        </HelixReactor>

        <div className="qg-rise mt-9 text-center" style={{ ["--qg-i" as string]: 3 }}>
          <div className="qg-display text-[27px] leading-none">QGuard</div>
          <div className="qg-eyebrow mt-2.5">Messaging &amp; Vault</div>
        </div>

        <div className="qg-rise mt-7" style={{ ["--qg-i" as string]: 5 }}>
          <span className="qg-pill qg-tone-ok">
            <ShieldCheck size={12} />
            Post-quantum secure
          </span>
        </div>
      </div>
    );
  }

  const slide = SLIDES[index];
  const Icon = slide.icon;
  const last = index === SLIDES.length - 1;

  return (
    <div
      className="qg-stage mobile-safe-top mobile-safe-bottom fixed inset-0 z-50 flex flex-col overflow-hidden px-6 pb-7 pt-4"
      onTouchStart={(event) => {
        touchStartX.current = event.touches[0]?.clientX ?? null;
      }}
      onTouchEnd={(event) => {
        const start = touchStartX.current;
        touchStartX.current = null;
        if (start === null) return;
        const delta = (event.changedTouches[0]?.clientX ?? start) - start;
        if (Math.abs(delta) < 48) return;
        go(delta < 0 ? index + 1 : index - 1);
      }}
    >
      {/* Progress + skip. Segments show how much of the tour is left, which the
          usual dot row does not. */}
      <div className="flex items-center gap-3">
        <div className="flex flex-1 gap-1.5">
          {SLIDES.map((item, i) => (
            <span
              key={item.eyebrow}
              className="h-[3px] flex-1 overflow-hidden rounded-full"
              style={{ background: "var(--qg-hairline)" }}
            >
              <span
                className="block h-full rounded-full transition-all duration-500"
                style={{
                  width: i <= index ? "100%" : "0%",
                  background: "linear-gradient(90deg, var(--qg-flux), var(--qg-helix))",
                }}
              />
            </span>
          ))}
        </div>
        <button
          type="button"
          onClick={finish}
          className="qg-focusable qg-mono text-[11.5px] font-semibold"
          style={{ color: "var(--qg-text-3)" }}
        >
          Skip
        </button>
      </div>

      {/* pb biases the centred group upward so the space above the CTA reads as
          breathing room rather than a hole. */}
      <div className="flex flex-1 flex-col items-center justify-center pb-12 text-center">
        {/* key={index} restarts the entrance animation on every slide change. */}
        <div
          key={index}
          className="flex flex-col items-center"
          style={{
            ["--qg-helix" as string]: slide.accent,
            ["--qg-helix-bright" as string]: slide.accentBright,
          }}
        >
          <HelixReactor variant="mark" live size={252}>
            <span
              className="flex h-[92px] w-[92px] items-center justify-center rounded-[26px]"
              style={{
                background: "var(--qg-panel)",
                border: "1px solid var(--qg-hairline)",
                color: slide.accent,
                boxShadow: "var(--qg-glow)",
              }}
            >
              <Icon size={38} strokeWidth={1.6} />
            </span>
          </HelixReactor>

          <div className="qg-rise mt-8" style={{ ["--qg-i" as string]: 1 }}>
            <div className="qg-eyebrow" style={{ color: slide.accent }}>{slide.eyebrow}</div>
            <h2 className="qg-display mt-2.5 text-[25px] leading-[1.12]">{slide.title}</h2>
          </div>

          <p
            className="qg-rise mt-3.5 max-w-[19rem] text-[13.5px] leading-6"
            style={{ ["--qg-i" as string]: 2, color: "var(--qg-text-2)" }}
          >
            {slide.body}
          </p>

          <div className="qg-rise mt-5 flex flex-wrap justify-center gap-1.5" style={{ ["--qg-i" as string]: 3 }}>
            {slide.chips.map((chip) => (
              <span key={chip} className="qg-pill qg-tone-mute">{chip}</span>
            ))}
          </div>
        </div>
      </div>

      <button type="button" onClick={() => (last ? finish() : go(index + 1))} className="qg-btn qg-focusable">
        {last ? "Get started" : "Continue"}
        <ArrowRight size={16} />
      </button>
    </div>
  );
}
