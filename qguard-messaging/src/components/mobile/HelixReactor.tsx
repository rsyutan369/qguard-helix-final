import { useId, type ReactNode } from "react";

/**
 * One ring of the reactor. `value` is 0..1 completeness for that layer of the
 * cryptographic stack and is what actually sets the arc length — the gauge is a
 * readout, not an illustration.
 */
export interface ReactorRing {
  id: string;
  label: string;
  value: number;
  /** "mute" means the layer was not measured — never render that as a failure. */
  tone: "ok" | "info" | "warn" | "alert" | "mute";
}

/**
 * Graphic tone colours (arcs, dots, meters). Deliberately NOT the label colours
 * — those are held to a text-contrast floor and read muddy as strokes.
 * Exported so every mobile surface tints a shape from the same source.
 */
export const TONE_VAR: Record<ReactorRing["tone"], string> = {
  ok: "var(--qg-g-ok)",
  info: "var(--qg-g-info)",
  warn: "var(--qg-g-warn)",
  alert: "var(--qg-g-alert)",
  mute: "var(--qg-text-3)",
};

// Outermost ring first. Radii are chosen so the 7px strokes leave an even 9px
// channel between layers at the 200-unit viewBox.
const RADII = [88, 71, 54, 37];

interface HelixReactorProps {
  /** "readout" draws data-bound arcs; "mark" draws empty tracks as a brand device. */
  variant?: "readout" | "mark";
  rings?: ReactorRing[];
  /** Sweep only turns while the live stream is connected, so motion == status. */
  live?: boolean;
  size?: number;
  children?: ReactNode;
}

/**
 * The Helix Reactor — the one signature element of the mobile app.
 *
 * Concentric arcs map to the four real layers of the QGuard cryptographic
 * stack (identity → handshake → session → storage), each drawn to the length of
 * that layer's measured readiness. The outer sweep rotates only while the
 * realtime stream is connected; the halo breathes. Under prefers-reduced-motion
 * every arc renders at its final value with no animation (see mobile.css).
 */
export default function HelixReactor({
  variant = "readout",
  rings = [],
  live = false,
  size = 232,
  children,
}: HelixReactorProps) {
  const uid = useId().replace(/:/g, "");
  const visible = rings.slice(0, RADII.length);

  // The halo picks up the worst tone on show, so the ambient glow carries the
  // same verdict as the arcs instead of always reading "healthy blue".
  const worst = visible.reduce<ReactorRing["tone"]>((acc, ring) => {
    // "mute" (not measured) must never outrank a real verdict — an unmeasured
    // layer is not evidence of a problem.
    const order = { alert: 3, warn: 2, info: 1, ok: 0, mute: 0 } as const;
    return order[ring.tone] > order[acc] ? ring.tone : acc;
  }, "ok");

  const haloColor = variant === "mark" ? "var(--qg-helix)" : TONE_VAR[worst];

  return (
    <div
      className={`qg-reactor${variant === "mark" ? " qg-reactor--mark" : ""}`}
      style={{
        width: size,
        height: size,
        // Consumed by .qg-reactor-halo / .qg-reactor-sweep in mobile.css.
        ["--qg-halo-color" as string]: haloColor,
        ["--qg-sweep-color" as string]: "var(--qg-helix-bright)",
      }}
    >
      <span className="qg-reactor-halo" aria-hidden />
      {live && <span className="qg-reactor-sweep" aria-hidden />}
      {live && variant === "mark" && <span className="qg-reactor-sweep-reverse" aria-hidden />}

      <svg
        viewBox="0 0 200 200"
        width={size}
        height={size}
        className="absolute inset-0"
        aria-hidden
      >
        <defs>
          {visible.map((ring, index) => (
            <linearGradient key={ring.id} id={`${uid}-g${index}`} x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor={TONE_VAR[ring.tone]} stopOpacity="0.55" />
              <stop offset="55%" stopColor={TONE_VAR[ring.tone]} />
              <stop offset="100%" stopColor="var(--qg-helix-bright)" />
            </linearGradient>
          ))}
        </defs>

        <g transform="rotate(-90 100 100)">
          {RADII.map((radius, index) => {
            const circumference = 2 * Math.PI * radius;
            const ring = visible[index];
            // Leave a 6% breather so a full ring still reads as a ring, not a
            // closed circle with an invisible seam.
            const span = ring ? Math.max(0, Math.min(1, ring.value)) * 0.94 : 0;

            return (
              <g key={radius}>
                {/* Track */}
                <circle
                  cx="100"
                  cy="100"
                  r={radius}
                  fill="none"
                  stroke={variant === "mark" ? "var(--qg-helix)" : "var(--qg-hairline-strong)"}
                  strokeWidth={variant === "mark" ? 1.5 : 5}
                  strokeDasharray={variant === "mark" ? "2 7" : undefined}
                  opacity={variant === "mark" ? 0.45 - index * 0.07 : 0.55}
                />

                {ring && span > 0 && (
                  <>
                    {/* Soft under-stroke stands in for a blur filter — SVG
                        filters are costly in the Android WebView. */}
                    <circle
                      className="qg-reactor-arc"
                      cx="100"
                      cy="100"
                      r={radius}
                      fill="none"
                      stroke={TONE_VAR[ring.tone]}
                      strokeWidth={13}
                      strokeLinecap="round"
                      opacity={0.16}
                      strokeDasharray={circumference}
                      style={{
                        ["--qg-dash-from" as string]: `${circumference}`,
                        ["--qg-dash-to" as string]: `${circumference * (1 - span)}`,
                        ["--qg-i" as string]: index,
                      }}
                    />
                    <circle
                      className="qg-reactor-arc"
                      cx="100"
                      cy="100"
                      r={radius}
                      fill="none"
                      stroke={`url(#${uid}-g${index})`}
                      strokeWidth={5.5}
                      strokeLinecap="round"
                      strokeDasharray={circumference}
                      style={{
                        ["--qg-dash-from" as string]: `${circumference}`,
                        ["--qg-dash-to" as string]: `${circumference * (1 - span)}`,
                        ["--qg-i" as string]: index,
                      }}
                    />
                  </>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      <div className="relative z-10 flex flex-col items-center justify-center text-center">{children}</div>
    </div>
  );
}
