// Unlock patterns on a 4 × 4 grid — the rules of src-tauri/src/vault/pattern.rs,
// which checks every pattern again. Dots are numbered 0–15, row by row.
//
// 4 × 4 because all 3 × 3 patterns together are only ~389,000 (fewer than the
// 6-digit PINs); 4 × 4 has ~1.3 million patterns of exactly 6 dots and ~79
// million of 8.

export const PATTERN_GRID = 4;
export const PATTERN_DOTS = PATTERN_GRID * PATTERN_GRID;
export const PATTERN_MIN_DOTS = 6;

function gcd(a: number, b: number): number {
  return b === 0 ? Math.abs(a) : gcd(b, a % b);
}

/** Dots strictly between `a` and `b` on the straight line joining them. */
export function dotsBetween(a: number, b: number): number[] {
  if (a === b) return [];
  const [ar, ac, br, bc] = [Math.floor(a / PATTERN_GRID), a % PATTERN_GRID, Math.floor(b / PATTERN_GRID), b % PATTERN_GRID];
  const [dr, dc] = [br - ar, bc - ac];
  const steps = gcd(dr, dc);
  const out: number[] = [];
  for (let k = 1; k < steps; k += 1) out.push((ar + (dr / steps) * k) * PATTERN_GRID + ac + (dc / steps) * k);
  return out;
}

/**
 * The pattern after the pointer reaches `dot`, the way the pad draws it: dots
 * on the way that are not connected yet are picked up first, in order, so a
 * stroke never jumps over one. A dot already in the pattern is ignored.
 */
export function extendPattern(dots: number[], dot: number): number[] {
  if (dot < 0 || dot >= PATTERN_DOTS || dots.includes(dot)) return dots;
  const last = dots[dots.length - 1];
  const picked = last === undefined ? [] : dotsBetween(last, dot).filter((between) => !dots.includes(between));
  return [...dots, ...picked, dot];
}

/** Whether the core will accept these dots as a pattern. */
export function isValidPattern(dots: number[]): boolean {
  if (dots.length < PATTERN_MIN_DOTS || new Set(dots).size !== dots.length) return false;
  return dots.every((dot, position) => {
    if (!Number.isInteger(dot) || dot < 0 || dot >= PATTERN_DOTS) return false;
    if (position === 0) return true;
    const seen = dots.slice(0, position);
    return dotsBetween(dots[position - 1], dot).every((between) => seen.includes(between));
  });
}

/** The canonical text the core stretches: `4x4:0-1-2-…`. */
export function encodePattern(dots: number[]): string {
  return `4x4:${dots.join("-")}`;
}

/** A rough guide shown while setting a pattern. */
export function patternStrength(dots: number[]): "too-short" | "fair" | "strong" {
  if (dots.length < PATTERN_MIN_DOTS) return "too-short";
  return dots.length >= 8 ? "strong" : "fair";
}
