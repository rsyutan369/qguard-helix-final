/* =============================================================================
   QGuard Messaging promo — soundtrack
   An original score synthesised for this cut, plus sparse sound effects from the
   bundled Pixabay-licensed library (assets/sfx, see its CREDITS.md).

   Run from the project root:   node tools/make-audio.mjs
   Writes:                      assets/audio/soundtrack.wav  (48 kHz stereo)

   120 BPM · one beat = 0.5s · one bar = 2s · 30 bars. Every chord change is a
   scene change (see SCENES in js/qg.js):

     bars  1–3   0–6s    Dm pedal          the threat
     bar   4     6s      F add9            the brand            (the light arrives)
     bars  5–6           C/E · B♭maj7
     bars  7–9   12s     F/A · B♭ · C      desktop + mobile     (groove enters)
     bars 10–21  18s     Dm · B♭ · F · C   chat ×3, vault ×3    (×3)
     bars 22–25  42s     F · C · Dm · B♭   the exact suite      (lift)
     bars 26–27  50s     B♭ · C            the three statements
     bars 28–30  54s     F add9            close

   Everything is deterministic: seeded noise, no clocks.
   ========================================================================== */
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SR = 48000;
const DUR = 60;
const N = SR * DUR;
const BEAT = 0.5;
const bar = (n) => (n - 1) * 2; // start time of bar n (1-based)

/* --- utilities ------------------------------------------------------------ */
const mtof = (m) => 440 * Math.pow(2, (m - 69) / 12);
const dB = (d) => Math.pow(10, d / 20);
const clamp = (v, a, b) => (v < a ? a : v > b ? b : v);

function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

class Bus {
  constructor() {
    this.L = new Float32Array(N);
    this.R = new Float32Array(N);
  }
  add(i, l, r) {
    if (i >= 0 && i < N) {
      this.L[i] += l;
      this.R[i] += r;
    }
  }
}

// equal-power pan, p in [-1, 1]
function pan(p) {
  const a = ((p + 1) * Math.PI) / 4;
  return [Math.cos(a), Math.sin(a)];
}

// Zavalishin TPT state-variable filter: stable under fast modulation.
class SVF {
  constructor() {
    this.ic1 = 0;
    this.ic2 = 0;
  }
  set(fc, q) {
    const g = Math.tan((Math.PI * clamp(fc, 20, SR * 0.45)) / SR);
    this.k = 1 / q;
    this.a1 = 1 / (1 + g * (g + this.k));
    this.a2 = g * this.a1;
    this.a3 = g * this.a2;
  }
  // returns low-pass; band and high are left on the instance
  tick(v0) {
    const v3 = v0 - this.ic2;
    const v1 = this.a1 * this.ic1 + this.a2 * v3;
    const v2 = this.ic2 + this.a2 * this.ic1 + this.a3 * v3;
    this.ic1 = 2 * v1 - this.ic1;
    this.ic2 = 2 * v2 - this.ic2;
    this.bp = v1;
    this.hp = v0 - this.k * v1 - v2;
    return v2;
  }
}

// band-limited saw (PolyBLEP)
function polyblep(t, dt) {
  if (t < dt) {
    t /= dt;
    return t + t - t * t - 1;
  }
  if (t > 1 - dt) {
    t = (t - 1) / dt;
    return t * t + t + t + 1;
  }
  return 0;
}

function adsr(t, dur, a, d, s, r) {
  if (t < 0) return 0;
  if (t < a) return t / a;
  if (t < a + d) return 1 - (1 - s) * ((t - a) / d);
  if (t < dur) return s;
  const x = (t - dur) / r;
  return x >= 1 ? 0 : s * (1 - x) * (1 - x);
}

/* --- buses ---------------------------------------------------------------- */
const pad = new Bus(); // warm chords
const keys = new Bus(); // FM electric piano + bells
const arp = new Bus(); // muted plucks
const bass = new Bus();
const drums = new Bus();
const fx = new Bus(); // drones, risers, booms
const sfx = new Bus(); // library sound effects

/* --- instruments ---------------------------------------------------------- */

// Warm pad: three detuned saws per note through a slow low-pass.
function padNote(at, dur, midi, gain, cutoff, attack = 0.5, release = 1.4) {
  const f = mtof(midi);
  const det = [-0.07, 0, 0.07];
  const pans = [-0.55, 0, 0.55];
  const start = Math.floor(at * SR);
  const len = Math.floor((dur + release) * SR);
  for (let v = 0; v < 3; v++) {
    const fv = f * Math.pow(2, det[v] / 12);
    const dt = fv / SR;
    let ph = (v * 0.37 + (midi % 7) * 0.11) % 1;
    const flt = new SVF();
    const [pl, pr] = pan(pans[v]);
    for (let i = 0; i < len; i++) {
      const t = i / SR;
      const env = adsr(t, dur, attack, 0.3, 0.85, release);
      if (env <= 0 && t > dur) break;
      ph += dt;
      if (ph >= 1) ph -= 1;
      let s = 2 * ph - 1 - polyblep(ph, dt);
      if ((i & 31) === 0) flt.set(cutoff * (0.75 + 0.25 * env) * (1 + 0.12 * Math.sin(t * 0.9 + v)), 0.7);
      s = flt.tick(s);
      const g = s * env * gain * 0.33;
      pad.add(start + i, g * pl, g * pr);
    }
  }
}

// FM electric piano: sine carrier, 1:1 modulator with a decaying index, a
// quiet 14:1 tine on the attack. Soft, clear, never harsh.
function epNote(at, dur, midi, gain, p = 0, bright = 1) {
  const f = mtof(midi);
  const start = Math.floor(at * SR);
  const rel = 0.5;
  const len = Math.floor((dur + rel) * SR);
  const [pl, pr] = pan(p);
  const w = (2 * Math.PI * f) / SR;
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    const amp = Math.exp(-t * 2.2) * (t < dur ? 1 : Math.max(0, 1 - (t - dur) / rel)) * Math.min(1, t / 0.004);
    const idx = (1.5 * bright * Math.exp(-t * 5) + 0.25) * Math.min(1, 440 / f + 0.3);
    const tine = 0.16 * bright * Math.exp(-t * 26) * Math.sin(w * 14 * i);
    const s = Math.sin(w * i + idx * Math.sin(w * i)) + tine;
    const g = s * amp * gain;
    keys.add(start + i, g * pl, g * pr);
  }
}

// FM bell: for the reveal and for things that arrive one after another.
function bellNote(at, midi, gain, p = 0, decay = 3.2) {
  const f = mtof(midi);
  const start = Math.floor(at * SR);
  const len = Math.floor(2.2 * SR);
  const [pl, pr] = pan(p);
  const w = (2 * Math.PI * f) / SR;
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    const amp = Math.exp(-t * decay) * Math.min(1, t / 0.003);
    const idx = 2.2 * Math.exp(-t * 6);
    const s = Math.sin(w * i + idx * Math.sin(w * 3.5 * i));
    const g = s * amp * gain;
    keys.add(start + i, g * pl, g * pr);
  }
}

// Muted pluck: triangle-ish tone through a fast-closing low-pass.
function pluck(at, midi, gain, p = 0, open = 1) {
  const f = mtof(midi);
  const start = Math.floor(at * SR);
  const len = Math.floor(0.42 * SR);
  const dt = f / SR;
  let ph = 0;
  const flt = new SVF();
  const [pl, pr] = pan(p);
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    const env = Math.exp(-t * 11) * Math.min(1, t / 0.002);
    ph += dt;
    if (ph >= 1) ph -= 1;
    let s = 2 * ph - 1 - polyblep(ph, dt);
    if ((i & 15) === 0) flt.set(420 + 4600 * open * Math.exp(-t * 13), 1.2);
    s = flt.tick(s);
    const g = s * env * gain;
    arp.add(start + i, g * pl, g * pr);
  }
}

function bassNote(at, dur, midi, gain, long = false) {
  const f = mtof(midi);
  const start = Math.floor(at * SR);
  const rel = long ? 0.5 : 0.08;
  const len = Math.floor((dur + rel) * SR);
  const dt = f / SR;
  let ph = 0;
  const flt = new SVF();
  const w = (2 * Math.PI * f) / SR;
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    const env = long ? adsr(t, dur, 0.06, 0.2, 0.9, rel) : adsr(t, dur, 0.004, 0.12, 0.55, rel);
    ph += dt;
    if (ph >= 1) ph -= 1;
    let s = 2 * ph - 1 - polyblep(ph, dt);
    if ((i & 15) === 0) flt.set(long ? 160 : 150 + 420 * Math.exp(-t * 14), 0.9);
    s = flt.tick(s) * 0.55 + Math.sin(w * i) * 0.8;
    const g = Math.tanh(s * 1.3) * env * gain;
    bass.add(start + i, g, g);
  }
}

const noise = rng(90210);

function kick(at, gain) {
  const start = Math.floor(at * SR);
  const len = Math.floor(0.42 * SR);
  let ph = 0;
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    const f = 44 + 110 * Math.exp(-t * 34);
    ph += (2 * Math.PI * f) / SR;
    const env = Math.exp(-t * 8.5) * Math.min(1, t / 0.0015);
    const click = Math.exp(-t * 260) * 0.25 * (noise() * 2 - 1);
    const g = (Math.sin(ph) * env + click) * gain;
    drums.add(start + i, g, g);
  }
}

function hat(at, gain, p = 0, decay = 70) {
  const start = Math.floor(at * SR);
  const len = Math.floor(0.09 * SR);
  const flt = new SVF();
  flt.set(8600, 1.4);
  const [pl, pr] = pan(p);
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    flt.tick(noise() * 2 - 1);
    const g = flt.hp * Math.exp(-t * decay) * gain;
    drums.add(start + i, g * pl, g * pr);
  }
}

function snap(at, gain) {
  const start = Math.floor(at * SR);
  const len = Math.floor(0.2 * SR);
  const flt = new SVF();
  flt.set(1650, 2.2);
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    // three quick bursts, like a soft clap
    const b = Math.exp(-((t % 0.011) * 300)) * (t < 0.033 ? 1 : 0) + Math.exp(-(t - 0.033) * 34) * (t >= 0.033 ? 1 : 0);
    flt.tick(noise() * 2 - 1);
    const g = flt.bp * b * gain;
    drums.add(start + i, g * 0.9, g * 1.0);
  }
}

function shaker(at, gain, p = 0) {
  const start = Math.floor(at * SR);
  const len = Math.floor(0.07 * SR);
  const flt = new SVF();
  flt.set(6200, 0.9);
  const [pl, pr] = pan(p);
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    flt.tick(noise() * 2 - 1);
    const env = Math.min(1, t / 0.012) * Math.exp(-t * 46);
    const g = flt.hp * env * gain;
    drums.add(start + i, g * pl, g * pr);
  }
}

function tick(at, gain, p = 0, freq = 3200) {
  const start = Math.floor(at * SR);
  const len = Math.floor(0.03 * SR);
  const flt = new SVF();
  flt.set(freq, 4);
  const [pl, pr] = pan(p);
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    flt.tick(noise() * 2 - 1);
    const g = flt.bp * Math.exp(-t * 190) * gain;
    drums.add(start + i, g * pl, g * pr);
  }
}

// Low boom for cuts and landings.
function boom(at, gain, f0 = 62, decay = 2.6) {
  const start = Math.floor(at * SR);
  const len = Math.floor(1.8 * SR);
  let ph = 0;
  const flt = new SVF();
  flt.set(220, 0.7);
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    const f = f0 * (0.55 + 0.45 * Math.exp(-t * 7));
    ph += (2 * Math.PI * f) / SR;
    const env = Math.exp(-t * decay) * Math.min(1, t / 0.003);
    const n = flt.tick(noise() * 2 - 1) * Math.exp(-t * 9) * 0.5;
    const g = (Math.sin(ph) + n) * env * gain;
    fx.add(start + i, g, g);
  }
}

// Filtered-noise swell that rises (or falls) into a cut.
function swell(from, to, gain, f0, f1, reverse = false) {
  const start = Math.floor(from * SR);
  const len = Math.floor((to - from) * SR);
  const fl = new SVF();
  const fr = new SVF();
  for (let i = 0; i < len; i++) {
    const p = i / len;
    const k = reverse ? 1 - p : p;
    if ((i & 15) === 0) {
      const fc = f0 * Math.pow(f1 / f0, k);
      fl.set(fc, 2.4);
      fr.set(fc * 1.07, 2.4);
    }
    fl.tick(noise() * 2 - 1);
    fr.tick(noise() * 2 - 1);
    const env = Math.pow(k, 2.2) * Math.min(1, (len - i) / (0.012 * SR)) * Math.min(1, i / (0.02 * SR));
    fx.add(start + i, fl.bp * env * gain, fr.bp * env * gain);
  }
}

/* --- harmony -------------------------------------------------------------- */
const CH = {
  Dm: { root: 38, pad: [50, 57, 62, 65, 69], arp: [62, 65, 69, 74, 76, 69] },
  Bb: { root: 34, pad: [46, 53, 58, 62, 65, 69], arp: [62, 65, 70, 74, 77, 70] },
  F: { root: 41, pad: [53, 57, 60, 65, 67, 69], arp: [60, 65, 69, 72, 77, 69] },
  C: { root: 36, pad: [48, 55, 60, 64, 67], arp: [60, 64, 67, 72, 76, 67] },
  "C/E": { root: 40, pad: [52, 55, 60, 64, 67], arp: [60, 64, 67, 72, 76, 67] },
  "F/A": { root: 33, pad: [45, 53, 57, 60, 65, 67], arp: [60, 65, 69, 72, 77, 69] },
  Fadd9: { root: 29, pad: [41, 53, 60, 65, 67, 69, 72], arp: [65, 67, 69, 72, 77, 81] },
  Bbmaj7: { root: 34, pad: [46, 53, 57, 62, 65, 69], arp: [62, 65, 69, 74, 77, 69] },
};

// bar number → chord
const PROG = {
  4: "Fadd9", 5: "C/E", 6: "Bbmaj7",
  7: "F/A", 8: "Bb", 9: "C",
  10: "Dm", 11: "Bb", 12: "F", 13: "C",
  14: "Dm", 15: "Bb", 16: "F", 17: "C",
  18: "Dm", 19: "Bb", 20: "F", 21: "C",
  22: "F", 23: "C", 24: "Dm", 25: "Bb",
  26: "Bb", 27: "C",
  28: "Fadd9", 29: "Fadd9", 30: "Fadd9",
};

/* Per-bar energy: which layers play. Night scenes (05, 08, 09) pull back. */
const FULL = { kick: [0, 1, 2, 3], hat: 1, snap: 1, bass: 1, arp: 1 };
const LIGHT = { kick: [0, 2], hat: 0.7, snap: 0, bass: 0.8, arp: 0.8 };
const INSIDE = { kick: [], hat: 0.5, snap: 0, bass: 0.6, arp: 1 };
const HALF = { kick: [0, 2.5], hat: 0.6, snap: 0.5, bass: 0.7, arp: 0.9 };
const LAYERS = {
  7: LIGHT, 8: LIGHT, 9: { ...LIGHT, snap: 0.6 },
  10: FULL, 11: FULL,
  12: INSIDE, 13: INSIDE,
  14: FULL, 15: FULL,
  16: FULL, 17: FULL,
  18: HALF, 19: HALF,
  20: { ...HALF, hat: 1 }, 21: { ...HALF, hat: 1 },
  22: FULL, 23: FULL, 24: FULL, 25: FULL,
};

/* --- score ---------------------------------------------------------------- */

// A — the threat (0–6s): a D pedal, a clock, a heartbeat.
{
  const start = 0;
  const len = Math.floor(6.3 * SR);
  const w1 = (2 * Math.PI * mtof(26)) / SR; // D1
  const w2 = (2 * Math.PI * mtof(38)) / SR; // D2
  const flt = new SVF();
  flt.set(130, 0.8);
  for (let i = 0; i < len; i++) {
    const t = i / SR;
    const env = Math.min(1, t / 1.6) * (t > 5.7 ? Math.max(0, 1 - (t - 5.7) / 0.6) : 1);
    const trem = 0.82 + 0.18 * Math.sin(2 * Math.PI * 0.5 * t);
    const rumble = flt.tick(noise() * 2 - 1) * 0.22;
    const s = (Math.sin(w1 * i) * 0.55 + Math.sin(w2 * i) * 0.2 + rumble) * env * trem * 0.34;
    fx.add(start + i, s, s);
  }
  // dark, closed pad: D minor, then the ninth leaning on it
  for (const m of [50, 57, 62, 65]) padNote(0.4, 5.3, m, 0.22, 520, 1.4, 0.5);
  padNote(2.0, 3.7, 64, 0.16, 640, 1.2, 0.5);
  padNote(4.0, 1.8, 69, 0.14, 900, 1.5, 0.3);
  // the clock
  for (let k = 0; k < 22; k++) {
    const t = 0.5 + k * 0.25;
    tick(t, k % 2 === 0 ? 0.26 : 0.15, k % 2 === 0 ? -0.35 : 0.35, k % 2 === 0 ? 3000 : 3800);
  }
  // the heartbeat
  for (const t of [0.02, 1.0, 2.0, 3.0, 4.0, 5.0]) kick(t, t === 2.0 ? 0.75 : 0.5);
  boom(2.0, 0.32, 58, 2.2);
  // the helix and the rise into the light
  swell(3.9, 6.0, 0.5, 260, 7200);
  for (let k = 0; k < 16; k++) {
    const t = 4.5 + k * 0.09;
    bellNote(t, [62, 65, 69, 72, 74, 77, 81, 84][k % 8] + (k >= 8 ? 12 : 0), 0.035 + k * 0.004, (k % 2 ? 0.5 : -0.5), 5);
  }
}

// B — the brand (6–12s): the light arrives on F.
boom(6.0, 0.42, 70, 2.1);
kick(6.0, 0.6);
for (let b = 4; b <= 6; b++) {
  const c = CH[PROG[b]];
  const at = bar(b);
  for (const m of c.pad) padNote(at, 1.95, m, 0.2, 1500 + (b === 4 ? 500 : 0), b === 4 ? 0.03 : 0.25, 1.0);
  c.pad.slice(1).forEach((m, i) => epNote(at + i * 0.028, 1.7, m + 12, 0.11, (i - 2) * 0.22));
  bassNote(at, 1.9, c.root + (c.root < 34 ? 12 : 0), 0.34, true);
  if (b > 4) kick(at, 0.42);
}
// the logo settles: a small bright run
[77, 81, 84, 89].forEach((m, i) => bellNote(6.12 + i * 0.11, m, 0.1, i % 2 ? 0.4 : -0.4));
// the name and the promise: soft plucks on the eighths
for (let k = 0; k < 16; k++) {
  const t = 8.0 + k * 0.25;
  const c = CH[PROG[t < 10 ? 5 : 6]];
  pluck(t, c.arp[k % c.arp.length], 0.2, k % 2 ? 0.45 : -0.45, 0.7);
}
// five chips, one per eighth: an ascending pentatonic
[72, 74, 77, 79, 81].forEach((m, i) => bellNote(9.5 + i * 0.25, m, 0.12, (i - 2) * 0.3));

// C, D — groove (bars 7–25)
const kickTimes = [];
for (let b = 7; b <= 25; b++) {
  const c = CH[PROG[b]];
  const L = LAYERS[b];
  const at = bar(b);
  const night = b === 12 || b === 13 || (b >= 18 && b <= 21);
  const lift = b >= 22;

  // pad
  for (const m of c.pad) padNote(at, 1.96, m, lift ? 0.21 : night ? 0.2 : 0.18, lift ? 3600 : night ? 1100 : 2500, 0.18, 0.7);

  // electric piano: the downbeat chord and a push on the "and" of two
  c.pad.slice(1).forEach((m, i) => epNote(at + i * 0.012, 0.9, m + 12, 0.085, (i - 2) * 0.2, lift ? 1.2 : 1));
  if (!night) c.pad.slice(2).forEach((m, i) => epNote(at + 0.75 + i * 0.01, 0.5, m + 12, 0.06, (2 - i) * 0.2));

  // bass
  if (L.bass) {
    if (night) {
      bassNote(at, 1.9, c.root, 0.36 * L.bass, true);
    } else {
      for (let k = 0; k < 8; k++) {
        const oct = k === 3 || k === 6 ? 12 : 0;
        bassNote(at + k * 0.25, 0.2, c.root + oct, 0.34 * L.bass);
      }
    }
  }

  // drums
  for (const q of L.kick) {
    kick(at + q * BEAT, 0.5);
    kickTimes.push(at + q * BEAT);
  }
  for (let q = 0; q < 4; q++) {
    const t = at + q * BEAT;
    if (L.hat) {
      hat(t + 0.25, 0.24 * L.hat, 0.3, 80);
      if (L.hat >= 1) {
        for (let k = 0; k < 4; k++) shaker(t + k * 0.125, k % 2 ? 0.16 : 0.1, k % 2 ? -0.45 : 0.45);
      }
    }
    if (L.snap && (q === 1 || q === 3)) snap(t, 0.4 * L.snap);
  }

  // arp: sixteenths, quiet, alternating sides
  if (L.arp) {
    for (let k = 0; k < 16; k++) {
      if (!lift && !night && (k === 3 || k === 11)) continue;
      const note = c.arp[(k * (night ? 1 : 5)) % c.arp.length] + (lift && k % 4 === 2 ? 12 : 0);
      pluck(at + k * 0.125, note, (night ? 0.16 : 0.13) * L.arp, k % 2 ? 0.5 : -0.5, night ? 0.5 : lift ? 1.15 : 0.85);
    }
  }
}

// a small motif for the vault and the suite, two notes a bar
const MOTIF = { 16: [81, 84], 17: [79, 76], 22: [81, 84], 23: [79, 84], 24: [81, 77], 25: [74, 77] };
for (const [b, notes] of Object.entries(MOTIF)) {
  bellNote(bar(+b), notes[0], 0.085, -0.25, 2.4);
  bellNote(bar(+b) + 1.0, notes[1], 0.075, 0.25, 2.4);
}

// E — the three statements (50–54s): one hit each, then the rise.
for (const [t, c] of [[50, "Bb"], [51, "Bb"], [52, "C"]]) {
  boom(t, 0.36, 66, 2.6);
  kick(t, 0.6);
  kickTimes.push(t);
  CH[c].pad.forEach((m) => padNote(t, t === 52 ? 1.95 : 0.9, m, 0.22, 1900, 0.01, 0.35));
  CH[c].pad.slice(1).forEach((m, i) => epNote(t + i * 0.008, 0.7, m + 12, 0.1, (i - 2) * 0.2, 1.3));
  bassNote(t, t === 52 ? 1.9 : 0.85, CH[c].root, 0.4, true);
}
swell(52.0, 54.0, 0.55, 300, 8200);
for (let k = 0; k < 16; k++) hat(52.0 + k * 0.125, 0.03 + k * 0.006, k % 2 ? 0.4 : -0.4, 110);

// F — close (54–60s): home.
boom(54.0, 0.42, 70, 1.9);
kick(54.0, 0.6);
kickTimes.push(54.0);
{
  const c = CH.Fadd9;
  for (const m of c.pad) padNote(54.0, 4.6, m, 0.21, 2000, 0.03, 1.3);
  c.pad.slice(1).forEach((m, i) => epNote(54.0 + i * 0.03, 3.0, m + 12, 0.11, (i - 3) * 0.2, 1.2));
  bassNote(54.0, 4.6, 29 + 12, 0.36, true);
  [77, 81, 84, 89].forEach((m, i) => bellNote(54.12 + i * 0.11, m, 0.1, i % 2 ? 0.4 : -0.4));
  // the line, the buttons, the address: a slow falling answer
  [[55.0, 84], [55.5, 81], [56.0, 79], [56.5, 77], [57.0, 72], [57.5, 77]].forEach(([t, m], i) => bellNote(t, m, 0.085, i % 2 ? 0.3 : -0.3, 2.2));
  for (let k = 0; k < 12; k++) pluck(54.5 + k * 0.25, c.arp[k % c.arp.length], 0.12 * (1 - k / 14), k % 2 ? 0.45 : -0.45, 0.8);
}

/* --- sound effects --------------------------------------------------------
   From the bundled library. `peak: true` slides the file so its loudest moment
   lands on the cue (an impact on the cut, a riser cresting on the reveal). */
const SFX_DIR = join(ROOT, "assets", "sfx");

function loadSfx(name) {
  const file = join(SFX_DIR, name + ".mp3");
  if (!existsSync(file)) throw new Error("missing sfx: " + file);
  const r = spawnSync("ffmpeg", ["-v", "error", "-i", file, "-f", "f32le", "-ac", "2", "-ar", String(SR), "-"], { maxBuffer: 1 << 28 });
  if (r.status !== 0) throw new Error("ffmpeg failed on " + name + ": " + r.stderr);
  const f = new Float32Array(r.stdout.buffer, r.stdout.byteOffset, Math.floor(r.stdout.byteLength / 4));
  const n = f.length / 2;
  let peak = 0;
  let peakAt = 0;
  for (let i = 0; i < n; i++) {
    const a = Math.max(Math.abs(f[2 * i]), Math.abs(f[2 * i + 1]));
    if (a > peak) {
      peak = a;
      peakAt = i;
    }
  }
  return { data: f, n, peak, peakAt };
}

const cache = {};
function cue(name, at, gain, o = {}) {
  const s = cache[name] || (cache[name] = loadSfx(name));
  const from = Math.floor((o.from || 0) * SR);
  const to = o.to ? Math.min(s.n, Math.floor(o.to * SR)) : s.n;
  let start = Math.floor(at * SR);
  if (o.peak) start -= s.peakAt - from;
  if (o.endAt !== undefined) start = Math.floor(o.endAt * SR) - (to - from);
  const norm = (gain * 0.9) / Math.max(s.peak, 1e-6);
  const fadeIn = Math.floor((o.fadeIn || 0.004) * SR);
  const fadeOut = Math.floor((o.fadeOut || 0.03) * SR);
  const [pl, pr] = pan(o.pan || 0);
  const len = to - from;
  for (let i = 0; i < len; i++) {
    const env = Math.min(1, i / fadeIn) * Math.min(1, (len - i) / fadeOut);
    const k = (from + i) * 2;
    sfx.add(start + i, s.data[k] * norm * env * pl * 1.414, s.data[k + 1] * norm * env * pr * 1.414);
  }
}

// 01 — threat
cue("glitch-3", 2.0, 0.2, { to: 1.6, fadeOut: 0.5 });
// the riser file is 10.03s; play its last 4.6s so it crests on the bloom
cue("riser", 0, 0.4, { from: 5.4, endAt: 6.0, fadeIn: 1.4, fadeOut: 0.02 });
// 02 — brand
cue("impact-bass-1", 6.0, 0.3, { peak: true, fadeOut: 0.4 });
cue("sparkle", 6.1, 0.2, { fadeOut: 0.4 });
// 02 → 03, and device arrivals
cue("whoosh-short", 12.0, 0.26, { peak: true });
cue("whoosh-short", 14.1, 0.2, { peak: true, pan: 0.4 });
cue("pop", 13.25, 0.14, { pan: -0.1 });
cue("pop", 14.7, 0.14, { pan: 0.4 });
cue("pop", 15.5, 0.14, { pan: 0.2 });
cue("ping", 16.1, 0.16, { pan: 0.4, fadeOut: 0.3 });
cue("pop", 16.5, 0.14, { pan: -0.4 });
// 03 → 04: into the chat
cue("whoosh", 18.0, 0.34, { peak: true });
cue("typing", 19.25, 0.22, { to: 1.0, pan: 0.3, fadeOut: 0.08 });
cue("click", 20.5, 0.3, { pan: 0.3 });
cue("pop", 20.56, 0.2, { pan: 0.3 });
cue("pop", 21.0, 0.12, { pan: -0.4 });
cue("pop", 21.25, 0.12, { pan: -0.3 });
// 04 → 05: inside the message
cue("whoosh", 22.0, 0.34, { peak: true });
cue("click-soft", 23.2, 0.3, { pan: -0.5 });
cue("chime", 25.0, 0.2, { pan: 0.5, fadeOut: 0.5 });
// 05 → 06: the call
cue("whoosh-short", 26.0, 0.26, { peak: true });
cue("notification", 26.5, 0.16, { fadeOut: 0.5 });
cue("ping", 28.0, 0.2, { fadeOut: 0.3 });
cue("click", 28.5, 0.28);
cue("chime", 29.0, 0.24, { fadeOut: 0.5 });
// 06 → 07: the vault
cue("whoosh", 30.0, 0.34, { peak: true });
cue("whoosh-short", 31.6, 0.18, { peak: true, pan: 0.2 });
cue("pop", 32.02, 0.2, { pan: 0.3 });
cue("click", 32.5, 0.3, { pan: 0.3 });
cue("pop", 33.0, 0.12, { pan: -0.4 });
cue("pop", 33.25, 0.12, { pan: -0.3 });
cue("pop", 33.5, 0.12, { pan: -0.4 });
// 07 → 08: the envelope
cue("whoosh", 34.0, 0.34, { peak: true });
cue("whoosh-short", 36.75, 0.24, { peak: true });
cue("impact-bass-1", 37.0, 0.2, { peak: true, fadeOut: 0.4 });
// 08 → 09: the terminal
cue("whoosh-short", 38.0, 0.26, { peak: true });
[38.12, 38.3, 38.5, 38.75, 39.0, 39.25, 39.5, 39.75].forEach((t, i) => cue("key-press", t, 0.2, { pan: i % 2 ? -0.35 : -0.15 }));
cue("typing", 39.8, 0.2, { to: 0.7, pan: -0.25, fadeOut: 0.08 });
cue("chime", 40.5, 0.26, { fadeOut: 0.5 });
// 09 → 10: the suite
cue("whoosh", 42.0, 0.36, { peak: true });
cue("sparkle", 42.05, 0.16, { fadeOut: 0.4 });
[43.5, 44.5, 45.5, 46.5].forEach((t, i) => cue("pop", t, 0.18, { pan: -0.2 + i * 0.1 }));
cue("click-soft", 47.5, 0.26);
// 11 — three statements, and the rise into the close
cue("impact-bass-2", 50.0, 0.26, { peak: true, fadeOut: 0.3 });
cue("impact-bass-1", 51.0, 0.24, { peak: true, fadeOut: 0.3 });
cue("impact-bass-2", 52.0, 0.26, { peak: true, fadeOut: 0.3 });
cue("riser", 0, 0.38, { from: 8.0, endAt: 54.0, fadeIn: 0.9, fadeOut: 0.02 });
// 12 — close
cue("impact-bass-1", 54.0, 0.3, { peak: true, fadeOut: 0.4 });
cue("sparkle", 54.1, 0.2, { fadeOut: 0.4 });
cue("pop", 56.5, 0.16, { pan: -0.15 });
cue("pop", 56.75, 0.16, { pan: 0.15 });
cue("click-soft", 57.0, 0.2);

// rows of the suite and the layers of the envelope arrive as rising bells
[65, 67, 69, 72].forEach((m, i) => bellNote(43.5 + i, m + 12, 0.1, -0.2 + i * 0.13));
[62, 65, 69, 74].forEach((m, i) => bellNote(34.0 + i * 0.5, m + 12, 0.1, -0.5 + i * 0.33));
// the reactor fills: a run that lands on 100%
for (let k = 0; k < 12; k++) pluck(14.6 + k * 0.125, [65, 69, 72, 77][k % 4] + (k >= 8 ? 12 : 0), 0.14 + k * 0.006, 0.45, 1);

/* --- effects -------------------------------------------------------------- */

// Freeverb (Jezar), scaled to 48 kHz.
function reverb(inL, inR, room, damp, wet) {
  const scale = SR / 44100;
  const combs = [1116, 1188, 1277, 1356, 1422, 1491, 1557, 1617].map((v) => Math.round(v * scale));
  const alls = [556, 441, 341, 225].map((v) => Math.round(v * scale));
  const outL = new Float32Array(N);
  const outR = new Float32Array(N);
  for (let ch = 0; ch < 2; ch++) {
    const input = ch === 0 ? inL : inR;
    const out = ch === 0 ? outL : outR;
    const spread = ch === 0 ? 0 : 23;
    const cb = combs.map((len) => ({ buf: new Float32Array(len + spread), idx: 0, store: 0 }));
    const ab = alls.map((len) => ({ buf: new Float32Array(len + spread), idx: 0 }));
    for (let i = 0; i < N; i++) {
      const x = (input[i] + (ch === 0 ? inR[i] : inL[i]) * 0.25) * 0.015;
      let acc = 0;
      for (let c = 0; c < cb.length; c++) {
        const k = cb[c];
        const y = k.buf[k.idx];
        k.store = y * (1 - damp) + k.store * damp;
        k.buf[k.idx] = x + k.store * room;
        if (++k.idx >= k.buf.length) k.idx = 0;
        acc += y;
      }
      for (let a = 0; a < ab.length; a++) {
        const k = ab[a];
        const b = k.buf[k.idx];
        const y = -acc + b;
        k.buf[k.idx] = acc + b * 0.5;
        if (++k.idx >= k.buf.length) k.idx = 0;
        acc = y;
      }
      out[i] = acc * wet;
    }
  }
  return [outL, outR];
}

// Ping-pong delay, dotted eighth.
function delay(bus, time, feedback, wet) {
  const d = Math.round(time * SR);
  const bl = new Float32Array(d);
  const br = new Float32Array(d);
  let idx = 0;
  const lp = [0, 0];
  for (let i = 0; i < N; i++) {
    const dl = bl[idx];
    const dr = br[idx];
    lp[0] += 0.35 * (dl - lp[0]);
    lp[1] += 0.35 * (dr - lp[1]);
    bl[idx] = bus.L[i] + lp[1] * feedback;
    br[idx] = bus.R[i] * 0.6 + lp[0] * feedback;
    if (++idx >= d) idx = 0;
    bus.L[i] += dl * wet;
    bus.R[i] += dr * wet;
  }
}

delay(arp, 0.375, 0.42, 0.34);
delay(keys, 0.375, 0.3, 0.2);

// The kick ducks the sustained parts a little, so the low end stays clean.
{
  const duck = new Float32Array(N).fill(1);
  for (const t of kickTimes) {
    const s = Math.floor(t * SR);
    const len = Math.floor(0.26 * SR);
    for (let i = 0; i < len; i++) {
      const p = i / len;
      const g = 0.5 + 0.5 * Math.pow(p, 1.6);
      if (s + i < N && g < duck[s + i]) duck[s + i] = g;
    }
  }
  for (const b of [pad, bass, fx]) {
    for (let i = 0; i < N; i++) {
      b.L[i] *= duck[i];
      b.R[i] *= duck[i];
    }
  }
}

/* --- mix ------------------------------------------------------------------ */
const LEVEL = { pad: 1.25, keys: 2.3, arp: 1.9, bass: 0.78, drums: 0.82, fx: 0.7, sfx: 0.95 };
const SEND = { pad: 0.5, keys: 0.6, arp: 0.5, bass: 0, drums: 0.12, fx: 0.25, sfx: 0.14 };
const buses = { pad, keys, arp, bass, drums, fx, sfx };

const dryL = new Float32Array(N);
const dryR = new Float32Array(N);
const sendL = new Float32Array(N);
const sendR = new Float32Array(N);
for (const [name, b] of Object.entries(buses)) {
  const lv = LEVEL[name];
  const sd = SEND[name];
  for (let i = 0; i < N; i++) {
    dryL[i] += b.L[i] * lv;
    dryR[i] += b.R[i] * lv;
    sendL[i] += b.L[i] * lv * sd;
    sendR[i] += b.R[i] * lv * sd;
  }
}
const [wetL, wetR] = reverb(sendL, sendR, 0.86, 0.38, 0.8);

// high-pass at 28 Hz, gentle saturation, and fades at the very ends
const hpL = new SVF();
const hpR = new SVF();
hpL.set(28, 0.707);
hpR.set(28, 0.707);
const outL = new Float32Array(N);
const outR = new Float32Array(N);
let peak = 0;
let prePeak = 0;
for (let i = 0; i < N; i++) prePeak = Math.max(prePeak, Math.abs(dryL[i] + wetL[i]), Math.abs(dryR[i] + wetR[i]));
const TRIM = 1.15 / prePeak; // loudest instant reaches tanh at 1.15: transparent below, rounded only at the very top
console.log("level into the soft clipper: " + (20 * Math.log10(prePeak)).toFixed(2) + " dBFS, trimmed by " + (20 * Math.log10(TRIM)).toFixed(2) + " dB");
for (let i = 0; i < N; i++) {
  const t = i / SR;
  const edge = Math.min(1, t / 0.03) * (t > 58.3 ? Math.max(0, 1 - (t - 58.3) / 1.65) ** 1.5 : 1);
  hpL.tick((dryL[i] + wetL[i]) * TRIM);
  hpR.tick((dryR[i] + wetR[i]) * TRIM);
  const l = Math.tanh(hpL.hp) * edge;
  const r = Math.tanh(hpR.hp) * edge;
  outL[i] = l;
  outR[i] = r;
  peak = Math.max(peak, Math.abs(l), Math.abs(r));
}

/* --- write ---------------------------------------------------------------- */
function writeWav(path, L, R, gain) {
  const bytes = 3;
  const data = Buffer.alloc(N * 2 * bytes);
  let o = 0;
  for (let i = 0; i < N; i++) {
    for (const ch of [L, R]) {
      const v = Math.round(clamp(ch[i] * gain, -1, 1) * 8388607);
      data.writeIntLE(v, o, 3);
      o += 3;
    }
  }
  const h = Buffer.alloc(44);
  h.write("RIFF", 0);
  h.writeUInt32LE(36 + data.length, 4);
  h.write("WAVEfmt ", 8);
  h.writeUInt32LE(16, 16);
  h.writeUInt16LE(1, 20);
  h.writeUInt16LE(2, 22);
  h.writeUInt32LE(SR, 24);
  h.writeUInt32LE(SR * 2 * bytes, 28);
  h.writeUInt16LE(2 * bytes, 32);
  h.writeUInt16LE(8 * bytes, 34);
  h.write("data", 36);
  h.writeUInt32LE(data.length, 40);
  writeFileSync(path, Buffer.concat([h, data]));
}

const outDir = join(ROOT, "assets", "audio");
mkdirSync(outDir, { recursive: true });
const raw = join(outDir, "soundtrack-raw.wav");
writeWav(raw, outL, outR, 0.89 / peak);

// per-bus level report (RMS over the groove, 18–50s) — a mixing aid
const rmsDb = (b) => {
  let acc = 0;
  const a0 = 18 * SR;
  const a1 = 50 * SR;
  for (let i = a0; i < a1; i++) acc += b.L[i] * b.L[i] + b.R[i] * b.R[i];
  return (10 * Math.log10(acc / (2 * (a1 - a0)) + 1e-12)).toFixed(1);
};
console.log("bus RMS dB (18–50s):", Object.entries(buses).map(([n, b]) => n + " " + rmsDb(b)).join(" · "));
console.log("raw mix peak before normalise: " + (20 * Math.log10(peak)).toFixed(2) + " dBFS");

/* Loudness: measure with EBU R128, then apply one static gain to land at
   -14 LUFS integrated with true peak under -1 dBTP. No dynamic processing. */
const TARGET = -14;
const meas = spawnSync("ffmpeg", ["-hide_banner", "-nostats", "-i", raw, "-af", "ebur128=peak=true", "-f", "null", "-"], { encoding: "utf8" });
const text = meas.stderr || "";
const sum = text.slice(text.lastIndexOf("Summary:"));
const I = parseFloat((sum.match(/I:\s*(-?[\d.]+) LUFS/) || [])[1]);
const TP = parseFloat((sum.match(/Peak:\s*(-?[\d.]+) dBFS/) || [])[1]);
if (!Number.isFinite(I) || !Number.isFinite(TP)) throw new Error("could not read loudness: " + sum);
let gain = TARGET - I;
if (TP + gain > -1.0) gain = -1.0 - TP;
const final = join(outDir, "soundtrack.wav");
const enc = spawnSync("ffmpeg", ["-hide_banner", "-v", "error", "-y", "-i", raw, "-af", "volume=" + gain.toFixed(2) + "dB", "-c:a", "pcm_s24le", "-ar", String(SR), final], { encoding: "utf8" });
if (enc.status !== 0) throw new Error(enc.stderr);
console.log("measured " + I + " LUFS, true peak " + TP + " dBTP · gain " + gain.toFixed(2) + " dB → " + (I + gain).toFixed(1) + " LUFS, " + (TP + gain).toFixed(1) + " dBTP");
rmSync(raw);
console.log("written: assets/audio/soundtrack.wav");
