// New-message sounds, synthesised with Web Audio (no audio files to ship or
// fetch). The context is created lazily and resumed on use: WebView autoplay
// rules leave it suspended until the user has interacted with the app, which
// they always have by the time a message arrives (the unlock screen).

import type { MessageSound } from "@/lib/chat-preferences";

let context: AudioContext | null = null;

function audioContext(): AudioContext | null {
  if (context) return context;
  const Ctor = window.AudioContext ?? (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctor) return null;
  try {
    context = new Ctor();
  } catch {
    context = null;
  }
  return context;
}

/** [frequency Hz, start s, length s, peak gain] for each note. */
const TONES: Record<Exclude<MessageSound, "none">, Array<[number, number, number, number]>> = {
  chime: [[880, 0, 0.16, 0.09], [1318.5, 0.12, 0.26, 0.08]],
  pop: [[620, 0, 0.09, 0.12]],
  soft: [[523.25, 0, 0.32, 0.06], [659.25, 0.14, 0.34, 0.05]],
};

let lastPlayedAt = 0;

/** Play a message sound. Several messages in a burst make one sound, not many. */
export function playMessageSound(sound: MessageSound): void {
  if (sound === "none") return;
  const now = Date.now();
  if (now - lastPlayedAt < 1200) return;
  lastPlayedAt = now;
  const ctx = audioContext();
  if (!ctx) return;
  void ctx.resume().catch(() => undefined);
  const start = ctx.currentTime + 0.02;
  for (const [frequency, offset, length, peak] of TONES[sound]) {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.value = frequency;
    gain.gain.setValueAtTime(0, start + offset);
    gain.gain.linearRampToValueAtTime(peak, start + offset + 0.015);
    gain.gain.exponentialRampToValueAtTime(0.0001, start + offset + length);
    osc.connect(gain).connect(ctx.destination);
    osc.start(start + offset);
    osc.stop(start + offset + length + 0.02);
  }
}

/** For the settings preview button: always plays, ignoring the burst limit. */
export function previewMessageSound(sound: MessageSound): void {
  lastPlayedAt = 0;
  playMessageSound(sound);
}
