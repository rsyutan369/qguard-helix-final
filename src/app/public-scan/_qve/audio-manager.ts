/**
 * Quantum Visualization Engine™ — Audio Manager.
 *
 * Four short UI cues (packet, pass, warning, critical) played through Howler.
 *
 * The waveforms are synthesised into WAV data-URIs at first unmute rather than
 * shipped as binary assets. Two reasons that matters here: no extra network
 * requests on the anonymous front door, and no opaque media files to review in a
 * public-facing bundle. Nothing is created — not even an AudioContext — until
 * the user explicitly unmutes, so the page makes no sound and costs no memory by
 * default.
 */
'use client';

import React from 'react';
import type { Howl } from 'howler';
import type { ScanEventSeverity } from './types';

export type QveCue = 'packet' | 'pass' | 'warning' | 'critical' | 'complete';

interface CueSpec {
  /** Start / end frequency in Hz — a short glide reads as a UI blip. */
  from: number;
  to: number;
  durationMs: number;
  gain: number;
  /** Adds a soft second partial for a richer, less beep-like tone. */
  harmonic?: number;
}

const CUES: Record<QveCue, CueSpec> = {
  packet: { from: 1180, to: 1620, durationMs: 70, gain: 0.1, harmonic: 2 },
  pass: { from: 720, to: 1080, durationMs: 150, gain: 0.14, harmonic: 1.5 },
  warning: { from: 560, to: 420, durationMs: 220, gain: 0.16 },
  critical: { from: 340, to: 190, durationMs: 340, gain: 0.2, harmonic: 0.5 },
  complete: { from: 620, to: 1240, durationMs: 420, gain: 0.15, harmonic: 2 },
};

const SAMPLE_RATE = 22_050;

/** Base64 for a byte array, without pulling in a polyfill. */
function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary);
}

/**
 * Render a cue to a 16-bit mono PCM WAV data-URI. Amplitude is shaped by a
 * raised-cosine attack and an exponential decay so there is no click at either
 * edge — a clicking UI sound is worse than silence.
 */
function synthesize(spec: CueSpec): string {
  const samples = Math.max(1, Math.round((spec.durationMs / 1000) * SAMPLE_RATE));
  const headerLength = 44;
  const buffer = new ArrayBuffer(headerLength + samples * 2);
  const view = new DataView(buffer);

  const writeAscii = (offset: number, text: string) => {
    for (let index = 0; index < text.length; index += 1) view.setUint8(offset + index, text.charCodeAt(index));
  };

  writeAscii(0, 'RIFF');
  view.setUint32(4, 36 + samples * 2, true);
  writeAscii(8, 'WAVE');
  writeAscii(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true); // PCM
  view.setUint16(22, 1, true); // mono
  view.setUint32(24, SAMPLE_RATE, true);
  view.setUint32(28, SAMPLE_RATE * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeAscii(36, 'data');
  view.setUint32(40, samples * 2, true);

  const attack = Math.min(samples * 0.25, SAMPLE_RATE * 0.008);
  let phase = 0;
  let harmonicPhase = 0;

  for (let index = 0; index < samples; index += 1) {
    const t = index / samples;
    const frequency = spec.from + (spec.to - spec.from) * t;
    phase += (2 * Math.PI * frequency) / SAMPLE_RATE;
    harmonicPhase += (2 * Math.PI * frequency * (spec.harmonic ?? 0)) / SAMPLE_RATE;

    const rise = index < attack ? 0.5 - 0.5 * Math.cos((Math.PI * index) / attack) : 1;
    const decay = Math.exp(-3.2 * t);
    const tone = Math.sin(phase) + (spec.harmonic ? 0.35 * Math.sin(harmonicPhase) : 0);
    const amplitude = (tone / (spec.harmonic ? 1.35 : 1)) * spec.gain * rise * decay;

    view.setInt16(headerLength + index * 2, Math.max(-1, Math.min(1, amplitude)) * 0x7fff, true);
  }

  return `data:audio/wav;base64,${toBase64(new Uint8Array(buffer))}`;
}

/* ------------------------------------------------------------------ manager - */

class AudioManager {
  private sounds = new Map<QveCue, Howl>();
  private loading: Promise<void> | null = null;
  private ready = false;
  /** Rate limit: a burst of packets must not turn into a machine-gun. */
  private lastPlayedAt = new Map<QveCue, number>();

  /** Lazily import Howler and build the cue bank. Idempotent. */
  async prepare(): Promise<void> {
    if (this.ready) return;
    if (this.loading) return this.loading;
    this.loading = (async () => {
      const { Howl: HowlCtor } = await import('howler');
      for (const [cue, spec] of Object.entries(CUES) as Array<[QveCue, CueSpec]>) {
        this.sounds.set(
          cue,
          new HowlCtor({ src: [synthesize(spec)], format: ['wav'], volume: 1, preload: true }),
        );
      }
      this.ready = true;
    })();
    return this.loading;
  }

  play(cue: QveCue, minGapMs = 60): void {
    if (!this.ready) return;
    const now = performance.now();
    if (now - (this.lastPlayedAt.get(cue) ?? 0) < minGapMs) return;
    this.lastPlayedAt.set(cue, now);
    this.sounds.get(cue)?.play();
  }

  dispose(): void {
    for (const sound of this.sounds.values()) sound.unload();
    this.sounds.clear();
    this.ready = false;
    this.loading = null;
  }
}

const manager = new AudioManager();

export function cueForSeverity(severity: ScanEventSeverity): QveCue | null {
  if (severity === 'critical' || severity === 'high') return 'critical';
  if (severity === 'medium' || severity === 'low') return 'warning';
  return null;
}

/**
 * Audio is opt-in and remembered for the session only (not persisted — a page
 * that starts making noise on a later visit is a bug, not a feature).
 */
export function useQveAudio(): {
  enabled: boolean;
  toggle: () => void;
  play: (cue: QveCue, minGapMs?: number) => void;
} {
  const [enabled, setEnabled] = React.useState(false);

  const toggle = React.useCallback(() => {
    setEnabled((current) => {
      const next = !current;
      if (next) void manager.prepare();
      return next;
    });
  }, []);

  const play = React.useCallback(
    (cue: QveCue, minGapMs?: number) => {
      if (!enabled) return;
      manager.play(cue, minGapMs);
    },
    [enabled],
  );

  return { enabled, toggle, play };
}
