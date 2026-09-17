// AES-256-GCM per-frame sealing for E2EE media. Nonce (12B) = contextTag(4B) | counter(8B BE).
// Wire format: [header (headerLength, unencrypted)][ciphertext+16B tag][8B BE counter].
//
// The unencrypted header and the frame counter are both bound into the GCM tag
// as additional authenticated data. They HAVE to travel in the clear — the RTP
// depacketizer reads the header, and the counter is the nonce, so neither can be
// encrypted — but leaving them merely unencrypted also left them unauthenticated,
// and anything on the media path could rewrite them without detection. Flipping
// VP8's keyframe/delta marker or rewriting the counter cannot recover plaintext,
// but it can corrupt or stall a decoder, and "the attacker cannot read it" is not
// the same claim as "the attacker cannot change it". As AAD they are covered by
// the tag: any edit makes the frame fail to open, and a failed frame is dropped.

/**
 * Unencrypted leading bytes the RTP (de)packetizer needs — the Chrome
 * insertable-streams convention for VP8 video (10 bytes on a keyframe, 3 on a
 * delta) and Opus audio (1). Shared by every encoded-transform plumbing so the
 * encrypt and decrypt sides always split the frame identically.
 */
export function headerLength(kind: "audio" | "video", frame: { type?: "key" | "delta" }): number {
  if (kind === "audio") return 1;
  return frame.type === "key" ? 10 : 3;
}

export async function importAesGcmKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function nonce(contextTag: Uint8Array, counter: bigint): Uint8Array {
  const n = new Uint8Array(12);
  n.set(contextTag.subarray(0, 4), 0);
  const view = new DataView(n.buffer);
  view.setBigUint64(4, counter, false); // big-endian
  return n;
}

/**
 * Everything that travels in the clear, in the order it appears on the wire:
 * the codec header followed by the 8-byte counter. Both sides build this the
 * same way from the frame they actually have, so a receiver that was handed
 * different bytes computes different AAD and the tag check fails.
 */
function aad(header: Uint8Array, counter: bigint): Uint8Array {
  const out = new Uint8Array(header.length + 8);
  out.set(header, 0);
  new DataView(out.buffer).setBigUint64(header.length, counter, false);
  return out;
}

export async function sealFrame(
  key: CryptoKey, contextTag: Uint8Array, counter: bigint, headerLength: number, frame: Uint8Array,
): Promise<ArrayBuffer> {
  const header = frame.subarray(0, headerLength);
  const payload = frame.subarray(headerLength);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce(contextTag, counter) as BufferSource,
        additionalData: aad(header, counter) as BufferSource,
      },
      key,
      payload as BufferSource,
    ),
  );
  const out = new Uint8Array(headerLength + ct.length + 8);
  out.set(header, 0);
  out.set(ct, headerLength);
  new DataView(out.buffer).setBigUint64(out.length - 8, counter, false);
  return out.buffer;
}

export async function openFrame(
  key: CryptoKey, contextTag: Uint8Array, headerLength: number, frame: Uint8Array,
): Promise<ArrayBuffer> {
  if (frame.length < headerLength + 8 + 16) throw new Error("frame too short");
  const counter = new DataView(frame.buffer, frame.byteOffset + frame.length - 8, 8).getBigUint64(0, false);
  const header = frame.subarray(0, headerLength);
  const ct = frame.subarray(headerLength, frame.length - 8);
  const pt = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce(contextTag, counter) as BufferSource,
        additionalData: aad(header, counter) as BufferSource,
      },
      key,
      ct as BufferSource,
    ),
  );
  const out = new Uint8Array(headerLength + pt.length);
  out.set(header, 0);
  out.set(pt, headerLength);
  return out.buffer;
}

/** Read the frame counter a sealed frame carries in its trailing 8 bytes. */
export function frameCounter(frame: Uint8Array): bigint {
  if (frame.length < 8) throw new Error("frame too short");
  return new DataView(frame.buffer, frame.byteOffset + frame.length - 8, 8).getBigUint64(0, false);
}

/**
 * Anti-replay window over the per-direction frame counter (RFC 3711 / 4303
 * style: a highest-seen mark plus a bitmap of the frames behind it).
 *
 * AES-GCM proves a frame was produced by the key holder. It does NOT prove the
 * frame is arriving for the first time — a replayed frame carries its original
 * counter, header and tag, so it decrypts perfectly. On a media path that means
 * anything sitting between the peers (a TURN relay, a hostile network) can
 * re-inject earlier audio or video and the decoder will play it. That is
 * tampering with a call without ever breaking its encryption.
 *
 * RTP is genuinely unordered and lossy, so the window has to tolerate
 * reordering: anything newer than the mark is accepted, anything within
 * WINDOW_SIZE frames behind it is accepted exactly once, and anything older is
 * too stale to distinguish from a replay and is refused.
 */
export class FrameReplayWindow {
  private static readonly WINDOW_SIZE = 256n;
  private highest = -1n;
  /** Bit i set == counter (highest - i) has already been accepted. */
  private seen = 0n;

  /** May this counter be accepted? Does not record it — see `commit`. */
  check(counter: bigint): boolean {
    if (counter < 0n) return false;
    if (this.highest < 0n) return true;
    if (counter > this.highest) return true;
    const behind = this.highest - counter;
    if (behind >= FrameReplayWindow.WINDOW_SIZE) return false;
    return ((this.seen >> behind) & 1n) === 0n;
  }

  /**
   * Record an accepted counter. Called only AFTER the frame authenticates, so
   * forged counters cannot consume window slots or drag the mark forward.
   */
  commit(counter: bigint): void {
    if (counter > this.highest) {
      const shift = this.highest < 0n ? counter + 1n : counter - this.highest;
      this.seen = shift >= FrameReplayWindow.WINDOW_SIZE ? 1n : ((this.seen << shift) | 1n);
      this.highest = counter;
      // Keep the bitmap bounded; bits that fall off are older than the window
      // and are refused by `check` anyway.
      const mask = (1n << FrameReplayWindow.WINDOW_SIZE) - 1n;
      this.seen &= mask;
      return;
    }
    const behind = this.highest - counter;
    if (behind < FrameReplayWindow.WINDOW_SIZE) this.seen |= 1n << behind;
  }
}
