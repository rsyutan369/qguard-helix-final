// Profile pictures for Mesh and XFER, synchronised between trusted devices.
//
// The native core (src-tauri/src/offline/avatar.rs) owns the pictures: this
// device's thumbnail, and the pictures trusted peers sent over their
// authenticated channel, each stored under the fingerprint that authenticated
// it. The status snapshot carries only SHA3-256 digests; this module fetches
// an image once per digest and keeps it for the session, so a picture change
// on the other device (a new digest) refreshes every view, and an unchanged
// picture is never fetched twice.

import { createContext, useContext, useEffect, useSyncExternalStore } from "react";
import { safeInvoke } from "@/lib/tauri";

/** The signed-in account the offline workspace belongs to. */
export const OfflineAccountContext = createContext<string | null>(null);

const images = new Map<string, string>();
const pending = new Set<string>();
const listeners = new Set<() => void>();
let version = 0;

function emit() {
  version += 1;
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

const snapshot = () => version;

const DIGEST = /^[0-9a-f]{64}$/;

async function load(account: string, peer: string | null, digest: string) {
  const key = `${peer ?? "local"}:${digest}`;
  if (pending.has(key)) return;
  pending.add(key);
  try {
    const picture = await safeInvoke<{ digest: string; dataUrl: string } | null>("offline_avatar", {
      peer: peer ?? undefined, expectedAccount: account,
    });
    // Only an image whose digest matches what the snapshot announced is
    // shown; a newer one is picked up when the snapshot reports it.
    if (picture && DIGEST.test(picture.digest) && picture.dataUrl.startsWith("data:image/")) {
      images.set(picture.digest, picture.dataUrl);
      emit();
    }
  } catch {
    // No picture available yet (not synced, or the account changed).
  } finally {
    pending.delete(key);
  }
}

/**
 * The picture a trusted peer shared (`peer` = its fingerprint) or this
 * account's own picture (`peer` = null), given the digest the native status
 * reports. Null while loading or when there is none: callers show initials.
 */
export function useOfflineAvatar(peer: string | null | undefined, digest: string | null | undefined): string | null {
  const account = useContext(OfflineAccountContext);
  useSyncExternalStore(subscribe, snapshot, snapshot);
  const valid = digest && DIGEST.test(digest) ? digest : null;
  useEffect(() => {
    if (account && valid && peer !== undefined && !images.has(valid)) void load(account, peer, valid);
  }, [account, peer, valid]);
  return valid ? images.get(valid) ?? null : null;
}

/** Largest picture the native core accepts (bytes). */
const MAX_BYTES = 46 * 1024;
const SIZE = 192;

/** Load an image through an <img> element. */
function loadImage(url: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.decoding = "async";
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("The profile picture could not be read."));
    image.src = url;
  });
}

/**
 * A square JPEG thumbnail (centre crop) of an image URL, as base64. Small
 * enough to cross a Bluetooth channel in a moment.
 *
 * The picture is read through an <img> element, never fetch(): the app's
 * Content-Security-Policy allows blob: and data: for images (img-src) but not
 * for connections (connect-src), so fetch() of the profile picture's blob: URL
 * is refused inside the desktop and Android apps. That refusal is what kept
 * every device from ever sharing its picture in 1.5.1.
 */
export async function avatarThumbnail(url: string): Promise<string> {
  const image = await loadImage(url);
  const width = image.naturalWidth;
  const height = image.naturalHeight;
  const side = Math.min(width, height);
  if (!side) throw new Error("The profile picture is empty.");
  const canvas = document.createElement("canvas");
  canvas.width = SIZE;
  canvas.height = SIZE;
  const context = canvas.getContext("2d");
  if (!context) throw new Error("The profile picture could not be drawn.");
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, SIZE, SIZE);
  context.imageSmoothingQuality = "high";
  context.drawImage(image, (width - side) / 2, (height - side) / 2, side, side, 0, 0, SIZE, SIZE);
  for (const quality of [0.84, 0.7, 0.55, 0.4]) {
    const encoded = canvas.toDataURL("image/jpeg", quality);
    const base64 = encoded.startsWith("data:image/jpeg;base64,") ? encoded.slice("data:image/jpeg;base64,".length) : "";
    if (base64 && Math.floor(base64.length * 3 / 4) <= MAX_BYTES) return base64;
  }
  throw new Error("The profile picture could not be made small enough.");
}

/**
 * Keep the picture this device shares with trusted devices in step with the
 * signed-in profile. `avatarUrl` undefined means "not known yet" (profile
 * still loading, or offline): nothing changes. Null means "no picture".
 */
export function useOfflineAvatarSync({ accountId, enabled, avatarUrl }: {
  accountId: string | null | undefined; enabled: boolean; avatarUrl: string | null | undefined;
}) {
  useEffect(() => {
    if (!enabled || !accountId || avatarUrl === undefined) return;
    // The native side accepts the picture only after the offline account
    // check, which runs in parallel: retry for a bounded time.
    let cancelled = false;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const sync = async () => {
      try {
        const image = avatarUrl ? await avatarThumbnail(avatarUrl) : null;
        if (cancelled) return;
        await safeInvoke("offline_set_avatar", { image, expectedAccount: accountId });
      } catch {
        attempts += 1;
        if (!cancelled && attempts < 24) timer = setTimeout(() => void sync(), 5_000);
      }
    };
    void sync();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [accountId, enabled, avatarUrl]);
}
