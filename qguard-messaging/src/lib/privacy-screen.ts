import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

/**
 * The conversation privacy screen (archived / hidden chats behind a PIN or
 * password). A SCREEN, not encryption: messages are end-to-end encrypted, and
 * the workspace lock in the Rust core protects them at rest.
 *
 * Its verifier used to be PBKDF2-HMAC-SHA-256 in the WebView, because WebCrypto
 * offers neither Argon2id nor SHA-3. In the app it is now made by the core —
 * Argon2id + HKDF-SHA3-256, like the app PIN (`privacy_screen_seal`), or
 * PBKDF2-HMAC-SHA-512 + HKDF-SHA3-256 while FIPS approved mode is on. A stored
 * verifier of any other kind still opens the screen and is replaced on that
 * successful unlock (the old WebView one is checked by the core too); a
 * browser preview, which has no core, keeps using PBKDF2 in WebCrypto.
 */

export const PRIVACY_SCREEN_KDF = "argon2id-sha3-v1";
export const PRIVACY_SCREEN_KDF_APPROVED = "pbkdf2-sha512-sha3-v2";
type CoreKdf = typeof PRIVACY_SCREEN_KDF | typeof PRIVACY_SCREEN_KDF_APPROVED;

function isCoreKdf(value: unknown): value is CoreKdf {
  return value === PRIVACY_SCREEN_KDF || value === PRIVACY_SCREEN_KDF_APPROVED;
}
const LEGACY_ITERATIONS = 600_000;
// A stored PBKDF2 verifier weaker than this was not written by any released build.
const LEGACY_MIN_ITERATIONS = 100_000;

export interface ChatProtectionConfig {
  /** Absent = the legacy PBKDF2-SHA-256 verifier. */
  kdf?: CoreKdf;
  salt_b64: string;
  verifier_b64: string;
  /** PBKDF2 only. */
  iterations?: number;
  created_at: string;
}

export function chatProtectionStorageKey(userId: string): string {
  return `qguard-chat-protection:${userId}`;
}

export function parseChatProtectionConfig(raw: string | null): ChatProtectionConfig | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<ChatProtectionConfig>;
    if (!parsed.salt_b64 || !parsed.verifier_b64) return null;
    const created_at = parsed.created_at ?? new Date().toISOString();
    if (isCoreKdf(parsed.kdf)) {
      return { kdf: parsed.kdf, salt_b64: parsed.salt_b64, verifier_b64: parsed.verifier_b64, created_at };
    }
    if (parsed.kdf !== undefined) return null;
    if (!Number.isInteger(parsed.iterations) || (parsed.iterations ?? 0) < LEGACY_MIN_ITERATIONS) return null;
    return { salt_b64: parsed.salt_b64, verifier_b64: parsed.verifier_b64, iterations: parsed.iterations, created_at };
  } catch {
    return null;
  }
}

export function readChatProtectionConfig(userId: string): ChatProtectionConfig | null {
  try {
    return parseChatProtectionConfig(localStorage.getItem(chatProtectionStorageKey(userId)));
  } catch {
    return null;
  }
}

export function writeChatProtectionConfig(userId: string, config: ChatProtectionConfig): void {
  localStorage.setItem(chatProtectionStorageKey(userId), JSON.stringify(config));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function legacyVerifier(secret: string, saltB64: string, iterations: number): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: toArrayBuffer(base64ToBytes(saltB64)), iterations },
    keyMaterial,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

interface CoreSeal {
  kdf: string;
  salt_b64: string;
  verifier_b64: string;
}

export async function createChatProtectionConfig(secret: string): Promise<ChatProtectionConfig> {
  if (isTauriRuntime()) {
    const seal = await safeInvoke<CoreSeal>("privacy_screen_seal", { secret });
    const kdf = isCoreKdf(seal.kdf) ? seal.kdf : PRIVACY_SCREEN_KDF;
    return { kdf, salt_b64: seal.salt_b64, verifier_b64: seal.verifier_b64, created_at: new Date().toISOString() };
  }
  const saltB64 = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
  return {
    salt_b64: saltB64,
    verifier_b64: await legacyVerifier(secret, saltB64, LEGACY_ITERATIONS),
    iterations: LEGACY_ITERATIONS,
    created_at: new Date().toISOString(),
  };
}

/**
 * Check `secret`. On success with a legacy verifier inside the app, also
 * returns its replacement, which the caller stores.
 */
export async function verifyChatProtectionSecret(
  secret: string,
  config: ChatProtectionConfig,
): Promise<{ ok: boolean; upgraded: ChatProtectionConfig | null }> {
  if (isCoreKdf(config.kdf)) {
    if (!isTauriRuntime()) return { ok: false, upgraded: null };
    const ok = await safeInvoke<boolean>("privacy_screen_verify", {
      secret,
      seal: { kdf: config.kdf, salt_b64: config.salt_b64, verifier_b64: config.verifier_b64 },
    });
    // Sealed under the other KDF than this device now uses (FIPS approved mode
    // was switched): re-seal while the secret is at hand.
    const current = ok ? await safeInvoke<string>("privacy_screen_kdf", undefined, config.kdf) : config.kdf;
    if (!ok || current === config.kdf) return { ok, upgraded: null };
    const upgraded = await createChatProtectionConfig(secret).catch(() => null);
    return { ok, upgraded: upgraded && { ...upgraded, created_at: config.created_at } };
  }
  const iterations = config.iterations ?? LEGACY_ITERATIONS;
  const ok = isTauriRuntime()
    ? await safeInvoke<boolean>("privacy_screen_verify_legacy", {
        secret,
        saltB64: config.salt_b64,
        verifierB64: config.verifier_b64,
        iterations,
      })
    : (await legacyVerifier(secret, config.salt_b64, iterations)) === config.verifier_b64;
  if (!ok || !isTauriRuntime()) return { ok, upgraded: null };
  // Opened with the old verifier: replace it while the secret is at hand.
  const upgraded = await createChatProtectionConfig(secret).catch(() => null);
  return { ok, upgraded: upgraded && { ...upgraded, created_at: config.created_at } };
}
