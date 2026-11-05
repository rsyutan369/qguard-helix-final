export function bytesToBytea(value: unknown): string {
  const bytes = Array.isArray(value) ? value.map((item) => Number(item) & 0xff) : [];
  return `\\x${bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function byteaToBytes(value: unknown): number[] {
  if (Array.isArray(value)) return value.map((item) => Number(item) & 0xff);
  if (value instanceof Uint8Array) return Array.from(value);
  if (typeof value === "string") {
    const hex = value.startsWith("\\x") ? value.slice(2) : value;
    if (/^[0-9a-fA-F]*$/.test(hex) && hex.length % 2 === 0) {
      const out: number[] = [];
      for (let index = 0; index < hex.length; index += 2) {
        out.push(Number.parseInt(hex.slice(index, index + 2), 16));
      }
      return out;
    }
  }
  if (value && typeof value === "object" && "data" in value && Array.isArray((value as { data?: unknown }).data)) {
    return ((value as { data: unknown[] }).data).map((item) => Number(item) & 0xff);
  }
  return [];
}

/**
 * Base64 for bytes crossing the Tauri IPC. Commands take bytes as base64
 * strings, never as a raw `Uint8Array` body: Android delivers every call as
 * JSON (a raw body arrives as an array of numbers), and so does desktop once
 * its IPC falls back to postMessage. Chunked so a 25 MiB attachment does not
 * build one argument list per byte.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const stride = 0x8000;
  for (let index = 0; index < bytes.length; index += stride) {
    binary += String.fromCharCode(...bytes.subarray(index, index + stride));
  }
  return btoa(binary);
}

/**
 * The bytes of a command that returns `tauri::ipc::Response`. Over the custom
 * IPC protocol they arrive as an ArrayBuffer; over the postMessage fallback
 * (Android, or desktop when the protocol is unavailable) Tauri hands back an
 * array of numbers. `new Blob([numbers])` would turn that array into the TEXT
 * "137,80,78,…" — a preview that does not render and an upload that is not the
 * file — so every binary result goes through here first.
 */
export function ipcArrayBuffer(value: unknown): ArrayBuffer {
  if (value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) {
    return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
  }
  if (Array.isArray(value)) return Uint8Array.from(value as number[]).buffer;
  throw new Error("The app returned no file data.");
}

export function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export function randomHex(bytes: number): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
