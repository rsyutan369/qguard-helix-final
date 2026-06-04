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

export function randomHex(bytes: number): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
