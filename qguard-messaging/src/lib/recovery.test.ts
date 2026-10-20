import { describe, expect, it } from "vitest";
import { base64ToBlob, fileToBase64 } from "@/lib/recovery";

describe("backup file bytes", () => {
  it("survive the save → choose-file round trip unchanged, including large and binary content", async () => {
    const bytes = new Uint8Array(200_000);
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = (index * 31 + 7) & 0xff;
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const b64 = btoa(binary);
    const blob = base64ToBlob(b64);
    expect(blob.size).toBe(bytes.length);
    expect(await fileToBase64(blob)).toBe(b64);
  });

  it("an empty file is an empty string, not an error", async () => {
    expect(await fileToBase64(new Blob([]))).toBe("");
  });
});
