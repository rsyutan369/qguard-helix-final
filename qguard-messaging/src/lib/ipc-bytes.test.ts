import { describe, expect, it } from "vitest";
import indexHtml from "../../index.html?raw";
import tauriConfig from "../../src-tauri/tauri.conf.json";
import { ipcArrayBuffer } from "./encoding";

// Vault previews broke twice over: binary command results arrived as arrays of
// numbers (turned into the TEXT "137,80,…" by `new Blob`), and the page's own
// CSP had no media-src, so a decrypted video's blob: URL was refused.

describe("binary results from the core", () => {
  const png = [0x89, 0x50, 0x4e, 0x47];

  it("are the same bytes however the IPC delivered them", () => {
    for (const delivered of [Uint8Array.from(png).buffer, Uint8Array.from(png), png]) {
      expect([...new Uint8Array(ipcArrayBuffer(delivered))]).toEqual(png);
    }
  });

  it("keep only the viewed slice of a larger buffer", () => {
    const view = new Uint8Array([9, ...png, 9]).subarray(1, 5);
    expect([...new Uint8Array(ipcArrayBuffer(view))]).toEqual(png);
  });

  it("become a Blob of the file, not of its numbers", async () => {
    const blob = new Blob([ipcArrayBuffer(png)], { type: "image/png" });
    expect(blob.size).toBe(png.length);
    expect([...new Uint8Array(await blob.arrayBuffer())]).toEqual(png);
  });

  it("fail loudly when there is nothing", () => {
    expect(() => ipcArrayBuffer(undefined)).toThrow(/no file data/);
    expect(() => ipcArrayBuffer("137,80,78,71")).toThrow(/no file data/);
  });
});

function directives(policy: string): Map<string, string[]> {
  return new Map(
    policy
      .split(";")
      .map((part) => part.trim().split(/\s+/))
      .filter((tokens) => tokens[0])
      .map(([name, ...sources]) => [name, sources]),
  );
}

const policies = {
  "tauri.conf.json": tauriConfig.app.security.csp,
  "index.html": indexHtml.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/)?.[1] ?? "",
};

describe.each(Object.entries(policies))("the %s content security policy", (_where, policy) => {
  const csp = directives(policy);

  it("is present", () => {
    expect(csp.get("default-src")).toEqual(["'self'"]);
  });

  it("lets the app reach its own IPC protocol (else every call falls back to postMessage)", () => {
    expect(csp.get("connect-src")).toEqual(expect.arrayContaining(["ipc:", "http://ipc.localhost"]));
  });

  it("lets decrypted previews play from memory", () => {
    expect(csp.get("img-src")).toContain("blob:");
    expect(csp.get("media-src")).toContain("blob:");
  });

  it("still allows no script but the app's own", () => {
    expect(csp.get("script-src")).toEqual(["'self'"]);
  });
});
