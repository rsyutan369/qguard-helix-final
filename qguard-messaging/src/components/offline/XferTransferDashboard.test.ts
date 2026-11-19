import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OfflineStatus, OfflineTransfer } from "@/lib/offline";
import { XferTransferDashboard } from "./XferTransferDashboard";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const now = 1_795_000_000_000;
const local = "a".repeat(64);
const peer = "b".repeat(64);
const status: OfflineStatus = {
  running: true,
  lanDiscoveryRunning: true,
  autoStart: false,
  fingerprint: local,
  port: 41000,
  platform: "android",
  networkError: null,
  peers: [{
    fingerprint: peer, label: "Design workstation", address: null, trusted: true, platform: "windows", pairedAt: now / 1_000 - 60,
    lastSeen: now / 1_000, authenticatedAt: now / 1_000, discovery: ["lan"],
  }],
};
const transfer: OfflineTransfer = {
  id: "transfer-fixture",
  direction: "incoming",
  sender: peer,
  recipient: local,
  files: [
    { name: "Quarterly/Report.pdf", size: 512, verifiedBytes: 512, verified: false },
    { name: "Quarterly/Notes.txt", size: 512, verifiedBytes: 128, verified: false },
  ],
  status: "active",
  folderName: "Quarterly",
  currentFile: 1,
  verifiedBytes: 640,
  totalBytes: 1024,
  createdAt: now / 1_000 - 10,
  expiresAt: now / 1_000 + 3600,
  localCopyRetained: false,
  bytesPerSecond: 128,
  averageBytesPerSecond: 64,
  elapsedMs: 10_000,
  error: null,
};

let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

async function render(record: OfflineTransfer) {
  await act(async () => root.render(createElement(XferTransferDashboard, {
    transfer: record, status, localIdentity: { displayName: "Test recipient", deviceName: "Lab tablet" }, onBack: vi.fn(),
  })));
}

function metric(label: string) {
  return [...host.querySelectorAll(".xfer-live-metrics dt")].find((node) => node.textContent?.trim() === label)
    ?.nextElementSibling?.textContent;
}

beforeEach(() => {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
});

describe("XFER transfer dashboard", () => {
  it("shows authenticated participants, folder progress, and measured speed and time", async () => {
    await render({
      ...transfer,
      throughput: [{ atMs: now - 5_000, bytesPerSecond: 256 }, { atMs: now, bytesPerSecond: 128 }],
    });
    const participants = [...host.querySelectorAll(".xfer-live-participant")];
    expect(participants[0]?.textContent).toContain("Sender");
    expect(participants[0]?.textContent).toContain("Design workstation");
    expect(participants[0]?.textContent).toContain("Windows");
    expect(participants[1]?.textContent).toContain("Receiver");
    expect(participants[1]?.textContent).toContain("Test recipient");
    expect(participants[1]?.textContent).toContain("Lab tablet");
    expect(host.querySelector('[role="progressbar"]')?.getAttribute("aria-valuenow")).toBe("62");
    expect(host.querySelector(".xfer-live-file-summary h3")?.textContent).toBe("Quarterly");
    expect(host.querySelector(".xfer-live-file-summary")?.textContent).toContain("Current file Quarterly/Notes.txt");
    expect(metric("Current speed")).toBe("128 B/s");
    expect(metric("Average speed")).toBe("64 B/s");
    expect(metric("Estimated time remaining")).toBe("00:00:03");
    expect(metric("Elapsed time")).toBe("00:00:10");
    expect(metric("Remaining bytes")).toBe("384 B");
    expect(host.querySelector('figure svg[role="img"]')?.getAttribute("aria-label")).toContain("latest 128 B/s, peak 256 B/s");
    expect(host.querySelector(".xfer-live-manifest")?.textContent).toContain("512 B received");
    expect(host.querySelector(".xfer-live-manifest")?.textContent).not.toContain("Integrity verified");
  });

  it("names the paired owner, shows stalls as measured zeros and pauses as breaks", async () => {
    const owned: OfflineStatus = { ...status, peers: [{ ...status.peers[0], owner: "Alex Rivera" }] };
    await act(async () => root.render(createElement(XferTransferDashboard, {
      transfer: {
        ...transfer,
        bytesPerSecond: 0,
        throughput: [
          { atMs: now - 30_000, bytesPerSecond: 512 }, { atMs: now - 29_000, bytesPerSecond: 640 },
          // A long silence: the run was paused, so no samples exist.
          { atMs: now - 6_000, bytesPerSecond: 600 }, { atMs: now - 5_000, bytesPerSecond: 0 },
          { atMs: now - 4_000, bytesPerSecond: 0 },
        ],
      },
      status: owned, localIdentity: { displayName: "Test recipient" }, onBack: vi.fn(),
    })));
    const sender = host.querySelector(".xfer-live-participant");
    expect(sender?.textContent).toContain("Alex Rivera");
    expect(sender?.textContent).toContain("Design workstation");
    expect(sender?.textContent).toContain("Verified device");
    expect(sender?.querySelector(".xfer-live-avatar")?.textContent).toBe("AR");
    expect(metric("Current speed")).toBe("Stalled");
    expect(host.querySelector(".xfer-live")?.getAttribute("data-stalled")).toBe("true");
    expect(host.querySelectorAll(".xfer-live-chart-gap")).toHaveLength(1);
    expect(host.querySelectorAll(".xfer-live-chart-stall")).toHaveLength(2);
    const label = host.querySelector('figure svg[role="img"]')?.getAttribute("aria-label");
    expect(label).toContain("2 stalled samples");
    expect(label).toContain("1 pause or interruption");
    expect(host.querySelector(".xfer-live-chart-legend")?.textContent).toContain("Paused or interrupted");
  });

  it("completes only with a verified receipt and shows the shared session and file digests", async () => {
    const digest = "3a".repeat(32);
    await render({
      ...transfer,
      status: "verified",
      verifiedBytes: 1024,
      verifiedFiles: 2,
      completedAtMs: now,
      sessionId: "7F3A91D4C2B011EE",
      files: transfer.files.map((file) => ({ ...file, verified: true, digest })),
      security: {
        phase: "verified", mode: "Hybrid", keyEstablishment: "ML-KEM-768 + X25519",
        signatures: "ML-DSA-65 + Ed25519", encryption: "AES-256-GCM", integrity: "SHA3-256",
      },
    });
    expect(host.querySelector("h2")?.textContent).toBe("Successfully transferred");
    expect(host.querySelector('[role="progressbar"]')?.getAttribute("aria-valuenow")).toBe("100");
    const receipt = host.querySelector(".xfer-live-receipt")?.textContent;
    expect(receipt).toContain("Design workstation");
    expect(receipt).toContain("Test recipient");
    expect(receipt).toContain("SHA3-256 · 2 of 2 verified");
    expect(receipt).toContain("ML-KEM-768 + X25519 · AES-256-GCM");
    const security = host.querySelector(".xfer-live-security")?.textContent;
    expect(security).toContain("Hybrid post-quantum protection");
    expect(security).toContain("ML-DSA-65 + Ed25519");
    expect(security).toContain("7F3A 91D4 C2B0 11EE");
    expect(security).toContain("SHA3-256 verified · 2 of 2 files");
    const manifest = host.querySelector(".xfer-live-manifest");
    expect(manifest?.querySelector(".xfer-live-digest")?.getAttribute("title")).toBe(digest);
    expect(manifest?.textContent).toContain("3a3a3a3a3a3a…3a3a3a3a");
  });

  it("never presents an integrity failure as complete", async () => {
    await render({
      ...transfer, status: "failed", errorKind: "integrity", verifiedBytes: 1024,
      error: "File integrity verification failed. Start a new transfer from the original files.",
      security: { phase: "error", mode: "Hybrid", keyEstablishment: "ML-KEM-768 + X25519", signatures: null, encryption: "AES-256-GCM", integrity: "SHA3-256" },
    });
    expect(host.querySelector("h2")?.textContent).toBe("Transfer needs attention");
    expect(host.querySelector('[role="progressbar"]')?.getAttribute("aria-valuenow")).toBe("99");
    expect(host.textContent).toContain("Integrity verification failed");
    expect(host.querySelector(".xfer-live-security")?.getAttribute("data-error")).toBe("true");
    expect(host.querySelector(".xfer-live-receipt")).toBeNull();
    expect(host.textContent).not.toContain("Successfully transferred");
  });

  it("withholds security claims and graphs in the absence of native evidence", async () => {
    await render({ ...transfer, status: "interrupted", error: "Connection lost before the peer verified the transfer." });
    expect(host.querySelector(".xfer-live-security")?.textContent).toContain("Session security unavailable");
    expect(host.querySelector(".xfer-live-security")?.textContent).not.toMatch(/AES|ML-KEM|ML-DSA/);
    expect(metric("Current speed")).toBe("Unavailable");
    expect(metric("Estimated time remaining")).toBe("Unavailable");
    expect(host.querySelector('figure svg[role="img"]')).toBeNull();
    expect(host.textContent).toContain("No recent throughput measurements");
    expect(host.textContent).toContain("Connection lost before the peer verified the transfer.");
    expect(host.textContent).not.toContain("Successfully transferred");
  });
});
