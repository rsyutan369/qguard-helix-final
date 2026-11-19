import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CryptoModuleStatus } from "@/lib/crypto-module";

const api = vi.hoisted(() => ({ fetchCryptoModuleStatus: vi.fn(), setApprovedMode: vi.fn() }));
vi.mock("@/lib/crypto-module", () => api);

import { FipsModuleCard } from "@/components/FipsModuleCard";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function status(overrides: Partial<CryptoModuleStatus> = {}): CryptoModuleStatus {
  return {
    module: { backend: "rustcrypto", name: "RustCrypto + dalek + PQClean (bundled)", version: "aes-gcm 0.10", fipsModuleVersion: null, fipsStatus: null },
    fipsValidatedModule: false,
    certificate: null,
    approvedMode: false,
    approvedModeSource: "setting",
    selfTest: { passed: true, backend: "rustcrypto", ranAt: "2026-11-03T00:00:00Z", durationMs: 41, results: [{ name: "ML-KEM-1024", passed: true }, { name: "ML-DSA-87", passed: true }] },
    algorithms: [
      { id: "ml-kem-1024", name: "ML-KEM-1024", standard: "FIPS 203", usedFor: "Key establishment", approved: true, validated: false, note: null },
      { id: "x25519", name: "X25519", standard: "RFC 7748", usedFor: "Hybrid", approved: false, validated: false, note: "Not FIPS-approved." },
    ],
    outsideBoundary: ["Call audio and video frames are encrypted with AES-256-GCM by the WebView's WebCrypto."],
    credentials: [{ id: "vault-pin", label: "Quantum Vault PIN", kdf: "Argon2id (64 MiB, 3 passes)", approvedKdf: false, meetsApprovedMode: false, note: "Use a password." }],
    pbkdf2: { prf: "HMAC-SHA-512", iterations: 600000, saltBits: 128, vaultPasswordMinChars: 14 },
    ...overrides,
  };
}

async function render() {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(createElement(FipsModuleCard));
  });
  return { container, root };
}

function buttonNamed(container: HTMLElement, text: string): HTMLButtonElement {
  const button = Array.from(container.querySelectorAll("button")).find((candidate) => candidate.textContent?.includes(text));
  if (!button) throw new Error(`no button "${text}"`);
  return button as HTMLButtonElement;
}

async function openAdvanced(container: HTMLElement) {
  await act(async () => {
    buttonNamed(container, "Advanced: FIPS 140-3 approved mode").click();
  });
}

beforeEach(() => {
  api.fetchCryptoModuleStatus.mockReset();
  api.setApprovedMode.mockReset();
  document.body.innerHTML = "";
});

describe("FipsModuleCard", () => {
  it("shows only the self-test by default and keeps module details under Advanced", async () => {
    api.fetchCryptoModuleStatus.mockResolvedValue(status());
    const { container } = await render();
    const compact = container.textContent ?? "";
    expect(compact).toContain("Self-test passed: 2 known-answer and pairwise tests in 41 ms");
    expect(compact).toContain("ML-KEM-1024");
    expect(compact).not.toContain("RustCrypto");
    expect(compact).not.toContain("CMVP");
    expect(compact).not.toContain("Turn approved mode on");
    await openAdvanced(container);
    expect(container.textContent).toContain("RustCrypto + dalek + PQClean");
  });

  it("reports an unvalidated module as unvalidated, with the self-test the core ran", async () => {
    api.fetchCryptoModuleStatus.mockResolvedValue(status());
    const { container } = await render();
    await openAdvanced(container);
    const text = container.textContent ?? "";
    expect(text).toContain("Not a CMVP-validated module");
    expect(text).toContain("Self-test passed: 2 known-answer and pairwise tests in 41 ms");
    expect(text).toContain("Approved mode off");
    expect(text).not.toContain("CMVP certificate #");
    // The vault PIN caveat is shown because the core reported a vault PIN.
    expect(text).toContain("Your Quantum Vault opens with a PIN");
  });

  it("names the certificate only for a validated module build", async () => {
    api.fetchCryptoModuleStatus.mockResolvedValue(status({
      module: { backend: "wolfcrypt", name: "wolfCrypt FIPS 140-3 module", version: "wolfSSL 5.2.3", fipsModuleVersion: "5.2.3", fipsStatus: 0 },
      fipsValidatedModule: true,
      certificate: { number: 5548, module: "wolfCrypt", moduleVersion: "5.2.3", standard: "FIPS 140-3 Level 1", validatedOn: "2026-10-09", sunset: "2031-10-08", url: "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5548", covers: ["aes-256-gcm"], testedPlatforms: [] },
      credentials: [],
    }));
    const { container } = await render();
    await openAdvanced(container);
    const link = container.querySelector("a");
    expect(link?.textContent).toContain("CMVP certificate #5548");
    expect(link?.getAttribute("href")).toContain("/certificate/5548");
  });

  it("switches approved mode through the core and shows what the core then reports", async () => {
    api.fetchCryptoModuleStatus.mockResolvedValue(status({ credentials: [] }));
    api.setApprovedMode.mockResolvedValue(status({ approvedMode: true, credentials: [] }));
    const { container } = await render();
    await openAdvanced(container);
    await act(async () => {
      buttonNamed(container, "Turn approved mode on").click();
    });
    expect(api.setApprovedMode).toHaveBeenCalledWith(true);
    expect(container.textContent).toContain("Approved mode on");
    expect(container.textContent).toContain("PBKDF2-HMAC-SHA-512 (600,000 iterations)");
  });

  it("refuses to switch approved mode on after a failed self-test, and says what failed", async () => {
    api.fetchCryptoModuleStatus.mockResolvedValue(status({
      selfTest: { passed: false, backend: "rustcrypto", ranAt: "2026-11-03T00:00:00Z", durationMs: 40, results: [{ name: "AES-256-GCM", passed: false, detail: "decrypt mismatch" }] },
    }));
    const { container } = await render();
    // A failed self-test is never hidden behind Advanced.
    expect(container.textContent).toContain("Self-test failed");
    await openAdvanced(container);
    expect(container.textContent).toContain("AES-256-GCM: decrypt mismatch");
    expect(buttonNamed(container, "Turn approved mode on").disabled).toBe(true);
  });

  it("cannot be switched when a build or the operator decides it", async () => {
    api.fetchCryptoModuleStatus.mockResolvedValue(status({ approvedMode: true, approvedModeSource: "build", credentials: [] }));
    const { container } = await render();
    // Opens on its own: the build decides approved mode.
    expect(container.textContent).toContain("FIPS approved mode on · this build");
    expect(buttonNamed(container, "Turn approved mode off").disabled).toBe(true);
  });

  it("renders nothing outside the app", async () => {
    api.fetchCryptoModuleStatus.mockResolvedValue(null);
    const { container } = await render();
    expect(container.innerHTML).toBe("");
  });
});
