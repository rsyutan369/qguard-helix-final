import { createElement } from "react";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const scanner = vi.hoisted(() => ({ onResult: null as ((value: string) => void) | null }));
const trust = vi.hoisted(() => ({ trustLinkedDevice: vi.fn() }));

vi.mock("@/lib/supabase", () => ({
  supabaseUrl: "https://project.supabase.co",
  supabaseAnonKey: "anon-key",
  supabase: { auth: { getSession: async () => ({ data: { session: { access_token: "approver-token" } } }) } },
}));
vi.mock("@/lib/qr-scanner", () => ({
  useQrScanner: (_active: boolean, onResult: (value: string) => void) => {
    scanner.onResult = onResult;
    return { videoRef: { current: null }, error: null, starting: false };
  },
}));
vi.mock("@/lib/device-link-trust", () => trust);

import { LinkDeviceDialog } from "@/components/devices/LinkDeviceDialog";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const LINK_ID = "6f9b7f5e-2a1c-4b1e-9a7d-0c2b9b7c3d11";
const NEW_DEVICE = "f1d2c3b4-a596-4877-8899-aabbccddeeff";
const SECRET = "A".repeat(43);

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

let root: Root;
let host: HTMLDivElement;
let routes: Record<string, () => Response>;
let calls: Array<{ route: string; body: Record<string, unknown>; auth: string | undefined }>;

const text = () => document.body.textContent ?? "";
const button = (label: string) => [...document.querySelectorAll("button")].find((b) => b.textContent?.trim() === label);
const settle = async (ms = 0) => {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, ms));
  });
};

beforeEach(() => {
  calls = [];
  routes = {
    "/inspect": () => respond({ linkId: LINK_ID, label: "Windows desktop", platform: "windows", ip: "203.0.113.9", createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() }),
    "/approve": () => respond({ linkId: LINK_ID, status: "approved", method: "email_token" }),
    "/reject": () => respond({ linkId: LINK_ID, status: "rejected" }),
    "/status": () => respond({ linkId: LINK_ID, status: "consumed", label: "Windows desktop", linkedDeviceId: NEW_DEVICE, linkProof: "a".repeat(64), failureReason: null }),
  };
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const route = String(input).replace(/^.*\/device-link/, "");
    calls.push({ route, body: JSON.parse(String(init?.body ?? "{}")), auth: (init?.headers as Record<string, string>)?.Authorization });
    return routes[route]?.() ?? respond({ error: { code: "NOT_FOUND", message: "nope" } }, 404);
  });
  trust.trustLinkedDevice.mockReset();
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  vi.restoreAllMocks();
});

async function open(onLinked = vi.fn()) {
  await act(async () => {
    root.render(createElement(LinkDeviceDialog, { open: true, userId: "user-1", approverDeviceId: "approver-device", onClose: vi.fn(), onLinked }));
  });
  return onLinked;
}

describe("LinkDeviceDialog", () => {
  it("scans, shows who is asking with a warning, approves, then verifies and trusts the scanned device", async () => {
    trust.trustLinkedDevice.mockResolvedValue({ trusted: true, label: "Windows desktop" });
    const onLinked = await open();
    expect(text()).toContain("Link a device");

    await act(async () => scanner.onResult!(`qguard-link:v2:AB12-CD34-EF56#${SECRET}`));
    await settle();
    expect(text()).toContain("Windows desktop");
    expect(text()).toContain("203.0.113.9");
    expect(text()).toContain("Scanned — will be verified");
    expect(text()).toMatch(/Never scan a code someone sent you/);
    expect(calls[0]).toMatchObject({ route: "/inspect", body: { code: "AB12-CD34-EF56" }, auth: "Bearer approver-token" });
    // The binding secret never leaves the approving device.
    expect(JSON.stringify(calls)).not.toContain(SECRET);

    await act(async () => button("Link device")!.click());
    await settle(10);
    expect(calls.find((call) => call.route === "/approve")?.body).toEqual({ code: "AB12-CD34-EF56", deviceId: "approver-device" });
    await settle(10);

    expect(trust.trustLinkedDevice).toHaveBeenCalledWith(expect.objectContaining({
      linkId: LINK_ID,
      bindingSecret: SECRET,
      linkedDeviceId: NEW_DEVICE,
      linkProof: "a".repeat(64),
      approverDeviceId: "approver-device",
    }));
    expect(text()).toContain("Windows desktop is linked");
    expect(onLinked).toHaveBeenCalled();
    expect(JSON.stringify(calls)).not.toContain(SECRET);
  });

  it("signs in a typed code but leaves the device for manual approval (no binding secret)", async () => {
    await open();
    await act(async () => button("Type the code instead")!.click());
    const input = document.querySelector<HTMLInputElement>("#link-code")!;
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
      setter.call(input, "ab12cd34ef56");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => button("Continue")!.closest("form")!.requestSubmit());
    await settle();
    expect(text()).toContain("Typed — manual review");
    await act(async () => button("Link device")!.click());
    await settle(10);
    await settle(10);
    expect(trust.trustLinkedDevice).not.toHaveBeenCalled();
    expect(text()).toContain("approve the new device in the Device Trust Center");
  });

  it("'Not me' rejects the request on the server", async () => {
    await open();
    await act(async () => scanner.onResult!(`qguard-link:v2:AB12-CD34-EF56#${SECRET}`));
    await settle();
    await act(async () => button("Not me")!.click());
    await settle();
    expect(calls.map((call) => call.route)).toContain("/reject");
    expect(calls.map((call) => call.route)).not.toContain("/approve");
    expect(text()).toContain("Request declined");
  });

  it("refuses a QR code that is not a QGuard link without contacting the server", async () => {
    await open();
    await act(async () => scanner.onResult!("https://login.example.com/?session=steal"));
    await settle();
    expect(text()).toContain("isn't a QGuard Helix link code");
    expect(calls).toHaveLength(0);
  });

  it("shows the server's reason when the code has expired", async () => {
    routes["/inspect"] = () => respond({ error: { code: "LINK_EXPIRED", message: "This QR code has expired. Refresh it on the new device." } }, 410);
    await open();
    await act(async () => scanner.onResult!(`qguard-link:v2:AB12-CD34-EF56#${SECRET}`));
    await settle();
    expect(text()).toContain("This QR code has expired");
  });
});
