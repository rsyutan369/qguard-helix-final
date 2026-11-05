import { describe, expect, test } from "vitest";
import { parseRelayRow, relayValidUntil } from "@/lib/call-ice";
// The Edge Function's pure logic (supabase/functions/call-relay in the platform repo).
import { bearerToken, parseCloudflareIceServers } from "../../../supabase/functions/call-relay/logic";

const NOW = new Date("2026-11-05T12:00:00Z");

describe("call-relay: Cloudflare response → relay row", () => {
  test("generate-ice-servers shape: STUN and TURN split, :53 dropped, credential carried", () => {
    const relay = parseCloudflareIceServers(
      {
        iceServers: [
          { urls: ["stun:stun.cloudflare.com:3478", "stun:stun.cloudflare.com:53"] },
          {
            urls: [
              "turn:turn.cloudflare.com:3478?transport=udp",
              "turn:turn.cloudflare.com:53?transport=udp",
              "turn:turn.cloudflare.com:3478?transport=tcp",
              "turns:turn.cloudflare.com:5349?transport=tcp",
              "turns:turn.cloudflare.com:443?transport=tcp",
            ],
            username: "user-1",
            credential: "secret-1",
          },
        ],
      },
      NOW,
      3600,
    );
    expect(relay).not.toBeNull();
    expect(relay!.stun_urls).toEqual(["stun:stun.cloudflare.com:3478"]);
    expect(relay!.turn_urls).toEqual([
      "turn:turn.cloudflare.com:3478?transport=udp",
      "turn:turn.cloudflare.com:3478?transport=tcp",
      "turns:turn.cloudflare.com:5349?transport=tcp",
      "turns:turn.cloudflare.com:443?transport=tcp",
    ]);
    expect(relay!.turn_username).toBe("user-1");
    expect(relay!.turn_credential).toBe("secret-1");
    expect(relay!.expires_at).toBe("2026-11-05T13:00:00.000Z");
  });

  test("older single-object shape is accepted too", () => {
    const relay = parseCloudflareIceServers(
      { iceServers: { urls: ["stun:stun.cloudflare.com:3478", "turn:turn.cloudflare.com:3478?transport=udp"], username: "u", credential: "c" } },
      NOW,
    );
    expect(relay?.turn_urls).toEqual(["turn:turn.cloudflare.com:3478?transport=udp"]);
    expect(relay?.stun_urls).toEqual(["stun:stun.cloudflare.com:3478"]);
  });

  test("no usable relay → null (no TURN url, or a TURN url without credentials)", () => {
    expect(parseCloudflareIceServers({ iceServers: [{ urls: ["stun:stun.cloudflare.com:3478"] }] }, NOW)).toBeNull();
    expect(parseCloudflareIceServers({ iceServers: [{ urls: ["turn:turn.cloudflare.com:3478"] }] }, NOW)).toBeNull();
    expect(parseCloudflareIceServers({ iceServers: [{ urls: ["turn:turn.cloudflare.com:53"], username: "u", credential: "c" }] }, NOW)).toBeNull();
    expect(parseCloudflareIceServers(null, NOW)).toBeNull();
    expect(parseCloudflareIceServers({ error: "nope" }, NOW)).toBeNull();
  });

  test("the function's response parses with the app's relay-row parser", () => {
    const minted = parseCloudflareIceServers(
      { iceServers: [{ urls: ["turn:turn.cloudflare.com:3478?transport=udp"], username: "u", credential: "c" }] },
      NOW,
    );
    expect(parseRelayRow(minted)).toEqual({
      stunUrls: [],
      turnUrls: ["turn:turn.cloudflare.com:3478?transport=udp"],
      turnUsername: "u",
      turnCredential: "c",
    });
  });

  test("bearer token extraction", () => {
    expect(bearerToken("Bearer abc.def")).toBe("abc.def");
    expect(bearerToken("bearer abc")).toBe("abc");
    expect(bearerToken("Basic abc")).toBeNull();
    expect(bearerToken(null)).toBeNull();
  });
});

describe("relay cache lifetime", () => {
  const now = NOW.getTime();
  test("a relay row is re-read every 5 minutes", () => {
    expect(relayValidUntil(now, null)).toBe(now + 5 * 60_000);
  });
  test("minted credentials are kept until an hour before they expire", () => {
    expect(relayValidUntil(now, now + 24 * 3600_000)).toBe(now + 23 * 3600_000);
  });
  test("but never refetched more often than every 5 minutes", () => {
    expect(relayValidUntil(now, now + 30 * 60_000)).toBe(now + 5 * 60_000);
  });
});
