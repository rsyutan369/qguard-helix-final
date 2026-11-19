import { describe, expect, it } from "vitest";
import { playResultMessage, purchasesForAccount, resultAfter, type PlayState } from "./play-billing";

const state: PlayState = {
  available: true,
  seq: 4,
  lastResult: { seq: 4, action: "purchase", status: "pending", code: 0, detail: "", at: 1 },
  purchases: [
    { purchaseToken: "t-mine", orderId: "GPA.1", products: ["qh_pro_monthly"], state: "purchased", acknowledged: false, accountId: "a".repeat(64) },
    { purchaseToken: "t-other", orderId: "GPA.2", products: ["qh_starter_monthly"], state: "purchased", acknowledged: true, accountId: "b".repeat(64) },
    { purchaseToken: "t-legacy", orderId: "GPA.3", products: ["qh_basic_monthly"], state: "pending", acknowledged: false, accountId: "" },
  ],
};

describe("play bridge helpers", () => {
  it("reports only results newer than the one already handled", () => {
    expect(resultAfter(state, 3)?.status).toBe("pending");
    expect(resultAfter(state, 4)).toBeNull();
    expect(resultAfter({ available: false }, 0)).toBeNull();
  });

  it("keeps purchases made for this account (or with no recorded binding)", () => {
    expect(purchasesForAccount(state, "a".repeat(64)).map((p) => p.purchaseToken)).toEqual(["t-mine", "t-legacy"]);
  });

  it("explains every failure in actionable words and stays quiet on a user cancel", () => {
    expect(playResultMessage("cancelled")).toBeNull();
    expect(playResultMessage("pending")).toMatch(/not been given access yet/);
    for (const status of ["network", "billing_unavailable", "product_unavailable", "invalid_request", "already_owned", "error"]) {
      expect(playResultMessage(status)).toBeTruthy();
    }
  });
});
