// Typed client for the native Google Play Billing bridge
// (src-tauri/gen/android/.../PlayBilling.kt via src-tauri/src/commands/billing.rs).
//
// The bridge only ever reports what Google Play's client library said. A
// purchase becomes access ONLY after the billing service verifies the token
// with the Google Play Developer API (see verifyPlayPurchase in billing-api.ts).

import { safeInvoke } from "@/lib/tauri";

export interface PlayPurchase {
  purchaseToken: string;
  orderId: string;
  products: string[];
  state: "purchased" | "pending" | "unspecified";
  acknowledged: boolean;
  autoRenewing?: boolean;
  /** obfuscatedAccountId Google recorded for the purchase ("" if none). */
  accountId?: string;
  purchaseTime?: number;
}

export interface PlayProduct {
  productId: string;
  title?: string;
  name?: string;
  basePlanId?: string;
  /** Localized price string from Google Play, e.g. "€0.99" — what the buyer is charged. */
  formattedPrice?: string;
  priceAmountMicros?: number;
  priceCurrencyCode?: string;
  /** ISO-8601 period, e.g. P1M / P1Y. */
  billingPeriod?: string;
}

export interface PlayResult {
  seq: number;
  action: "purchase" | "refresh" | "products" | "setup" | string;
  status: PlayResultStatus | string;
  code: number;
  detail: string;
  at: number;
}

export type PlayResultStatus =
  | "ok"
  | "flow_started"
  | "purchased"
  | "pending"
  | "cancelled"
  | "network"
  | "billing_unavailable"
  | "product_unavailable"
  | "invalid_request"
  | "already_owned"
  | "not_owned"
  | "error";

export interface PlayState {
  available: boolean;
  platform?: string;
  connectionState?: string;
  seq?: number;
  lastResult?: PlayResult | Record<string, never>;
  purchases?: PlayPurchase[];
  products?: PlayProduct[];
  unavailableProducts?: string[];
}

export const NO_PLAY: PlayState = { available: false };

export function readPlayState(): Promise<PlayState> {
  return safeInvoke<PlayState>("billing_state", undefined, NO_PLAY);
}

export function queryPlayProducts(productIds: string[]): Promise<unknown> {
  return safeInvoke("billing_query_products", { productIds }, null);
}

export function refreshPlayPurchases(): Promise<unknown> {
  return safeInvoke("billing_refresh_purchases", undefined, null);
}

export async function launchPlayPurchase(args: {
  productId: string;
  accountId: string;
  oldPurchaseToken: string | null;
  replacement: "upgrade" | "downgrade";
}): Promise<void> {
  // Errors (invalid input, no Play) propagate: the caller shows them.
  await safeInvoke("billing_launch_purchase", args);
}

/** The latest result newer than `afterSeq`, if any. */
export function resultAfter(state: PlayState, afterSeq: number): PlayResult | null {
  const result = state.lastResult as PlayResult | undefined;
  return result && typeof result.seq === "number" && result.seq > afterSeq ? result : null;
}

/** Actionable, user-facing text for a Play outcome (never raw debug text). */
export function playResultMessage(status: string): string | null {
  switch (status) {
    case "cancelled":
      return null; // the buyer closed the sheet — nothing to report
    case "pending":
      return "Your payment is pending in Google Play. Your plan starts automatically once Google confirms the payment — you have not been given access yet.";
    case "network":
      return "Google Play could not be reached. Check your connection and try again.";
    case "billing_unavailable":
      return "Google Play Billing isn't available on this device. Make sure the Play Store is installed, up to date and signed in.";
    case "product_unavailable":
      return "This plan isn't available in Google Play for your account or country right now.";
    case "invalid_request":
      return "Google Play rejected the purchase request. Update the app and try again.";
    case "already_owned":
      return "You already own this subscription on Google Play. Tap Restore purchases to link it to this account.";
    case "error":
      return "Google Play reported an error. Try again in a moment.";
    default:
      return null;
  }
}

/** Purchases this device holds that were bought for `accountId` (or with no binding recorded). */
export function purchasesForAccount(state: PlayState, accountId: string | null): PlayPurchase[] {
  return (state.purchases ?? []).filter((purchase) => !purchase.accountId || !accountId || purchase.accountId === accountId);
}
