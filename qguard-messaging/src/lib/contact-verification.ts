import { isTauriRuntime, safeInvoke } from "@/lib/tauri";
import type { CallPeerIdentityPayload } from "@/lib/call-targets";

/**
 * Verified contacts and call challenge phrases (roadmap Phase 3;
 * src-tauri/src/commands/contact_verification.rs).
 *
 * The core decides everything here. These wrappers carry its answers to the
 * UI, and the describe* helpers turn them into plain sentences. "Verified"
 * always means: the user compared the safety number for these exact keys in
 * this app — it proves the device, not the human holding it.
 */

export type PairingState = "none" | "waiting_for_them" | "needs_your_verification" | "paired";
export type VerificationMethod = "safety_number" | "qr_code";

export interface ContactVerificationStatus {
  userId: string;
  deviceId: string;
  standing: "pinned" | "new" | "key_changed" | "unknown";
  safetyNumber: string;
  fingerprint: string;
  verifiedAt: number | null;
  method: VerificationMethod | null;
  pairing: PairingState;
}

/** One side's call-pairing half, as the core produced it (opaque to the UI). */
export type PairingOffer = Record<string, unknown> & { fromDeviceId: string; toDeviceId: string; offerId: string };

export interface PairingReceipt {
  status: ContactVerificationStatus;
  /** The other device lacks our half: send it a fresh offer. */
  replyNeeded: boolean;
}

export interface ContactAssurance {
  recorded: boolean;
  verifiedAt: number | null;
  pairing: PairingState;
}

export interface CallPhrase {
  words: string[];
  secondsLeft: number;
  pairing: PairingState;
  verifiedAt: number | null;
}

export const fetchContactVerification = (peer: CallPeerIdentityPayload) =>
  safeInvoke<ContactVerificationStatus>("contact_verification_status", { peer });

export const markContactVerified = (peer: CallPeerIdentityPayload, safetyNumber: string, method: VerificationMethod) =>
  safeInvoke<ContactVerificationStatus>("contact_mark_verified", { peer, safetyNumber, method });

export const clearContactVerification = (peer: CallPeerIdentityPayload) =>
  safeInvoke<ContactVerificationStatus>("contact_clear_verification", { peer });

export const createPairingOffer = (peer: CallPeerIdentityPayload) =>
  safeInvoke<PairingOffer>("contact_pairing_offer", { peer });

export const receivePairingOffer = (offer: PairingOffer, sender: CallPeerIdentityPayload) =>
  safeInvoke<PairingReceipt>("contact_pairing_receive", { offer, sender });

export async function fetchContactAssurance(peerUserId: string, peerDeviceId: string): Promise<ContactAssurance | null> {
  if (!isTauriRuntime()) return null;
  return safeInvoke<ContactAssurance>("contact_assurance", { peerUserId, peerDeviceId });
}

export const fetchCallPhrase = (peerUserId: string, peerDeviceId: string, callId: string) =>
  safeInvoke<CallPhrase>("call_phrase", { peerUserId, peerDeviceId, callId });

export const checkCallPhrase = (peerUserId: string, peerDeviceId: string, callId: string, spoken: string) =>
  safeInvoke<boolean>("call_phrase_check", { peerUserId, peerDeviceId, callId, spoken });

/** Plain-English pairing state, for the verification panel. */
export function describePairing(pairing: PairingState, name: string): string {
  switch (pairing) {
    case "paired":
      return `Paired: during a call with ${name}, you can each show a four-word phrase only your two devices can produce.`;
    case "waiting_for_them":
      return `Waiting for ${name}: their app pairs back once they verify you too and open this chat.`;
    case "needs_your_verification":
      return `${name} has verified you. Verify them too to pair your devices for calls.`;
    case "none":
      return "Not paired yet.";
  }
}

/**
 * What the incoming-call screen may say before answering. Only what this
 * device's own record holds for the calling device id; the caller's keys are
 * checked when the call is set up, and a device presenting other keys is
 * refused there.
 */
export function describeIncomingAssurance(assurance: ContactAssurance | null, name: string): { tone: "ok" | "warn" | "danger"; text: string; confirmToAnswer: boolean } | null {
  if (!assurance) return null;
  if (!assurance.recorded) {
    return {
      tone: "danger",
      text: `This call comes from a device you have not approved for ${name}. A familiar voice proves nothing — answer only if you expected it, and verify them before sharing anything.`,
      confirmToAnswer: true,
    };
  }
  if (assurance.verifiedAt === null) {
    return {
      tone: "warn",
      text: `${name}'s registered device, but you haven't verified them. A cloned voice can't prove who is calling.`,
      confirmToAnswer: false,
    };
  }
  return {
    tone: "ok",
    text: assurance.pairing === "paired"
      ? `From a device you verified for ${name}. Once connected, ask for their phrase to be sure it's still them.`
      : `From a device you verified for ${name}.`,
    confirmToAnswer: false,
  };
}
