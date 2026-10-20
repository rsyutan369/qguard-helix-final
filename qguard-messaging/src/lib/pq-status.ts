import type { DevicePinStanding } from "@/lib/device-pins";
import { CURRENT_KEM_COMBINER, kemInteroperates, usesBoundCombiner, type PublishedSuite } from "@/lib/kem-suite";
import { advertisesRatchet, type RatchetSessionSummary } from "@/lib/ratchet-status";

/**
 * What can truthfully be said about how well ONE conversation is protected
 * against a future quantum computer — the chat header's protection badge.
 *
 * Built only from evidence this client really holds:
 *
 *   - the contact devices messages are being sealed to right now, with the
 *     suite each one published and the core's pin verdict for it;
 *   - the devices that were dropped from delivery, and why;
 *   - messages in this conversation that actually opened here, with the hybrid
 *     combiner their ciphertext says it was made with (the core refuses an
 *     unknown combiner, so a message that opened PROVES its label);
 *   - the core's own words about this device's prekey rotation.
 *
 * It never decides trust. "Pinned", "registered", "authenticated" are verdicts
 * the Rust core returned; this only aggregates them, and it says nothing when
 * there is nothing to go on (see `unknown`), the same discipline as
 * `describeCallSecurity`.
 *
 * Every message is sealed to every delivery device, so a conversation is only
 * as strong as its weakest one: the level is the worst over all of them.
 */

export type PqLevel =
  /** Nothing to go on yet: no delivery device and no opened message. */
  | "unknown"
  /** Post-quantum, but something weaker than this build's best is in use, or messages cannot be delivered. */
  | "attention"
  /** Hybrid X25519 + ML-KEM-1024 with the bound combiner everywhere it was measured. */
  | "protected"
  /** As `protected`, and every delivery device is the one this device recorded for the contact. */
  | "protected-pinned";

export interface PqStatusLine {
  /** False for something the user should know is weaker than it could be. */
  ok: boolean;
  text: string;
}

export interface PqDeliveryDevice {
  deviceId: string;
  label: string;
  suite: PublishedSuite;
  /** The core's pin verdict; undefined when it has not been asked (yet). */
  standing: DevicePinStanding | undefined;
}

export type PqExclusionReason = "older_build" | "awaiting_approval" | "key_changed" | "invalid_identity";

export interface PqExcludedDevice {
  label: string;
  reason: PqExclusionReason;
}

export interface PqOpenedMessage {
  incoming: boolean;
  /**
   * The hybrid combiner behind the key that opened it; "" = legacy. Null for a
   * ratchet message whose session this device no longer holds: no evidence
   * either way about the combiner.
   */
  kemCombiner: string | null;
  /** The core's verdict: the sender's keys are the ones registered for that device. */
  authenticated: boolean;
  /** How the core says the key was established; absent from older cores. */
  protocol?: "one_shot" | "ratchet";
}

/**
 * The core's report on post-quantum ratchet sessions (`messaging_ratchet_status`),
 * or null when it was not asked or did not answer.
 */
export interface PqRatchetEvidence {
  /** This device advertises the ratchet and starts sessions. */
  enabledHere: boolean;
  /** The session file opened; false = sessions cannot be judged right now. */
  available: boolean;
  /** The active session per delivery device id, as the core holds it. */
  sessions: Record<string, RatchetSessionSummary>;
}

export interface PqStatusEvidence {
  /** False in a browser preview: the core (and its pin record) is not there. */
  inApp: boolean;
  peerName: string;
  deliveryDevices: PqDeliveryDevice[];
  excludedDevices: PqExcludedDevice[];
  openedMessages: PqOpenedMessage[];
  /** The core could not open its record of contacts' devices. */
  pinsUnavailable: boolean;
  /** `PrekeyStatus.forwardSecrecyHealthy/Summary` for this device, or null when not measured. */
  forwardSecrecy: { healthy: boolean; summary: string } | null;
  /** Ratchet sessions, in the core's words; null/absent when not measured. */
  ratchet?: PqRatchetEvidence | null;
}

export interface PqStatus {
  level: PqLevel;
  /** Two or three words for the chip. */
  label: string;
  /** One sentence: the chip's tooltip and the explainer's first line. */
  headline: string;
  /** The explainer. Each line is traceable to one piece of evidence. */
  lines: PqStatusLine[];
}

/** How many recent opened messages are considered. Old history says little about today. */
export const PQ_STATUS_MESSAGE_WINDOW = 20;

const LABELS: Record<PqLevel, string> = {
  unknown: "Not measured yet",
  attention: "Needs attention",
  // The two protected levels share a label so it fits a phone header; the
  // chip's icon and the headline say which one it is.
  protected: "Quantum-safe",
  "protected-pinned": "Quantum-safe",
};

const EXCLUSION_TEXT: Record<PqExclusionReason, string> = {
  older_build: "runs an older build whose keys cannot open anything this app seals, so nothing is sent to it until it is updated",
  awaiting_approval: "appeared after you first exchanged keys and is waiting for your approval, so nothing is sent to it yet",
  key_changed: "is presenting different identity keys than the ones recorded for it, so nothing is sent to it",
  invalid_identity: "has an identity that does not verify, so nothing is sent to it",
};

function plural(count: number, one: string, many: string): string {
  return count === 1 ? one : many;
}

export function derivePqStatus(evidence: PqStatusEvidence): PqStatus {
  const name = evidence.peerName.trim() || "this contact";
  const devices = evidence.deliveryDevices;
  const opened = evidence.openedMessages.slice(0, PQ_STATUS_MESSAGE_WINDOW);
  const lines: PqStatusLine[] = [];
  let attention = false;

  // ---- Outgoing: what the core will seal with, per delivery device ---------
  // The core picks the combiner from the device's published suite
  // (`KemCombiner::for_peer_suite`), so the suite IS the evidence for the next
  // message. A non-interoperating device cannot be a delivery device (the page
  // filters it out); it is re-checked here so a filter change cannot turn into
  // a green badge.
  const unreadable = devices.filter((device) => !kemInteroperates(device.suite));
  const legacy = devices.filter((device) => kemInteroperates(device.suite) && !usesBoundCombiner(device.suite));
  if (devices.length > 0) {
    if (unreadable.length > 0) {
      attention = true;
      lines.push({
        ok: false,
        text: `${unreadable.map((device) => device.label).join(", ")} ${plural(unreadable.length, "does", "do")} not publish this build's ML-KEM (FIPS 203) keys.`,
      });
    }
    if (legacy.length > 0) {
      attention = true;
      lines.push({
        ok: false,
        text: `${legacy.map((device) => device.label).join(", ")} ${plural(legacy.length, "is", "are")} on an older version, so messages to ${plural(legacy.length, "it", "them")} use the earlier way of combining the two keys. Still post-quantum, but updating ${name}'s app restores the stronger form.`,
      });
    }
    if (unreadable.length === 0 && legacy.length === 0) {
      lines.push({
        ok: true,
        text: `Every message to ${name} is sealed with a classical key (X25519) and a post-quantum key (ML-KEM-1024) together, on ${devices.length} ${plural(devices.length, "device", "devices")}. Breaking it needs both broken.`,
      });
    }
  }

  // ---- Delivery gaps -------------------------------------------------------
  for (const excluded of evidence.excludedDevices) {
    lines.push({ ok: false, text: `${excluded.label} ${EXCLUSION_TEXT[excluded.reason]}.` });
  }
  if (devices.length === 0 && evidence.excludedDevices.length > 0) attention = true;

  // ---- Incoming: what the contact's app actually used ----------------------
  const incoming = opened.filter((message) => message.incoming);
  // A ciphertext's combiner label is the same string a device publishes as its
  // capability (`KemCombiner::label`). A null combiner is a ratchet message
  // whose session is gone from this device: it proves nothing either way.
  const incomingLegacy = incoming.filter((message) => message.kemCombiner !== null && message.kemCombiner !== CURRENT_KEM_COMBINER).length;
  const unauthenticated = incoming.filter((message) => !message.authenticated).length;
  if (incoming.length > 0) {
    if (incomingLegacy > 0) {
      attention = true;
      lines.push({
        ok: false,
        text: `${incomingLegacy} of the last ${incoming.length} ${plural(incoming.length, "message", "messages")} from ${name} used the earlier way of combining the keys — their app is out of date.`,
      });
    } else {
      lines.push({ ok: true, text: `The last ${incoming.length} ${plural(incoming.length, "message", "messages")} from ${name} arrived post-quantum sealed.` });
    }
    if (unauthenticated > 0) {
      attention = true;
      lines.push({
        ok: false,
        text: `${unauthenticated} recent ${plural(unauthenticated, "message", "messages")} could not be tied to a device registered for ${name}. Treat ${plural(unauthenticated, "it", "them")} with care.`,
      });
    }
  }

  // ---- Device identity ------------------------------------------------------
  const unjudged = devices.filter((device) => device.standing !== "pinned");
  if (devices.length > 0) {
    if (!evidence.inApp) {
      lines.push({ ok: false, text: "Device changes can only be checked inside the QGuard app." });
    } else if (evidence.pinsUnavailable) {
      lines.push({ ok: false, text: "Device changes cannot be checked right now: this device's record of your contacts' devices could not be opened." });
    } else if (unjudged.length > 0) {
      lines.push({ ok: false, text: `${unjudged.map((device) => device.label).join(", ")} ${plural(unjudged.length, "has", "have")} not been checked against the devices this app recorded for ${name} yet.` });
    } else {
      lines.push({ ok: true, text: `Every device receiving these messages is one this app recorded for ${name}. (This proves the device, not the person — compare safety numbers to be sure who holds it.)` });
    }
  }

  // ---- Per-message ratchet, in the core's own words --------------------------
  // Said only when this device runs it: with the ratchet off, every message is
  // a one-shot envelope and the forward-secrecy line below is the whole story.
  const ratchet = evidence.ratchet;
  if (ratchet?.enabledHere && devices.length > 0) {
    if (!ratchet.available) {
      lines.push({ ok: false, text: "This device's secure sessions could not be opened right now, so messages go out one-shot sealed until they can." });
    } else {
      const withoutCapability = devices.filter((device) => !advertisesRatchet(device.suite));
      const capable = devices.filter((device) => advertisesRatchet(device.suite));
      const ratcheted = capable.filter((device) => ratchet.sessions[device.deviceId]?.ratcheted);
      const waiting = capable.filter((device) => !ratchet.sessions[device.deviceId]?.ratcheted);
      if (ratcheted.length > 0) {
        lines.push({
          ok: true,
          text: ratcheted.length === devices.length
            ? `Per-message ratchet: every message to ${name} gets its own key, deleted once used, and a stolen device key stops working after the next reply. A fresh ML-KEM-1024 exchange is mixed in at least every 50 messages or 24 hours.`
            : `Per-message ratchet on ${ratcheted.map((device) => device.label).join(", ")}: each message gets its own key, deleted once used, with a fresh ML-KEM-1024 exchange at least every 50 messages or 24 hours.`,
        });
      }
      if (waiting.length > 0) {
        lines.push({
          ok: true,
          text: `${waiting.map((device) => device.label).join(", ")}: the per-message ratchet ${plural(waiting.length, "starts", "start")} with the next message and takes full effect once ${name} replies.`,
        });
      }
      if (withoutCapability.length > 0) {
        lines.push({
          ok: true,
          text: `${withoutCapability.map((device) => device.label).join(", ")} ${plural(withoutCapability.length, "does", "do")} not support the per-message ratchet yet, so messages to ${plural(withoutCapability.length, "it", "them")} are one-shot sealed (still post-quantum; forward secrecy per prekey rotation).`,
        });
      }
    }
  }
  const incomingRatchet = incoming.filter((message) => message.protocol === "ratchet").length;
  if (incomingRatchet > 0) {
    lines.push({ ok: true, text: `${incomingRatchet} of the last ${incoming.length} ${plural(incoming.length, "message", "messages")} from ${name} arrived on a per-message ratchet session.` });
  }

  // ---- Forward secrecy, in the core's own words -----------------------------
  // Only alongside something to qualify: with no device and no message the
  // badge says nothing beyond its headline.
  if (devices.length > 0 || opened.length > 0) {
    lines.push(evidence.forwardSecrecy
      ? { ok: evidence.forwardSecrecy.healthy, text: `On this device: ${evidence.forwardSecrecy.summary}` }
      : { ok: false, text: "Forward secrecy on this device is not measured right now." });
  }

  // ---- Level ----------------------------------------------------------------
  let level: PqLevel;
  if (devices.length === 0 && opened.length === 0 && evidence.excludedDevices.length === 0) {
    level = "unknown";
  } else if (attention) {
    level = "attention";
  } else if (devices.length === 0) {
    // Only history to go on, and nothing to send to now: it can be said that
    // what arrived was protected, not that what is sent next will be.
    level = "unknown";
  } else if (evidence.inApp && !evidence.pinsUnavailable && unjudged.length === 0) {
    level = "protected-pinned";
  } else {
    level = "protected";
  }

  return { level, label: LABELS[level], headline: headlineFor(level, name, devices.length), lines };
}

/**
 * How the devices of the people you message are protected, from the suites
 * those devices published — the cross-conversation view for the dashboard and
 * the security report.
 *
 * It says what the NEXT message to each device would be sealed with (that is
 * what the published suite decides), not what any past message was. Devices
 * are counted, not conversations: per-conversation levels need pin verdicts
 * and opened envelopes, which only the open conversation has.
 */
export interface ContactDeviceProtection {
  /** Active contact devices considered. */
  total: number;
  /** Sealed to with ML-KEM-1024 (FIPS 203) + X25519 and the bound combiner. */
  strongest: number;
  /** FIPS 203 ML-KEM, but the earlier (legacy) way of combining the keys. */
  olderCombiner: number;
  /** Pre-FIPS-203 key material: nothing this build seals can be opened there. */
  cannotReceive: number;
}

export function summarizeContactDeviceProtection(
  devices: { user_id: string; suite: PublishedSuite }[],
  localUserId: string,
): ContactDeviceProtection {
  const summary: ContactDeviceProtection = { total: 0, strongest: 0, olderCombiner: 0, cannotReceive: 0 };
  for (const device of devices) {
    if (device.user_id === localUserId) continue;
    summary.total += 1;
    if (!kemInteroperates(device.suite)) summary.cannotReceive += 1;
    else if (usesBoundCombiner(device.suite)) summary.strongest += 1;
    else summary.olderCombiner += 1;
  }
  return summary;
}

/** True when any line is a warning — the chip must then not read as spotless. */
export function pqStatusHasWarnings(status: PqStatus): boolean {
  return status.lines.some((line) => !line.ok);
}

function headlineFor(level: PqLevel, name: string, deviceCount: number): string {
  switch (level) {
    case "unknown":
      return deviceCount === 0
        ? `Nothing can be said yet: ${name} has no device this app can send to.`
        : "Nothing can be said yet: no message has been sent or opened here.";
    case "attention":
      return "Protected, but something here is weaker than it should be — see below.";
    case "protected":
      return `Messages with ${name} are sealed with post-quantum encryption.`;
    case "protected-pinned":
      return `Messages with ${name} are sealed with post-quantum encryption, only to devices this app recorded for them.`;
  }
}
