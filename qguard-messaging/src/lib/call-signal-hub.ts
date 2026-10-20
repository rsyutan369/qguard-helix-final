import type { CallSignalRow } from "@/lib/call-types";
import { subscribeCallSignals, type CallSignalChannel } from "@/lib/call-signaling";

/**
 * One signal subscription shared by several call engines (roadmap 7.2, group
 * calls). A group call is a mesh of ordinary one-to-one links, each run by its
 * own engine instance; every signal must reach EXACTLY ONE of them, or the
 * engine that does not own a call answers "busy" and tears it down.
 *
 * Routing, decided synchronously when a signal arrives:
 *   1. a call id already assigned to an engine goes to that engine;
 *   2. a first contact (ring/offer) carrying a group invite is offered to the
 *      group coordinator, which assigns it a link slot — or refuses it (null),
 *      in which case it is answered "busy" by the coordinator;
 *   3. everything else goes to the primary (one-to-one) engine, exactly as
 *      before group calls existed.
 */
export const PRIMARY_SLOT = "primary";

export type ChooseSlot = (row: CallSignalRow) => string | null;

export function hasGroupInvite(row: CallSignalRow): boolean {
  const group = row.payload?.group;
  return Boolean(group && typeof group === "object" && !Array.isArray(group));
}

/** Pure routing: which engine gets `row` (null: nobody — refuse it). */
export function routeSignal(row: CallSignalRow, routes: Map<string, string>, chooseSlot: ChooseSlot): string | null {
  const known = routes.get(row.call_id);
  if (known) return known;
  if ((row.signal_type === "ring" || row.signal_type === "offer") && hasGroupInvite(row)) {
    const slot = chooseSlot(row);
    if (slot) routes.set(row.call_id, slot);
    return slot;
  }
  return PRIMARY_SLOT;
}

export interface CallSignalHub {
  /** Attach an engine; returns the channel interface the engine already uses. */
  attach: (slot: string, onSignal: (row: CallSignalRow) => void) => CallSignalChannel;
  /** Pin an outgoing call to the engine that placed it. */
  claim: (callId: string, slot: string) => void;
  /** Forget a finished call's routing. */
  release: (callId: string) => void;
}

export function createCallSignalHub(opts: {
  userId: string;
  deviceId: string;
  chooseSlot: ChooseSlot;
  onRefused?: (row: CallSignalRow) => void;
  subscribe?: typeof subscribeCallSignals;
}): CallSignalHub {
  const routes = new Map<string, string>();
  const handlers = new Map<string, (row: CallSignalRow) => void>();
  let shared: CallSignalChannel | null = null;

  const deliver = (row: CallSignalRow) => {
    const slot = routeSignal(row, routes, opts.chooseSlot);
    if (!slot) {
      if (row.signal_type === "ring") opts.onRefused?.(row);
      return;
    }
    handlers.get(slot)?.(row);
  };

  const ensure = (): CallSignalChannel => {
    if (!shared) {
      shared = (opts.subscribe ?? subscribeCallSignals)({ userId: opts.userId, deviceId: opts.deviceId, onSignal: deliver });
    }
    return shared;
  };

  return {
    attach: (slot, onSignal) => {
      handlers.set(slot, onSignal);
      const channel = ensure();
      return {
        boost: (ms) => channel.boost(ms),
        refresh: () => channel.refresh(),
        close: () => {
          if (handlers.get(slot) === onSignal) handlers.delete(slot);
          if (handlers.size === 0 && shared) {
            shared.close();
            shared = null;
          }
        },
      };
    },
    claim: (callId, slot) => { routes.set(callId, slot); },
    release: (callId) => { routes.delete(callId); },
  };
}
