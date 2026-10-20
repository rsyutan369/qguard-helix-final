import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createCallSignalHub, PRIMARY_SLOT } from "@/lib/call-signal-hub";
import { sendCallSignal } from "@/lib/call-signaling";
import { buildCallPeer, type CallCandidateDevice, type CallPeer } from "@/lib/call-targets";
import type { CallSignalRow } from "@/lib/call-types";
import { byteaToBytes } from "@/lib/encoding";
import {
  GROUP_LINK_SLOTS,
  admitGroupRing,
  makeGroupInvite,
  meshTargets,
  parseGroupInvite,
  type GroupInvite,
  type GroupLinkSlot,
} from "@/lib/group-call";
import { supabase } from "@/lib/supabase";
import { useSecureCall } from "@/lib/use-secure-call";

type Engine = ReturnType<typeof useSecureCall>;

const LIVE = ["ringing", "calling", "connecting", "connected"];

export interface GroupLinkView {
  slot: GroupLinkSlot;
  peerUserId: string;
  phase: string;
  remoteStream: MediaStream | null;
}

/** Everything a member needs to ring another member's devices (same data as message delivery). */
async function loadCallPeer(userId: string, displayName: string): Promise<CallPeer | null> {
  const { data, error } = await supabase
    .from("messaging_devices")
    .select("id,user_id,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature,trust_state,revoked_at,last_seen_at")
    .eq("user_id", userId)
    .neq("trust_state", "revoked")
    .order("last_seen_at", { ascending: false, nullsFirst: false });
  if (error || !data) return null;
  const candidates: CallCandidateDevice[] = (data as Array<Record<string, unknown>>)
    .filter((row) => !row.revoked_at)
    .map((row) => ({
      user_id: String(row.user_id),
      device_id: String(row.id),
      x25519_identity_public: byteaToBytes(row.x25519_identity_public),
      mlkem_identity_public: byteaToBytes(row.mlkem_identity_public),
      ed25519_identity_public: byteaToBytes(row.ed25519_identity_public),
      mldsa_identity_public: byteaToBytes(row.mldsa_identity_public),
      identity_signature: (row.identity_signature as CallCandidateDevice["identity_signature"]) ?? null,
    }));
  return buildCallPeer(candidates, displayName);
}

/**
 * Group calls (roadmap 7.2): a mesh of one-to-one links between up to three
 * people. Owns the shared signal hub, the primary (one-to-one) engine and two
 * link engines. A group link is accepted without ringing ONLY when the user
 * already accepted that same group call (see `admitGroupRing`).
 */
export function useCallEngines(userId: string, deviceId: string) {
  const [group, setGroup] = useState<{ invite: GroupInvite; joined: boolean } | null>(null);
  const groupRef = useRef(group);
  groupRef.current = group;
  const slotPeersRef = useRef(new Map<GroupLinkSlot, string>());
  const [slotPeers, setSlotPeers] = useState<Record<string, string>>({});
  const primaryLiveRef = useRef(false);
  const linksRef = useRef<Record<GroupLinkSlot, Engine | null>>({ "group-1": null, "group-2": null });

  const publishSlots = () => setSlotPeers(Object.fromEntries(slotPeersRef.current));

  const freeSlot = (): GroupLinkSlot | null => GROUP_LINK_SLOTS.find((slot) => (
    !slotPeersRef.current.has(slot) && !LIVE.includes(linksRef.current[slot]?.state.phase ?? "idle")
  )) ?? null;

  const hub = useMemo(() => {
    if (!userId || !deviceId) return null;
    return createCallSignalHub({
      userId,
      deviceId,
      chooseSlot: (row: CallSignalRow) => {
        const invite = parseGroupInvite(row.payload?.group);
        if (!invite) return null;
        const current = groupRef.current?.invite ?? null;
        if (!admitGroupRing({ invite, fromUserId: row.from_user_id, conversationId: row.conversation_id, myUserId: userId, current, oneToOneBusy: primaryLiveRef.current })) {
          return null;
        }
        const slot = freeSlot();
        if (!slot) return null;
        slotPeersRef.current.set(slot, row.from_user_id);
        publishSlots();
        if (!groupRef.current) {
          const next = { invite: current ?? invite, joined: false };
          groupRef.current = next;
          setGroup(next);
        }
        return slot;
      },
      onRefused: (row: CallSignalRow) => {
        void sendCallSignal({
          call_id: row.call_id, conversation_id: row.conversation_id,
          from_user_id: userId, from_device_id: deviceId,
          to_user_id: row.from_user_id, to_device_id: row.from_device_id,
          signal_type: "busy", payload: {},
        }).catch(() => undefined);
      },
    });
    // freeSlot/publishSlots read refs only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceId, userId]);

  const engineDevice = hub ? deviceId : "";
  const primary = useSecureCall({ userId, deviceId: engineDevice, hub, slot: PRIMARY_SLOT, isBusy: () => groupRef.current !== null });
  const link1 = useSecureCall({ userId, deviceId: engineDevice, hub, slot: "group-1" });
  const link2 = useSecureCall({ userId, deviceId: engineDevice, hub, slot: "group-2" });
  linksRef.current = { "group-1": link1, "group-2": link2 };
  primaryLiveRef.current = LIVE.includes(primary.state.phase);

  // A link that ended frees its slot; when no link is left the group call is over.
  useEffect(() => {
    let changed = false;
    for (const slot of GROUP_LINK_SLOTS) {
      const phase = linksRef.current[slot]?.state.phase ?? "idle";
      if (slotPeersRef.current.has(slot) && (phase === "ended" || phase === "idle")) {
        // "idle" right after assignment is the moment before the ring is handled.
        if (phase === "ended") {
          slotPeersRef.current.delete(slot);
          changed = true;
        }
      }
    }
    if (changed) publishSlots();
    const anyLive = GROUP_LINK_SLOTS.some((slot) => LIVE.includes(linksRef.current[slot]?.state.phase ?? "idle"));
    if (groupRef.current && !anyLive && slotPeersRef.current.size === 0) {
      groupRef.current = null;
      setGroup(null);
    }
    // Phases are the trigger; refs carry the rest.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [link1.state.phase, link2.state.phase]);

  // Joined: a ringing link of this call is answered without asking again.
  useEffect(() => {
    if (!group?.joined) return;
    for (const slot of GROUP_LINK_SLOTS) {
      const engine = linksRef.current[slot];
      if (engine?.state.phase === "ringing" && engine.state.role === "callee") void engine.accept();
    }
  }, [group?.joined, link1.state.phase, link2.state.phase]);

  const ringMembers = useCallback(async (invite: GroupInvite, targets: string[], names: Record<string, string>) => {
    for (const target of targets) {
      const slot = freeSlot();
      if (!slot) return;
      const peer = await loadCallPeer(target, names[target] ?? "Group member");
      if (!peer) continue;
      slotPeersRef.current.set(slot, target);
      publishSlots();
      await linksRef.current[slot]?.startCall(peer, invite.conversationId, { group: invite });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** Inviter: ring the other two (peers already resolved by the chat page). */
  const startGroupCall = useCallback(async (conversationId: string, peers: CallPeer[]) => {
    if (groupRef.current || primaryLiveRef.current) throw new Error("You are already on a call.");
    const invite = makeGroupInvite(conversationId, userId, peers.map((peer) => peer.userId));
    const next = { invite, joined: true };
    groupRef.current = next;
    setGroup(next);
    await Promise.all(peers.map(async (peer, index) => {
      const slot = GROUP_LINK_SLOTS[index];
      slotPeersRef.current.set(slot, peer.userId);
      publishSlots();
      await linksRef.current[slot]?.startCall(peer, conversationId, { group: invite });
    }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);

  /** Invited: accept every ringing link, then ring the members after me. */
  const joinGroupCall = useCallback(async (names: Record<string, string>) => {
    const current = groupRef.current;
    if (!current) return;
    const next = { ...current, joined: true };
    groupRef.current = next;
    setGroup(next);
    for (const slot of GROUP_LINK_SLOTS) {
      const engine = linksRef.current[slot];
      if (engine?.state.phase === "ringing") await engine.accept();
    }
    await ringMembers(current.invite, meshTargets(current.invite, userId, slotPeersRef.current.values()), names);
  }, [ringMembers, userId]);

  const leaveGroupCall = useCallback(() => {
    for (const slot of GROUP_LINK_SLOTS) {
      const engine = linksRef.current[slot];
      if (!engine) continue;
      if (engine.state.phase === "ringing") engine.reject();
      else if (LIVE.includes(engine.state.phase)) engine.hangup();
    }
    slotPeersRef.current.clear();
    publishSlots();
    groupRef.current = null;
    setGroup(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const links: GroupLinkView[] = GROUP_LINK_SLOTS
    .filter((slot) => slotPeers[slot])
    .map((slot) => ({
      slot,
      peerUserId: slotPeers[slot],
      phase: (slot === "group-1" ? link1 : link2).state.phase,
      remoteStream: (slot === "group-1" ? link1 : link2).remoteStream,
    }));

  const setGroupMic = useCallback((enabled: boolean) => {
    for (const slot of GROUP_LINK_SLOTS) {
      const engine = linksRef.current[slot];
      if (engine && engine.micEnabled !== enabled && LIVE.includes(engine.state.phase)) engine.toggleMic();
    }
  }, []);
  const setGroupCamera = useCallback((enabled: boolean) => {
    for (const slot of GROUP_LINK_SLOTS) {
      const engine = linksRef.current[slot];
      if (engine && engine.cameraEnabled !== enabled && LIVE.includes(engine.state.phase)) engine.toggleCamera();
    }
  }, []);

  const localStream = link1.localStream ?? link2.localStream;
  const anyGroupLive = GROUP_LINK_SLOTS.some((slot) => LIVE.includes((slot === "group-1" ? link1 : link2).state.phase));

  return {
    primary,
    group: {
      invite: group?.invite ?? null,
      joined: group?.joined ?? false,
      links,
      live: anyGroupLive,
      localStream,
      micEnabled: link1.micEnabled && link2.micEnabled,
      cameraEnabled: link1.cameraEnabled && link2.cameraEnabled,
      startGroupCall,
      joinGroupCall,
      leaveGroupCall,
      setGroupMic,
      setGroupCamera,
    },
  };
}
