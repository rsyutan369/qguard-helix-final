import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { CallFailureNotice } from "@/components/call/CallFailureNotice";
import { IncomingCallModal } from "@/components/call/IncomingCallModal";
import { InCallOverlay } from "@/components/call/InCallOverlay";
import { GroupCallOverlay, IncomingGroupCallModal } from "@/components/call/GroupCallOverlay";
import { useCallEngines } from "@/lib/use-group-call";
import { setCallActive } from "@/lib/call-activity";
import { fetchContactAssurance, type ContactAssurance } from "@/lib/contact-verification";
import { supabase } from "@/lib/supabase";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";
import { useSecureCall, type CallPeer } from "@/lib/use-secure-call";

type CallEngine = ReturnType<typeof useSecureCall>;

interface CallContextValue extends Omit<CallEngine, "startCall"> {
  startCall: (peer: CallPeer, conversationId: string) => Promise<void>;
  peerName: string;
  /** Group calls (roadmap 7.2): a mesh of one-to-one links, up to 3 people. */
  startGroupCall: (conversationId: string, peers: CallPeer[]) => Promise<void>;
  groupCallActive: boolean;
}

const CallContext = createContext<CallContextValue | null>(null);

export function useCall(): CallContextValue {
  const value = useContext(CallContext);
  if (!value) throw new Error("useCall must be used inside CallProvider");
  return value;
}

/** Flash the taskbar / bring attention to the window for an incoming call. */
async function requestWindowAttention(): Promise<void> {
  if (!isTauriRuntime()) return;
  try {
    const { getCurrentWindow, UserAttentionType } = await import("@tauri-apps/api/window");
    await getCurrentWindow().requestUserAttention(UserAttentionType.Critical);
  } catch {
    // Attention flash is best-effort decoration; never let it affect the call.
  }
}

/**
 * App-level quantum-encrypted call host. Mounts the signal subscription and
 * the incoming/in-call overlays ABOVE the router and the workspace lock, so an
 * incoming video call rings no matter which page is open (the historical bug:
 * calls only rang while Secure Chat itself was mounted). Message content stays
 * behind the workspace lock — answering a call never unlocks chat history.
 */
export function CallProvider({ userId, children }: { userId: string; children: ReactNode }) {
  // The local device id comes from the Rust identity state. Retried because a
  // first run generates ML-KEM/ML-DSA key material, which can take a moment.
  const [deviceId, setDeviceId] = useState("");
  useEffect(() => {
    if (!userId || !isTauriRuntime()) return undefined;
    let cancelled = false;
    (async () => {
      for (let attempt = 0; attempt < 6 && !cancelled; attempt += 1) {
        const bundle = await safeInvoke<{ device_id?: string } | null>("keys_upload_identity_bundle", { userId }, null);
        if (cancelled) return;
        if (bundle?.device_id) { setDeviceId(bundle.device_id); return; }
        await new Promise((resolve) => window.setTimeout(resolve, 1_500));
      }
    })();
    return () => { cancelled = true; };
  }, [userId]);

  const engines = useCallEngines(userId, deviceId);
  const call = engines.primary;
  const groupCall = engines.group;
  // Names for everyone in a group call (resolved from profiles, like a caller's).
  const [groupNames, setGroupNames] = useState<Record<string, string>>({});
  const groupMembersKey = groupCall.invite ? groupCall.invite.members.join(",") : "";
  useEffect(() => {
    if (!groupMembersKey) return undefined;
    let cancelled = false;
    void supabase.from("profiles").select("id,name,username").in("id", groupMembersKey.split(",")).then(({ data }) => {
      if (cancelled || !data) return;
      setGroupNames(Object.fromEntries((data as Array<{ id: string; name: string | null; username: string | null }>)
        .map((row) => [row.id, row.name?.trim() || (row.username ? `@${row.username}` : "Group member")])));
    });
    if (!groupCall.joined) void requestWindowAttention();
    return () => { cancelled = true; };
  }, [groupMembersKey, groupCall.joined]);
  const [peerName, setPeerName] = useState("Secure contact");
  // What this device's own record holds for the ringing device id: shown
  // before answering. Null until the core answers (or outside the app).
  const [incomingAssurance, setIncomingAssurance] = useState<ContactAssurance | null>(null);
  useEffect(() => {
    setIncomingAssurance(null);
    if (call.state.phase !== "ringing" || call.state.role !== "callee" || !call.state.peerUserId || !call.state.peerDeviceId) return undefined;
    let cancelled = false;
    fetchContactAssurance(call.state.peerUserId, call.state.peerDeviceId)
      .then((assurance) => { if (!cancelled) setIncomingAssurance(assurance); })
      .catch(() => { if (!cancelled) setIncomingAssurance(null); });
    return () => { cancelled = true; };
  }, [call.state.phase, call.state.role, call.state.peerUserId, call.state.peerDeviceId]);

  // Hold the app-lock open for the lifetime of a call. Without this the Android
  // PIN gate fires on the first `visibilitystate: hidden` -- a screen dim, a
  // volume overlay, a notification shade -- and tears down the live call.
  // Cleared on unmount so a crashed/closed provider can never wedge it open.
  const callLive = ["ringing", "calling", "connecting", "connected"].includes(call.state.phase) || groupCall.live || Boolean(groupCall.invite);
  useEffect(() => {
    setCallActive(callLive);
    return () => setCallActive(false);
  }, [callLive]);

  // Incoming ring: resolve the caller's display name and flash the taskbar.
  useEffect(() => {
    if (call.state.phase !== "ringing" || call.state.role !== "callee" || !call.state.peerUserId) return undefined;
    let cancelled = false;
    void supabase
      .from("profiles")
      .select("name,username,email")
      .eq("id", call.state.peerUserId)
      .maybeSingle()
      .then(({ data }) => {
        if (cancelled || !data) return;
        setPeerName(String(data.name || data.username || data.email || "Secure contact"));
      });
    void requestWindowAttention();
    return () => { cancelled = true; };
  }, [call.state.phase, call.state.role, call.state.peerUserId]);

  const startCall = useCallback(async (peer: CallPeer, conversationId: string) => {
    setPeerName(peer.displayName || "Secure contact");
    await call.startCall(peer, conversationId);
  }, [call.startCall]); // eslint-disable-line react-hooks/exhaustive-deps

  // A call that fails leaves `phase: "ended"` with a reason attached, but the
  // in-call overlay is already gone by then -- so the reason needs its own
  // surface or it is simply lost. Keyed on the call id so a repeat failure of a
  // NEW call re-shows the notice after the user dismissed the previous one.
  const [dismissedErrorCallId, setDismissedErrorCallId] = useState<string | null>(null);
  const failure = call.state.phase === "ended"
    && call.state.error
    && call.state.callId !== dismissedErrorCallId
    ? call.state.error
    : null;
  const failedCallId = call.state.callId;
  const dismissFailure = useCallback(() => setDismissedErrorCallId(failedCallId), [failedCallId]);

  const value = useMemo<CallContextValue>(() => ({
    ...call,
    startCall,
    peerName,
    startGroupCall: groupCall.startGroupCall,
    groupCallActive: Boolean(groupCall.invite),
  }), [call, groupCall.invite, groupCall.startGroupCall, peerName, startCall]);

  return (
    <CallContext.Provider value={value}>
      {children}
      {call.state.phase === "ringing" && call.state.role === "callee" && (
        <IncomingCallModal
          callerName={peerName}
          callerUserId={call.state.peerUserId ?? null}
          assurance={incomingAssurance}
          onAccept={() => void call.accept()}
          onReject={() => call.reject()}
        />
      )}
      {["calling", "connecting", "connected"].includes(call.state.phase) && (
        <InCallOverlay
          state={call.state}
          localStream={call.localStream}
          remoteStream={call.remoteStream}
          micEnabled={call.micEnabled}
          cameraEnabled={call.cameraEnabled}
          reconnecting={call.reconnecting}
          peerName={peerName}
          peerUserId={call.state.peerUserId ?? null}
          quality={call.quality}
          onSetQuality={(q) => void call.setQuality(q)}
          stats={call.stats}
          onHangup={() => call.hangup()}
          onToggleMic={() => call.toggleMic()}
          onToggleCamera={() => call.toggleCamera()}
          screenShare={call.screenShareSupported
            ? { active: call.screenSharing, start: call.startScreenShare, stop: call.stopScreenShare }
            : undefined}
        />
      )}
      {groupCall.invite && !groupCall.joined && (
        <IncomingGroupCallModal
          inviterName={groupNames[groupCall.invite.inviterUserId] ?? "Someone"}
          otherNames={groupCall.invite.members
            .filter((member) => member !== userId && member !== groupCall.invite!.inviterUserId)
            .map((member) => groupNames[member] ?? "a group member")}
          onJoin={() => void groupCall.joinGroupCall(groupNames)}
          onDecline={() => groupCall.leaveGroupCall()}
        />
      )}
      {groupCall.invite && groupCall.joined && (
        <GroupCallOverlay
          links={groupCall.links}
          localStream={groupCall.localStream}
          names={groupNames}
          micEnabled={groupCall.micEnabled}
          cameraEnabled={groupCall.cameraEnabled}
          onToggleMic={() => groupCall.setGroupMic(!groupCall.micEnabled)}
          onToggleCamera={() => groupCall.setGroupCamera(!groupCall.cameraEnabled)}
          onLeave={() => groupCall.leaveGroupCall()}
        />
      )}
      {failure && <CallFailureNotice message={failure} onDismiss={dismissFailure} />}
    </CallContext.Provider>
  );
}
