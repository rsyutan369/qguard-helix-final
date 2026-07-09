import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { IncomingCallModal } from "@/components/call/IncomingCallModal";
import { InCallOverlay } from "@/components/call/InCallOverlay";
import { supabase } from "@/lib/supabase";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";
import { useSecureCall, type CallPeer } from "@/lib/use-secure-call";

type CallEngine = ReturnType<typeof useSecureCall>;

interface CallContextValue extends Omit<CallEngine, "startCall"> {
  startCall: (peer: CallPeer, conversationId: string) => Promise<void>;
  peerName: string;
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

  const call = useSecureCall({ userId, deviceId });
  const [peerName, setPeerName] = useState("Secure contact");

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

  const value = useMemo<CallContextValue>(() => ({ ...call, startCall, peerName }), [call, peerName, startCall]);

  return (
    <CallContext.Provider value={value}>
      {children}
      {call.state.phase === "ringing" && call.state.role === "callee" && (
        <IncomingCallModal callerName={peerName} callerUserId={call.state.peerUserId ?? null} onAccept={() => void call.accept()} onReject={() => call.reject()} />
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
          onHangup={() => call.hangup()}
          onToggleMic={() => call.toggleMic()}
          onToggleCamera={() => call.toggleCamera()}
        />
      )}
    </CallContext.Provider>
  );
}
