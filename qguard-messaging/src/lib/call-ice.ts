const DEFAULT_STUN = [
  "stun:stun.l.google.com:19302",
  "stun:stun1.l.google.com:19302",
];

export function buildRtcConfiguration(): RTCConfiguration {
  const iceServers: RTCIceServer[] = [{ urls: DEFAULT_STUN }];
  const turnUrl = import.meta.env.VITE_TURN_URL as string | undefined;
  if (turnUrl) {
    iceServers.push({
      urls: turnUrl,
      username: (import.meta.env.VITE_TURN_USERNAME as string | undefined) ?? "",
      credential: (import.meta.env.VITE_TURN_CREDENTIAL as string | undefined) ?? "",
    });
  }
  return { iceServers, iceTransportPolicy: "all", bundlePolicy: "max-bundle" };
}