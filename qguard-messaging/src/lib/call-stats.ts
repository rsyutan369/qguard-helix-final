// Live call diagnostics. Samples RTCPeerConnection.getStats() every 2s while a
// call is connected and reduces the report to one structured snapshot: media
// route (direct vs TURN relay), negotiated codec, encode/decode resolution +
// framerate, live bitrates, RTT, jitter, packet loss, and — critically — the
// encoder's qualityLimitationReason ("cpu" | "bandwidth"), which names the
// exact cause whenever the picture degrades. Every sample is also logged as a
// structured console line so a degraded call can be diagnosed after the fact
// from DevTools / adb logcat without reproducing it.

export interface CallStatsSample {
  /** Milliseconds since the monitor started. */
  atMs: number;
  /** "direct" (host/srflx/prflx pair) or "relay" (TURN) or null while unknown. */
  route: "direct" | "relay" | null;
  localCandidateType: string | null;
  remoteCandidateType: string | null;
  /** Current selected-pair round trip time, milliseconds. */
  rttMs: number | null;
  /** Sender-side bandwidth estimate, bits per second. */
  availableOutgoingBitrate: number | null;
  videoCodec: string | null;
  /** Outbound (what WE encode/send). */
  outWidth: number | null;
  outHeight: number | null;
  outFps: number | null;
  outBitrate: number | null;
  /** Why the encoder is limiting quality: "none" | "cpu" | "bandwidth" | "other". */
  qualityLimitationReason: string | null;
  /** Inbound (what we receive/decode from the peer). */
  inWidth: number | null;
  inHeight: number | null;
  inFps: number | null;
  inBitrate: number | null;
  inPacketsLost: number | null;
  inJitterMs: number | null;
  inFramesDropped: number | null;
  audioInJitterMs: number | null;
  audioInPacketsLost: number | null;
  audioOutBitrate: number | null;
}

/** The subset of RTCStats fields the summarizer reads (structural typing). */
type StatsEntry = Record<string, unknown>;

function num(entry: StatsEntry, key: string): number | null {
  const value = entry[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function str(entry: StatsEntry, key: string): string | null {
  const value = entry[key];
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** bytes delta between samples → bits per second. */
function bitrate(bytesNow: number | null, bytesPrev: number | null, elapsedMs: number): number | null {
  if (bytesNow === null || bytesPrev === null || elapsedMs <= 0) return null;
  const delta = bytesNow - bytesPrev;
  if (delta < 0) return null;
  return Math.round((delta * 8 * 1000) / elapsedMs);
}

export interface PreviousCounters {
  atMs: number;
  videoOutBytes: number | null;
  videoInBytes: number | null;
  audioOutBytes: number | null;
}

/**
 * Pure reduction of a getStats() report (as an entry array) to one sample.
 * Exported for unit tests; the monitor below feeds it live reports.
 */
export function summarizeCallStats(
  entries: StatsEntry[],
  atMs: number,
  prev: PreviousCounters | null,
): { sample: CallStatsSample; counters: PreviousCounters } {
  const sample: CallStatsSample = {
    atMs,
    route: null, localCandidateType: null, remoteCandidateType: null,
    rttMs: null, availableOutgoingBitrate: null,
    videoCodec: null,
    outWidth: null, outHeight: null, outFps: null, outBitrate: null,
    qualityLimitationReason: null,
    inWidth: null, inHeight: null, inFps: null, inBitrate: null,
    inPacketsLost: null, inJitterMs: null, inFramesDropped: null,
    audioInJitterMs: null, audioInPacketsLost: null, audioOutBitrate: null,
  };
  const counters: PreviousCounters = { atMs, videoOutBytes: null, videoInBytes: null, audioOutBytes: null };
  const byId = new Map<string, StatsEntry>();
  for (const entry of entries) {
    const id = str(entry, "id");
    if (id) byId.set(id, entry);
  }

  let selectedPair: StatsEntry | null = null;
  for (const entry of entries) {
    const type = str(entry, "type");
    if (type === "transport") {
      const pairId = str(entry, "selectedCandidatePairId");
      if (pairId && byId.has(pairId)) selectedPair = byId.get(pairId) ?? null;
    }
    // Fallback for engines that expose `selected` on the pair itself.
    if (type === "candidate-pair" && entry.selected === true && !selectedPair) selectedPair = entry;
  }
  if (!selectedPair) {
    // Last resort: the only succeeded+nominated pair.
    for (const entry of entries) {
      if (str(entry, "type") === "candidate-pair" && str(entry, "state") === "succeeded" && entry.nominated === true) {
        selectedPair = entry;
        break;
      }
    }
  }
  if (selectedPair) {
    const rtt = num(selectedPair, "currentRoundTripTime");
    sample.rttMs = rtt === null ? null : Math.round(rtt * 1000);
    sample.availableOutgoingBitrate = num(selectedPair, "availableOutgoingBitrate");
    const local = byId.get(str(selectedPair, "localCandidateId") ?? "");
    const remote = byId.get(str(selectedPair, "remoteCandidateId") ?? "");
    sample.localCandidateType = local ? str(local, "candidateType") : null;
    sample.remoteCandidateType = remote ? str(remote, "candidateType") : null;
    if (sample.localCandidateType || sample.remoteCandidateType) {
      sample.route =
        sample.localCandidateType === "relay" || sample.remoteCandidateType === "relay" ? "relay" : "direct";
    }
  }

  const elapsed = prev ? atMs - prev.atMs : 0;
  for (const entry of entries) {
    const type = str(entry, "type");
    const kind = str(entry, "kind") ?? str(entry, "mediaType");
    if (type === "outbound-rtp" && kind === "video") {
      sample.outWidth = num(entry, "frameWidth");
      sample.outHeight = num(entry, "frameHeight");
      sample.outFps = num(entry, "framesPerSecond");
      sample.qualityLimitationReason = str(entry, "qualityLimitationReason");
      counters.videoOutBytes = num(entry, "bytesSent");
      sample.outBitrate = bitrate(counters.videoOutBytes, prev?.videoOutBytes ?? null, elapsed);
      const codecEntry = byId.get(str(entry, "codecId") ?? "");
      if (codecEntry) sample.videoCodec = str(codecEntry, "mimeType");
    } else if (type === "inbound-rtp" && kind === "video") {
      sample.inWidth = num(entry, "frameWidth");
      sample.inHeight = num(entry, "frameHeight");
      sample.inFps = num(entry, "framesPerSecond");
      sample.inPacketsLost = num(entry, "packetsLost");
      const jitter = num(entry, "jitter");
      sample.inJitterMs = jitter === null ? null : Math.round(jitter * 1000);
      sample.inFramesDropped = num(entry, "framesDropped");
      counters.videoInBytes = num(entry, "bytesReceived");
      sample.inBitrate = bitrate(counters.videoInBytes, prev?.videoInBytes ?? null, elapsed);
      if (!sample.videoCodec) {
        const codecEntry = byId.get(str(entry, "codecId") ?? "");
        if (codecEntry) sample.videoCodec = str(codecEntry, "mimeType");
      }
    } else if (type === "inbound-rtp" && kind === "audio") {
      const jitter = num(entry, "jitter");
      sample.audioInJitterMs = jitter === null ? null : Math.round(jitter * 1000);
      sample.audioInPacketsLost = num(entry, "packetsLost");
    } else if (type === "outbound-rtp" && kind === "audio") {
      counters.audioOutBytes = num(entry, "bytesSent");
      sample.audioOutBitrate = bitrate(counters.audioOutBytes, prev?.audioOutBytes ?? null, elapsed);
    }
  }

  return { sample, counters };
}

const SAMPLE_INTERVAL_MS = 2_000;

/**
 * Start sampling a live peer connection. Returns a stop function; the monitor
 * also stops itself if the connection closes. Each sample is delivered to
 * `onSample` (for the in-call diagnostics UI) and logged to the console.
 */
export function startCallStatsMonitor(
  pc: RTCPeerConnection,
  onSample: (sample: CallStatsSample) => void,
): () => void {
  const startedAt = Date.now();
  let prev: PreviousCounters | null = null;
  let stopped = false;

  const tick = async () => {
    if (stopped || pc.connectionState === "closed") return;
    try {
      const report = await pc.getStats();
      const entries: StatsEntry[] = [];
      report.forEach((entry) => entries.push(entry as unknown as StatsEntry));
      const { sample, counters } = summarizeCallStats(entries, Date.now() - startedAt, prev);
      prev = counters;
      if (stopped) return;
      onSample(sample);
      // One structured line per sample — greppable in DevTools / adb logcat.
      console.info(
        `[call-stats] route=${sample.route ?? "?"} (${sample.localCandidateType ?? "?"}→${sample.remoteCandidateType ?? "?"})`
        + ` rtt=${sample.rttMs ?? "?"}ms codec=${sample.videoCodec ?? "?"}`
        + ` out=${sample.outWidth ?? "?"}x${sample.outHeight ?? "?"}@${sample.outFps ?? "?"}fps/${sample.outBitrate ?? "?"}bps`
        + ` limit=${sample.qualityLimitationReason ?? "?"}`
        + ` in=${sample.inWidth ?? "?"}x${sample.inHeight ?? "?"}@${sample.inFps ?? "?"}fps/${sample.inBitrate ?? "?"}bps`
        + ` loss=${sample.inPacketsLost ?? "?"} jitter=${sample.inJitterMs ?? "?"}ms`
        + ` bwe=${sample.availableOutgoingBitrate ?? "?"}bps`,
      );
    } catch {
      // getStats can reject during teardown; the next tick (if any) retries.
    }
  };

  const timer = window.setInterval(() => { void tick(); }, SAMPLE_INTERVAL_MS);
  void tick();
  return () => {
    stopped = true;
    window.clearInterval(timer);
  };
}
