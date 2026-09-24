import type { SecurityHardeningCheck, SecurityHardeningStatus, TlsPolicy } from "@/lib/types";

/**
 * Transport evidence: what the connection to the backend ACTUALLY negotiated.
 *
 * Every byte this app sends to Supabase rides the WebView's own TLS stack. The
 * app can configure that stack on Windows (WebView2 switches, see
 * `security::tls_policy` in the Rust core) but not on Android, where the system
 * WebView owns it. Until now the Transport Policy check therefore reported the
 * CONFIGURATION only: "enforced" on Windows because a flag was passed, and a
 * permanent warning on Android because no flag could be. Neither was evidence
 * about the wire. A WebView2 runtime can silently ignore an unknown
 * `--enable-features` name, and an Android WebView that negotiates TLS 1.3 with
 * X25519MLKEM768 on every request still read as a failed control — the one
 * check holding a fully working phone at "8/9 · Review coverage".
 *
 * The backend edge answers `/cdn-cgi/trace` with the parameters of the very
 * connection the request arrived on (`tls=TLSv1.3`, `kex=X25519MLKEM768`).
 * Fetching it through the WebView measures the WebView's own negotiation with
 * the host every other request uses, which turns the check from "what we asked
 * for" into "what the server saw". The response travels inside that same TLS
 * session, so a network attacker cannot rewrite it without breaking TLS.
 *
 * Privacy: the trace also echoes the caller's public IP and location. Only the
 * transport fields are read; the rest is discarded here and never stored, sent
 * or logged.
 */

export type KeyAgreementClass = "hybrid-pq" | "pq" | "pre-standard-pq" | "classical";

export interface TransportMeasurement {
  /** Backend host the measurement was taken against. */
  host: string;
  /** Negotiated protocol version as reported by the edge, e.g. "TLSv1.3". */
  tls: string;
  /** Negotiated key-agreement group, e.g. "X25519MLKEM768". */
  kex: string;
  /** Application protocol of the measured connection, e.g. "http/2". */
  http: string | null;
  keyAgreement: KeyAgreementClass;
  measuredAt: string;
}

export const TRANSPORT_CHECK_ID = "tls_transport_policy";
const TRANSPORT_CHECK_LABEL = "Transport Policy (TLS 1.3 + hybrid PQ)";
const PROBE_PATH = "/cdn-cgi/trace";
const PROBE_TIMEOUT_MS = 6_000;

/**
 * Hybrid = a classical group combined with ML-KEM (FIPS 203), the approved
 * hybrid the check label promises (X25519 + ML-KEM). A pure ML-KEM group is
 * still quantum-safe and is reported separately rather than folded in.
 *
 * The Kyber draft groups (`X25519Kyber768Draft00`) predate FIPS 203 and are
 * NOT ML-KEM — the wire formats differ, and browsers dropped the draft when
 * they adopted the standard. It gets its own class so it can never be reported
 * as the approved standard: this codebase has already shipped one defect of
 * exactly that kind (a Kyber implementation labelled ML-KEM).
 */
export function classifyKeyAgreement(kex: string): KeyAgreementClass {
  const value = kex.trim();
  if (/ml-?kem/i.test(value)) {
    return /x25519|x448|secp|p-?256|p-?384|p-?521/i.test(value) ? "hybrid-pq" : "pq";
  }
  return /kyber/i.test(value) ? "pre-standard-pq" : "classical";
}

function isTls13(tls: string): boolean {
  return /^tlsv?1\.3$/i.test(tls.trim());
}

/** "TLSv1.3" (the edge's spelling) -> "TLS 1.3" for user-facing text. */
function formatTlsVersion(tls: string): string {
  const match = /^tlsv?\s*(\d)\.(\d)$/i.exec(tls.trim());
  return match ? `TLS ${match[1]}.${match[2]}` : tls;
}

function describeGroup(measurement: TransportMeasurement): string {
  if (measurement.keyAgreement === "hybrid-pq") return `${measurement.kex} (hybrid post-quantum key agreement)`;
  if (measurement.keyAgreement === "pq") return `${measurement.kex} (post-quantum key agreement)`;
  if (measurement.keyAgreement === "pre-standard-pq") return `${measurement.kex} (the pre-standard Kyber draft, not ML-KEM)`;
  return `${measurement.kex} (classical key agreement)`;
}

/** Parse a `/cdn-cgi/trace` body. Null unless both tls= and kex= are present. */
export function parseEdgeTrace(
  body: string,
  host: string,
  measuredAt: string = new Date().toISOString(),
): TransportMeasurement | null {
  const fields = new Map<string, string>();
  for (const line of body.split(/\r?\n/)) {
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim();
    // Allow-list: nothing outside the transport parameters is ever kept.
    if (key === "tls" || key === "kex" || key === "http") {
      fields.set(key, line.slice(separator + 1).trim());
    }
  }
  const tls = fields.get("tls");
  const kex = fields.get("kex");
  if (!tls || !kex) return null;
  return {
    host,
    tls,
    kex,
    http: fields.get("http") || null,
    keyAgreement: classifyKeyAgreement(kex),
    measuredAt,
  };
}

/**
 * Measure the negotiated transport to `baseUrl`. Returns null — never a guess —
 * when the probe cannot complete (offline, blocked, or a host whose edge does
 * not publish a trace).
 */
export async function measureTransport(
  baseUrl: string | undefined,
  fetchImpl: typeof fetch = fetch,
): Promise<TransportMeasurement | null> {
  let origin: URL;
  try {
    origin = new URL(String(baseUrl ?? ""));
  } catch {
    return null;
  }
  if (origin.protocol !== "https:") return null;

  const controller = typeof AbortController === "function" ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS) : undefined;
  try {
    const response = await fetchImpl(`${origin.origin}${PROBE_PATH}`, {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      signal: controller?.signal,
    });
    if (!response.ok) return null;
    return parseEdgeTrace(await response.text(), origin.host);
  } catch {
    return null;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function transportCheck(active: boolean, detail: string): SecurityHardeningCheck {
  return {
    id: TRANSPORT_CHECK_ID,
    label: TRANSPORT_CHECK_LABEL,
    status: active ? "active" : "warning",
    active,
    detail,
  };
}

const E2EE_NOTE = "Message, call and vault payloads stay end-to-end encrypted with ML-KEM regardless of the transport.";

/**
 * The Transport Policy check, decided from the configured policy AND the live
 * measurement.
 *
 * - A measurement always wins over configuration when it contradicts it: a
 *   WebView2 runtime that ignored the post-quantum request fails the check even
 *   though the flag was set.
 * - Android passes only on a measurement. The detail says it was verified, not
 *   pinned, because the app has no way to pin it there.
 * - Windows compat mode stays a warning: it is a deliberate, named policy
 *   downgrade, and one PQ connection does not undo a policy that permits TLS 1.2.
 * - No measurement falls back to the configuration alone, exactly as before.
 */
export function transportPolicyCheck(
  policy: TlsPolicy,
  measurement: TransportMeasurement | null,
): SecurityHardeningCheck {
  const enforced = policy.enforced_by_app;
  const strict = policy.mode === "strict";

  if (!measurement) {
    if (enforced && strict) {
      return transportCheck(true, `${policy.detail} Live verification of the negotiated parameters is unavailable right now.`);
    }
    return transportCheck(false, `${policy.detail} The negotiated parameters could not be measured right now, so they are not verified.`);
  }

  const observed = `${measurement.host} negotiated ${formatTlsVersion(measurement.tls)} with ${describeGroup(measurement)}`;
  // Only ML-KEM (FIPS 203) groups count: the approved hybrid is X25519 + ML-KEM.
  const quantumSafe = isTls13(measurement.tls)
    && (measurement.keyAgreement === "hybrid-pq" || measurement.keyAgreement === "pq");

  if (enforced && !strict) {
    return transportCheck(
      false,
      `Compat policy (QGUARD_TLS_POLICY=compat) permits TLS 1.2 on this device. The current connection to ${observed}.`,
    );
  }

  if (quantumSafe) {
    return transportCheck(
      true,
      enforced
        ? `Enforced and verified: the app pins TLS 1.3 and requests hybrid post-quantum key agreement, and the live connection to ${observed}.`
        : `Verified on the live connection: ${observed}. The system WebView owns the TLS stack on this OS, so the app measures the negotiated parameters on every refresh instead of pinning them.`,
    );
  }

  if (!isTls13(measurement.tls)) {
    return transportCheck(
      false,
      `The live connection to ${observed}, below the TLS 1.3 minimum. A TLS-inspecting proxy or an outdated WebView is the usual cause. ${E2EE_NOTE}`,
    );
  }

  if (measurement.keyAgreement === "pre-standard-pq") {
    return transportCheck(
      false,
      enforced
        ? `TLS 1.3 is enforced, but the live connection to ${observed}: this WebView2 runtime predates ML-KEM (FIPS 203). Update the Microsoft Edge WebView2 Runtime to negotiate X25519MLKEM768. ${E2EE_NOTE}`
        : `The live connection to ${observed}. That group predates ML-KEM (FIPS 203) and has been retired by current browsers; update Android System WebView from Google Play to negotiate X25519MLKEM768. ${E2EE_NOTE}`,
    );
  }

  return transportCheck(
    false,
    enforced
      ? `TLS 1.3 is enforced, but the live connection to ${observed}: this WebView2 runtime did not use the requested hybrid post-quantum group. Update the Microsoft Edge WebView2 Runtime. ${E2EE_NOTE}`
      : `The live connection to ${observed}. Android's system WebView chooses the key agreement; update Android System WebView from Google Play to get X25519MLKEM768. ${E2EE_NOTE}`,
  );
}

/**
 * Replace the Rust-reported transport check with the evidence-based one, in
 * place. Pure: the input status (cached by the loader) is not mutated.
 */
export function mergeTransportEvidence(
  hardening: SecurityHardeningStatus,
  measurement: TransportMeasurement | null,
): SecurityHardeningStatus {
  if (!hardening.checks.some((check) => check.id === TRANSPORT_CHECK_ID)) return hardening;
  const replacement = transportPolicyCheck(hardening.tls_policy, measurement);
  return {
    ...hardening,
    checks: hardening.checks.map((check) => (check.id === TRANSPORT_CHECK_ID ? replacement : check)),
  };
}
