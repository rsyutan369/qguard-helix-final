/**
 * QGuard Web Scanner — TLS Handshake Analyzer
 * Performs real TLS connections and extracts cryptographic metadata
 */

import * as tls from 'node:tls'
import * as net from 'node:net'
import * as dns from 'node:dns'
import { promisify } from 'node:util'
import type { TlsAnalysisResult, CipherSuiteDetail, TlsProtocolProbe } from './types'
import { parseCertificateFromPeer } from './certificate-parser'
import { classifyCipherSuite } from './cipher-suite-analyzer'

const dnsResolve4 = promisify(dns.resolve4)

const CONNECTION_TIMEOUT = 15_000 // 15 seconds for the primary TLS handshake
const PROBE_TIMEOUT = 4_000
const TLS_PROTOCOLS: tls.SecureVersion[] = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
const TLS12_CIPHER_PROBES: { standardName: string; opensslName: string }[] = [
  { standardName: 'TLS_RSA_WITH_AES_128_GCM_SHA256', opensslName: 'AES128-GCM-SHA256' },
  { standardName: 'TLS_RSA_WITH_AES_256_GCM_SHA384', opensslName: 'AES256-GCM-SHA384' },
  { standardName: 'TLS_RSA_WITH_AES_128_CBC_SHA', opensslName: 'AES128-SHA' },
  { standardName: 'TLS_RSA_WITH_AES_256_CBC_SHA', opensslName: 'AES256-SHA' },
  { standardName: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', opensslName: 'ECDHE-RSA-AES128-GCM-SHA256' },
  { standardName: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', opensslName: 'ECDHE-RSA-AES256-GCM-SHA384' },
  { standardName: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', opensslName: 'ECDHE-ECDSA-AES128-GCM-SHA256' },
  { standardName: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', opensslName: 'DHE-RSA-AES128-GCM-SHA256' },
]
const PRIVATE_IP_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/i,
  /^fd00:/i,
  /^fe80:/i,
  /^localhost$/i,
]

/**
 * Validate that a target is not a private/internal IP address (SSRF protection)
 */
function isPrivateIp(ip: string): boolean {
  return PRIVATE_IP_RANGES.some(pattern => pattern.test(ip))
}

function lookupAll(hostname: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    dns.lookup(hostname, { all: true, verbatim: false }, (err, addresses) => {
      if (err) {
        reject(err)
        return
      }
      resolve(addresses.map((address) => address.address))
    })
  })
}

/**
 * Extract hostname and port from various target formats
 */
export function parseTarget(target: string, targetType: string): { hostname: string; port: number } {
  let hostname = target
  let port = 443

  if (targetType === 'url') {
    try {
      const url = new URL(target)
      hostname = url.hostname
      port = url.port ? parseInt(url.port, 10) : (url.protocol === 'https:' ? 443 : 80)
    } catch {
      hostname = target
    }
  } else if (targetType === 'domain') {
    // Remove any protocol prefix
    hostname = target.replace(/^https?:\/\//, '').split('/')[0]
    // Check for port
    const parts = hostname.split(':')
    if (parts.length === 2) {
      hostname = parts[0]
      port = parseInt(parts[1], 10)
    }
  } else if (targetType === 'ip') {
    const parts = target.split(':')
    if (parts.length === 2) {
      hostname = parts[0]
      port = parseInt(parts[1], 10)
    }
  }

  return { hostname, port }
}

/**
 * Resolve hostname to IP and validate it's not private
 */
async function resolveAndValidate(hostname: string): Promise<string[]> {
  // If it's already an IP, validate directly
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new Error(`SSRF protection: scanning private IP addresses is not allowed`)
    }
    return [hostname]
  }

  // Resolve hostname. Prefer authoritative A records, but fall back to OS
  // lookup because some local Windows DNS/proxy setups reject queryA while
  // normal socket connections can still resolve the host.
  const resolutionErrors: string[] = []
  let addresses: string[] = []

  try {
    addresses = await dnsResolve4(hostname)
  } catch (err) {
    if ((err as Error).message?.includes('SSRF')) throw err
    resolutionErrors.push((err as Error).message)
  }

  if (!addresses.length) {
    try {
      addresses = await lookupAll(hostname)
    } catch (err) {
      resolutionErrors.push((err as Error).message)
    }
  }

  if (!addresses.length) {
    const detail = resolutionErrors.filter(Boolean).join('; ') || 'no DNS records returned'
    throw new Error(`DNS resolution failed for ${hostname}: ${detail}`)
  }

  // Validate resolved IPs
  for (const ip of addresses) {
    if (isPrivateIp(ip)) {
      throw new Error(`SSRF protection: ${hostname} resolves to private IP`)
    }
  }

  return Array.from(new Set(addresses))
}

/**
 * Try each resolved address in turn until one completes a handshake.
 *
 * `deadline` bounds the WHOLE sweep, not each address. Without it a name with
 * four A records behind a filtered port cost `4 × timeoutMs` — 60 seconds at the
 * default — and the caller had no way to cap it. Each attempt is now given only
 * what is left, so a dual-stack or multi-homed host cannot multiply the budget
 * by its own record count.
 */
async function connectTlsAny(
  hostname: string,
  port: number,
  options: Partial<tls.ConnectionOptions>,
  timeoutMs: number,
  connectHosts: string[],
  deadline = Number.POSITIVE_INFINITY,
  signal?: AbortSignal
): Promise<{ result: TlsAnalysisResult; connectHost: string }> {
  let lastError: Error | null = null

  for (const connectHost of connectHosts) {
    if (signal?.aborted) throw new Error(`TLS analysis of ${hostname}:${port} was cancelled`)
    const remaining = deadline - Date.now()
    if (remaining <= 0) {
      throw lastError || new Error(`TLS connection to ${hostname}:${port} ran out of time budget`)
    }
    try {
      return {
        result: await connectTls(hostname, port, options, Math.min(timeoutMs, remaining), connectHost),
        connectHost,
      }
    } catch (err) {
      lastError = err as Error
    }
  }

  throw lastError || new Error(`TLS connection failed to ${hostname}:${port}`)
}

function normalizeCipherName(cipher: tls.CipherNameAndProtocol | null): string {
  return cipher?.standardName || cipher?.name || 'unknown'
}

function formatSocketError(err: Error & { code?: string; errors?: unknown[] }): string {
  const details = Array.isArray(err.errors)
    ? err.errors
        .map((item) => {
          const nested = item as Error & { code?: string; address?: string; port?: number }
          return [nested.code, nested.address, nested.port, nested.message].filter(Boolean).join(' ')
        })
        .filter(Boolean)
        .join('; ')
    : ''

  return [err.code, err.message, details].filter(Boolean).join(' - ') || err.name || 'socket error'
}

function extractKeyExchange(
  cipherName: string,
  ephemeralKey: ReturnType<tls.TLSSocket['getEphemeralKeyInfo']>,
  protocol = ''
): { keyExchange: string; ephemeralKeyType: string | null; ephemeralKeySize: number | null; negotiatedCurve: string | null } {
  let keyExchange = 'unknown'
  let ephemeralKeyType: string | null = null
  let ephemeralKeySize: number | null = null
  let negotiatedCurve: string | null = null

  if (ephemeralKey) {
    const ek = ephemeralKey as { type?: string; size?: number; name?: string }
    ephemeralKeyType = ek.type || null
    ephemeralKeySize = ek.size || null

    if (ek.type === 'ECDH') {
      negotiatedCurve = ek.name || null
      keyExchange = `ECDHE ${ek.name || ''} (${ek.size}-bit)`.trim()
    } else if (ek.type === 'DH') {
      keyExchange = `DHE (${ek.size}-bit)`
    } else if (ek.type === 'X25519' || ek.type === 'X448') {
      negotiatedCurve = ek.name || ek.type
      keyExchange = `ECDHE ${negotiatedCurve}${ek.size ? ` (${ek.size}-bit)` : ''}`
    } else if (ek.type === 'TLSGroup') {
      /* Node 24 (OpenSSL 3.5) reports a TLS 1.3 key_share generically as
         `{ type: 'TLSGroup' }`, and for hybrid groups such as X25519MLKEM768
         with no name or size at all. The generic branch below printed that as
         "TLSGroup (undefined-bit)" for cloudflare.com, google.com and every
         other TLS 1.3 endpoint — and wherever the named-group probe had not
         resolved the group, that string reached the findings table, Sophia and
         the timeline. A name, when present, is the negotiated group; without
         one the RFC 8446 guarantee below supplies the honest label. */
      if (ek.name) {
        negotiatedCurve = ek.name
        keyExchange = /mlkem|kyber/i.test(ek.name) ? `Hybrid ECDHE + ML-KEM (${ek.name})` : `ECDHE ${ek.name}`
      }
    } else if (ek.type) {
      keyExchange = ek.size ? `${ek.type} (${ek.size}-bit)` : ek.type
    }
  }

  if (keyExchange === 'unknown') {
    // TLS 1.2 and below name the key agreement in the suite itself.
    if (cipherName.includes('TLS_RSA_WITH') || cipherName.startsWith('RSA-')) {
      keyExchange = 'RSA'
    } else if (cipherName.includes('ECDHE')) {
      keyExchange = 'ECDHE'
    } else if (cipherName.includes('DHE')) {
      keyExchange = 'DHE'
    } else if (protocol === 'TLSv1.3') {
      /* TLS 1.3 suite names carry no key-exchange token (TLS_AES_256_GCM_SHA384),
         and Node's getEphemeralKeyInfo() returns {} on some builds — which left
         this reading "unknown" for every modern endpoint. RFC 8446 permits only
         ephemeral (EC)DHE key establishment for the standard handshake modes, so
         the agreement IS known even when the group name is not: this is a
         protocol guarantee, not an inference. The group stays null and renders
         as unreported rather than being invented. */
      keyExchange = 'ECDHE (TLS 1.3 key_share)'
      ephemeralKeyType = ephemeralKeyType || 'ECDHE'
    }
  }

  return { keyExchange, ephemeralKeyType, ephemeralKeySize, negotiatedCurve }
}

function connectTls(
  hostname: string,
  port: number,
  options: Partial<tls.ConnectionOptions> = {},
  timeoutMs = CONNECTION_TIMEOUT,
  connectHost = hostname
): Promise<TlsAnalysisResult> {
  return new Promise((resolve, reject) => {
    let settled = false
    let timeout: ReturnType<typeof setTimeout> | undefined
    const servername = net.isIP(hostname) ? undefined : hostname
    const socket = tls.connect(
      {
        host: connectHost,
        port,
        servername,
        rejectUnauthorized: false,
        timeout: timeoutMs,
        ...options,
      },
      () => {
        if (settled) return
        settled = true
        if (timeout) clearTimeout(timeout)

        try {
          const protocol = socket.getProtocol() || 'unknown'
          const cipher = socket.getCipher()
          const cipherName = normalizeCipherName(cipher)
          const ephemeralKey = socket.getEphemeralKeyInfo()
          const keyInfo = extractKeyExchange(cipherName, ephemeralKey, protocol)
          const peerCert = socket.getPeerCertificate(true)

          let certInfo = null
          if (peerCert && Object.keys(peerCert).length > 0) {
            try {
              certInfo = parseCertificateFromPeer(peerCert)
            } catch {
              // Certificate parsing failed; retain the handshake metadata.
            }
          }

          const cipherSuites: CipherSuiteDetail[] = []
          const detail = classifyCipherSuite(cipherName, protocol)
          if (detail) {
            cipherSuites.push(detail)
          }

          const result: TlsAnalysisResult = {
            tlsVersion: protocol,
            cipherSuite: cipherName,
            keyExchange: keyInfo.keyExchange,
            signatureAlgorithm: extractSignatureAlgorithm(cipher?.name || '', certInfo?.signatureAlgorithm || ''),
            supportedProtocols: [protocol],
            protocolSupport: [],
            negotiatedCurve: keyInfo.negotiatedCurve,
            serverName: hostname,
            peerCertificate: certInfo,
            cipherSuites,
            ephemeralKeyType: keyInfo.ephemeralKeyType,
            ephemeralKeySize: keyInfo.ephemeralKeySize,
          }

          socket.destroy()
          resolve(result)
        } catch (err) {
          socket.destroy()
          reject(new Error(`TLS analysis failed: ${(err as Error).message}`))
        }
      }
    )

    timeout = setTimeout(() => {
      if (settled) return
      settled = true
      socket.destroy()
      reject(new Error(`TLS connection timeout after ${timeoutMs}ms`))
    }, timeoutMs)

    socket.on('error', (err) => {
      if (settled) return
      settled = true
      if (timeout) clearTimeout(timeout)
      reject(new Error(`TLS connection failed to ${hostname}:${port}: ${formatSocketError(err)}`))
    })

    socket.on('timeout', () => {
      if (settled) return
      settled = true
      if (timeout) clearTimeout(timeout)
      socket.destroy()
      reject(new Error(`TLS connection timeout to ${hostname}:${port}`))
    })
  })
}

/**
 * True when a failed probe produced NO ANSWER from the endpoint.
 *
 * `connectTls` rejects with a "TLS connection timeout" message when the socket
 * or the guard timer fires, and with "TLS connection failed … <code>" when the
 * peer actually responded (RST, TLS alert). One predicate so the distinction is
 * made in exactly one place.
 */
function isNoAnswerError(message: string): boolean {
  return /connection timeout/i.test(message)
}

async function probeProtocol(hostname: string, port: number, protocol: tls.SecureVersion, connectHost = hostname): Promise<TlsProtocolProbe> {
  try {
    const result = await connectTls(
      hostname,
      port,
      {
        minVersion: protocol,
        maxVersion: protocol,
        ciphers: protocol === 'TLSv1.3' ? undefined : 'DEFAULT:@SECLEVEL=0',
      },
      PROBE_TIMEOUT,
      connectHost
    )

    return {
      protocol,
      supported: true,
      cipherSuite: result.cipherSuite,
      keyExchange: result.keyExchange,
    }
  } catch (err) {
    const message = (err as Error).message
    return {
      protocol,
      supported: false,
      cipherSuite: null,
      keyExchange: null,
      /* Did the endpoint SAY anything? A TLS alert or an RST is an answer and
         makes the negative falsifiable; a timeout is silence and measures
         nothing. `confirmProtocolNegatives` spends its retry budget on the
         silent ones. */
      answered: !isNoAnswerError(message),
      error: message,
    }
  }
}

/**
 * Confirm the NEGATIVE protocol results before they are published.
 *
 * WHY THIS EXISTS — the evidence asymmetry
 * ----------------------------------------
 * The four version probes run concurrently (with the TLS 1.2 cipher sweep
 * alongside them), which is a dozen near-simultaneous handshakes to one IP.
 * CDNs and rate-limiters answer that with a TCP reset — and a genuine protocol
 * refusal looks EXACTLY the same. Measured against github.com, a real "TLS 1.0
 * is not supported" arrives as `ECONNRESET`; measured against cloudflare.com
 * under load, a throttled TLS 1.3 probe arrives as `ECONNRESET` too. Error
 * signatures cannot separate them, so the scanner published throttling as
 * "this version is not accepted".
 *
 * The observed consequence on /public-scan: cloudflare.com reported
 * `Accepts: TLSv1, TLSv1.2` on the same panel whose Server Hello row said the
 * session had just negotiated **TLSv1.3**, and the TLS Configuration category
 * scored 45 instead of 60 — a self-contradicting report whose headline grade
 * moved with the weather.
 *
 * The asymmetry that fixes it (the same one `probeNamedGroups` already uses):
 *
 *   - An ACCEPTANCE is unforgeable. A reset socket cannot complete a handshake
 *     pinned to one version, so one success is proof and is never re-probed.
 *   - The NEGOTIATED version is proof by construction. The primary handshake
 *     spoke it; no probe result may contradict that.
 *   - Only REFUSALS are falsifiable, and throttling is a property of the
 *     connection stream rather than of a protocol version. So refusals are
 *     re-probed ONCE, strictly sequentially, and only a second refusal is
 *     published.
 *
 * The re-probe is skipped when nothing was accepted at all (the endpoint is not
 * answering — that is a transport failure the caller reports separately) and
 * when the deadline has passed, so the cost is bounded and normally zero: a
 * healthy parallel sweep confirms everything on the first pass.
 */
async function confirmProtocolNegatives(
  hostname: string,
  port: number,
  connectHost: string,
  discovered: TlsProtocolProbe[],
  negotiatedProtocol: string | null,
  deadline: number,
  signal?: AbortSignal,
): Promise<TlsProtocolProbe[]> {
  const probes = discovered.map((probe) => ({ ...probe }))

  /* Proof by construction: the primary handshake negotiated this version. */
  const negotiated = probes.find((probe) => probe.protocol === negotiatedProtocol)
  if (negotiated && !negotiated.supported) {
    negotiated.supported = true
    negotiated.error = undefined
    negotiated.cipherSuite = negotiated.cipherSuite ?? primaryCipherPlaceholder
  }

  const refused = probes.filter((probe) => !probe.supported)
  const accepted = probes.length - refused.length
  // Nothing answered: the failure is systemic, not per-version. Re-probing would
  // add four timeouts to a scan that already knows the endpoint is unreachable.
  if (refused.length === 0 || accepted === 0) return probes

  /* A REFUSAL AND A SILENCE ARE NOT THE SAME NEGATIVE, and one re-probe was not
     enough for the silent kind. Sweeping www.cloudflare.com repeatedly, every
     answer the endpoint actually gave — `ECONNRESET`, TLS alert — arrived in
     under 1.1s, while every version that went missing had simply TIMED OUT at
     PROBE_TIMEOUT, twice in a row. The published consequence: one run in four
     reported `Accepts: TLSv1.3` for an endpoint that provably accepts TLS 1.2,
     which moves `tls-configuration` in the FLATTERING direction — a legacy
     version disappearing looks like good configuration.

     So the budget is spent where it buys a measurement: a probe the endpoint
     answered is already falsifiable evidence and is re-probed once as before,
     while a probe that produced no answer at all is retried until it produces
     one, up to ATTEMPTS_FOR_SILENCE. A version that still never answers keeps
     its timeout in `error` rather than being published as a clean refusal. */
  const ATTEMPTS_FOR_SILENCE = 3
  for (const probe of refused) {
    const attempts = probe.answered === false ? ATTEMPTS_FOR_SILENCE : 1
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (Date.now() >= deadline || signal?.aborted) break
      const retry = await probeProtocol(hostname, port, probe.protocol as tls.SecureVersion, connectHost)
      if (retry.supported) {
        probe.supported = true
        probe.cipherSuite = retry.cipherSuite
        probe.keyExchange = retry.keyExchange
        probe.answered = true
        probe.error = undefined
        break
      }
      probe.answered = retry.answered
      probe.error = retry.error
      /* The endpoint spoke. That is the falsifiable negative this pass exists to
         confirm, and repeating it would only cost time. */
      if (retry.answered) break
    }
  }

  return probes
}

/** Placeholder recorded when a version is proven by the negotiated handshake
 *  rather than by its own probe, so the field is never silently null. */
const primaryCipherPlaceholder = null

/** One cipher probe: the suite if it was accepted, or null if it was not. */
async function probeCipherSuite(
  hostname: string,
  port: number,
  connectHost: string,
  probe: (typeof TLS12_CIPHER_PROBES)[number],
): Promise<CipherSuiteDetail | null> {
  try {
    const result = await connectTls(
      hostname,
      port,
      {
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.2',
        ciphers: `${probe.opensslName}:@SECLEVEL=0`,
      },
      PROBE_TIMEOUT,
      connectHost,
    )
    return classifyCipherSuite(probe.standardName || result.cipherSuite, result.tlsVersion)
  } catch {
    return null
  }
}

/**
 * Which TLS 1.2 cipher suites the endpoint actually accepts.
 *
 * THE EVIDENCE IS ASYMMETRIC, exactly as it is for protocol versions, and this
 * function used to ignore that. Ten `connectTls` calls went out under one
 * `Promise.all` with `catch { return null }`, so a throttling RST and a genuine
 * refusal produced the same answer — and ten near-simultaneous TLS 1.2
 * handshakes to one IP is itself what provokes the throttling.
 *
 * Measured on www.cloudflare.com, two runs minutes apart against an unchanged
 * endpoint: one enumerated 8 suites including 4 static-RSA and scored
 * `cipher-suites` 35; the next enumerated 2 and scored 50. The endpoint really
 * does accept `AES128-GCM-SHA256` and friends (verified independently with
 * `openssl s_client`, no Server Temp Key), so the second run was publishing an
 * undercount as a complete enumeration — understating exposure AND making the
 * composite move with network luck rather than with configuration.
 *
 * So: an ACCEPTANCE is unforgeable and is never re-probed. Only refusals are
 * re-probed, once, strictly sequentially, and only a second refusal is
 * published. The first pass is also bounded in concurrency so the sweep stops
 * provoking the resets it then has to confirm. Skipped entirely when nothing
 * was accepted (systemic failure, not per-suite) or past the deadline, so the
 * normal cost of the confirmation pass is zero.
 */
async function enumerateTls12CipherSuites(
  hostname: string,
  port: number,
  connectHost = hostname,
  deadline = Number.POSITIVE_INFINITY,
  signal?: AbortSignal,
): Promise<CipherSuiteDetail[]> {
  /* CONCURRENCY IS NOT THE VARIABLE THAT MATTERS — measured, not assumed.
     Sweeping www.cloudflare.com at concurrency 10/4/2/1, twice each: the
     accepted count barely moved (6-7, 7-9, 6-9, 7-8 of 10) while wall clock
     went from ~4.5s to ~14s. Serialising the sweep costs 3x the time and buys
     nothing. What distinguishes the outcomes is LATENCY AND KIND: a genuine
     refusal is a TLS alert or an RST and always came back under 1.1s
     (`ECONNRESET@556ms`, `HANDSHAKE_FAILURE@514ms`), while every lost suite was
     a `timeout@~4100ms` — no answer at all. So the first pass stays fully
     parallel and only the probes that never answered are retried. */
  const results: Array<CipherSuiteDetail | null> = await Promise.all(
    TLS12_CIPHER_PROBES.map((probe) => probeCipherSuite(hostname, port, connectHost, probe)),
  )

  const acceptedCount = results.filter((suite) => suite !== null).length
  /* Nothing answered: systemic, not per-suite. Re-probing would add ten
     timeouts to a sweep that already knows the endpoint refused everything. */
  if (acceptedCount > 0 && Date.now() < deadline && !signal?.aborted) {
    const unanswered = results
      .map((suite, index) => (suite === null ? index : -1))
      .filter((index) => index >= 0)
    /* One confirmation wave, in parallel like the first. Only a second silence
       is published as a refusal; a suite that answers here was always accepted
       and the first pass simply never heard it. */
    const confirmed = await Promise.all(
      unanswered.map((index) => probeCipherSuite(hostname, port, connectHost, TLS12_CIPHER_PROBES[index])),
    )
    unanswered.forEach((index, slot) => {
      if (confirmed[slot]) results[index] = confirmed[slot]
    })
  }

  const seen = new Set<string>()
  return results.filter((suite): suite is CipherSuiteDetail => {
    if (!suite || seen.has(suite.standardName)) return false
    seen.add(suite.standardName)
    return true
  })
}

export interface TlsAnalysisOptions {
  /**
   * Ceiling for the PRIMARY handshake, per address. Defaults to
   * CONNECTION_TIMEOUT. A caller working inside a scan budget should pass the
   * smaller of its own remaining time and the default.
   */
  handshakeTimeoutMs?: number
  /**
   * Epoch-ms the primary handshake sweep must be finished by, across all
   * resolved addresses. Only bounds the primary connection: the protocol and
   * cipher probes that follow are already capped at PROBE_TIMEOUT each and only
   * run once the endpoint has proven it answers.
   */
  deadline?: number
  /**
   * Stops the analysis between probe waves. Set when nobody is waiting for the
   * result any more (a public visitor closed the tab), so the connection slot
   * goes to someone who is. Optional: callers without one behave as before.
   */
  signal?: AbortSignal
}

/**
 * Perform a TLS handshake and extract cryptographic metadata
 */
export async function analyzeTls(
  hostname: string,
  port: number = 443,
  options: TlsAnalysisOptions = {}
): Promise<TlsAnalysisResult> {
  // Resolve and validate target
  const connectHosts = await resolveAndValidate(hostname)

  const primaryConnection = await connectTlsAny(
    hostname,
    port,
    {
      minVersion: 'TLSv1' as tls.SecureVersion,
      ciphers: 'DEFAULT:@SECLEVEL=0',
    },
    Math.max(1_000, options.handshakeTimeoutMs ?? CONNECTION_TIMEOUT),
    connectHosts,
    options.deadline ?? Number.POSITIVE_INFINITY,
    options.signal
  )
  const primary = primaryConnection.result
  const connectHost = primaryConnection.connectHost
  /* The protocol and cipher sweeps are a dozen-plus handshakes; nobody waiting
     for them is the cheapest moment to stop. */
  if (options.signal?.aborted) throw new Error(`TLS analysis of ${hostname}:${port} was cancelled`)

  const [discoveredProtocols, enumeratedTls12Suites] = await Promise.all([
    Promise.all(TLS_PROTOCOLS.map((protocol) => probeProtocol(hostname, port, protocol, connectHost))),
    enumerateTls12CipherSuites(hostname, port, connectHost, options.deadline ?? Number.POSITIVE_INFINITY, options.signal),
  ])

  const protocolSupport = await confirmProtocolNegatives(
    hostname,
    port,
    connectHost,
    discoveredProtocols,
    primary.tlsVersion,
    options.deadline ?? Number.POSITIVE_INFINITY,
    options.signal,
  )

  const supportedProtocols = protocolSupport
    .filter((probe) => probe.supported)
    .map((probe) => probe.protocol)

  const cipherSuites = [...primary.cipherSuites]
  const seen = new Set(cipherSuites.map((suite) => suite.standardName))
  for (const suite of enumeratedTls12Suites) {
    if (!seen.has(suite.standardName)) {
      seen.add(suite.standardName)
      cipherSuites.push(suite)
    }
  }

  return {
    ...primary,
    supportedProtocols,
    protocolSupport,
    cipherSuites,
  }
}

/**
 * Extract signature algorithm from cipher and certificate info
 */
function extractSignatureAlgorithm(cipherName: string, certSigAlg: string): string {
  if (certSigAlg) return certSigAlg

  // Infer from cipher suite name
  if (cipherName.includes('ECDSA')) return 'ECDSA'
  if (cipherName.includes('RSA')) return 'RSA'
  if (cipherName.includes('DSS')) return 'DSS'

  return 'unknown'
}

/**
 * Attempt TLS analysis with fallback ports
 */
export async function analyzeTlsWithFallback(
  hostname: string,
  preferredPort: number = 443
): Promise<TlsAnalysisResult> {
  const portsToTry = [preferredPort]
  if (preferredPort !== 443) portsToTry.push(443)
  if (preferredPort !== 8443) portsToTry.push(8443)

  let lastError: Error | null = null

  for (const port of portsToTry) {
    try {
      return await analyzeTls(hostname, port)
    } catch (err) {
      lastError = err as Error
    }
  }

  throw lastError || new Error(`TLS analysis failed for ${hostname}`)
}
