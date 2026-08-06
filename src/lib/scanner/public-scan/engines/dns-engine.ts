/**
 * QGuard Helix — DNS Intelligence Engine
 *
 * Resolves the complete publicly observable DNS surface: A, AAAA, CNAME, MX,
 * TXT, NS, SOA, CAA, DNSSEC, SPF, DKIM and DMARC.
 *
 * TRANSPORT RESILIENCE
 * --------------------
 * The system stub resolver answers `lookup()` on virtually every network, but
 * record-type queries (`resolveCaa`, `resolveTxt`, …) go out on UDP/53, which a
 * large share of corporate networks, hotel Wi-Fi and consumer ISPs refuse
 * outright. Relying on it alone makes CAA/SPF/DMARC report "Unknown" for
 * reasons that have nothing to do with the target's posture.
 *
 * This engine therefore queries DNS-over-HTTPS (RFC 8484 / JSON) on port 443 as
 * a first-class transport, falling back across two independent resolvers before
 * it will report Unknown. DoH also returns the AD bit, which is how DNSSEC
 * validation status is determined.
 */

import { promises as dnsPromises, setServers } from 'node:dns'
import net from 'node:net'
import {
  type Evidence,
  type EngineResult,
  clampScore,
  emptyResult,
  runEngine,
  withTimeout,
} from './contract'

const DNS_TIMEOUT = 4_000
const DOH_TIMEOUT = 5_000

/** Independent DoH resolvers, tried in order. Both speak the JSON API. */
const DOH_RESOLVERS = [
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Google', url: 'https://dns.google/resolve' },
] as const

/** Numeric RR types used by the DoH JSON API. */
const RR = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  DS: 43,
  DNSKEY: 48,
  CAA: 257,
} as const

export interface CaaRecord {
  flags: number
  tag: string
  value: string
  raw: string
}

export interface DnsIntelligence {
  host: string
  registrableDomain: string

  addresses: string[]
  ipv4: string[]
  ipv6: string[]
  addressCount: number

  cname: string[]
  nameservers: string[]
  mailExchangers: Array<{ priority: number; exchange: string }>
  soa: string | null
  txtRecords: string[]

  /** CAA at the exact name, or inherited from the registrable domain. */
  caaRecords: CaaRecord[]
  caaPresent: boolean
  /** True only when a resolver returned an authoritative answer for CAA. */
  caaQueryable: boolean
  caaSource: string | null
  /** Which name the CAA RRset was found on (issuance is checked up the tree). */
  caaAtName: string | null

  spf: string | null
  dmarc: string | null
  dkimSelectorsFound: string[]

  dnssecSigned: boolean
  dnssecValidated: boolean
  dnssecQueryable: boolean

  /** Which transports actually answered, for the provenance line. */
  transports: string[]
  systemResolverAvailable: boolean
  dohAvailable: boolean
  resolvedVia: string
  error: string | null
}

function emptyDns(host: string): DnsIntelligence {
  return {
    host,
    registrableDomain: registrableDomain(host),
    addresses: [],
    ipv4: [],
    ipv6: [],
    addressCount: 0,
    cname: [],
    nameservers: [],
    mailExchangers: [],
    soa: null,
    txtRecords: [],
    caaRecords: [],
    caaPresent: false,
    caaQueryable: false,
    caaSource: null,
    caaAtName: null,
    spf: null,
    dmarc: null,
    dkimSelectorsFound: [],
    dnssecSigned: false,
    dnssecValidated: false,
    dnssecQueryable: false,
    transports: [],
    systemResolverAvailable: false,
    dohAvailable: false,
    resolvedVia: 'none',
    error: null,
  }
}

/** Best-effort registrable domain (label heuristic; no PSL dependency). */
export function registrableDomain(host: string): string {
  const labels = host.split('.').filter(Boolean)
  if (labels.length <= 2) return labels.join('.')
  const twoPart = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'])
  const tail = labels.slice(-3)
  if (tail[1] && twoPart.has(tail[1]) && tail[2] && tail[2].length <= 3) return tail.join('.')
  return labels.slice(-2).join('.')
}

// ─── DNS-over-HTTPS ───────────────────────────────────────────────────────────

interface DohAnswer {
  name: string
  type: number
  TTL: number
  data: string
}

interface DohResponse {
  Status: number
  /** Authenticated Data — the resolver validated DNSSEC for this answer. */
  AD?: boolean
  Answer?: DohAnswer[]
  Authority?: DohAnswer[]
  resolver: string
}

/**
 * Query a record type over DoH. Returns null only when *every* resolver failed
 * to respond — a NOERROR/NODATA answer is a real result and comes back with an
 * empty Answer array.
 */
async function doh(name: string, type: number): Promise<DohResponse | null> {
  for (const resolver of DOH_RESOLVERS) {
    try {
      const url = `${resolver.url}?name=${encodeURIComponent(name)}&type=${type}&do=1`
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT)
      try {
        const response = await fetch(url, {
          headers: { accept: 'application/dns-json' },
          signal: controller.signal,
        })
        if (!response.ok) continue
        const body = (await response.json()) as DohResponse
        // Status 0 = NOERROR, 3 = NXDOMAIN. Both are authoritative answers.
        if (body.Status === 0 || body.Status === 3) {
          return { ...body, resolver: resolver.name }
        }
      } finally {
        clearTimeout(timer)
      }
    } catch {
      // Try the next resolver rather than concluding anything.
    }
  }
  return null
}

/**
 * DoH returns CAA either in presentation format (`0 issue "letsencrypt.org"`,
 * Google) or as an unknown-RR hex blob (`\# 22 00 05 6973...`, Cloudflare).
 * Both are parsed so the result does not depend on which resolver answered.
 */
export function parseCaaData(data: string): CaaRecord | null {
  const trimmed = data.trim()

  // Presentation format: <flags> <tag> "<value>"
  const presentation = trimmed.match(/^(\d+)\s+([a-z]+)\s+"?([^"]*)"?$/i)
  if (presentation) {
    return {
      flags: Number(presentation[1]),
      tag: presentation[2].toLowerCase(),
      value: presentation[3].trim(),
      raw: `${presentation[1]} ${presentation[2]} "${presentation[3].trim()}"`,
    }
  }

  // Unknown-RR hex format (RFC 3597): \# <len> <hex bytes>
  const hex = trimmed.match(/^\\#\s+\d+\s+([0-9a-f\s]+)$/i)
  if (hex) {
    const bytes = Buffer.from(hex[1].replace(/\s+/g, ''), 'hex')
    if (bytes.length < 2) return null
    const flags = bytes[0]
    const tagLength = bytes[1]
    if (bytes.length < 2 + tagLength) return null
    const tag = bytes.subarray(2, 2 + tagLength).toString('ascii').toLowerCase()
    const value = bytes.subarray(2 + tagLength).toString('ascii')
    return { flags, tag, value, raw: `${flags} ${tag} "${value}"` }
  }

  return null
}

async function caaViaDoh(name: string): Promise<{ records: CaaRecord[]; resolver: string } | null> {
  const response = await doh(name, RR.CAA)
  if (!response) return null
  const records = (response.Answer ?? [])
    .filter((answer) => answer.type === RR.CAA)
    .map((answer) => parseCaaData(answer.data))
    .filter((record): record is CaaRecord => record !== null)
  return { records, resolver: response.resolver }
}

// ─── System resolver helpers ──────────────────────────────────────────────────

/**
 * Does the system stub resolver answer RECORD-TYPE queries on this host at all?
 *
 * `dns.lookup()` (getaddrinfo) works essentially everywhere, but `resolve4`,
 * `resolveCaa`, `resolveTxt` and friends go out on UDP/53, which a large share
 * of corporate networks, container runtimes and consumer ISPs refuse outright.
 * Measured on a network that blocks it, every one of those calls still costs
 * real latency before failing — `resolve6` alone took 3.26s to return
 * ECONNREFUSED, and the engine made seven such calls per scan.
 *
 * Whether UDP/53 is reachable is a property of the SCANNER'S network, not of the
 * target, so it is answered once and reused. The result is re-tested
 * periodically because a runtime can be moved onto a network that does allow it.
 */
const RESOLVER_PROBE_TTL_MS = 5 * 60 * 1000
let systemResolverState: { usable: boolean; checkedAt: number } | null = null

/** Codes meaning "the transport is unavailable", not "the name has no records". */
const RESOLVER_DEAD_CODES = new Set(['ECONNREFUSED', 'ETIMEOUT', 'ETIMEDOUT', 'ESERVFAIL', 'ECANCELLED'])

function noteResolverOutcome(err: unknown): void {
  const code = (err as NodeJS.ErrnoException | undefined)?.code ?? ''
  if (!RESOLVER_DEAD_CODES.has(code)) return
  systemResolverState = { usable: false, checkedAt: Date.now() }
}

function systemResolverUsable(): boolean {
  if (!systemResolverState) return true
  if (Date.now() - systemResolverState.checkedAt > RESOLVER_PROBE_TTL_MS) {
    systemResolverState = null
    return true
  }
  return systemResolverState.usable
}

/** `resolveX` that reports transport death and resolves to a fallback. */
async function viaSystemResolver<T>(query: () => Promise<T>, fallback: T, timeoutMs: number): Promise<T> {
  if (!systemResolverUsable()) return fallback
  try {
    return await withTimeout(
      query().catch((err) => {
        noteResolverOutcome(err)
        throw err
      }),
      Math.max(0, timeoutMs),
      fallback,
    )
  } catch {
    return fallback
  }
}

async function systemCaa(name: string): Promise<{ records: CaaRecord[]; authoritative: boolean }> {
  if (!systemResolverUsable()) return { records: [], authoritative: false }
  try {
    const records = await dnsPromises.resolveCaa(name)
    return {
      authoritative: true,
      records: records
        .map((record) => {
          const entry = record as unknown as Record<string, string | number | undefined>
          const tag = ['issue', 'issuewild', 'iodef', 'contactemail', 'contactphone'].find(
            (candidate) => entry[candidate] !== undefined,
          )
          if (!tag) return null
          const value = String(entry[tag])
          const flags = Number(entry.critical ?? 0)
          return { flags, tag, value, raw: `${flags} ${tag} "${value}"` }
        })
        .filter((record): record is CaaRecord => record !== null),
    }
  } catch (err) {
    noteResolverOutcome(err)
    const code = (err as NodeJS.ErrnoException).code
    // ENODATA / ENOTFOUND are authoritative "no CAA published" answers.
    return { records: [], authoritative: code === 'ENODATA' || code === 'ENOTFOUND' }
  }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

export async function runDnsEngine(
  host: string,
  /**
   * Wall-clock ceiling. The addresses and CAA policy are load-bearing for the
   * assessment; nameservers, MX, SPF/DMARC and DKIM selectors are context. When
   * the budget runs short the context is skipped and said so, rather than
   * letting a slow resolver chain hold the whole scan open.
   */
  budgetMs = 8_000,
): Promise<EngineResult<DnsIntelligence>> {
  return runEngine('dns-intelligence', emptyDns(host), async () => {
    const data = emptyDns(host)
    const evidence: Evidence[] = []
    const notes: string[] = []
    const deadline = Date.now() + Math.max(3_000, budgetMs)
    const remaining = () => deadline - Date.now()

    if (net.isIP(host)) {
      // A literal IP has no DNS surface to assess.
      data.addresses = [host]
      data.ipv4 = net.isIPv4(host) ? [host] : []
      data.ipv6 = net.isIPv6(host) ? [host] : []
      data.addressCount = 1
      data.resolvedVia = 'literal-ip'
      notes.push('Target is a literal IP address; DNS records are not applicable.')
      return { data, ok: true, confidence: 100, evidence, notes, error: null }
    }

    const apex = data.registrableDomain

    // Make sure the system resolver has servers configured; some environments
    // hand Node an empty list, which fails every query instantly.
    try {
      if (dnsPromises.getServers().length === 0) setServers(['1.1.1.1', '8.8.8.8'])
    } catch {
      /* resolver configuration is best-effort */
    }

    /* ── Addresses ────────────────────────────────────────────────────────
       The authoritative A/AAAA queries and the OS stub resolver are raced
       rather than tried in series. `lookup()` uses getaddrinfo and answers on
       networks where UDP/53 is blocked — precisely the case where the record
       queries are slowest — so waiting for them to fail first added their full
       latency to every scan for an answer the stub already had. Authoritative
       records still WIN when they arrive; the stub is only the fallback. */
    const [v4, v6, looked] = await Promise.all([
      viaSystemResolver(() => dnsPromises.resolve4(host), [] as string[], DNS_TIMEOUT),
      viaSystemResolver(() => dnsPromises.resolve6(host), [] as string[], DNS_TIMEOUT),
      withTimeout(
        dnsPromises.lookup(host, { all: true }),
        DNS_TIMEOUT,
        [] as Array<{ address: string; family: number }>,
      ),
    ])
    data.systemResolverAvailable = v4.length > 0 || v6.length > 0
    data.ipv4 = v4
    data.ipv6 = v6
    if (data.systemResolverAvailable) {
      data.transports.push('system resolver')
      data.resolvedVia = v4.length ? 'A' : 'AAAA'
    }

    if (!data.systemResolverAvailable && looked.length) {
      data.ipv4 = looked.filter((entry) => entry.family === 4).map((entry) => entry.address)
      data.ipv6 = looked.filter((entry) => entry.family === 6).map((entry) => entry.address)
      data.transports.push('OS stub resolver')
      data.resolvedVia = 'os-resolver'
      notes.push('Record-type DNS queries were unavailable; addresses came from the OS stub resolver.')
    }

    // DoH is the last resort for addresses — it costs a full HTTPS round trip
    // and only matters when neither local transport answered at all.
    if (!data.ipv4.length && !data.ipv6.length) {
      const [a, aaaa] = await Promise.all([doh(host, RR.A), doh(host, RR.AAAA)])
      if (a || aaaa) {
        data.dohAvailable = true
        data.transports.push(`DoH (${a?.resolver ?? aaaa?.resolver})`)
        data.ipv4 = (a?.Answer ?? []).filter((x) => x.type === RR.A).map((x) => x.data)
        data.ipv6 = (aaaa?.Answer ?? []).filter((x) => x.type === RR.AAAA).map((x) => x.data)
        data.cname = (a?.Answer ?? []).filter((x) => x.type === RR.CNAME).map((x) => x.data)
        data.resolvedVia = data.ipv4.length ? 'A (DoH)' : data.ipv6.length ? 'AAAA (DoH)' : 'none'
        notes.push('System resolver refused record-type queries; answered over DNS-over-HTTPS.')
      }
    }

    data.addresses = Array.from(new Set([...data.ipv4, ...data.ipv6]))
    data.addressCount = data.addresses.length
    if (data.addressCount) {
      evidence.push({
        label: 'Public addresses',
        observedValue: data.addresses.slice(0, 6).join(', '),
        detectionMethod: data.dohAvailable ? 'DNS-over-HTTPS query' : 'DNS query',
        evidenceSource: data.transports[0] ?? 'resolver',
        confidence: 100,
      })
    } else {
      data.error = 'No public A/AAAA records resolved'
    }

    // ── CAA: system resolver first, DoH as an equal-standing fallback ────────
    // Issuance is checked at the name and inherited up the tree, so both are
    // queried before concluding "no policy".
    for (const name of [host, apex].filter((value, index, all) => all.indexOf(value) === index)) {
      if (remaining() <= 0) break
      /* The system resolver and DoH are raced rather than tried in series. They
         are independent transports answering the same question, and the loop
         runs for up to two names — four sequential waits of 4-5s each was up to
         18s of the DNS engine's wall clock spent waiting for a fallback that
         the faster transport had usually already answered. */
      const [viaSystem, viaDohRaced] = await Promise.all([
        withTimeout(systemCaa(name), Math.min(DNS_TIMEOUT, Math.max(0, remaining())), {
          records: [] as CaaRecord[],
          authoritative: false,
        }),
        withTimeout(caaViaDoh(name), Math.min(DOH_TIMEOUT, Math.max(0, remaining())), null),
      ])
      if (viaSystem.authoritative) {
        data.caaQueryable = true
        data.caaSource = 'system resolver'
        data.caaAtName = name
        if (viaSystem.records.length) {
          data.caaRecords = viaSystem.records
          break
        }
        continue
      }

      const viaDoh = viaDohRaced
      if (viaDoh) {
        data.caaQueryable = true
        data.dohAvailable = true
        data.caaSource = `${viaDoh.resolver} (DoH)`
        data.caaAtName = name
        if (viaDoh.records.length) {
          data.caaRecords = viaDoh.records
          break
        }
      }
    }
    data.caaPresent = data.caaRecords.length > 0
    if (data.caaQueryable) {
      evidence.push({
        label: 'CAA issuance policy',
        observedValue: data.caaPresent
          ? data.caaRecords.map((record) => record.raw).join(' | ')
          : 'no CAA records published',
        detectionMethod: data.caaSource?.includes('DoH') ? 'DNS-over-HTTPS query' : 'DNS query',
        evidenceSource: `${data.caaSource} · ${data.caaAtName}`,
        confidence: 100,
      })
      if (data.caaSource?.includes('DoH') && !data.systemResolverAvailable) {
        notes.push('CAA resolved over DNS-over-HTTPS because UDP/53 was unavailable.')
      }
    } else {
      notes.push('CAA could not be queried over any transport.')
    }

    // ── Supporting records (best-effort; absence is never a failure) ─────────
    // Everything below is context, not a control, so each query is capped at
    // whatever budget is actually left. `withTimeout` resolves to the fallback
    // rather than rejecting, so a starved query degrades to "not observed".
    const supportingBudget = () => Math.max(0, Math.min(DOH_TIMEOUT, remaining()))
    const [ns, mx, txt, soa, apexTxt, dmarcTxt, dnskey] = await Promise.all([
      viaSystemResolver(() => dnsPromises.resolveNs(apex), [] as string[], Math.min(DNS_TIMEOUT, supportingBudget())),
      viaSystemResolver(() => dnsPromises.resolveMx(apex), [] as Array<{ priority: number; exchange: string }>, Math.min(DNS_TIMEOUT, supportingBudget())),
      viaSystemResolver(() => dnsPromises.resolveTxt(host), [] as string[][], Math.min(DNS_TIMEOUT, supportingBudget())),
      withTimeout(doh(apex, RR.SOA), supportingBudget(), null),
      withTimeout(doh(apex, RR.TXT), supportingBudget(), null),
      withTimeout(doh(`_dmarc.${apex}`, RR.TXT), supportingBudget(), null),
      withTimeout(doh(apex, RR.DNSKEY), supportingBudget(), null),
    ])

    /* The NS and MX DoH fallbacks used to be two more SEQUENTIAL awaits after
       the batch above. They are independent of each other, so they run together
       — and only when the primary query actually came back empty. */
    const [nsFallback, mxFallback] = await Promise.all([
      ns.length || remaining() <= 0 ? null : withTimeout(doh(apex, RR.NS), supportingBudget(), null),
      mx.length || remaining() <= 0 ? null : withTimeout(doh(apex, RR.MX), supportingBudget(), null),
    ])

    data.nameservers = ns.length
      ? ns.slice(0, 8)
      : (nsFallback?.Answer ?? [])
          .filter((answer) => answer.type === RR.NS)
          .map((answer) => answer.data.replace(/\.$/, ''))
          .slice(0, 8)

    data.mailExchangers = mx.length
      ? mx.slice(0, 8)
      : (mxFallback?.Answer ?? [])
          .filter((answer) => answer.type === RR.MX)
          .map((answer) => {
            const [priority, exchange] = answer.data.split(/\s+/)
            return { priority: Number(priority) || 0, exchange: (exchange ?? '').replace(/\.$/, '') }
          })
          .slice(0, 8)

    data.soa = soa?.Answer?.find((answer) => answer.type === RR.SOA)?.data ?? null

    const flatTxt = txt.map((chunks) => chunks.join(''))
    const dohTxt = (apexTxt?.Answer ?? [])
      .filter((answer) => answer.type === RR.TXT)
      .map((answer) => answer.data.replace(/^"|"$/g, '').replace(/" "/g, ''))
    // Extract policy records from the COMPLETE set before truncating for
    // display — a busy apex can carry 30+ TXT records and SPF is rarely first.
    const allTxt = Array.from(new Set([...flatTxt, ...dohTxt]))
    data.spf = allTxt.find((record) => /^v=spf1\b/i.test(record)) ?? null
    data.txtRecords = allTxt.slice(0, 20)
    data.dmarc =
      (dmarcTxt?.Answer ?? [])
        .filter((answer) => answer.type === RR.TXT)
        .map((answer) => answer.data.replace(/^"|"$/g, '').replace(/" "/g, ''))
        .find((record) => /^v=DMARC1\b/i.test(record)) ?? null

    // DKIM selectors are per-sender and cannot be enumerated blind; probe the
    // handful of well-known defaults and report only what actually answers.
    // Six more DoH round trips for a field no control reads — skipped outright
    // once the budget is spent, and the note says so rather than implying the
    // domain publishes none.
    if (remaining() > 1_500) {
      const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail']
      const dkimResults = await Promise.all(
        dkimSelectors.map(async (selector) => {
          const response = await withTimeout(
            doh(`${selector}._domainkey.${apex}`, RR.TXT),
            Math.max(0, Math.min(DOH_TIMEOUT, remaining())),
            null,
          )
          const found = (response?.Answer ?? []).some(
            (answer) => answer.type === RR.TXT && /v=DKIM1/i.test(answer.data),
          )
          return found ? selector : null
        }),
      )
      data.dkimSelectorsFound = dkimResults.filter((selector): selector is string => selector !== null)
    } else {
      notes.push('DKIM selector discovery was skipped to stay inside the DNS time budget; no claim is made either way.')
    }

    // DNSSEC: DNSKEY presence proves the zone is signed; the AD bit proves a
    // validating resolver actually verified the chain.
    if (dnskey) {
      data.dnssecQueryable = true
      data.dnssecSigned = (dnskey.Answer ?? []).some((answer) => answer.type === RR.DNSKEY)
      data.dnssecValidated = Boolean(dnskey.AD)
      evidence.push({
        label: 'DNSSEC',
        observedValue: data.dnssecSigned
          ? `zone signed${data.dnssecValidated ? ', resolver-validated (AD)' : ''}`
          : 'zone not signed',
        detectionMethod: 'DNS-over-HTTPS query',
        evidenceSource: `${dnskey.resolver} (DoH) · DNSKEY`,
        confidence: 100,
      })
    }

    if (data.spf) {
      evidence.push({
        label: 'SPF',
        observedValue: data.spf,
        detectionMethod: 'DNS query',
        evidenceSource: `TXT ${apex}`,
        confidence: 100,
      })
    }
    if (data.dmarc) {
      evidence.push({
        label: 'DMARC',
        observedValue: data.dmarc,
        detectionMethod: 'DNS-over-HTTPS query',
        evidenceSource: `TXT _dmarc.${apex}`,
        confidence: 100,
      })
    }

    const confidence = clampScore(
      (data.addressCount ? 45 : 0) +
        (data.caaQueryable ? 25 : 0) +
        (data.nameservers.length ? 15 : 0) +
        (data.dnssecQueryable ? 15 : 0),
    )

    return {
      data,
      ok: data.addressCount > 0,
      confidence,
      evidence,
      notes,
      error: data.error,
    }
  })
}

export { emptyDns }
export type { EngineResult }
export const DNS_ENGINE_EMPTY = emptyResult('dns-intelligence', emptyDns(''))
