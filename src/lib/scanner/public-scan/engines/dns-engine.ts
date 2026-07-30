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

async function systemCaa(name: string): Promise<{ records: CaaRecord[]; authoritative: boolean }> {
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
    const code = (err as NodeJS.ErrnoException).code
    // ENODATA / ENOTFOUND are authoritative "no CAA published" answers.
    return { records: [], authoritative: code === 'ENODATA' || code === 'ENOTFOUND' }
  }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

export async function runDnsEngine(host: string): Promise<EngineResult<DnsIntelligence>> {
  return runEngine('dns-intelligence', emptyDns(host), async () => {
    const data = emptyDns(host)
    const evidence: Evidence[] = []
    const notes: string[] = []

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

    // ── Addresses: system resolver, then DoH, then the OS stub resolver ──────
    const [v4, v6] = await Promise.all([
      withTimeout(dnsPromises.resolve4(host), DNS_TIMEOUT, [] as string[]),
      withTimeout(dnsPromises.resolve6(host), DNS_TIMEOUT, [] as string[]),
    ])
    data.systemResolverAvailable = v4.length > 0 || v6.length > 0
    data.ipv4 = v4
    data.ipv6 = v6
    if (data.systemResolverAvailable) {
      data.transports.push('system resolver')
      data.resolvedVia = v4.length ? 'A' : 'AAAA'
    }

    if (!data.systemResolverAvailable) {
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

    if (!data.ipv4.length && !data.ipv6.length) {
      const looked = await withTimeout(
        dnsPromises.lookup(host, { all: true }),
        DNS_TIMEOUT,
        [] as Array<{ address: string; family: number }>,
      )
      if (looked.length) {
        data.ipv4 = looked.filter((entry) => entry.family === 4).map((entry) => entry.address)
        data.ipv6 = looked.filter((entry) => entry.family === 6).map((entry) => entry.address)
        data.transports.push('OS stub resolver')
        data.resolvedVia = 'os-resolver'
        notes.push('Only the OS stub resolver answered; record-type detail is limited.')
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
      const viaSystem = await withTimeout(systemCaa(name), DNS_TIMEOUT, {
        records: [] as CaaRecord[],
        authoritative: false,
      })
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

      const viaDoh = await withTimeout(caaViaDoh(name), DOH_TIMEOUT, null)
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
    const [ns, mx, txt, soa, apexTxt, dmarcTxt, dnskey] = await Promise.all([
      withTimeout(dnsPromises.resolveNs(apex), DNS_TIMEOUT, [] as string[]),
      withTimeout(dnsPromises.resolveMx(apex), DNS_TIMEOUT, [] as Array<{ priority: number; exchange: string }>),
      withTimeout(dnsPromises.resolveTxt(host), DNS_TIMEOUT, [] as string[][]),
      withTimeout(doh(apex, RR.SOA), DOH_TIMEOUT, null),
      withTimeout(doh(apex, RR.TXT), DOH_TIMEOUT, null),
      withTimeout(doh(`_dmarc.${apex}`, RR.TXT), DOH_TIMEOUT, null),
      withTimeout(doh(apex, RR.DNSKEY), DOH_TIMEOUT, null),
    ])

    data.nameservers = ns.length
      ? ns.slice(0, 8)
      : ((await withTimeout(doh(apex, RR.NS), DOH_TIMEOUT, null))?.Answer ?? [])
          .filter((answer) => answer.type === RR.NS)
          .map((answer) => answer.data.replace(/\.$/, ''))
          .slice(0, 8)

    data.mailExchangers = mx.length
      ? mx.slice(0, 8)
      : ((await withTimeout(doh(apex, RR.MX), DOH_TIMEOUT, null))?.Answer ?? [])
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
    const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail']
    const dkimResults = await Promise.all(
      dkimSelectors.map(async (selector) => {
        const response = await withTimeout(doh(`${selector}._domainkey.${apex}`, RR.TXT), DOH_TIMEOUT, null)
        const found = (response?.Answer ?? []).some(
          (answer) => answer.type === RR.TXT && /v=DKIM1/i.test(answer.data),
        )
        return found ? selector : null
      }),
    )
    data.dkimSelectorsFound = dkimResults.filter((selector): selector is string => selector !== null)

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
