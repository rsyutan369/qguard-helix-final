/**
 * QGuard Helix — Public Scan SSRF containment.
 *
 * The public assessment endpoint takes an arbitrary hostname from an
 * unauthenticated caller and opens TLS/HTTP connections to it. That is the
 * product, but it also makes the API server a confused deputy: without the
 * guards here, `evil.example` with an `A 169.254.169.254` record (or a plain
 * `302 -> http://10.0.0.5/`) turns the scanner into a reader of cloud metadata
 * and internal services.
 *
 * The containment model has three parts, because any one alone is bypassable:
 *
 *  1. LITERAL ADDRESSES are checked directly. Node's `net.connect` skips the
 *     `lookup` hook entirely when the host is already an IP, so a pinning
 *     lookup cannot see — let alone block — `http://10.0.0.5/`.
 *
 *  2. RESOLVED ADDRESSES are checked inside a custom `lookup` (see
 *     {@link safeLookup}). Validating in the lookup makes the check and the
 *     connection ATOMIC: the socket connects to exactly the address this
 *     function validated, so there is no window for DNS rebinding to swap a
 *     public answer for a private one between check and connect. A separate
 *     "resolve, validate, then connect by name" sequence is exactly the
 *     time-of-check/time-of-use bug rebinding exploits.
 *
 *  3. Every address for a name must pass. A dual-stack host that answers with
 *     one public and one private address is rejected, not partially trusted.
 *
 * Passing `lookup` rather than substituting the IP into `host` is deliberate:
 * SNI, the `Host:` header and certificate name verification all keep seeing the
 * real hostname, so containment cannot silently corrupt the assessment itself.
 */

import dns from 'node:dns'
import net from 'node:net'

/**
 * Non-public IPv4/IPv6 space: loopback, RFC1918, link-local (including the
 * 169.254.169.254 cloud metadata address), CGNAT, IPv6 ULA/link-local, and the
 * unspecified/reserved blocks. Kept here as the single source of truth so the
 * route layer and the connection layer can never disagree.
 */
export const PRIVATE_IP_PATTERNS: readonly RegExp[] = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^0\./,
  /^169\.254\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  // 192.0.0.0/24, 192.0.2.0/24 (TEST-NET-1), 198.18/15 benchmarking,
  // 198.51.100/24, 203.0.113/24, 224+ multicast/reserved.
  /^192\.0\.0\./,
  /^192\.0\.2\./,
  /^198\.1[89]\./,
  /^198\.51\.100\./,
  /^203\.0\.113\./,
  /^(22[4-9]|2[3-5]\d)\./,
  /^::$/,
  /^::1$/,
  /^f[cd][0-9a-f]{2}:/i,
  /^fe[89ab][0-9a-f]:/i,
]

/**
 * Normalise an address before pattern matching. `::ffff:10.0.0.1` is an IPv4
 * address wearing an IPv6 costume — matched against the IPv6 patterns it looks
 * perfectly public, which is a classic allowlist bypass. Also drops a zone id
 * (`fe80::1%eth0`).
 */
export function normalizeAddress(ip: string): string {
  const withoutZone = ip.trim().toLowerCase().split('%')[0]
  const mapped = withoutZone.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)
  if (mapped) return mapped[1]
  // Some resolvers render the mapped form in hex (::ffff:0a00:0001).
  const hexMapped = withoutZone.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/)
  if (hexMapped) {
    const high = Number.parseInt(hexMapped[1], 16)
    const low = Number.parseInt(hexMapped[2], 16)
    return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`
  }
  return withoutZone
}

/** True when `ip` is outside publicly routable space and must never be scanned. */
export function isPrivateAddress(ip: string): boolean {
  const normalized = normalizeAddress(ip)
  if (!net.isIP(normalized)) return true // unparseable: fail closed
  return PRIVATE_IP_PATTERNS.some((pattern) => pattern.test(normalized))
}

/** Hostnames that never belong to a public target, regardless of what DNS says. */
const BLOCKED_HOSTS = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
])
const BLOCKED_HOST_SUFFIXES = ['.local', '.internal', '.localdomain', '.home.arpa', '.lan', '.intranet']

export interface HostVerdict {
  ok: boolean
  code?: string
  message?: string
}

/**
 * Synchronous, DNS-free checks: name blocklist plus literal-address space.
 * Cheap enough to run on every redirect hop, and the ONLY thing that catches a
 * literal private IP (which bypasses `lookup` altogether).
 */
export function checkHostSyntax(host: string): HostVerdict {
  const normalized = host.trim().toLowerCase().replace(/^\[|\]$/g, '')
  if (!normalized) {
    return { ok: false, code: 'INVALID_TARGET', message: 'Enter a domain or https:// URL to assess.' }
  }
  if (BLOCKED_HOSTS.has(normalized) || BLOCKED_HOST_SUFFIXES.some((suffix) => normalized.endsWith(suffix))) {
    return {
      ok: false,
      code: 'PRIVATE_TARGET',
      message: 'Internal and loopback hostnames cannot be assessed publicly.',
    }
  }
  if (net.isIP(normalized) && isPrivateAddress(normalized)) {
    return {
      ok: false,
      code: 'PRIVATE_TARGET',
      message: 'Private and reserved IP ranges cannot be assessed publicly.',
    }
  }
  return { ok: true }
}

/** Thrown through the lookup callback so a blocked connection is distinguishable. */
export class BlockedAddressError extends Error {
  readonly code = 'SSRF_BLOCKED'
  constructor(host: string, address: string) {
    super(`Refusing to connect: ${host} resolves to the non-public address ${address}.`)
    this.name = 'BlockedAddressError'
  }
}

/**
 * A drop-in `lookup` for `tls.connect` / `https.request` that resolves a name
 * and refuses to hand back any address outside public space.
 *
 * Because the socket connects to precisely the addresses returned here, this is
 * both the validation and the pin — there is no interval in which a second DNS
 * answer could redirect the connection (DNS rebinding).
 *
 * Typed as `net.LookupFunction` so it is assignable wherever Node accepts a
 * custom resolver: that interface passes `dns.LookupOptions` (whose `all` is an
 * optional boolean), which a narrower `LookupOneOptions | LookupAllOptions`
 * signature cannot accept.
 */
export const safeLookup: net.LookupFunction = (hostname, options, callback) => {
  const wantsAll = options?.all === true

  const syntax = checkHostSyntax(hostname)
  if (!syntax.ok) {
    callback(Object.assign(new BlockedAddressError(hostname, hostname), { code: 'SSRF_BLOCKED' }), '')
    return
  }

  dns.lookup(
    hostname,
    { ...(options ?? {}), all: true, verbatim: true } as dns.LookupAllOptions,
    (err, addresses) => {
      if (err) {
        callback(err, '')
        return
      }
      const list = addresses ?? []
      if (list.length === 0) {
        callback(Object.assign(new Error(`No address records for ${hostname}.`), { code: 'ENOTFOUND' }), '')
        return
      }
      // Strict: ONE non-public answer disqualifies the name. A host that mixes
      // public and private records is either misconfigured or attacking us.
      const blocked = list.find((entry) => isPrivateAddress(entry.address))
      if (blocked) {
        callback(new BlockedAddressError(hostname, blocked.address), '')
        return
      }
      if (wantsAll) {
        callback(null, list)
        return
      }
      callback(null, list[0].address, list[0].family)
    },
  )
}

/**
 * Pre-flight resolution for the route layer, so a blocked target produces a
 * clear `PRIVATE_TARGET` error instead of an opaque "connection failed" report.
 * The connection layer still validates independently — this is for the message,
 * not for the security boundary.
 */
export async function verifyPublicHost(host: string): Promise<HostVerdict & { addresses?: string[] }> {
  const syntax = checkHostSyntax(host)
  if (!syntax.ok) return syntax
  if (net.isIP(host)) return { ok: true, addresses: [host] }

  try {
    const addresses = await dns.promises.lookup(host, { all: true, verbatim: true })
    if (addresses.length === 0) {
      return { ok: false, code: 'UNRESOLVABLE_TARGET', message: `${host} has no DNS address records.` }
    }
    const blocked = addresses.find((entry) => isPrivateAddress(entry.address))
    if (blocked) {
      return {
        ok: false,
        code: 'PRIVATE_TARGET',
        message: 'This hostname resolves to a private or reserved address and cannot be assessed publicly.',
      }
    }
    return { ok: true, addresses: addresses.map((entry) => entry.address) }
  } catch {
    return {
      ok: false,
      code: 'UNRESOLVABLE_TARGET',
      message: `${host} could not be resolved. Check the spelling and try again.`,
    }
  }
}

/** Ports a redirect hop may be followed to. */
const FOLLOWABLE_PORTS = new Set([80, 443, 8443, 9443, 4443, 10443])

/**
 * Whether a redirect may be followed. Redirect following is its own SSRF vector
 * — and a more convenient one than DNS, since the attacker needs no zone
 * control, just a `Location:` header on a host that already passed validation.
 */
export function canFollowRedirect(rawUrl: string): HostVerdict {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    return { ok: false, code: 'INVALID_REDIRECT', message: 'Redirect target is not a valid URL.' }
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, code: 'INVALID_REDIRECT', message: `Refusing to follow a ${url.protocol} redirect.` }
  }
  const port = Number(url.port || (url.protocol === 'http:' ? 80 : 443))
  if (!FOLLOWABLE_PORTS.has(port)) {
    return { ok: false, code: 'INVALID_REDIRECT', message: `Refusing to follow a redirect to port ${port}.` }
  }
  return checkHostSyntax(url.hostname)
}
