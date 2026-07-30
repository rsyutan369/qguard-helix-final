/**
 * Quantum Visualization Engine™ — infrastructure strip.
 *
 * The six-tile band under the hero: addresses, assessed port, protocols,
 * CDN / WAF, server and edge topology.
 *
 * EVIDENCE DISCIPLINE — every tile names what it was counted from, and any tile
 * the public edge cannot see says "Not observable" rather than guessing:
 *
 *   IP Addresses  → dns.addressCount (A + AAAA actually resolved)
 *   Open Ports    → the port the TLS handshake actually completed on. This is
 *                   deliberately NOT a port scan: the public scanner probes one
 *                   endpoint, so claiming a port count would be fabrication.
 *   Protocols     → tls.supportedProtocols, from per-version probes
 *   CDN / WAF     → http fingerprint, from response-header signatures only
 *   Server        → the Server response header, when disclosed
 *   Edge topology → derived from CDN signature + address count, with the
 *                   derivation stated in the tooltip
 *
 * Before a scan the tiles render their idle legend, which is what they *will*
 * measure — never a placeholder value.
 */
'use client';

import React from 'react';
import { motion } from 'motion/react';
import { Globe, MapPin, Network, Server, ShieldHalf, Waypoints, type LucideIcon } from 'lucide-react';
import type { PublicScanReport } from '@/lib/scanner/public-scan/types';

export interface InfraTile {
  key: string;
  label: string;
  value: string;
  /** Evidence provenance, surfaced as the tile's tooltip. */
  basis: string;
  icon: LucideIcon;
  /** True when the value is a measured observation rather than an idle legend. */
  measured: boolean;
  /** Accent for measured, notable values (protocols, PQ). */
  tone?: string;
}

const IDLE_TILES: InfraTile[] = [
  { key: 'addresses', label: 'IP Addresses', value: '—', basis: 'Public A and AAAA records resolved for the host', icon: MapPin, measured: false },
  { key: 'ports', label: 'Assessed Port', value: '—', basis: 'The HTTPS port the assessment connects to', icon: Waypoints, measured: false },
  { key: 'protocols', label: 'Protocols', value: '—', basis: 'TLS 1.0 → 1.3, probed one version at a time', icon: Network, measured: false },
  { key: 'cdn', label: 'CDN / WAF', value: '—', basis: 'Inferred from response-header signatures only', icon: ShieldHalf, measured: false },
  { key: 'server', label: 'Server', value: '—', basis: 'The Server response header, when disclosed', icon: Server, measured: false },
  { key: 'topology', label: 'Edge Topology', value: '—', basis: 'Derived from CDN signature and resolved address count', icon: Globe, measured: false },
];

export function buildInfraTiles(report: PublicScanReport | null): InfraTile[] {
  if (!report) return IDLE_TILES;

  const dns = report.evidence.engines.dns.data;
  const http = report.evidence.http;
  const fingerprint = report.evidence.engines.http.data.fingerprint;
  const tls = report.evidence.tls;
  const handshakeOk = Boolean(tls);

  /** Human protocol list, e.g. "TLS 1.2 / 1.3". */
  const protocols = tls?.supportedProtocols.length
    ? tls.supportedProtocols
        .map((protocol) => protocol.replace(/^TLSv?/i, 'TLS ').replace(/\s+/g, ' ').trim())
        .join(' / ')
    : 'Not observable';

  const cdn = fingerprint.cdn ?? fingerprint.waf ?? fingerprint.reverseProxy ?? null;

  // Topology is a derivation, not a geo lookup — a public TLS scan has no
  // location evidence, and inventing one would be exactly the fabrication this
  // scanner argues against.
  const topology = !dns.addressCount
    ? 'Not observable'
    : fingerprint.cdn
      ? 'Anycast · global edge'
      : dns.addressCount > 1
        ? `Multi-homed · ${dns.addressCount} endpoints`
        : 'Single origin';

  return [
    {
      key: 'addresses',
      label: 'IP Addresses',
      value: dns.addressCount ? String(dns.addressCount) : 'Unresolved',
      basis: dns.addressCount
        ? `${dns.ipv4.length} IPv4 · ${dns.ipv6.length} IPv6 · resolved via ${dns.resolvedVia}`
        : (dns.error ?? 'No public A/AAAA records returned'),
      icon: MapPin,
      measured: dns.addressCount > 0,
    },
    {
      key: 'ports',
      label: 'Assessed Port',
      value: handshakeOk ? `1 (${report.target.port})` : `0 (${report.target.port})`,
      basis: handshakeOk
        ? `TLS handshake completed on port ${report.target.port}. The public scanner assesses one HTTPS endpoint and does not port-scan.`
        : `Port ${report.target.port} did not complete a TLS handshake`,
      icon: Waypoints,
      measured: handshakeOk,
    },
    {
      key: 'protocols',
      label: 'Protocols',
      value: protocols,
      basis: tls?.protocolSupport.length
        ? `${tls.protocolSupport.length} versions probed individually · negotiated ${tls.tlsVersion}`
        : 'Protocol enumeration did not complete',
      icon: Network,
      measured: Boolean(tls?.supportedProtocols.length),
      tone: tls?.supportedProtocols.some((protocol) => /1\.3/.test(protocol)) ? '#22d3ee' : '#fbbf24',
    },
    {
      key: 'cdn',
      label: 'CDN / WAF',
      value: cdn ?? (http.reachable ? 'Direct origin' : 'Not observable'),
      basis: fingerprint.signals.length
        ? `Signature from: ${fingerprint.signals.slice(0, 4).join(', ')}`
        : 'No CDN, WAF or proxy header signature present',
      icon: ShieldHalf,
      measured: Boolean(cdn) || http.reachable,
    },
    {
      key: 'server',
      label: 'Server',
      value: http.server ?? (http.reachable ? 'Not disclosed' : 'Unreachable'),
      basis: http.reachable
        ? [`HTTP ${http.statusCode}`, http.poweredBy ? `X-Powered-By ${http.poweredBy}` : null, report.evidence.alpn ? `ALPN ${report.evidence.alpn}` : null]
            .filter(Boolean)
            .join(' · ')
        : (http.error ?? 'Origin did not answer'),
      icon: Server,
      measured: http.reachable,
    },
    {
      key: 'topology',
      label: 'Edge Topology',
      value: topology,
      basis: fingerprint.cdn
        ? `${fingerprint.cdn} terminates TLS, so the edge is provider-operated and globally distributed. No geolocation is claimed — a TLS scan carries no location evidence.`
        : `Derived from ${dns.addressCount} resolved address(es) and the absence of a CDN signature. No geolocation is claimed.`,
      icon: Globe,
      measured: dns.addressCount > 0,
    },
  ];
}

export const InfrastructureStrip = React.memo(function InfrastructureStrip({
  tiles,
  animate,
}: {
  tiles: InfraTile[];
  animate: boolean;
}) {
  return (
    <dl className="grid grid-cols-2 divide-white/[0.06] sm:grid-cols-3 lg:grid-cols-6 lg:divide-x">
      {tiles.map((tile, index) => (
        <motion.div
          key={tile.key}
          initial={animate ? { opacity: 0, y: 8 } : false}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: index * 0.04, ease: [0.22, 1, 0.36, 1] }}
          className="flex min-w-0 items-center gap-2.5 border-b border-white/[0.06] px-4 py-3.5 last:border-b-0 sm:border-b-0"
          title={tile.basis}
        >
          <span
            aria-hidden
            className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-cyan-400/20 bg-cyan-400/[0.06] text-cyan-300/90"
          >
            <tile.icon className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <dt className="truncate text-[11.5px] font-semibold text-slate-400">{tile.label}</dt>
            <dd
              className="truncate text-[14px] font-black leading-tight"
              style={{ color: tile.measured ? (tile.tone ?? '#e2e8f0') : '#475569' }}
            >
              {tile.value}
            </dd>
          </div>
        </motion.div>
      ))}
    </dl>
  );
});
