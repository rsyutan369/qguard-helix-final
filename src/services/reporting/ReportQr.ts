import QRCode from 'qrcode';
import type { EnterpriseAssessmentReport } from './schemas/ReportSchema';

/**
 * Report verification QR (Improvements_04 #9 — Executive Certification Summary).
 *
 * The QR encodes the public verification URL carrying the report's integrity
 * verification token (an unsecured JWT holding the SHA3-256 hash + report id,
 * minted in ReportEngine.attachIntegrity). Scanning it opens /verify-report,
 * which decodes the token so the reader can compare the decoded hash against
 * the hash printed on the certification page — any alteration of the report
 * content changes the hash.
 *
 * Rendering is exporter-appropriate:
 *  - `qrMatrix`  → synchronous module matrix (PDF draws crisp vector squares)
 *  - `qrSvg`     → synchronous inline SVG (HTML export stays synchronous)
 *  - `qrPngDataUrl` → async PNG data URL (DOCX / PPTX image embedding)
 */

const FALLBACK_ORIGIN = 'https://qguardhelix.com';
const QUIET_ZONE = 4; // modules of white border per QR spec

/**
 * Origin for the public verification URL (I5#3). Resolution order:
 *  1. `VITE_REPORT_VERIFICATION_ORIGIN` (browser build) / `REPORT_VERIFICATION_ORIGIN`
 *     (Node tooling) — the explicit production endpoint.
 *  2. The current window origin, ONLY when it is not a development host — a
 *     customer-facing report must never carry a localhost verification URL.
 *  3. The public product domain fallback.
 */
function verificationOrigin(): string {
  try {
    const viteEnv = (import.meta as ImportMeta & { env?: Record<string, string | undefined> }).env;
    const configured = viteEnv?.VITE_REPORT_VERIFICATION_ORIGIN;
    if (configured) return configured.replace(/\/+$/, '');
  } catch {
    /* import.meta.env unavailable in this runtime */
  }
  if (typeof process !== 'undefined') {
    const fromNode = process.env?.REPORT_VERIFICATION_ORIGIN || process.env?.VITE_REPORT_VERIFICATION_ORIGIN;
    if (fromNode) return fromNode.replace(/\/+$/, '');
  }
  if (typeof window !== 'undefined' && window.location?.origin) {
    const origin = window.location.origin;
    const isDevHost = /^https?:\/\/(localhost|127\.|0\.0\.0\.0|\[?::1\]?)(:|\/|$)/i.test(origin);
    if (!isDevHost) return origin;
  }
  return FALLBACK_ORIGIN;
}

/**
 * Public verification URL for a signed report; null until integrity is attached.
 * Structurally typed so every sealed report family (assessment, asset / CBOM)
 * resolves to the same verification page.
 */
export function reportVerificationUrl(report: Pick<EnterpriseAssessmentReport, 'integrity'> | { integrity?: { verificationToken?: string } | null }): string | null {
  const token = report.integrity?.verificationToken;
  if (!token) return null;
  return `${verificationOrigin()}/verify-report?token=${encodeURIComponent(token)}`;
}

/** Synchronous QR module matrix (true = dark module). */
export function qrMatrix(text: string): boolean[][] {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const size = qr.modules.size;
  const rows: boolean[][] = [];
  for (let r = 0; r < size; r += 1) {
    const row: boolean[] = [];
    for (let c = 0; c < size; c += 1) row.push(Boolean(qr.modules.get(r, c)));
    rows.push(row);
  }
  return rows;
}

/** Synchronous inline SVG markup (for the sync HTML exporter). */
export function qrSvg(text: string, sizePx = 132): string {
  const matrix = qrMatrix(text);
  const size = matrix.length;
  const total = size + QUIET_ZONE * 2;
  // One <path> for all dark modules keeps the markup compact.
  let d = '';
  matrix.forEach((row, r) => {
    row.forEach((dark, c) => {
      if (dark) d += `M${c + QUIET_ZONE} ${r + QUIET_ZONE}h1v1h-1z`;
    });
  });
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${sizePx}" height="${sizePx}" viewBox="0 0 ${total} ${total}" role="img" aria-label="Report verification QR code" shape-rendering="crispEdges"><rect width="${total}" height="${total}" fill="#FFFFFF"/><path d="${d}" fill="#0F172A"/></svg>`;
}

/** Async PNG data URL (for DOCX / PPTX image embedding). */
export async function qrPngDataUrl(text: string, width = 240): Promise<string> {
  return QRCode.toDataURL(text, {
    errorCorrectionLevel: 'M',
    margin: QUIET_ZONE,
    width,
    color: { dark: '#0F172AFF', light: '#FFFFFFFF' },
  });
}
