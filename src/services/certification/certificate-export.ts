import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import type { QuantumTrustCertificate } from '@/types/quantum-certification';

/**
 * Quantum Trust Certificate export utilities.
 *
 * The certificate is a self-contained SVG (no external assets), so every export
 * derives losslessly from the live DOM SVG element:
 *  - SVG  → XMLSerializer markup
 *  - PNG  → rasterised via an offscreen canvas (never tainted — all inline)
 *  - PDF  → pdf-lib landscape page embedding the rasterised PNG
 *  - JSON → machine-readable certificate + integrity metadata
 *  - Audit package → JSON supplied by the backend /package endpoint
 */

function svgMarkup(svg: SVGSVGElement): string {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  if (!clone.getAttribute('width')) clone.setAttribute('width', '1012');
  if (!clone.getAttribute('height')) clone.setAttribute('height', '812');
  return new XMLSerializer().serializeToString(clone);
}

export function certificateSvgString(svg: SVGSVGElement): string {
  return `<?xml version="1.0" encoding="UTF-8"?>\n${svgMarkup(svg)}`;
}

/** Rasterise the certificate SVG to a PNG data URL at the given pixel scale. */
export async function certificatePngDataUrl(svg: SVGSVGElement, scale = 2): Promise<string> {
  const markup = svgMarkup(svg);
  const svgBlob = new Blob([markup], { type: 'image/svg+xml;charset=utf-8' });
  const url = URL.createObjectURL(svgBlob);
  try {
    const image = await new Promise<HTMLImageElement>((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error('Failed to rasterise certificate SVG'));
      img.src = url;
    });
    const width = 1012 * scale;
    const height = 812 * scale;
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('Canvas 2D context unavailable');
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, width, height);
    ctx.drawImage(image, 0, 0, width, height);
    return canvas.toDataURL('image/png');
  } finally {
    URL.revokeObjectURL(url);
  }
}

function dataUrlToBytes(dataUrl: string): Uint8Array {
  const base64 = dataUrl.split(',')[1] || '';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export async function exportCertificateSvg(svg: SVGSVGElement, certificate: QuantumTrustCertificate): Promise<void> {
  const blob = new Blob([certificateSvgString(svg)], { type: 'image/svg+xml;charset=utf-8' });
  downloadBlob(blob, `${certificate.certificateId}.svg`);
}

export async function exportCertificatePng(svg: SVGSVGElement, certificate: QuantumTrustCertificate): Promise<void> {
  const dataUrl = await certificatePngDataUrl(svg, 2);
  const blob = await (await fetch(dataUrl)).blob();
  downloadBlob(blob, `${certificate.certificateId}.png`);
}

/** Enterprise PDF: the certificate on a landscape page + a verification footer page. */
export async function exportCertificatePdf(svg: SVGSVGElement, certificate: QuantumTrustCertificate): Promise<void> {
  const pngDataUrl = await certificatePngDataUrl(svg, 2);
  const doc = await PDFDocument.create();
  doc.setTitle(`Quantum Trust Certificate — ${certificate.organization}`);
  doc.setAuthor('QGuard Helix — Quantum Trust Certification Engine');
  doc.setSubject(`Certificate ${certificate.certificateId}`);
  doc.setProducer('QGuard Helix');

  // Landscape A4-ish page sized to the certificate aspect ratio (1012:812).
  const pageWidth = 842;
  const pageHeight = 674;
  const page = doc.addPage([pageWidth, pageHeight]);
  const png = await doc.embedPng(dataUrlToBytes(pngDataUrl));
  const margin = 16;
  const drawW = pageWidth - margin * 2;
  const drawH = (drawW * 812) / 1012;
  page.drawImage(png, { x: margin, y: (pageHeight - drawH) / 2, width: drawW, height: drawH });

  // Verification / integrity metadata page.
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);
  const meta = doc.addPage([595, 842]);
  const ink = rgb(0.04, 0.1, 0.23);
  const soft = rgb(0.23, 0.29, 0.4);
  let y = 780;
  meta.drawText('Quantum Trust Certificate — Verification Record', { x: 48, y, size: 16, font: bold, color: ink });
  y -= 34;
  const lines: Array<[string, string]> = [
    ['Certificate ID', certificate.certificateId],
    ['Organization', certificate.organization],
    ['Certification Level', `${certificate.levelLabel} (${certificate.level.toUpperCase()})`],
    ['Quantum Trust Score', `${certificate.trustScore}/1000`],
    ['Status', certificate.status.toUpperCase()],
    ['Issued', new Date(certificate.issuedAt).toUTCString()],
    ['Expires', new Date(certificate.expiresAt).toUTCString()],
    ['Overall Readiness', `${certificate.overallReadiness}%`],
    ['PQC Adoption', `${certificate.pqcAdoption}%`],
    ['Residual Risk', certificate.residualRiskLevel],
    ['Assessment Version', certificate.assessmentVersion],
    ['Verification URL', certificate.verificationUrl],
    ['Signature Algorithm', certificate.signature?.algorithm || 'ML-DSA-65 (FIPS 204)'],
  ];
  for (const [label, value] of lines) {
    meta.drawText(`${label}:`, { x: 48, y, size: 10, font: bold, color: soft });
    meta.drawText(value.length > 62 ? `${value.slice(0, 61)}…` : value, { x: 190, y, size: 10, font, color: ink });
    y -= 20;
  }
  y -= 10;
  meta.drawText('Certificate Hash (SHA3-256):', { x: 48, y, size: 10, font: bold, color: soft });
  y -= 16;
  const hash = certificate.certificateHash;
  meta.drawText(hash.slice(0, 64), { x: 48, y, size: 8, font, color: ink });
  if (hash.length > 64) {
    y -= 12;
    meta.drawText(hash.slice(64), { x: 48, y, size: 8, font, color: ink });
  }
  y -= 30;
  const notes = [
    'This certificate is issued by the QGuard Helix Quantum Trust Certification Engine only when',
    'every published eligibility criterion is met by measured assessment evidence. Certification is',
    'computed from evidence, never asserted, and is continuously re-validated: any post-quantum',
    'drift automatically suspends the certificate.',
    '',
    'To verify authenticity: recompute SHA3-256 over the canonical (sorted-key JSON) payload and',
    'confirm it equals the certificate hash, or visit the public verification portal above and look',
    'up the certificate ID — the portal verifies the ML-DSA-65 signature live on every request.',
  ];
  for (const note of notes) {
    meta.drawText(note, { x: 48, y, size: 9, font, color: soft });
    y -= 14;
  }

  const bytes = await doc.save();
  downloadBlob(new Blob([bytes], { type: 'application/pdf' }), `${certificate.certificateId}.pdf`);
}

export function exportCertificateJson(certificate: QuantumTrustCertificate): void {
  const machine = {
    format: 'qguard-helix-quantum-trust-certificate/1.0',
    certificate,
    verification: {
      url: certificate.verificationUrl,
      hashAlgorithm: 'SHA3-256',
      signatureAlgorithm: certificate.signature?.algorithm || 'ML-DSA-65',
      instructions: 'Recompute SHA3-256 over the canonical payload; verify the ML-DSA-65 signature with the issuer public key or the public verification portal.',
    },
    exportedAt: new Date().toISOString(),
  };
  const blob = new Blob([JSON.stringify(machine, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `${certificate.certificateId}.json`);
}

export function exportAuditPackage(pkg: Record<string, unknown>, certificateId: string): void {
  const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `${certificateId}-audit-package.json`);
}
