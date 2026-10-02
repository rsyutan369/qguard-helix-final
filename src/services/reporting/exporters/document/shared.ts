/**
 * Shared helpers for the enterprise document renderers (PDF, Word, Excel,
 * PowerPoint, HTML, CSV). Everything format-neutral lives here so the seven
 * renderers cannot drift on colours, ordering or wording.
 */
import type { InventoryReport } from '../../InventoryReport'
import type { BlockTone, DocumentSection, ReportDocument } from '../../ReportDocument'
import { TONE_HEX } from '../../ReportDocument'
import { reportVerificationUrl } from '../../ReportQr'

export type DocumentFormat = 'pdf' | 'docx' | 'xlsx' | 'pptx' | 'html' | 'csv' | 'json'

export const DOCUMENT_MIME: Record<DocumentFormat, string> = {
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  html: 'text/html',
  csv: 'text/csv',
  json: 'application/json',
}

/** Brand + ink palette shared with the Quantum Readiness report family. */
export const INK = '#0F172A'
export const INK_SOFT = '#334155'
export const MUTED = '#64748B'
export const LINE = '#E2E8F0'
export const BAND = '#F8FAFC'
export const BRAND = '#2478FF'
export const HEADER_BG = '#0F172A'

export function toneHex(tone: BlockTone | undefined): string {
  return TONE_HEX[tone || 'neutral'] || TONE_HEX.neutral
}

/** A lighter wash of a hex colour (for callout backgrounds), as hex. */
export function tint(hex: string, amount = 0.9): string {
  const clean = hex.replace('#', '')
  const channel = (i: number) => parseInt(clean.slice(i, i + 2), 16)
  const mix = (value: number) => Math.round(value + (255 - value) * amount)
  const out = [mix(channel(0)), mix(channel(2)), mix(channel(4))]
  return `#${out.map((v) => v.toString(16).padStart(2, '0')).join('').toUpperCase()}`
}

export function hexToRgb01(hex: string): [number, number, number] {
  const clean = hex.replace('#', '')
  return [parseInt(clean.slice(0, 2), 16) / 255, parseInt(clean.slice(2, 4), 16) / 255, parseInt(clean.slice(4, 6), 16) / 255]
}

export function noHash(hex: string): string {
  return hex.replace('#', '').toUpperCase()
}

export function dataUrlToBytes(dataUrl: string): Uint8Array {
  const base64 = dataUrl.split(',')[1] || ''
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
  return bytes
}

/** The raster kind a logo data URL carries, or null when no renderer can embed it. */
export function imageKind(dataUrl: string | null | undefined): 'png' | 'jpg' | null {
  if (!dataUrl) return null
  if (/^data:image\/png/i.test(dataUrl)) return 'png'
  if (/^data:image\/jpe?g/i.test(dataUrl)) return 'jpg'
  return null
}

/** Intrinsic PNG/JPEG size, for aspect-correct logos. */
export function imageSize(bytes: Uint8Array, kind: 'png' | 'jpg'): { width: number; height: number } | null {
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    if (kind === 'png') {
      if (bytes.length < 24 || bytes[0] !== 0x89) return null
      return { width: view.getUint32(16), height: view.getUint32(20) }
    }
    // JPEG: walk segments to the first SOFn marker.
    let offset = 2
    while (offset + 9 < bytes.length) {
      if (bytes[offset] !== 0xff) return null
      const marker = bytes[offset + 1]
      const length = view.getUint16(offset + 2)
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return { height: view.getUint16(offset + 5), width: view.getUint16(offset + 7) }
      }
      offset += 2 + length
    }
  } catch {
    /* unreadable header */
  }
  return null
}

export function fitBox(size: { width: number; height: number } | null, maxW: number, maxH: number) {
  if (!size || !size.width || !size.height) return { width: maxW, height: maxH }
  const scale = Math.min(maxW / size.width, maxH / size.height)
  return { width: Math.round(size.width * scale), height: Math.round(size.height * scale) }
}

/** Contents entries in reading order — every renderer uses the same list. */
export function contentsEntries(doc: ReportDocument): Array<{ id: string; title: string }> {
  return [
    { id: 'executive-summary', title: 'Executive Summary' },
    ...doc.sections.map((section: DocumentSection) => ({ id: section.id, title: section.title })),
    ...(doc.decisions.length ? [{ id: 'decisions', title: 'Executive Decision Register' }] : []),
    { id: 'validation', title: 'Validation, Reconciliation & Integrity' },
  ]
}

export function verificationUrl(report: InventoryReport): string | null {
  return reportVerificationUrl({ integrity: report.integrity })
}

/** File name: qguard-<slug>-<scope>-<date>-v<version>.<ext>. */
export function documentFilename(report: InventoryReport, format: DocumentFormat): string {
  const stamp = new Date(report.meta.generatedAt).toISOString().slice(0, 10)
  const slug = report.meta.filenameSlug || 'report'
  const version = report.meta.version ? `-v${report.meta.version.replace(/[^0-9a-z.]+/gi, '')}` : ''
  return `qguard-${slug}-${stamp}${version}.${format}`
}

/** "1 component" / "3 components" — a unit written plural is singularised for one. */
export function countLabel(value: number, unit?: string): string {
  const n = value.toLocaleString('en-US')
  if (!unit) return n
  return `${n} ${value === 1 && unit.endsWith('s') ? unit.slice(0, -1) : unit}`
}

export function percentOf(value: number, total: number): string {
  return total > 0 ? `${Math.round((value / total) * 1000) / 10}%` : '—'
}

export function utc(value: string | null | undefined): string {
  if (!value) return 'Not recorded'
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC` : 'Not recorded'
}

export const VALIDATION_LABEL = { pass: 'PASS', warn: 'WARN', fail: 'FAIL' } as const
