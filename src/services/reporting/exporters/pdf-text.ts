/**
 * WinAnsi text sanitisation for pdf-lib — ONE implementation, every PDF writer.
 *
 * pdf-lib's `StandardFonts` (Helvetica, Courier, …) encode with WinAnsi
 * (CP1252). Any code point outside Latin-1 throws at draw time:
 *
 *     Error: WinAnsi cannot encode "→" (0x2192)
 *
 * That is a HARD failure — the whole export dies, not just the offending cell —
 * and the text it dies on is evidence-derived, so it cannot be predicted from
 * the code. Real examples from this platform: `pqcReplacement` values shaped
 * "RSA-2048 → ML-KEM-768", advisor prose using ≥ / ≤, and product names carrying
 * ™. The fix is to map the common glyphs to ASCII and drop the rest.
 *
 * This lived as a private `san()` inside `PdfExporter.ts`, so the inventory
 * exporter added later drew unsanitised text and crashed on the first asset
 * whose recommendation contained an arrow. Shared here so a new PDF writer
 * cannot repeat that: import this, never re-implement it.
 *
 * Embedding a Unicode TTF via fontkit would preserve the glyphs, but it costs a
 * ~300KB font asset in the bundle for characters that carry no information an
 * ASCII equivalent loses.
 */

/**
 * Make a string safe for a WinAnsi standard font.
 *
 * Substitutions preserve meaning ("→" -> "->"), and anything still outside
 * Latin-1 is dropped rather than replaced with a placeholder, so a stray glyph
 * never becomes visible noise in a customer-facing register.
 */
export function sanitizeForWinAnsi(value: unknown): string {
  return String(value ?? '')
    .replace(/[→⇒➔➜]/g, '->')
    .replace(/[←⇐]/g, '<-')
    .replace(/[↔⇔]/g, '<->')
    .replace(/[↑⇑]/g, '^')
    .replace(/[↓⇓]/g, 'v')
    .replace(/™/g, '(TM)')
    .replace(/®/g, '(R)')
    .replace(/©/g, '(C)')
    .replace(/[•·]/g, '-')
    .replace(/[–—]/g, '-')
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/…/g, '...')
    .replace(/≥/g, '>=')
    .replace(/≤/g, '<=')
    .replace(/≠/g, '!=')
    .replace(/[✓✔]/g, 'Yes')
    .replace(/[✗✘×]/g, 'x')
    .replace(/[≈~]/g, '~')
    .replace(/°/g, ' deg')
    .replace(/ /g, ' ')
    // Tabs and newlines have no meaning inside a single drawText run and render
    // as garbage boxes; collapse them before the Latin-1 filter.
    .replace(/[\t\r\n]+/g, ' ')
    // eslint-disable-next-line no-control-regex
    .replace(/[^\x20-\xFF]/g, '')
}
