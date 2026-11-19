export const CSV_FORMULA_PREFIX = /^\s*[=+\-@＝＋－＠\t\r\n]/u

/**
 * Spreadsheet readers can interpret a quoted CSV value as a formula. Prefix
 * formula-like text before escaping delimiters and keep numeric inputs numeric.
 */
export function csvText(value: unknown): string {
  const text = String(value ?? '')
  return typeof value !== 'number' && CSV_FORMULA_PREFIX.test(text)
    ? "'" + text
    : text
}

function quote(text: string): string {
  return '"' + text.replaceAll('"', '""') + '"'
}

export function csvCell(value: unknown): string {
  const text = csvText(value)
  return /[",\r\n]/.test(text) ? quote(text) : text
}

export function quotedCsvCell(value: unknown): string {
  return quote(csvText(value))
}

