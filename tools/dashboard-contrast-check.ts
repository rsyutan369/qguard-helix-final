/**
 * Dashboard contrast integrity — nothing may be styled for one theme only.
 *
 *     npx tsx tools/dashboard-contrast-check.ts
 *
 * The dashboards were dark-only for most of their life, so panels hardcode
 * near-black backgrounds (`bg-[#0a0f1a]`) and light-end foregrounds
 * (`text-white/30`, `text-slate-200`). When the light theme shipped, the page
 * background flipped but those panels did not: a card stayed black on a white
 * page, and its labels stayed near-white — invisible.
 *
 * Two things keep that from recurring:
 *
 *  1. A light-theme compatibility layer in `src/index.css` remaps the known
 *     dark-only utilities inside `.qg-dashboard-main`. This suite asserts the
 *     layer still covers every dark surface the dashboards actually use — add a
 *     new `bg-[#0b1120]`-style panel and the layer must learn about it.
 *
 *  2. Semantic notice tokens (`--qg-notice-*`) exist so a warning banner is
 *     never painted with a foreground that only works on one ground. The stale
 *     assessment banner shipped as amber-100 on an amber wash: legible on dark,
 *     invisible on light.
 *
 * The escape hatch is `qg-force-dark` — put it on anything deliberately dark in
 * BOTH themes (a terminal, a code block, a dark visualisation).
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const css = readFileSync('src/index.css', 'utf8')

/** Relative luminance (WCAG). Below ~0.22 reads as a dark surface. */
function luminance(hex: string): number {
  const r = parseInt(hex.slice(0, 2), 16)
  const g = parseInt(hex.slice(2, 4), 16)
  const b = parseInt(hex.slice(4, 6), 16)
  return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255
}

function walk(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) out.push(...walk(full))
    else if (entry.endsWith('.tsx')) out.push(full)
  }
  return out
}

/*
 * `src/app/dashboard` alone was NOT enough, and the gap cost a whole page.
 *
 * /dashboard/scanner and the Crypto Exposure tabs are drawn almost entirely by
 * SHARED atoms that live outside that tree — `components/quantum-scan/ui.tsx`
 * (the `Panel` every card on the page is made of) and `components/exposure/*`.
 * This suite never read them, so the dark fills they introduce were invisible
 * to it and the light-theme layer was never asked to cover them.
 *
 * Any directory whose components render inside `.qg-dashboard-main` belongs
 * here, not just the route files.
 */
const files = [
  ...walk('src/app/dashboard'),
  ...walk('src/components/exposure'),
  ...walk('src/components/quantum-scan'),
]

/* ------------------------------------------------------------------ */
console.log('\n[1] Semantic notice tokens exist for BOTH themes')
for (const token of ['--qg-notice-bg', '--qg-notice-border', '--qg-notice-text', '--qg-notice-text-soft']) {
  const uses = css.split(token).length - 1
  assert(uses >= 2, `${token} is defined in the dark AND light theme blocks`, `${uses} definition(s)`)
}
assert(
  /html\.qg-theme-light[\s\S]*?--qg-notice-text:\s*#[0-9a-f]{6}/i.test(css),
  'the light theme defines a DARK notice foreground (not a light one on a light wash)',
)

/* ------------------------------------------------------------------ */
console.log('\n[2] Near-white semantic foregrounds are legible in light mode')
/*
 * `text-amber-100` on an amber wash reads on a dark ground and disappears on
 * the pale wash the light theme paints. Forty-eight banners across the
 * dashboards carry that pattern, so it is corrected in the LAYER rather than
 * rewritten at forty-eight call sites: every hue's light end (50/100/200)
 * flips to its dark end, which keeps the semantic colour (a warning still
 * reads amber) while restoring contrast.
 *
 * The SHARED shell is held to the higher standard. It drives thirteen pages, so
 * it paints from the semantic tokens directly rather than relying on the remap.
 */
const shell = readFileSync('src/app/dashboard/quantum-readiness/_shared.tsx', 'utf8')
assert(
  !/text-amber-(50|100|200)\b/.test(shell),
  'the shared Quantum Readiness shell uses --qg-notice-* tokens, not a near-white amber',
)
assert(
  shell.includes('bg-[var(--qg-notice-bg)]') && shell.includes('text-[var(--qg-notice-text)]'),
  'its banners are painted from the semantic notice tokens',
)

const tintLayer = css.slice(css.indexOf('Near-white SEMANTIC tints'))
const uncoveredHues = ['amber', 'red', 'emerald', 'orange', 'yellow', 'green', 'cyan', 'blue', 'violet', 'rose']
  .filter((hue) => !tintLayer.includes(`.text-${hue}-100`))
assert(
  uncoveredHues.length === 0,
  'every semantic hue used for status has its near-white end remapped for light mode',
  uncoveredHues.join(', ') || '16 hues covered',
)

/* ------------------------------------------------------------------ */
console.log('\n[3] Every hardcoded dark surface is covered by the light layer')

const layerStart = css.indexOf('LIGHT THEME — dashboard CONTENT compatibility layer')
assert(layerStart > 0, 'the light-theme content compatibility layer is present')
const layer = layerStart > 0 ? css.slice(layerStart) : ''

const darkHexes = new Set<string>()
for (const file of files) {
  const text = readFileSync(file, 'utf8')
  for (const m of text.matchAll(/bg-\[#([0-9a-fA-F]{6})\]/g)) {
    if (luminance(m[1]) < 0.22) darkHexes.add(m[1])
  }
}

/*
 * Coverage is asserted against the class AS THE MARKUP WRITES IT, not against
 * the bare hex.
 *
 * The original assertion looked for `.bg-\[\#080d1a\]` — the exact-utility
 * form — and passed, while the page it was meant to protect rendered black in
 * light mode. `bg-[#080d1a]/80` is a DIFFERENT class name: an opacity modifier
 * makes Tailwind emit its own utility, which `.bg-\[\#080d1a\]` does not
 * match. Two thirds of the dark fills in the dashboards carry a modifier, so
 * the check was green on a layer that reached almost none of them.
 *
 * The layer now matches `[class*="bg-[#hex]"]`, which covers the plain fill,
 * every `/alpha` variant and any variant prefix. This asserts that form.
 */
const covers = (h: string) => layer.includes(`[class*="bg-[#${h}]"]`)
const uncovered = [...darkHexes].filter((h) => !covers(h))
assert(
  uncovered.length === 0,
  'every dark background hex used by a dashboard is remapped for light mode',
  uncovered.length ? `uncovered: ${uncovered.map((h) => '#' + h).join(', ')}` : `${darkHexes.size} covered`,
)

/* The specific regression above: a dark fill written WITH an opacity modifier
   must be matched by a selector that can actually see it. */
const modifiedDarkHexes = new Set<string>()
for (const file of files) {
  const text = readFileSync(file, 'utf8')
  for (const m of text.matchAll(/bg-\[#([0-9a-fA-F]{6})\]\/\d+/g)) {
    if (luminance(m[1]) < 0.22) modifiedDarkHexes.add(m[1])
  }
}
const exactOnly = [...modifiedDarkHexes].filter((h) => !covers(h))
assert(
  exactOnly.length === 0,
  'dark fills carrying an opacity modifier (bg-[#hex]/80) are matched as a substring, not as an exact utility class',
  exactOnly.length
    ? `exact-class only: ${exactOnly.map((h) => '#' + h).join(', ')}`
    : `${modifiedDarkHexes.size} modifier-form fill(s) covered`,
)

/* ------------------------------------------------------------------ */
console.log('\n[4] The layer remaps the dark-only foreground ramps')
for (const [rule, why] of [
  ['text-white/8', 'near-opaque white body text'],
  ['text-white/3', 'muted white label text'],
  ['border-white/', 'hairline borders drawn for a dark ground'],
  ['.text-slate-100', 'the light end of the slate ramp (Sophia)'],
  ['.text-slate-300', 'the mid-light end of the slate ramp'],
  ['.bg-slate-900', 'dark slate panel fills'],
] as const) {
  assert(layer.includes(rule), `remaps ${why}`, rule)
}

/* ------------------------------------------------------------------ */
console.log('\n[5] Saturated chips keep their white foreground')
/*
 * Rule 2 of the layer must not reach inside a solid coloured chip: white on
 * #8b2aff is correct in both themes, and remapping it to dark text would break
 * contrast in the other direction.
 */
const colouredHexes = new Set<string>()
for (const file of files) {
  const text = readFileSync(file, 'utf8')
  for (const m of text.matchAll(/bg-\[#([0-9a-fA-F]{6})\]/g)) {
    if (luminance(m[1]) >= 0.22) colouredHexes.add(m[1])
  }
}
const unprotected = [...colouredHexes].filter(
  (h) => !layer.includes(`.bg-\\[\\#${h}\\] [class*="text-white"]`),
)
assert(
  unprotected.length === 0,
  'every saturated chip background re-asserts white text',
  unprotected.length ? `unprotected: ${unprotected.map((h) => '#' + h).join(', ')}` : `${colouredHexes.size} protected`,
)

/* ------------------------------------------------------------------ */
console.log('\n[6] The escape hatch exists and is honoured')
assert(layer.includes('qg-force-dark'), 'a `qg-force-dark` opt-out is documented in the layer')
assert(
  (layer.match(/:not\(\.qg-force-dark\)/g) || []).length >= 6,
  'every remap rule excludes the opt-out',
  `${(layer.match(/:not\(\.qg-force-dark\)/g) || []).length} rule(s)`,
)

/*
 * The hatch has to hold in BOTH light layers.
 *
 * There are two: this one, scoped to `.qg-dashboard-main`, and an older one
 * scoped to `.dashboard-theme-scope` further up the sheet. Only this one
 * carried the guard, so a `qg-force-dark` subtree still had its foreground
 * inverted by the older layer — the scanner hero's `text-white` heading
 * rendered near-black on the dark stage it is deliberately painted on. An
 * escape hatch that only half the sheet honours is not an escape hatch.
 */
const olderLayer = css.slice(
  css.indexOf('.qg-theme-light .dashboard-theme-scope'),
  css.indexOf('LIGHT THEME — dashboard CONTENT compatibility layer'),
)
const unguardedUtilityRemaps = olderLayer
  .split('\n')
  .filter((l) => l.trim().startsWith('.qg-theme-light .dashboard-theme-scope '))
  .filter((l) => l.includes('[class*=') || /\.dashboard-theme-scope \.(text|bg|border|divide|ring|placeholder)-/.test(l))
  .filter((l) => !l.includes('::'))
  .filter((l) => !l.includes(':not(.qg-force-dark)'))
assert(
  unguardedUtilityRemaps.length === 0,
  'the OLDER .dashboard-theme-scope light layer honours the same opt-out',
  unguardedUtilityRemaps.length
    ? `${unguardedUtilityRemaps.length} unguarded: ${unguardedUtilityRemaps[0].trim().slice(0, 70)}…`
    : 'all utility remaps guarded',
)

/* ------------------------------------------------------------------ */
console.log('\n[7] The layer is scoped — it cannot leak into dark mode or chrome')
const badScope = layer
  .split('\n')
  .filter((l) => l.trim().startsWith('.') && !l.includes('.qg-theme-light'))
assert(
  badScope.length === 0,
  'every selector in the layer is scoped to .qg-theme-light',
  badScope.slice(0, 3).join(' | ') || 'all scoped',
)
assert(
  !layer.includes('.qg-dashboard-sidebar'),
  'the content layer does not restyle the sidebar (that has its own rules)',
)

console.log(
  failures === 0
    ? '\n✓ CONTRAST INTEGRITY HOLDS — no surface is styled for one theme only\n'
    : `\n${failures} CHECK(S) FAILED ✗\n`,
)
process.exit(failures === 0 ? 0 : 1)
