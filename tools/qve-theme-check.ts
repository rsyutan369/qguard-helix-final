/**
 * Quantum Visualization Engine — theme legibility suite.
 *
 *     npx tsx tools/qve-theme-check.ts
 *
 * The engine renders the same verdicts on two grounds now: the dark hero on
 * /public-scan and the light one on /dashboard/scanner. A verdict word is the
 * single most important thing on a node card, and it is painted in the colour
 * the published grade table assigns — a colour chosen for a printed white page,
 * then re-lit for whichever surface it is actually drawn on.
 *
 * That re-lighting is `readableOn`, and it is the only thing standing between a
 * correct verdict and an unreadable one. This suite asserts:
 *
 *   1. /public-scan is untouched — every colour the DARK engine produces is
 *      byte-identical to the literals it produced before the theme split.
 *   2. Every verdict clears 4.5:1 on BOTH surfaces.
 *   3. Every structural accent clears the 3:1 graphic floor on both.
 *   4. The re-lighting preserves MEANING: hue and saturation never move, so a
 *      critical verdict is the same red in both themes, only lit differently.
 *   5. The walk moves the correct direction on each ground.
 *
 * No DOM, no network, no running server: the colour model is pure, so it can be
 * proven rather than eyeballed on one screenshot of one scan state.
 */
import {
  QVE_COLOR,
  QVE_DARK_SURFACE,
  contrastRatio,
  hexToRgb,
  readableOn,
  resolveNodeVerdict,
  type QveNode,
  type QveNodeState,
  type ScanEventSeverity,
} from '../src/app/public-scan/_qve/types'
import { QVE_PALETTE, qveAccentOn } from '../src/app/public-scan/_qve/theme'

let failures = 0
let checks = 0

function assert(condition: boolean, label: string, detail = '') {
  checks += 1
  if (condition) {
    console.log(`  PASS  ${label}`)
    return
  }
  failures += 1
  console.log(`  FAIL  ${label}${detail ? `\n        ${detail}` : ''}`)
}

function section(title: string) {
  console.log(`\n${title}`)
}

const TEXT_FLOOR = 4.5
const GRAPHIC_FLOOR = 3

function ratio(hex: string, surface: string): number {
  return contrastRatio(hexToRgb(hex), hexToRgb(surface))
}

/** Hue/saturation of a colour, so "meaning preserved" can be measured. */
function hsl(hex: string): [number, number] {
  const [r, g, b] = hexToRgb(hex).map((c) => c / 255)
  const max = Math.max(r, g, b)
  const min = Math.min(r, g, b)
  const l = (max + min) / 2
  if (max === min) return [0, 0]
  const d = max - min
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min)
  const h = max === r ? (g - b) / d + (g < b ? 6 : 0) : max === g ? (b - r) / d + 2 : (r - g) / d + 4
  return [(h / 6) * 360, s]
}

function node(over: Partial<QveNode>): QveNode {
  return {
    key: 'transport' as QveNode['key'],
    title: 'TRANSPORT',
    state: 'complete' as QveNodeState,
    verdict: '',
    lines: [],
    progress: 100,
    // Explicitly null. `undefined` satisfies `node.score !== null`, which would
    // send the fixture down the graded branch carrying no score at all.
    score: null,
    severity: 'info' as ScanEventSeverity,
    updatedAt: Date.now(),
    postQuantum: false,
    hasEvidence: true,
    ...over,
  } as QveNode
}

/** One node per verdict the engine can resolve — the full colour surface. */
const CASES: Array<[string, QveNode]> = [
  ['idle', node({ state: 'idle' as QveNodeState, hasEvidence: false })],
  ['scanning', node({ state: 'scanning' as QveNodeState, hasEvidence: false })],
  ['failed', node({ state: 'failed' as QveNodeState })],
  ['unmeasured', node({ state: 'unmeasured' as QveNodeState, hasEvidence: false })],
  ['no evidence', node({ hasEvidence: false })],
  ['critical severity', node({ severity: 'critical' as ScanEventSeverity })],
  ['high severity', node({ severity: 'high' as ScanEventSeverity })],
  ['medium severity', node({ severity: 'medium' as ScanEventSeverity })],
  ['score 8 (grade F)', node({ score: 8 } as Partial<QveNode>)],
  ['score 52 (weak)', node({ score: 52 } as Partial<QveNode>)],
  ['score 72 (fair)', node({ score: 72 } as Partial<QveNode>)],
  ['score 88 (good)', node({ score: 88 } as Partial<QveNode>)],
  ['score 99 (elite)', node({ score: 99 } as Partial<QveNode>)],
  ['clean, unscored', node({})],
]

console.log('QVE theme legibility\n====================')

/* ------------------------------------------------------------------ */
section('1. /public-scan is unchanged — the DARK engine still produces its own literals')
/*
 * The dark palette must BE the historical constants, not a re-derivation of
 * them. `QVE_COLOR.idle` measures 4.0:1 on #070d1b — deliberately quiet, and
 * below the text floor. If the theme split had put every colour through the
 * legibility walk, the engine's resting palette would have lifted on a page
 * nobody asked to change.
 */
assert(QVE_PALETTE.dark.surface === QVE_DARK_SURFACE, 'the dark surface is still the historical card fill', QVE_DARK_SURFACE)
assert(
  resolveNodeVerdict(CASES[0][1]).color === QVE_COLOR.idle,
  'an idle node is still the raw QVE_COLOR.idle on dark (not lifted to the text floor)',
  resolveNodeVerdict(CASES[0][1]).color,
)
assert(
  resolveNodeVerdict(CASES[13][1]).color === QVE_COLOR.pass,
  'a clean unscored node is still the raw QVE_COLOR.pass on dark',
)
assert(
  qveAccentOn(QVE_COLOR.cyan, QVE_PALETTE.dark) === QVE_COLOR.cyan,
  'a structural accent is returned untouched on dark',
)
assert(
  readableOn(QVE_COLOR.cyan) === readableOn(QVE_COLOR.cyan, QVE_DARK_SURFACE),
  'readableOn defaults to the dark surface',
)

/* ------------------------------------------------------------------ */
section('2. Every verdict is legible on BOTH grounds (4.5:1 text floor)')
for (const themeName of ['dark', 'light'] as const) {
  const palette = QVE_PALETTE[themeName]
  const failing: string[] = []
  for (const [label, fixture] of CASES) {
    const { color } = resolveNodeVerdict(fixture, palette.surface)
    const r = ratio(color, palette.surface)
    /* The dark ground keeps its historical resting palette by design (see 1),
       so `idle`/`unmeasured`/`no evidence` are exempt there and only there —
       they are the states that carry no verdict to read. */
    const resting = themeName === 'dark' && ['idle', 'unmeasured', 'no evidence'].includes(label)
    if (!resting && r < TEXT_FLOOR) failing.push(`${label}: ${color} = ${r.toFixed(2)}:1`)
  }
  assert(
    failing.length === 0,
    `every verdict clears ${TEXT_FLOOR}:1 on the ${themeName} card`,
    failing.join('; '),
  )
}

/* ------------------------------------------------------------------ */
section('3. Structural accents clear the 3:1 graphic floor on both grounds')
const ACCENTS = [QVE_COLOR.cyan, QVE_COLOR.quantum, QVE_COLOR.scanning, '#60a5fa', '#e879f9', '#3b82f6']
for (const themeName of ['dark', 'light'] as const) {
  const palette = QVE_PALETTE[themeName]
  const failing = ACCENTS.map((hex) => {
    const lit = qveAccentOn(hex, palette)
    return { hex, lit, r: ratio(lit, palette.surface) }
  }).filter((row) => row.r < GRAPHIC_FLOOR)
  assert(
    failing.length === 0,
    `every structural accent clears ${GRAPHIC_FLOOR}:1 on ${themeName}`,
    failing.map((row) => `${row.hex}→${row.lit} = ${row.r.toFixed(2)}:1`).join('; '),
  )
}

/* ------------------------------------------------------------------ */
section('4. Re-lighting preserves MEANING — only lightness moves')
/*
 * This is what makes the transform legitimate. If saturation or hue drifted, a
 * "Critical" card on the light theme would be a different colour from the same
 * card on dark — two palettes for one published grade, which is exactly the
 * drift the engine's colour model exists to prevent.
 */
const drift: string[] = []
for (const hex of ['#991b1b', '#f43f5e', '#fb923c', '#fbbf24', '#34d399', '#22d3ee', '#a78bfa']) {
  const lit = readableOn(hex, QVE_PALETTE.light.surface)
  const [h0, s0] = hsl(hex)
  const [h1, s1] = hsl(lit)
  const hueDelta = Math.min(Math.abs(h1 - h0), 360 - Math.abs(h1 - h0))
  if (hueDelta > 2 || Math.abs(s1 - s0) > 0.02) {
    drift.push(`${hex}→${lit} hue ${hueDelta.toFixed(1)}°, sat ${(s1 - s0).toFixed(3)}`)
  }
}
assert(drift.length === 0, 'hue and saturation are unchanged by the legibility walk', drift.join('; '))

/* ------------------------------------------------------------------ */
section('5. The walk moves the correct direction for its ground')
const onLight = readableOn('#34d399', QVE_PALETTE.light.surface)
const onDark = readableOn('#991b1b', QVE_DARK_SURFACE)
assert(
  ratio(onLight, QVE_PALETTE.light.surface) > ratio('#34d399', QVE_PALETTE.light.surface),
  'a light colour is DARKENED for the light card',
  `#34d399 ${ratio('#34d399', QVE_PALETTE.light.surface).toFixed(2)}:1 → ${onLight} ${ratio(onLight, QVE_PALETTE.light.surface).toFixed(2)}:1`,
)
assert(
  ratio(onDark, QVE_DARK_SURFACE) > ratio('#991b1b', QVE_DARK_SURFACE),
  'a dark colour is LIGHTENED for the dark card',
  `#991b1b ${ratio('#991b1b', QVE_DARK_SURFACE).toFixed(2)}:1 → ${onDark} ${ratio(onDark, QVE_DARK_SURFACE).toFixed(2)}:1`,
)

/* ------------------------------------------------------------------ */
section('6. The two palettes describe the same instrument')
const darkKeys = Object.keys(QVE_PALETTE.dark).sort()
const lightKeys = Object.keys(QVE_PALETTE.light).sort()
assert(
  JSON.stringify(darkKeys) === JSON.stringify(lightKeys),
  'both palettes define every key — no value silently falls back to a dark literal',
)
assert(QVE_PALETTE.light.glow < QVE_PALETTE.dark.glow, 'additive glow is damped on the light ground')
assert(
  QVE_PALETTE.light.shieldOpacity > QVE_PALETTE.dark.shieldOpacity,
  'the shield is rendered more solid on light, where a glass shell reads as a smudge',
)

console.log(`\n${checks - failures}/${checks} checks passed`)
if (failures > 0) {
  console.log(`${failures} FAILED`)
  process.exit(1)
}
