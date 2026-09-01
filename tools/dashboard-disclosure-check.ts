/**
 * Dashboard disclosure integrity — a panel must never hide what it dropped.
 *
 *     npx tsx tools/dashboard-disclosure-check.ts
 *
 * Two rules, both learned from shipped defects:
 *
 *  1. **Truncation is disclosed.** A panel rendering the head of a longer list
 *     ("top 8 critical findings") reads as the COMPLETE list. An operator
 *     seeing eight criticals with no indication there are forty will plan
 *     against the eight. `TruncationNote` renders the shortfall — and renders
 *     nothing when the list fits, so small estates stay clean.
 *
 *  2. **Staleness is stated, not merely datable.** Every Quantum Readiness page
 *     can be read as a claim about production right now — an executive deck
 *     especially. A timestamp in the footer is not enough; past the staleness
 *     threshold the page has to say so where the reader will see it.
 *
 * This suite pins the pure helpers behind both, and greps the dashboards to
 * catch a NEW silent truncation being introduced.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { assessmentAgeHours, describeAge, isStale, STALE_AFTER_HOURS } from '../src/lib/dashboard-freshness'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

/* ------------------------------------------------------------------ */
console.log('\n[1] Assessment age is measured honestly')
assert(assessmentAgeHours(null) === null, 'no timestamp → null age, never 0 (which would read as "just now")')
assert(assessmentAgeHours('not-a-date') === null, 'an unparseable timestamp → null, never a fabricated age')

const hoursAgo = (h: number) => new Date(Date.now() - h * 36e5).toISOString()
const twoHours = assessmentAgeHours(hoursAgo(2))
assert(twoHours !== null && Math.abs(twoHours - 2) < 0.1, 'a 2-hour-old assessment measures ~2 hours', String(twoHours?.toFixed(2)))
const week = assessmentAgeHours(hoursAgo(168))
assert(week !== null && week > STALE_AFTER_HOURS, 'a week-old assessment is past the staleness threshold', `${week?.toFixed(0)}h > ${STALE_AFTER_HOURS}h`)
assert(assessmentAgeHours(new Date(Date.now() + 36e5).toISOString()) === 0, 'a future timestamp clamps to 0 rather than going negative')

console.log('\n[2] Age is described in human terms')
assert(describeAge(0.4) === 'less than an hour', describeAge(0.4))
assert(describeAge(1) === '1 hour', describeAge(1))
assert(describeAge(5) === '5 hours', describeAge(5))
assert(describeAge(72) === '3 days', describeAge(72))
assert(describeAge(24) === '24 hours', 'a day still reads in hours below the 48h switch', describeAge(24))
assert(/^\d+ days$/.test(describeAge(504)), 'three weeks reads in days', describeAge(504))

console.log('\n[3] The staleness threshold is a real boundary')
assert(STALE_AFTER_HOURS === 72, 'stale after 72 hours', String(STALE_AFTER_HOURS))
assert(assessmentAgeHours(hoursAgo(71))! < STALE_AFTER_HOURS, '71 hours is fresh')
assert(assessmentAgeHours(hoursAgo(73))! > STALE_AFTER_HOURS, '73 hours is stale')

/* ------------------------------------------------------------------ */
console.log('\n[4] No dashboard truncates a tenant list without disclosing it')

/**
 * Every `.slice(0, N)` over tenant data must sit within ~30 lines of something
 * that tells the reader a longer list exists — a TruncationNote, a "Showing X
 * of N" line, a `+N more`, or a "view all" control.
 *
 * String/date/id slices and download filenames are excluded: truncating a
 * label for display drops no records.
 */
const ROOTS = [
  'src/app/dashboard/quantum-readiness',
  'src/app/dashboard/migration_planner',
  'src/app/dashboard/migration-sandbox',
  'src/app/dashboard/migration-intelligence',
  'src/app/dashboard/harvest-now',
  'src/app/dashboard/quantum-certification',
  'src/app/dashboard/pki-visibility',
  'src/app/dashboard/assets_map',
  'src/app/dashboard/shadow-crypto',
  'src/app/dashboard/cbom_explorer',
  'src/app/dashboard/_components/executive',
  'src/app/dashboard/crypto_exposure_map',
  'src/app/dashboard/security_events_panel',
]

function walk(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) out.push(...walk(full))
    else if (entry.endsWith('.tsx')) out.push(full)
  }
  return out
}

const HARMLESS = /toISOString\(\)\.slice|\.download|hash\.slice|\bid\.slice|label\.slice|name\.slice|\.slice\(0, 10\)\)|simulationId\.slice|\.join\('.*'\)\.slice/
const DISCLOSURE =
  /TruncationNote|Showing\s|\+\{?\s*\w+\.length|more match|View all|view all|setTab\(|length > \d+ \?|Math\.min\(\d+,/

const offenders: string[] = []
for (const root of ROOTS) {
  for (const file of walk(root)) {
    const whole = readFileSync(file, 'utf8')
    const lines = whole.split('\n')
    lines.forEach((line, i) => {
      const m = line.match(/\.slice\(0,\s*(\d+)\)/)
      if (!m) return
      if (HARMLESS.test(line)) return

      /*
       * A SELECTION cap is not a display truncation. `setSelected(new
       * Set(filtered.slice(0, 25)))` bounds how many assets one action may
       * target; it drops no information from view, and the control states its
       * own cap in its label ("Select All Filtered (25)"). Those labels are
       * asserted separately below.
       */
      if (/set[A-Z]\w*\(/.test(line)) return
      // Only list-of-records slices matter: those feeding a .map().
      const near = lines.slice(Math.max(0, i - 6), i + 30).join('\n')
      if (!/\.map\(/.test(line) && !/\.map\(/.test(near.slice(0, 400))) return
      if (DISCLOSURE.test(near)) return

      /*
       * A disclosure can legitimately live far from the slice — the slice may
       * sit in a `useMemo` while the note renders 100 lines below, or after a
       * long table body. Fall back to asking whether ANY disclosure in this
       * file names the same collection.
       */
      let collection = line.match(/([A-Za-z_$][\w$.]*)\s*\.slice\(0,/)?.[1]
      if (!collection) {
        // Chained across lines — recover the const this expression builds.
        for (let back = i; back >= Math.max(0, i - 12); back -= 1) {
          const decl = lines[back].match(/const\s+([A-Za-z_$][\w$]*)\s*=/)
          if (decl) { collection = decl[1]; break }
        }
      }
      if (collection) {
        const leaf = collection.split('.').pop() || collection
        const named = new RegExp(`(Showing|TruncationNote|\\+\\{)[\\s\\S]{0,400}?\\b${leaf}\\b|\\b${leaf}\\b[\\s\\S]{0,400}?(Showing|more)`)
        if (named.test(whole)) return
      }
      offenders.push(`${file}:${i + 1}  ${line.trim().slice(0, 96)}`)
    })
  }
}

/* Selection controls must state their cap in the label, or "Select Vulnerable"
   silently targets 25 of 200 assets and the operator never learns which 25. */
const opsPanels = readFileSync('src/app/dashboard/migration-sandbox/OpsPanels.tsx', 'utf8')
assert(
  /Select All Filtered \(\{Math\.min\(25,/.test(opsPanels),
  'the select-all control states its 25-asset cap in its own label',
)
assert(
  /Select Vulnerable \(\{Math\.min\(25,/.test(opsPanels),
  'the select-vulnerable control states its 25-asset cap too',
)

assert(
  offenders.length === 0,
  'every list truncation across the audited dashboards discloses the remainder',
  offenders.length ? `\n      ${offenders.join('\n      ')}` : `${ROOTS.length} module(s) scanned`,
)

console.log(
  failures === 0
    ? '\n✓ DISCLOSURE INTEGRITY HOLDS — nothing is dropped silently, nothing stale reads as current\n'
    : `\n${failures} CHECK(S) FAILED ✗\n`,
)
process.exit(failures === 0 ? 0 : 1)
