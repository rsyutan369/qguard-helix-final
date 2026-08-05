---
name: qguard-enterprise-ux
description: Enterprise UI implementation standards for QGuard Helix — premium dashboard composition, honest status vocabularies, empty and unknown states, responsive layout, animation discipline and accessibility. Use when building or changing any dashboard surface, panel, card, chart, status indicator or workflow rail.
priority: high
owner: qguard-helix
version: 1.0
---

# Enterprise UI & UX Implementation

Design judgement lives in the `UX-Engineer` role skill and
`_shared/ux-principles.md`. This is how it is implemented here.

## Every page answers seven questions

1. What is affected? 2. Why is it risky? 3. How urgent? 4. What next?
5. Has it been remediated? 6. Has that been verified? 7. Is the asset PQC-ready?

A panel that answers none of these is decoration.

## Status vocabularies must be disjoint and honest

The Discovery Workflow bug was, at the UI layer, a vocabulary failure: three very
different situations all rendered as one grey "Skipped".

| State | Means exactly |
|---|---|
| Complete | everything resolved, at least one measurement |
| Partial | measured, but something never reported — a real gap |
| Not applicable | legitimately did not apply — **and says why, inline** |
| Failed | errored — shows the error |
| Running / Waiting | not reached yet |

Rules:

- Never render "not measured" the same as "measured and clean". Green means
  *verified good*.
- A non-measuring state must state its reason **in the UI**, not only in a
  tooltip. "n/a" with no explanation is what users report as a bug.
- Prefer "Pending" over "Queued" in user-facing copy; keep the internal token.

## Empty, unknown and loading states are features

Every surface implements all four: loading, empty, unknown, error.

- **Empty** explains what to do ("Run an authorized scan"), not just "No data".
- **Unknown** is distinct from zero. A control that was not probed reads
  "Not probed", never "Fail".
- Withhold verdicts the evidence does not support — an incomplete run shows
  "Incomplete run — N modules never reported", not a grade.

## Composition

```
Hero (visualization + headline verdict)
Workflow rail (where the user is in DISCOVER→…→GOVERN)
Executive summary
Decomposition / evidence panels
Detail tables
Scope + coverage disclosure
```

Panels take the **derived model**, not raw state, so two panels cannot disagree.
See `qguard-data-integrity`.

## Data visualisation

- A visualization is never the source of a number — it renders one.
- Colour encodes severity consistently platform-wide; never re-map per chart.
- Disclose truncation ("60 of 825 analysed"). Silent capping reads as full
  coverage.
- Show the denominator: `3/3 modules · 1 n/a · 13 findings` beats a bare
  percentage.

## Animation discipline

- Animation paces the presentation of facts already received. It **never**
  advances progress on its own and never fabricates an event.
- Append-only logs must record settled observations only — a "running" line in an
  append-only timeline keeps its spinner forever.
- Respect `prefers-reduced-motion`: drain queues in one frame.
- Reconcile on run end so nothing is left spinning after the run is demonstrably
  over.

## Responsive

- Root grids: `grid-cols-[minmax(0,1fr)]`; main scroll container
  `overflow-x-hidden`. A wide table otherwise poisons the implicit track and the
  whole page pans sideways on a phone.
- Wide content scrolls **inside its own** `overflow-x-auto` container.
- Tap targets ≥ ~34 px; fixed-height panels break on tablets — prefer
  `h-full` flex fill over magic numbers.

## Accessibility

- Semantic landmarks; `role="tabpanel"` with `aria-labelledby` on tabbed surfaces.
- Status is never colour-only — pair with icon and text.
- Tooltips carry supplementary provenance, never the only copy of a reason.
- Maintain contrast in both themes; never assume a single theme.

## Checklist

- [ ] Surface answers the seven questions.
- [ ] Status vocabulary disjoint; every non-measuring state shows its reason.
- [ ] Loading / empty / unknown / error all implemented.
- [ ] Panels consume the derived model.
- [ ] Truncation and denominators disclosed.
- [ ] Animation paces facts only; reduced-motion honoured.
- [ ] No horizontal page scroll at mobile widths.
- [ ] Status conveyed by more than colour.
