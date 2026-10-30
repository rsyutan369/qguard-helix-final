# Governance hero design review

Latest revision: see [WHITE-GLASS.md](WHITE-GLASS.md) for the user-requested metallic white finish, flowing lights and clickable feature details. The original graphite build review below is retained as design history.

## Result

An original, interactive 3D trust anchor replaces the unrelated photonic film. The hero introduces QKMS, crypto policy, continuous trust and audit evidence as connected capabilities. It is a conceptual architecture illustration, with no tenant metrics, compliance results, or fabricated evidence.

The build follows the existing page's chaptered editorial grammar. Only the hero and its page-specific navigation appearance change. The signature is a capability selection that highlights a satellite and its path into the same layered anchor; native scroll separates the anchor layers. The registry was empty at planning time, so the fingerprint gate had no earlier rows to compare.

## Screenshot refinement

The baseline and all screenshots live in `artifacts/governance-trust-hero/`.

Round one showed three concrete weaknesses:

- The global light-theme `!important` rules overrode the navigation treatment. Page-specific selectors now give the existing navigation a graphite background and readable mint/ivory controls. At 1024px its links use 9px horizontal padding and 12px type so the launch action stays on one line.
- The generated SVG noise filter was too prominent. Its layer opacity fell from .12 to .035, leaving the architecture and copy to carry the composition.
- The object was too small and the supporting labels were faint. The wide-camera distance fell from 15.8 to 13.2 units; narrow-camera distance fell from 17.8 to 15.2. Diagram labels and detail text gained size and contrast.

The second browser pass also exposed an installed Motion hook that did not update when the OS preference changed after mount. A direct `matchMedia` subscription through React's `useSyncExternalStore` now updates the already-open hero. Pausing preserves the current pose rather than snapping toward the pointer target.

The contact-sheet review confirmed a continuous handoff to the existing page. The forced context-loss screenshot revealed Chrome's gray lost-context surface during the canvas opacity transition; fallback mode now immediately removes that canvas from display and reveals the local SVG without a transition.

## Visual rubric

Subjective assessment of the inspected desktop, tablet and phone screenshots:

| Criterion | Final score / 10 | Evidence |
|---|---:|---|
| First glance | 9 | Short, large headline and a single architectural object |
| Signature | 8 | Capability paths and a layered trust anchor |
| Typography | 9 | Existing Geist, deliberate scale, short measure |
| Composition | 8 | Clear copy/object hierarchy and quiet space |
| Colour/light | 9 | Graphite, mint and champagne materials |
| Media integration | 8 | Native geometry with no media rectangle or remote film |
| Motion | 8 | Assembly, restrained yaw, selection and scroll separation |
| Mobile | 8 | Readable CTAs, rescaled object, two-column capability rail |
| Copy | 9 | Capability-specific language and no invented numerical proof |
| Polish | 8 | Focus styles, pause, reactive reduced motion and local fallback |

Average: 8.4. No item below 7.

## Feeling check

Intended: recognition, curiosity, control, readiness. Inspected result: clarity from the short headline; curiosity from the original layered object; control from the selected-domain detail; a stable action to continue. The initial object size and navigation contrast weakened the middle two feelings, so those were revised. The composition resolves and remains readable; it does not fade away or require empty pinned travel.

## Motion-design deliverable

No video was generated. The six-moment storyboard and export brief are retained in `BRIEF.md`. The implemented native scene realizes the assembly, connection, separation and settled hold without requiring a video provider or FFmpeg.

## Verification record

The browser harness `artifacts/governance-trust-hero/verify.mjs` exercises six responsive sizes, reduced-motion stability, capability selection, keyboard interaction, pause/resume, consecutive scroll positions, offscreen rendering, context-loss fallback, capability navigation and route cleanup. Its final observed results are recorded separately in `verification.json`; this design review is not a substitute for those test results.

Observed verification passed at 1440x1000, 1440x900, 1024x768, 390x844, 375x812 and 320x740. No horizontal overflow occurred, and the primary action remained in the first viewport at each size. Four selections, native keyboard order, Enter activation, pause/resume, six scroll samples, offscreen suspension, GPU-loss fallback and route cleanup passed. Mobile Chrome touch emulation additionally verified advancing ambient motion, tap selection and switching reduced motion on while the page was open. The immediate-fallback retest confirmed the lost canvas has `display: none`, including the override of Three.js's inline canvas display style. TypeScript passed. Production builds passed with pre-existing CSS and bundle warnings. Browser errors were limited to the existing missing favicon.

Machine-readable evidence: `verification.json`, `mobile-motion-verification.json` and `fallback-verification.json`. The final production log is `build.log`. The scroll contact sheet was opened and inspected.

Physical phones, touch hardware, screen readers and alternate GPU drivers were not available for direct testing. Mobile screenshots are Chrome viewport emulation. The existing missing `/favicon.ico` request is recorded separately from hero errors.
