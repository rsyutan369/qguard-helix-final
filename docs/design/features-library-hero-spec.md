# QGuard Helix feature library hero

The user confirmed retaining the existing 15 feature sections after discovery found 15, rather than adding a sixteenth module. The attached filmography shelf is a visual reference; its film titles, Japanese copy, film artwork, detail dialog and instruction to lock body scrolling are not product requirements.

Use existing React, Motion and local feature artwork. Replace the hero video with fifteen CSS 3D books, one per ModuleEntry. Do not fetch or generate any replacement video. Each book and title is an ordinary hash link to its existing feature section. Arrows, chapter filter buttons, keyboard arrows and touch dragging select the book preview. Clicking a book always navigates directly, including an inactive spine. Native scrolling, browser history and keyboard activation remain functional.

Palette: warm paper #eeefec, ink #15232c, muted #566770, accent #2357a5, cyan details from the existing platform palette. Books alternate navy #1c3046, teal #21484c, graphite #313a43 and pale slate #dce1df. Keep labels and cover text as HTML, not baked into illustrations. Use the existing Geist/system sans font for enterprise clarity rather than imported film-specific serif/Japanese fonts.

Header within 1200px: 112px top padding, 24px horizontal gutters. Small uppercase platform-library label, existing headline adapted to stable text: For every algorithm. Be ready for what comes next. Display clamp(30px,3.2vw,48px), 600 weight, -.04em tracking. No cycling words or autoplay media.

Shelf: perspective 2200px, height 400px desktop. Book height 300px, spine 44px, cover 186px, gap 9px. Active book turns -90deg around Y, leans -4deg around Z and pulls forward 45px. Neighbouring books spread by half the active cover's extra width. Inactive spines lift 8px on hover. Cover artwork comes from the associated ModuleEntry.image, with a protected ink title area. Smooth transform transitions 650ms cubic-bezier(.2,.8,.2,1), no body scroll interception and no unnecessary continuous animation loop. Mask only shelf edges. Keep a visible 44px control target and focus outline for every book.

Caption below shelf: current chapter eyebrow, linked complete feature title, brief descriptor, 44px previous/next buttons. The caption changes with a 350ms masked rise. Active preview is announced politely; never auto-advances. All fifteen feature title links remain in a compact, wrapping index below the shelf. This index also ensures complete discoverability on small screens and touch devices.

Keep the user's full quantum-security message verbatim and the bold line Discover. Assess. Migrate. Validate. Prove. Put the paragraph in a readable 80ch block under the shelf, 15px/1.8, with the existing assessment and platform CTA destinations. Preserve all feature sections, data, lifecycle, benefits and comparison content.

At <=767px, book height 250px, spine 42px, cover 155px, shelf 330px. Only the nearby spines fit visually; swipe/arrows and the full title index expose every feature. No horizontal document overflow. Do not hide the native cursor. Reduced motion disables 3D travel, hover lift and caption entrance while keeping instant selection and native links.

Verification: test every book and index title against its actual section ID; assert video elements and video requests are absent; verify exact retained message, no missing cover artwork, keyboard selection and activation, swipe/click distinction, initial deep link, desktop/mobile/reduced-motion layout, browser errors, TypeScript and production build. Review early and settled screenshots and correct geometry, contrast and mobile readability.
