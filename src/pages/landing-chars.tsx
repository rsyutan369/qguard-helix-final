/**
 * Text split into per-letter spans for the homepage letter reveal
 * (see landing-motion.ts). Words stay unbreakable so a line never splits
 * mid-word. Put it inside an element that carries `data-letters` and an
 * `aria-label` with the full text; the spans themselves are hidden from
 * assistive technology.
 */
export function Chars({ text }: { text: string }) {
  return (
    <>
      {text.split(/(\s+)/).map((part, index) =>
        part.trim() === '' ? (
          part
        ) : (
          <span key={index} className="lp-word" aria-hidden="true">
            {Array.from(part).map((char, charIndex) => (
              <span key={charIndex} className="lp-ch">
                {char}
              </span>
            ))}
          </span>
        ),
      )}
    </>
  );
}

/** The small cyan dot on a primary button that grows into an arrow on hover. */
export function ButtonDot() {
  return (
    <span className="lp-btn__dot" aria-hidden="true">
      <svg viewBox="0 0 12 12" fill="none">
        <path d="M4.5 2.5 8 6l-3.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}
