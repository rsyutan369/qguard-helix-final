import { useMemo } from "react";
import qrcode from "qrcode-generator";

/**
 * A QR code drawn as one SVG path, with a 4-module quiet zone (ISO/IEC 18004).
 * Always dark-on-white, whatever the theme: cameras read inverted codes poorly.
 */
export function QrCode({ value, size = 232, label }: { value: string; size?: number; label: string }) {
  const { path, modules } = useMemo(() => {
    const code = qrcode(0, "M");
    code.addData(value, "Byte");
    code.make();
    const count = code.getModuleCount();
    const parts: string[] = [];
    for (let row = 0; row < count; row += 1) {
      for (let col = 0; col < count; col += 1) {
        if (code.isDark(row, col)) parts.push(`M${col + 4} ${row + 4}h1v1h-1z`);
      }
    }
    return { path: parts.join(""), modules: count + 8 };
  }, [value]);

  return (
    <svg
      role="img"
      aria-label={label}
      width={size}
      height={size}
      viewBox={`0 0 ${modules} ${modules}`}
      shapeRendering="crispEdges"
      className="block rounded-xl"
      style={{ background: "#ffffff" }}
    >
      <path d={path} fill="#0b0b14" />
    </svg>
  );
}
