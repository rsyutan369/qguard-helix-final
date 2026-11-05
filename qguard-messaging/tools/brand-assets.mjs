#!/usr/bin/env node
/**
 * Regenerate every QGuard Messaging brand raster from the master logo
 * (brand/qguard-messaging-logo.png): the in-app badge and favicon, the Tauri
 * desktop master, the Android adaptive launcher layers and legacy icons, the
 * Windows NSIS installer artwork and the Play Store listing icon.
 *
 * The master is the supplied transparent Q/helix/shield artwork. Its complete
 * square canvas is preserved; no circular crop is applied. Desktop .ico/.icns
 * and the platform PNG ladders are
 * produced afterwards by the Tauri CLI from src-tauri/app-icon.png:
 *
 *   node tools/brand-assets.mjs
 *   npx tauri icon src-tauri/app-icon.png
 *   node tools/brand-assets.mjs --android-only   # re-apply the adaptive icon
 *
 * `tauri icon` also rewrites the Android mipmaps with a flat, unmasked layout,
 * which is why the Android step is re-run after it.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MASTER = path.join(root, "brand", "qguard-messaging-logo.png");
const ANDROID_RES = path.join(root, "src-tauri", "gen", "android", "app", "src", "main", "res");

// Preserve the full master canvas, including the Q tail, helix and glow.

// Deep navy provides contrast behind the transparent mark wherever a
// platform requires an opaque or full-bleed surface.
const NAVY_CORE = "#0B1E5B";
const NAVY_EDGE = "#030817";

const DENSITIES = { mdpi: 1, hdpi: 1.5, xhdpi: 2, xxhdpi: 3, xxxhdpi: 4 };

async function badge(size) {
  const img = sharp(MASTER)
    .resize(size, size, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 }, kernel: "lanczos3" });
  // A light unsharp mask retains the shield and helix detail at small sizes.
  if (size <= 128) img.sharpen({ sigma: 0.6 });
  return img.png().toBuffer();
}

async function badgeOnCanvas(canvas, diameter, background = { r: 0, g: 0, b: 0, alpha: 0 }) {
  const inset = Math.round((canvas - diameter) / 2);
  return sharp({ create: { width: canvas, height: canvas, channels: 4, background } })
    .composite([{ input: await badge(diameter), left: inset, top: inset }])
    .png({ compressionLevel: 9 });
}

function navyPlateSvg(width, height, glowCy = height / 2, glowR = Math.max(width, height) * 0.62) {
  return Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}">
  <defs>
    <radialGradient id="field" cx="${width / 2}" cy="${glowCy}" r="${glowR}" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="${NAVY_CORE}"/>
      <stop offset="0.55" stop-color="#06123A"/>
      <stop offset="1" stop-color="${NAVY_EDGE}"/>
    </radialGradient>
  </defs>
  <rect width="100%" height="100%" fill="url(#field)"/>
</svg>`);
}

// Replacing an asset atomically also works when a Windows image preview has
// mapped the previous file. Never truncate a live icon in place.
function writeAtomic(file, bytes) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = file + '.qg-asset-tmp';
  fs.writeFileSync(temporary, bytes);
  fs.renameSync(temporary, file);
}

/** Minimal 24-bit bottom-up BMP encoder; NSIS/MUI2 only accepts BMP artwork. */
async function writeBmp(pipeline, file) {
  const { data, info } = await pipeline.flatten({ background: "#ffffff" }).removeAlpha().raw().toBuffer({ resolveWithObject: true });
  const { width, height } = info;
  const stride = Math.ceil((width * 3) / 4) * 4;
  const pixelBytes = stride * height;
  const out = Buffer.alloc(54 + pixelBytes);
  out.write("BM", 0, "ascii");
  out.writeUInt32LE(out.length, 2);
  out.writeUInt32LE(54, 10);
  out.writeUInt32LE(40, 14);
  out.writeInt32LE(width, 18);
  out.writeInt32LE(height, 22);
  out.writeUInt16LE(1, 26);
  out.writeUInt16LE(24, 28);
  out.writeUInt32LE(pixelBytes, 34);
  out.writeInt32LE(2835, 38);
  out.writeInt32LE(2835, 42);
  for (let y = 0; y < height; y++) {
    const row = 54 + (height - 1 - y) * stride;
    for (let x = 0; x < width; x++) {
      const src = (y * width + x) * 3;
      out[row + x * 3] = data[src + 2];
      out[row + x * 3 + 1] = data[src + 1];
      out[row + x * 3 + 2] = data[src];
    }
  }
  writeAtomic(file, out);
}

async function writePng(pipeline, file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  writeAtomic(file, await pipeline.toBuffer());
  console.log("wrote", path.relative(root, file));
}

async function desktopAndApp() {
  // Tauri master: badge almost edge-to-edge so it reads at taskbar sizes.
  await writePng(await badgeOnCanvas(1024, 1004), path.join(root, "src-tauri", "app-icon.png"));

  // In-app badge (rendered at up to ~92 CSS px on 3x screens) and favicon.
  await writePng(sharp(await badge(384)).webp({ quality: 92, alphaQuality: 100, effort: 6 }), path.join(root, "public", "brand", "qguard-messaging-badge.webp"));
  await writePng(sharp(await badge(64)).png({ compressionLevel: 9 }), path.join(root, "public", "brand", "favicon.png"));

  // Play Store listing icon: 512px, opaque, Google applies its own mask.
  const play = sharp(navyPlateSvg(512, 512)).composite([{ input: await badge(452), left: 30, top: 30 }]).png();
  await writePng(play, path.join(root, "brand", "play-store-icon-512.png"));

  // NSIS welcome/finish sidebar (164x314) and inner-page header (150x57).
  const installerDir = path.join(root, "src-tauri", "icons", "installer");
  fs.mkdirSync(installerDir, { recursive: true });
  const accent = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="164" height="314">
  <defs><linearGradient id="a" x1="0" x2="1"><stop offset="0" stop-color="#22D3EE"/><stop offset="0.5" stop-color="#3B82F6"/><stop offset="1" stop-color="#A855F7"/></linearGradient></defs>
  <rect x="32" y="262" width="100" height="2" rx="1" fill="url(#a)"/>
</svg>`);
  const sidebar = sharp(navyPlateSvg(164, 314, 122, 190)).composite([
    { input: await badge(136), left: 14, top: 54 },
    { input: accent, left: 0, top: 0 },
  ]);
  await writeBmp(sidebar, path.join(installerDir, "nsis-sidebar.bmp"));
  console.log("wrote", path.relative(root, path.join(installerDir, "nsis-sidebar.bmp")));

  const header = sharp({ create: { width: 150, height: 57, channels: 4, background: "#ffffff" } }).composite([
    { input: await badge(49), left: 97, top: 4 },
  ]);
  await writeBmp(header, path.join(installerDir, "nsis-header.bmp"));
  console.log("wrote", path.relative(root, path.join(installerDir, "nsis-header.bmp")));
}

async function android() {
  // `tauri icon` resets both of these to a flat white background; the navy
  // gradient lives in drawable/ic_launcher_background.xml.
  writeAtomic(
    path.join(ANDROID_RES, "mipmap-anydpi-v26", "ic_launcher.xml"),
    `<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
  <background android:drawable="@drawable/ic_launcher_background"/>
  <foreground android:drawable="@mipmap/ic_launcher_foreground"/>
</adaptive-icon>
`,
  );
  writeAtomic(
    path.join(ANDROID_RES, "values", "ic_launcher_background.xml"),
    `<?xml version="1.0" encoding="utf-8"?>
<resources>
  <!-- Flat fallback of drawable/ic_launcher_background (QGuard navy). -->
  <color name="ic_launcher_background">#FF06123A</color>
</resources>
`,
  );
  for (const [bucket, scale] of Object.entries(DENSITIES)) {
    const dir = path.join(ANDROID_RES, `mipmap-${bucket}`);
    // Adaptive foreground: the full master at 60dp on a 108dp canvas keeps
    // the visible Q tail inside a centred 66dp safe circle, including the
    // Android 12+ splash mask. Keep all five density buckets consistent.
    await writePng(await badgeOnCanvas(Math.round(108 * scale), Math.round(60 * scale)), path.join(dir, "ic_launcher_foreground.png"));
    // Legacy and round icons retain the transparent full mark on 48dp.
    const legacy = await badgeOnCanvas(Math.round(48 * scale), Math.round(46 * scale));
    const legacyBuf = await legacy.toBuffer();
    await writePng(sharp(legacyBuf), path.join(dir, "ic_launcher.png"));
    await writePng(sharp(legacyBuf), path.join(dir, "ic_launcher_round.png"));
  }
}

const androidOnly = process.argv.includes("--android-only");
if (!fs.existsSync(MASTER)) throw new Error(`master logo missing: ${MASTER}`);
if (!androidOnly) await desktopAndApp();
await android();
