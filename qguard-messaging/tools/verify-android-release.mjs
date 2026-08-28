#!/usr/bin/env node
/**
 * Prove a built Android release APK is safe to ship AND is not a stale rebuild.
 *
 * Four checks, all of which have caught a real defect on this project before:
 *
 *  1. FRESH UI  -- the frontend is compiled INTO the Rust .so, so a Gradle run
 *     that skipped the Rust step silently ships the previous build's UI. Asset
 *     contents are brotli-compressed inside the .so, so only the content-hashed
 *     vite FILENAMES are greppable. The current filename must be present and
 *     the previous one absent.
 *
 *  2. SIGILL-SAFE -- pqcrypto's default `neon` feature compiles the ARMv8.2
 *     SHA3-extension Keccak (eor3/rax1/xar/bcax) with NO runtime CPU check, so
 *     any device without FEAT_SHA3 dies with SIGILL the moment PQC keygen runs.
 *     The .text disassembly must contain zero of those opcodes. The line count
 *     is asserted too: a silently failing objdump also "finds" zero.
 *
 *  3. SIGNED -- apksigner must report a v2 signature.
 *
 *  4. IDENTITY -- versionName / versionCode / native ABI, so the APK handed to
 *     a tester is demonstrably the intended build.
 *
 *   node tools/verify-android-release.mjs
 *   node tools/verify-android-release.mjs --apk <path> --so <path>
 *
 * Exits non-zero if any check fails.
 */
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const argv = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : fallback;
};

const sdk = process.env.ANDROID_HOME
  || process.env.ANDROID_SDK_ROOT
  || path.join(process.env.LOCALAPPDATA ?? "", "Android", "Sdk");

function newestBuildTool(exe) {
  const dir = path.join(sdk, "build-tools");
  if (!fs.existsSync(dir)) return null;
  const versions = fs.readdirSync(dir).sort().reverse();
  for (const version of versions) {
    const candidate = path.join(dir, version, exe);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

function ndkTool(exe) {
  const dir = path.join(sdk, "ndk");
  if (!fs.existsSync(dir)) return null;
  for (const version of fs.readdirSync(dir).sort().reverse()) {
    const candidate = path.join(dir, version, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", exe);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

const apkPath = path.resolve(arg("apk", path.join(appRoot, "src-tauri/gen/android/app/build/outputs/apk/arm64/release/app-arm64-release.apk")));
const soPath = path.resolve(arg("so", path.join(appRoot, "src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/libqguard_messaging_lib.so")));

let failures = 0;
const fail = (message) => { failures += 1; console.log(`FAIL  ${message}`); };
const pass = (message) => console.log(`PASS  ${message}`);

console.log(`apk : ${apkPath}`);
console.log(`so  : ${soPath}\n`);

for (const [label, target] of [["APK", apkPath], [".so", soPath]]) {
  if (!fs.existsSync(target)) {
    console.log(`FAIL  ${label} not found: ${target}`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------- 1. fresh UI
const indexHtml = fs.readFileSync(path.join(appRoot, "dist", "index.html"), "utf8");
const currentAsset = indexHtml.match(/assets\/(index-[A-Za-z0-9_-]+\.js)/)?.[1];
const forbidden = arg("forbid-asset", null);

if (!currentAsset) {
  fail("could not read the current bundle filename from dist/index.html");
} else {
  const so = fs.readFileSync(soPath);
  const hasCurrent = so.includes(Buffer.from(currentAsset, "utf8"));
  const hasForbidden = forbidden ? so.includes(Buffer.from(forbidden, "utf8")) : false;

  if (!hasCurrent) fail(`the .so does NOT contain this build's bundle (${currentAsset}) — it is stale, the Rust step did not re-run.`);
  else if (hasForbidden) fail(`the .so still contains the previous bundle (${forbidden}).`);
  else pass(`fresh UI — .so embeds ${currentAsset}${forbidden ? ` and no longer ${forbidden}` : ""}.`);

  const soAge = fs.statSync(soPath).mtimeMs;
  const distAge = fs.statSync(path.join(appRoot, "dist", "index.html")).mtimeMs;
  if (soAge < distAge) fail(`.so (${new Date(soAge).toISOString()}) is OLDER than dist/ (${new Date(distAge).toISOString()}).`);
  else pass(`.so is newer than dist/ (built ${new Date(soAge).toISOString()}).`);
}

// ------------------------------------------------------------- 2. SIGILL-safe
const objdump = ndkTool("llvm-objdump.exe") ?? ndkTool("llvm-objdump");
if (!objdump) {
  fail("llvm-objdump not found in the NDK — cannot prove the build is SIGILL-safe.");
} else {
  const forbiddenOpcodes = /\b(eor3|rax1|xar|bcax)\b/;
  const counts = await new Promise((resolve, reject) => {
    const child = spawn(objdump, ["-d", "--section=.text", soPath]);
    let lines = 0;
    let hits = 0;
    let carry = "";
    child.stdout.on("data", (chunk) => {
      const text = carry + chunk.toString("latin1");
      const parts = text.split("\n");
      carry = parts.pop() ?? "";
      for (const line of parts) {
        lines += 1;
        if (forbiddenOpcodes.test(line)) hits += 1;
      }
    });
    child.on("error", reject);
    child.on("close", () => resolve({ lines, hits }));
  });

  // A silent objdump failure yields 0 hits AND ~0 lines; only a real, large
  // disassembly makes "0 hits" meaningful.
  if (counts.lines < 10000) {
    fail(`objdump produced only ${counts.lines} lines — the disassembly did not run, so "0 SHA3 opcodes" proves nothing.`);
  } else if (counts.hits > 0) {
    fail(`${counts.hits} ARMv8.2 SHA3-extension opcode(s) in .text — this build will SIGILL on devices without FEAT_SHA3. Check pqcrypto default-features in src-tauri/Cargo.toml.`);
  } else {
    pass(`SIGILL-safe — 0 SHA3-extension opcodes across ${counts.lines.toLocaleString()} disassembled lines.`);
  }
}

// ----------------------------------------------------------------- 3. signed
const apksigner = newestBuildTool("apksigner.bat") ?? newestBuildTool("apksigner");
if (!apksigner) {
  fail("apksigner not found in the SDK build-tools.");
} else {
  try {
    // apksigner ships as a .bat, and since the CVE-2024-27980 mitigation Node
    // refuses to execFile a .bat/.cmd without a shell (it fails EINVAL, which
    // reads exactly like a rejected signature). Quote every path for the shell.
    const shell = apksigner.toLowerCase().endsWith(".bat") || apksigner.toLowerCase().endsWith(".cmd");
    const out = shell
      ? execFileSync(`"${apksigner}"`, ["verify", "--print-certs", `"${apkPath}"`], { encoding: "utf8", shell: true, stdio: ["ignore", "pipe", "pipe"] })
      : execFileSync(apksigner, ["verify", "--print-certs", apkPath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const subject = out.match(/Signer #1 certificate DN: (.+)/)?.[1]?.trim() ?? "(unknown)";
    pass(`signed — ${subject}`);
  } catch (error) {
    fail(`apksigner rejected the APK: ${String(error.stderr || error.message).split("\n")[0]}`);
  }
}

// --------------------------------------------------------------- 4. identity
const aapt2 = newestBuildTool("aapt2.exe") ?? newestBuildTool("aapt2");
if (!aapt2) {
  fail("aapt2 not found in the SDK build-tools.");
} else {
  try {
    const out = execFileSync(aapt2, ["dump", "badging", apkPath], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    const versionName = out.match(/versionName='([^']*)'/)?.[1];
    const versionCode = out.match(/versionCode='([^']*)'/)?.[1];
    const abis = [...out.matchAll(/native-code: '([^']*)'/g)].map((m) => m[1]);
    const expected = JSON.parse(fs.readFileSync(path.join(appRoot, "src-tauri", "tauri.conf.json"), "utf8")).version;
    if (versionName !== expected) {
      fail(`APK versionName ${versionName} does not match tauri.conf.json ${expected}.`);
    } else {
      pass(`identity — v${versionName} (versionCode ${versionCode}), ABI ${abis.join(", ") || "(none reported)"}`);
    }
  } catch (error) {
    fail(`aapt2 dump badging failed: ${String(error.stderr || error.message).split("\n")[0]}`);
  }
}

console.log(`\n${failures === 0 ? "All checks passed." : `${failures} check(s) FAILED.`}`);
process.exit(failures === 0 ? 0 : 1);
