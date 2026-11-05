#!/usr/bin/env node
/**
 * Quantum Vault at-rest audit — READ-ONLY, decrypts nothing, needs no keys.
 *
 * Answers "is what is on this disk actually ciphertext?" for a real install,
 * where the unit tests (src-tauri/src/vault/*.rs, vault_stream.rs) answer it
 * for test data. For every file under <data>/vault/{store,pool}/<user>/:
 *
 *  Quantum Vault Storage (`objects/*.qvault`, v5 vault_stream containers)
 *    - header: magic, version, suite, which wraps exist, that it carries a
 *      hybrid Ed25519 + ML-DSA signature, and that it names no file;
 *    - body: byte entropy (AES-256-GCM output is ~8.0 bits/byte) and no
 *      plaintext file signature (JPEG/PNG/PDF/ZIP/MP4/…) anywhere.
 *  Index, thumbnails, cloud manifests, Hidden Vault pool
 *    - no header at all is expected; entropy and plaintext-signature checks.
 *  Everything
 *    - no ASCII run that looks like a file name with a common extension.
 *
 * Usage: node tools/vault-at-rest-audit.mjs [dataDir]
 *   dataDir defaults to %APPDATA%/qguard-messaging (desktop). On Android the
 *   same layout lives in the app's private data dir and needs `adb` + root or
 *   `run-as` on a debuggable build to read.
 * Exit code 1 if any file fails a check.
 */
import fs from "node:fs";
import path from "node:path";

const dataDir = process.argv[2] ?? path.join(process.env.APPDATA ?? "", "qguard-messaging");
const vaultDir = path.join(dataDir, "vault");
if (!fs.existsSync(vaultDir)) {
  console.error(`No vault folder at ${vaultDir}`);
  process.exit(2);
}

const SIGNATURES = [
  ["JPEG", [0xff, 0xd8, 0xff]],
  ["PNG", [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]],
  ["PDF", [...Buffer.from("%PDF-")]],
  ["ZIP/Office", [0x50, 0x4b, 0x03, 0x04]],
  ["MP4/MOV", [...Buffer.from("ftyp")]],
  ["GIF", [...Buffer.from("GIF8")]],
  ["RIFF/WEBP/WAV", [...Buffer.from("RIFF")]],
  ["RAR", [...Buffer.from("Rar!")]],
  ["7z", [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]],
  ["MP3/ID3", [...Buffer.from("ID3")]],
];
// At least 5 name characters: shorter runs turn up by chance in megabytes of
// ciphertext (a 557 KB pool file contained the random bytes "UOq.PDF").
const NAME_LIKE = /[A-Za-z0-9 _()-]{5,}\.(jpe?g|png|gif|heic|webp|pdf|docx?|xlsx?|pptx?|txt|csv|mp4|mov|mkv|mp3|wav|zip|rar|7z)\b/i;

function entropy(buf) {
  if (buf.length === 0) return 0;
  const counts = new Array(256).fill(0);
  for (const b of buf) counts[b] += 1;
  let h = 0;
  for (const c of counts) if (c) { const p = c / buf.length; h -= p * Math.log2(p); }
  return h;
}

/** Positions of plaintext file signatures. Short ones (≤4 bytes) occur by chance in large ciphertext, so only a hit at offset 0 counts for them. */
function signatureHits(buf) {
  const hits = [];
  for (const [label, sig] of SIGNATURES) {
    const needle = Buffer.from(sig);
    if (needle.length <= 4) {
      if (buf.subarray(0, needle.length).equals(needle)) hits.push(`${label}@0`);
    } else {
      const at = buf.indexOf(needle);
      if (at >= 0) hits.push(`${label}@${at}`);
    }
  }
  return hits;
}

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

const MAGIC = Buffer.from("QGUARDVS");
function parseContainer(buf) {
  if (!buf.subarray(0, 8).equals(MAGIC)) return null;
  const headerLen = buf.readUInt32BE(8);
  const header = JSON.parse(buf.subarray(12, 12 + headerLen).toString("utf8"));
  return { header, body: buf.subarray(12 + headerLen) };
}

/** Header keys, flattened ("suite.pq_signature"), so the report shows what is and is not in clear. */
function flatKeys(value, prefix = "") {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [prefix];
  return Object.entries(value).flatMap(([k, v]) => flatKeys(v, prefix ? `${prefix}.${k}` : k));
}

const results = [];
let failures = 0;
const fail = (file, why) => { failures += 1; results.push(`FAIL ${file}: ${why}`); };

const versions = new Map();
const suites = new Map();
let containers = 0;
let dualSigned = 0;
let pinBound = 0;
let recoveryWrapped = 0;
const headerKeySet = new Set();

for (const file of walk(vaultDir)) {
  const rel = path.relative(vaultDir, file).replace(/\\/g, "/");
  const kind = rel.startsWith("pool/") ? "hidden-pool" : rel.includes("/objects/") ? "container" : rel.includes("/thumbs/") ? "thumbnail" : rel.endsWith(".qvs") ? "index" : "other";
  const buf = fs.readFileSync(file);
  if (buf.length === 0) continue;

  let body = buf;
  if (kind === "container" || buf.subarray(0, 8).equals(MAGIC)) {
    const parsed = parseContainer(buf);
    if (!parsed) { fail(rel, "expected a QGUARDVS container"); continue; }
    containers += 1;
    const { header } = parsed;
    body = parsed.body;
    flatKeys(header).forEach((k) => headerKeySet.add(k));
    const version = header.version ?? header.v ?? "?";
    versions.set(version, (versions.get(version) ?? 0) + 1);
    const suite = header.suite ? JSON.stringify(header.suite) : "(none)";
    suites.set(suite, (suites.get(suite) ?? 0) + 1);
    const headerText = JSON.stringify(header);
    if (/ml.?dsa/i.test(headerText) && /ed25519/i.test(headerText)) dualSigned += 1;
    else fail(rel, "header does not carry a hybrid Ed25519 + ML-DSA signature");
    if (Number(version) >= 5) pinBound += 1;
    else fail(rel, `legacy device-bound container (v${version}) — open the vault and use Re-protect`);
    if (/recovery/i.test(Object.keys(header).join(" ")) || /recovery/i.test(headerText.slice(0, 4000))) recoveryWrapped += 1;
    if (NAME_LIKE.test(headerText)) fail(rel, "header contains something that looks like a file name");
  }

  const h = entropy(body);
  // A small file (a few hundred bytes) cannot reach 8.0 even when random.
  const minEntropy = body.length >= 64 * 1024 ? 7.99 : body.length >= 4096 ? 7.9 : body.length >= 512 ? 7.3 : 0;
  if (h < minEntropy) fail(rel, `entropy ${h.toFixed(3)} bits/byte over ${body.length} B — not ciphertext-like`);
  const hits = signatureHits(body);
  if (hits.length) fail(rel, `plaintext file signature(s): ${hits.join(", ")}`);
  if (NAME_LIKE.test(buf.toString("latin1"))) fail(rel, "contains a readable file name");
  results.push(`ok   ${kind.padEnd(11)} ${String(body.length).padStart(10)} B  entropy ${h.toFixed(4)}  ${rel.replace(/^[^/]+\/[0-9a-f-]{36}\//, "…/")}`);
}

console.log(`Vault at-rest audit — ${vaultDir}`);
console.log(results.join("\n"));
console.log("\nSummary");
console.log(`  files scanned ............ ${results.length}`);
console.log(`  vault containers ......... ${containers}  (versions: ${[...versions].map(([v, n]) => `v${v}×${n}`).join(", ") || "none"})`);
console.log(`  hybrid-signed headers .... ${dualSigned}/${containers}  (Ed25519 + ML-DSA)`);
console.log(`  PIN-bound (v5+) .......... ${pinBound}/${containers}`);
console.log(`  with a recovery wrap ..... ${recoveryWrapped}/${containers}`);
console.log(`  header suites ............ ${[...suites].map(([s, n]) => `${n}× ${s}`).join("\n                             ") || "—"}`);
console.log(`  header fields in clear ... ${[...headerKeySet].sort().join(", ") || "—"}`);
console.log(failures ? `\nRESULT: ${failures} problem(s) found` : "\nRESULT: every file is ciphertext-like; no plaintext signature or file name found");
process.exit(failures ? 1 : 0);
