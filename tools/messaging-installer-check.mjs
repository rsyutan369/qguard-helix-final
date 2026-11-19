import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Check the published bytes, rather than trusting the release filename or label.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const filename = 'QGuard-Messaging-Setup.exe';
const bytes = fs.readFileSync(path.join(root, 'public/downloads', filename));
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'public/downloads/latest.json'), 'utf8'));
const config = JSON.parse(fs.readFileSync(path.join(root, 'qguard-messaging/src-tauri/tauri.conf.json'), 'utf8'));
const website = fs.readFileSync(path.join(root, 'src/app/qguard-messaging/_shared.tsx'), 'utf8');
const installer = website.split('export const MESSAGING_INSTALLER = {')[1]?.split('\n};')[0];
assert(installer, 'Website installer metadata missing');
const field = name => installer.match(new RegExp(`${name}:\\s*'([^']+)'`))?.[1];
const sha256 = crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase();
assert.equal(field('version'), config.version, 'Website version differs from app');
assert.equal(manifest.version, config.version, 'Updater version differs from app');
assert.equal(field('sha256'), sha256, 'Website checksum differs from download');
assert.equal(field('fileName'), filename);
assert.equal(Number(installer.match(/sizeMb:\s*(\d+)/)?.[1]), Math.round(bytes.length / 1024 ** 2));

// NSIS stores the product version in its PE VS_VERSION_INFO resource.
const marker = bytes.indexOf(Buffer.from('VS_VERSION_INFO\0', 'utf16le'));
assert(marker >= 0, 'Installer version resource missing');
const fixed = Math.ceil((marker + Buffer.byteLength('VS_VERSION_INFO\0', 'utf16le')) / 4) * 4;
assert.equal(bytes.readUInt32LE(fixed), 0xfeef04bd, 'Invalid installer version resource');
const majorMinor = bytes.readUInt32LE(fixed + 16);
const patchRevision = bytes.readUInt32LE(fixed + 20);
assert.equal(`${majorMinor >>> 16}.${majorMinor & 0xffff}.${patchRevision >>> 16}`, config.version,
  'Installer embedded product version differs from app');

// Verify the Tauri/minisign signature against the app's existing trust root.
const decode = value => value.trim().startsWith('untrusted comment:')
  ? value.trim() : Buffer.from(value.trim(), 'base64').toString('utf8').trim();
const publicPacket = Buffer.from(decode(config.plugins.updater.pubkey).split(/\r?\n/)[1], 'base64');
const lines = decode(manifest.platforms['windows-x86_64'].signature).split(/\r?\n/);
const packet = Buffer.from(lines[1], 'base64');
assert.equal(publicPacket.length, 42);
assert.equal(packet.length, 74);
assert(packet.subarray(2, 10).equals(publicPacket.subarray(2, 10)), 'Updater signing key mismatch');
assert(lines[2].startsWith('trusted comment: '));
assert(lines[2].includes(`version:${manifest.version}`), 'Signed version differs from manifest');
const algorithm = packet.toString('ascii', 0, 2);
assert(['ED', 'Ed'].includes(algorithm), 'Unsupported updater signature algorithm');
const key = crypto.createPublicKey({
  key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publicPacket.subarray(10)]),
  format: 'der', type: 'spki',
});
const signature = packet.subarray(10);
const payload = algorithm === 'ED' ? crypto.createHash('blake2b512').update(bytes).digest() : bytes;
assert(crypto.verify(null, payload, key, signature), 'Installer updater signature invalid');
assert(crypto.verify(null, Buffer.concat([signature, Buffer.from(lines[2].slice(17))]), key,
  Buffer.from(lines[3], 'base64')), 'Updater trusted comment invalid');
const altered = Buffer.from(payload);
altered[0] ^= 1;
assert.equal(crypto.verify(null, altered, key, signature), false, 'Altered installer accepted');

console.log(JSON.stringify({ version: manifest.version, bytes: bytes.length, sha256,
  embeddedVersionVerified: true, updaterSignatureVerified: true, tamperingRejected: true }, null, 2));
