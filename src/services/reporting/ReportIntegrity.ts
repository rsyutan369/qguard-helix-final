import { sha3_256 } from '@noble/hashes/sha3.js';
import { UnsecuredJWT } from 'jose';

/**
 * Report integrity seal — shared by every report family.
 *
 * The Quantum Readiness assessment reports and the asset / CBOM reports are
 * sealed the same way: a SHA3-256 digest over the canonical document plus an
 * unsecured JWT carrying that digest, which `/verify-report` decodes. One
 * implementation, so a verification page and a QR code mean the same thing on
 * every document the platform emits.
 *
 * Pure and dependency-light (noble + jose) so it runs in the browser, in the API
 * and in the offline check tools.
 */

export interface IntegritySeal {
  algorithm: 'SHA3-256';
  hash: string;
  signedAt: string;
  verificationToken: string;
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/** SHA3-256 of a UTF-8 string, lowercase hex. */
export function sha3Hex(input: string): string {
  return hex(sha3_256(new TextEncoder().encode(input)));
}

/**
 * Seal a canonical document string. `claims.kind` distinguishes report families
 * on the verification page (e.g. `executive`, `asset-inventory`).
 */
export function sealDocument(canonical: string, claims: { reportId: string; kind: string }): IntegritySeal {
  const digest = sha3Hex(canonical);
  const signedAt = new Date().toISOString();
  const verificationToken = new UnsecuredJWT({ hash: digest, reportId: claims.reportId, kind: claims.kind })
    .setIssuedAt()
    .setSubject(claims.reportId)
    .setIssuer('qguard-helix-reporting')
    .encode();
  return { algorithm: 'SHA3-256', hash: digest, signedAt, verificationToken };
}
