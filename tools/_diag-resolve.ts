/** Throwaway: what does findAlgorithm resolve these names to? */
import { findAlgorithm } from '@/lib/crypto/knowledge-base';

for (const name of [
  'X25519MLKEM768', 'x25519', 'X25519', 'P-256', 'p256', 'secp256r1',
  'ECDSA', 'ECDH', 'ML-KEM', 'mlkem', 'ML-DSA', 'mldsa', 'kyber', 'dilithium',
  'sntrup761', 'SLH-DSA', 'Ed25519', 'RSA',
]) {
  const entry = findAlgorithm(name);
  console.log(
    `  ${name.padEnd(18)} -> ${entry ? `${entry.canonicalName.padEnd(14)} type=${entry.primitiveType.padEnd(20)} shor=${entry.shorBroken}` : 'null'}`,
  );
}
