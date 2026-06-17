/**
 * Dependency-free passphrase strength estimator for the Quantum Vault.
 *
 * The passphrase is the root of trust: it gates the Argon2id-wrapped master keys,
 * and that wrapped bundle is stored server-side (harvestable). So passphrase
 * entropy is the real Harvest-Now-Decrypt-Later parameter — a weak choice is
 * brute-forceable offline regardless of ML-KEM. This estimator blocks the weak
 * cases (short, repeated, sequential, common-word) at vault creation.
 *
 * It is intentionally lightweight (no zxcvbn / ~400 KB dictionary). Char-pool
 * entropy is generous to long memorable phrases but strict on the dangerous
 * patterns, which is the right bias for a *minimum* gate.
 */

export interface PassphraseStrength {
  score: 0 | 1 | 2 | 3 | 4
  label: 'Very weak' | 'Weak' | 'Fair' | 'Strong' | 'Excellent'
  entropyBits: number
  warnings: string[]
  suggestions: string[]
  acceptable: boolean
}

export const MIN_PASSPHRASE_LENGTH = 12
const MIN_ACCEPTABLE_ENTROPY = 60

const COMMON_FRAGMENTS = [
  'password', 'passphrase', 'letmein', 'welcome', 'admin', 'qwerty', 'azerty',
  'iloveyou', 'qguard', 'helix', 'vault', 'quantum', 'dragon', 'monkey',
  'secret', 'master', 'sunshine', 'football', 'baseball', 'princess', 'login',
  '123456', '111111', '000000', '654321', 'abc123', 'password1', 'qwerty123',
]

const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890']

function charPoolSize(pw: string): number {
  let pool = 0
  if (/[a-z]/.test(pw)) pool += 26
  if (/[A-Z]/.test(pw)) pool += 26
  if (/[0-9]/.test(pw)) pool += 10
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33
  return pool || 1
}

function uniqueRatio(pw: string): number {
  if (!pw.length) return 0
  return new Set(pw.split('')).size / pw.length
}

function hasSequentialRun(pw: string, len = 4): boolean {
  const lower = pw.toLowerCase()
  for (let i = 0; i + len <= lower.length; i++) {
    let asc = true
    let desc = true
    for (let j = 1; j < len; j++) {
      const a = lower.charCodeAt(i + j - 1)
      const b = lower.charCodeAt(i + j)
      if (b - a !== 1) asc = false
      if (a - b !== 1) desc = false
    }
    if (asc || desc) return true
  }
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i + len <= row.length; i++) {
      const seg = row.slice(i, i + len)
      if (lower.includes(seg) || lower.includes([...seg].reverse().join(''))) return true
    }
  }
  return false
}

export function estimatePassphraseStrength(pw: string): PassphraseStrength {
  const warnings: string[] = []
  const suggestions: string[] = []
  const lower = pw.toLowerCase()

  let entropy = pw.length * Math.log2(charPoolSize(pw))

  if (pw.length > 0 && uniqueRatio(pw) < 0.6) {
    entropy *= 0.6
    warnings.push('Too many repeated characters')
    suggestions.push('Use more distinct characters')
  }
  if (hasSequentialRun(pw)) {
    entropy *= 0.55
    warnings.push('Avoid sequences like “abcd”, “1234”, or keyboard runs')
  }
  if (/^(.)\1+$/.test(pw)) {
    entropy = Math.min(entropy, 8)
  }
  for (const fragment of COMMON_FRAGMENTS) {
    if (lower.includes(fragment)) {
      entropy = Math.min(entropy, 20)
      warnings.push('Contains a common word or predictable pattern')
      suggestions.push('Prefer 4+ random, unrelated words')
      break
    }
  }

  entropy = Math.max(0, Math.round(entropy))

  let score: number
  if (entropy < 28) score = 0
  else if (entropy < 40) score = 1
  else if (entropy < MIN_ACCEPTABLE_ENTROPY) score = 2
  else if (entropy < 90) score = 3
  else score = 4

  if (pw.length < MIN_PASSPHRASE_LENGTH) {
    score = Math.min(score, 1)
    suggestions.push(`Use at least ${MIN_PASSPHRASE_LENGTH} characters (${MIN_PASSPHRASE_LENGTH - pw.length} more)`)
  }

  const labels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Excellent'] as const
  const acceptable = pw.length >= MIN_PASSPHRASE_LENGTH && entropy >= MIN_ACCEPTABLE_ENTROPY && score >= 3

  if (!acceptable && suggestions.length === 0) {
    suggestions.push('Add length and mix character types, or use 4+ random words')
  }

  return {
    score: score as PassphraseStrength['score'],
    label: labels[score],
    entropyBits: entropy,
    warnings,
    suggestions,
    acceptable,
  }
}
