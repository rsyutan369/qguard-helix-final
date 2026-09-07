/**
 * Secret Discovery Engine (§12, §27, Spec-2 §12).
 *
 * THE HARD RULE, enforced structurally rather than by convention: a secret
 * VALUE never exists in a finding. This engine computes a SHA-free fingerprint
 * (FNV over the value, salted with the rule id) so two occurrences of the same
 * credential can be correlated, and then discards the value. Nothing
 * downstream — evidence, export, database, Sophia — can leak what was never
 * carried.
 *
 * Detection is two-track, which is what separates a usable secret scanner from
 * a noisy one:
 *
 *   PROVIDER RULES  — high-precision shapes (AKIA…, ghp_…, glpat-…, PEM
 *                     blocks). These are near-zero false positive and are
 *                     reported at HIGH confidence.
 *   ENTROPY RULES   — a secret-shaped assignment whose value has high Shannon
 *                     entropy. These are genuinely uncertain and are reported
 *                     at MEDIUM or LOW confidence, never as observed fact.
 *
 * Placeholder suppression matters more than any rule: `password = "changeme"`,
 * `API_KEY=your-key-here`, `secret: ${VAULT_SECRET}` and `token: <redacted>`
 * are the four things a scanner finds most often in real repositories, and all
 * four are documentation, not exposure.
 */

import type { FindingConfidence, FindingSeverity } from '../types';
import type { EngineContext, EngineResult, ExposureEngine, WorkspaceFile } from '../engine-contract';
import { buildEvidence, buildFinding, completed, reportStride } from '../engine-contract';
import { stableHash } from '../types';

/* ────────────────────────────────────────────────────────── provider rules ── */

export interface SecretRule {
  id: string;
  label: string;
  /** What kind of credential this is, shown in the UI. */
  type: string;
  regex: RegExp;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  /** Which capture group holds the secret material (for fingerprinting). */
  valueGroup?: number;
  /** Where the credential is used, for the remediation sentence. */
  remediation: string;
}

export const SECRET_RULES: SecretRule[] = [
  {
    id: 'secret-pem-private-key',
    label: 'PEM private key block',
    type: 'Private Key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/,
    severity: 'critical',
    confidence: 'high',
    remediation: 'Remove the key from the repository, rotate it at the issuing authority, and load it from a secret manager at runtime.',
  },
  {
    id: 'secret-putty-key',
    label: 'PuTTY private key',
    type: 'Private Key',
    regex: /PuTTY-User-Key-File-\d/,
    severity: 'critical',
    confidence: 'high',
    remediation: 'Rotate the SSH key pair and store the private half outside version control.',
  },
  {
    id: 'secret-aws-access-key',
    label: 'AWS access key id',
    type: 'Cloud Credential',
    regex: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/,
    severity: 'critical',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Deactivate the key in IAM, issue a replacement, and adopt short-lived role credentials.',
  },
  {
    id: 'secret-aws-secret-key',
    label: 'AWS secret access key',
    type: 'Cloud Credential',
    regex: /aws_?secret_?access_?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/i,
    severity: 'critical',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Deactivate the key pair in IAM immediately and rotate anything it signed.',
  },
  {
    id: 'secret-github-token',
    label: 'GitHub token',
    type: 'Repository Token',
    regex: /\b(gh[pousr]_[A-Za-z0-9]{30,})\b/,
    severity: 'critical',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Revoke the token in GitHub developer settings and replace it with a fine-grained, read-only token.',
  },
  {
    id: 'secret-gitlab-token',
    label: 'GitLab personal access token',
    type: 'Repository Token',
    regex: /\b(glpat-[A-Za-z0-9_-]{20,})\b/,
    severity: 'critical',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Revoke the token in GitLab and issue a scoped replacement.',
  },
  {
    id: 'secret-slack-token',
    label: 'Slack token',
    type: 'API Token',
    regex: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/,
    severity: 'high',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Revoke the token in the Slack app configuration.',
  },
  {
    id: 'secret-google-api-key',
    label: 'Google API key',
    type: 'API Key',
    regex: /\b(AIza[0-9A-Za-z_-]{35})\b/,
    severity: 'high',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Rotate the key in Google Cloud and apply an API and referrer restriction.',
  },
  {
    id: 'secret-gcp-service-account',
    label: 'GCP service account key',
    type: 'Cloud Credential',
    regex: /"type"\s*:\s*"service_account"/,
    severity: 'critical',
    confidence: 'high',
    remediation: 'Delete the service-account key in IAM and adopt Workload Identity Federation instead.',
  },
  {
    id: 'secret-azure-connection-string',
    label: 'Azure storage connection string',
    type: 'Cloud Credential',
    regex: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{40,})/,
    severity: 'critical',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Rotate the storage account key and move to Entra ID authentication with managed identity.',
  },
  {
    id: 'secret-stripe-key',
    label: 'Stripe secret key',
    type: 'Payment Credential',
    regex: /\b(sk_(?:live|test)_[A-Za-z0-9]{20,})\b/,
    severity: 'critical',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Roll the key in the Stripe dashboard immediately.',
  },
  {
    id: 'secret-openai-key',
    label: 'OpenAI API key',
    type: 'API Key',
    regex: /\b(sk-[A-Za-z0-9]{32,})\b/,
    severity: 'high',
    confidence: 'medium',
    valueGroup: 1,
    remediation: 'Revoke the key in the provider console.',
  },
  {
    id: 'secret-npm-token',
    label: 'npm access token',
    type: 'Registry Token',
    regex: /\b(npm_[A-Za-z0-9]{36})\b/,
    severity: 'high',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Revoke the token with `npm token revoke` and use a CI-scoped automation token.',
  },
  {
    id: 'secret-jwt',
    label: 'Encoded JWT',
    type: 'Token',
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
    severity: 'medium',
    confidence: 'medium',
    valueGroup: 1,
    remediation: 'Confirm whether the token is a live credential; if so, invalidate the session and rotate the signing key.',
  },
  {
    id: 'secret-db-url',
    label: 'Database connection URL with inline password',
    type: 'Database Credential',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^:\s'"]+:([^@\s'"]{4,})@/i,
    severity: 'critical',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Move the credential to a secret manager and rotate the database user password.',
  },
  {
    id: 'secret-basic-auth-url',
    label: 'HTTP URL with embedded credentials',
    type: 'Credential',
    regex: /https?:\/\/[^:\s'"/]+:([^@\s'"/]{4,})@/,
    severity: 'high',
    confidence: 'medium',
    valueGroup: 1,
    remediation: 'Remove inline credentials from URLs and pass them as headers sourced from a secret store.',
  },
  {
    id: 'secret-ssh-authorized-key',
    label: 'SSH authorized key entry',
    type: 'Public Key',
    regex: /\bssh-(rsa|dss|ed25519|ecdsa)\s+AAAA[0-9A-Za-z+/]{50,}/,
    severity: 'low',
    confidence: 'high',
    remediation: 'Public keys are not secret, but a committed authorized_keys file grants standing access — confirm the entry is intended.',
  },
  {
    id: 'secret-twilio',
    label: 'Twilio account SID / auth token',
    type: 'API Credential',
    regex: /\b(AC[0-9a-fA-F]{32}|SK[0-9a-fA-F]{32})\b/,
    severity: 'high',
    confidence: 'medium',
    valueGroup: 1,
    remediation: 'Rotate the auth token in the Twilio console.',
  },
  {
    id: 'secret-sendgrid',
    label: 'SendGrid API key',
    type: 'API Key',
    regex: /\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b/,
    severity: 'high',
    confidence: 'high',
    valueGroup: 1,
    remediation: 'Delete the key in SendGrid and issue a scoped replacement.',
  },
  {
    id: 'secret-private-key-var',
    label: 'Private key assigned inline',
    type: 'Private Key',
    regex: /(?:private_?key|signing_?key|encryption_?key)\s*[:=]\s*["'`]([A-Za-z0-9+/=]{32,})["'`]/i,
    severity: 'critical',
    confidence: 'medium',
    valueGroup: 1,
    remediation: 'Load key material from a KMS or secret manager rather than from source.',
  },
];

/* ─────────────────────────────────────────────────────────── entropy track ── */

/** Identifiers that make an assignment worth entropy-checking. */
const SECRET_IDENTIFIER = /\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth|credential|private[_-]?key|client[_-]?secret|encryption[_-]?key|signing[_-]?key)[A-Za-z0-9_.-]*)\s*[:=]\s*["'`]?([^\s"'`,;{}()\][]{8,120})["'`]?/gi;

/**
 * Placeholders. Every one of these appears in real repositories constantly, and
 * every one of them is documentation rather than a credential.
 */
const PLACEHOLDER = [
  /^(changeme|change[-_]me|placeholder|example|sample|dummy|test|testing|fake|foo|bar|baz|none|null|undefined|todo|tbd|xxx+|redacted|hidden|secret|password|not[-_]?set|empty)$/i,
  /* Hyphenated documentation placeholders: your-key-here, my-api-token,
     insert-secret-here, replace-with-your-key. `\w` does not match a hyphen, so
     these need their own character class or they stop at the first segment. */
  /^(your|my|our|insert|replace|enter|add|put|set)[-_][\w-]*$/i,
  /^[\w-]*(placeholder|goes[-_]here|here|example|sample)$/i,
  /^[\s*x.<>_-]+$/,
  /^\$\{[^}]+\}$/,
  /^\$[A-Z_][A-Z0-9_]*$/,
  /^\{\{[^}]+\}\}$/,
  /^%[A-Z_]+%$/,
  /^<[^>]+>$/,
  /^process\.env\./,
  /^os\.(getenv|environ)/,
  /^System\.getenv/,
  /^ENV\[/,
  /^(true|false|\d+)$/i,
  /^[a-f0-9]{7,8}$/i, // short git sha
  /^(sha256|sha512|md5):/i,
];

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

export function isPlaceholder(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 8) return true;
  return PLACEHOLDER.some((pattern) => pattern.test(trimmed));
}

/**
 * Entropy verdict for a candidate value.
 *
 * The thresholds are deliberately conservative: a base64 credential runs about
 * 5.0-6.0 bits/char, an English sentence about 3.5-4.0, and a kebab-case
 * identifier about 3.0. Flagging at 3.5 would flag every configuration string
 * in the repository.
 */
export function entropyVerdict(value: string): { flag: boolean; confidence: FindingConfidence; entropy: number } {
  const entropy = shannonEntropy(value);
  const hasMixedClasses = /[a-z]/.test(value) && /[A-Z0-9]/.test(value);
  const longEnough = value.length >= 16;

  if (entropy >= 4.8 && longEnough && hasMixedClasses) return { flag: true, confidence: 'medium', entropy };
  if (entropy >= 4.2 && value.length >= 32) return { flag: true, confidence: 'low', entropy };
  return { flag: false, confidence: 'low', entropy };
}

/* ────────────────────────────────────────────────────────────── the engine ── */

/** Files that are examples by name — findings there are informational. */
const EXAMPLE_FILE = /(^|\/)(\.env\.(example|sample|template|dist)|.*\.example|.*\.sample|.*\.template)$/i;
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|specs|fixtures?|testdata|mocks?|examples?)(\/|$)/i;

export const secretsEngine: ExposureEngine = {
  descriptor: {
    id: 'secret-discovery',
    label: 'Secret Discovery',
    description: 'Finds credentials, tokens, private keys and high-entropy secrets. Values are fingerprinted and discarded — never stored, transmitted or displayed.',
    mode: 'local',
    layer: 'secret',
    capability: 'secrets',
    dependsOn: ['file-discovery'],
    weight: 15,
    privacySensitive: true,
  },

  appliesTo(context) {
    return context.workspace.files.some((file) => file.content)
      ? { applicable: true }
      : { applicable: false, reason: 'No readable files were in scope.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const files = context.workspace.files.filter((file) => file.content && !context.isExcluded(file.path));
    const disabledRules = new Set(context.workspace.meta.disabledSecretRules as string[] | undefined ?? []);
    const findings: ReturnType<typeof buildFinding>[] = [];
    const fingerprints = new Set<string>();
    let processed = 0;

    /* One update per ~2% of the work, whatever the corpus size. */
    const secretStride = reportStride(files.length);
    for (const file of files) {
      if (context.isCancelled()) break;
      processed += 1;
      if (processed % secretStride === 0 || processed === files.length) {
        context.report('Scanning for credential material', { done: processed, total: files.length, unit: 'files' });
      }

      const content = file.content as string;
      const lines = content.split('\n');
      const isExample = EXAMPLE_FILE.test(file.path);
      const isTest = TEST_PATH.test(file.path);
      const historical = Boolean(file.commit);

      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        if (!line || line.length > 8_000) continue;

        /* ── provider rules ─────────────────────────────────────────── */
        for (const rule of SECRET_RULES) {
          if (disabledRules.has(rule.id)) continue;
          const match = line.match(rule.regex);
          if (!match) continue;

          const rawValue = rule.valueGroup ? match[rule.valueGroup] : match[0];
          if (rawValue && isPlaceholder(rawValue)) continue;

          // Fingerprint, then discard. This is the only place the value is read.
          const fingerprint = stableHash(`${rule.id}:${rawValue ?? match[0]}`);
          if (fingerprints.has(fingerprint)) continue;
          fingerprints.add(fingerprint);

          const severity = downgradeForContext(rule.severity, isExample, isTest);
          const finding = buildFinding({
            scanId: context.scanId,
            engineId: 'secret-discovery',
            mode: context.mode,
            layer: 'secret',
            category: 'Secret Exposure',
            subcategory: rule.type,
            title: `${rule.label} in ${file.path}`,
            description: [
              `A ${rule.type.toLowerCase()} matching the ${rule.label} shape was found${historical ? ' in Git history' : ''}. The value was fingerprinted for correlation and immediately discarded — it is not stored, transmitted or displayed anywhere in this platform.`,
              isExample ? 'The file is named as an example or template, so this is most likely documentation rather than a live credential.' : '',
              isTest ? 'The file is on a test path, which lowers but does not eliminate the risk.' : '',
            ].filter(Boolean).join(' '),
            severity,
            confidence: isExample ? 'low' : rule.confidence,
            detection: 'observed',
            quantumStatus: rule.type === 'Private Key' ? 'unknown' : 'not-applicable',
            quantumRationale:
              rule.type === 'Private Key'
                ? 'A committed private key is a present-tense compromise; its algorithm determines the additional quantum exposure once rotated.'
                : 'A credential has no quantum classification of its own.',
            recommendation: rule.remediation,
            evidence: [
              buildEvidence({
                summary: `${rule.label} matched at ${file.path}:${index + 1}. Value redacted.`,
                file: file.path,
                line: index + 1,
                snippet: line,
                ruleId: rule.id,
                reference: historical ? file.commit : undefined,
                localOnly: context.mode === 'local',
                attributes: {
                  secretType: rule.type,
                  fingerprint,
                  value: '[REDACTED]',
                  exampleFile: isExample,
                  historical,
                },
              }),
            ],
            identity: `${file.path}|${rule.id}|${fingerprint}`,
          });
          findings.push(finding);
          context.emit(finding);
        }

        /* ── entropy track ──────────────────────────────────────────── */
        if (disabledRules.has('secret-entropy')) continue;
        SECRET_IDENTIFIER.lastIndex = 0;
        let entropyMatch: RegExpExecArray | null;
        while ((entropyMatch = SECRET_IDENTIFIER.exec(line)) !== null) {
          const identifier = entropyMatch[1];
          const value = entropyMatch[2];
          if (isPlaceholder(value)) continue;
          const verdict = entropyVerdict(value);
          if (!verdict.flag) continue;

          const fingerprint = stableHash(`entropy:${value}`);
          if (fingerprints.has(fingerprint)) continue;
          fingerprints.add(fingerprint);

          const severity = downgradeForContext(isExample ? 'low' : 'high', isExample, isTest);
          const finding = buildFinding({
            scanId: context.scanId,
            engineId: 'secret-discovery',
            mode: context.mode,
            layer: 'secret',
            category: 'Secret Exposure',
            subcategory: 'High-entropy value',
            title: `Possible credential assigned to "${identifier}"`,
            description: `The identifier "${identifier}" is assigned a ${value.length}-character value with ${verdict.entropy.toFixed(2)} bits of entropy per character, which is characteristic of generated credential material rather than configuration. This is an entropy inference, not a confirmed credential — verify before rotating.`,
            severity,
            confidence: isExample ? 'low' : verdict.confidence,
            detection: 'potential',
            quantumStatus: 'not-applicable',
            recommendation: 'If this is a live credential, move it to a secret manager and rotate it. If it is not, add the rule to the scan exclusions so it stops being reported.',
            evidence: [
              buildEvidence({
                summary: `High-entropy assignment at ${file.path}:${index + 1}. Value redacted.`,
                file: file.path,
                line: index + 1,
                snippet: line,
                ruleId: 'secret-entropy',
                reference: historical ? file.commit : undefined,
                localOnly: context.mode === 'local',
                attributes: {
                  identifier,
                  entropyBitsPerChar: Number(verdict.entropy.toFixed(2)),
                  length: value.length,
                  fingerprint,
                  value: '[REDACTED]',
                  historical,
                },
              }),
            ],
            identity: `${file.path}|entropy|${fingerprint}`,
          });
          findings.push(finding);
          context.emit(finding);
        }
      }
    }

    return completed(findings, { secrets: findings.length }, { fingerprintCount: fingerprints.size });
  },
};

function downgradeForContext(severity: FindingSeverity, isExample: boolean, isTest: boolean): FindingSeverity {
  const ladder: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
  let index = ladder.indexOf(severity);
  if (isExample) index += 2;
  else if (isTest) index += 1;
  return ladder[Math.min(ladder.length - 1, index)];
}
