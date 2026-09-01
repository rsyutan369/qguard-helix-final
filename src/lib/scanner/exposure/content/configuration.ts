/**
 * Configuration Security Engine (§14).
 *
 * Reads the files that decide what cryptography a deployment ACTUALLY
 * negotiates — web-server configs, TLS profiles, SSH daemon configs, OpenSSL
 * policy, .env files, application settings — and reports cryptographic
 * misconfiguration with the setting that caused it.
 *
 * The rules are written against the CONFIGURATION DIRECTIVE, not against a bare
 * algorithm name, because that is the difference between a finding an engineer
 * can act on ("`ssl_protocols` on line 14 still offers TLSv1") and a finding
 * they cannot ("the word TLS appears in this file").
 *
 * Directive rules are also the only honest way to detect the ABSENCE of a
 * control: a config file that declares `ssl_protocols` and omits TLSv1.3 is a
 * measurable gap; a file that declares nothing is not, and is reported as such
 * rather than as a failure.
 */

import type { CryptoRole, FindingSeverity } from '../types';
import type { EngineContext, EngineResult, ExposureEngine, WorkspaceFile } from '../engine-contract';
import { buildEvidence, buildFinding, completed } from '../engine-contract';
import { canonicalAlgorithmName, classifyQuantum } from '../algorithms';
import { assessProtocol, cipherListPermits } from '@/lib/crypto/tls-intelligence';
import { STANDARDS, citeStandard } from '@/lib/crypto/knowledge-base';

type StandardKey = keyof typeof STANDARDS;

/* ─────────────────────────────────────────────────────────────── rule set ── */

export interface ConfigRule {
  id: string;
  label: string;
  /** Only run against files whose path matches. Empty = every config file. */
  appliesTo?: RegExp;
  regex: RegExp;
  severity: FindingSeverity;
  role: CryptoRole;
  algorithm?: string;
  description: string;
  recommendation: string;
  /** Set when a match is a GOOD sign — recorded as `info`, never as a problem. */
  positive?: boolean;
  /**
   * For cipher-list rules: the token this rule is about.
   *
   * An OpenSSL cipher string uses `!` to EXCLUDE, so `HIGH:!aNULL:!RC4` permits
   * neither anonymous key exchange nor RC4 — and a regex that greps for "RC4"
   * in it reports the exact opposite of what the configuration says. When this
   * field is set, the match is re-checked against the parsed list before the
   * finding is published.
   */
  cipherToken?: string;
  /**
   * Keys into the knowledge base's standards registry (§75, §76).
   *
   * Cited rather than restated, so the obligation label and the applicability
   * scope travel with the finding. A reader sees whether RFC 8996 is a formal
   * deprecation or an opinion, and whether CNSA 2.0 binds them at all.
   */
  standards?: StandardKey[];
}

export const CONFIG_RULES: ConfigRule[] = [
  /* ── TLS protocol versions ───────────────────────────────────────────── */
  {
    id: 'cfg-tls-1-0',
    label: 'TLS 1.0 enabled',
    /* The negative lookahead is load-bearing: without it `\bTLSv?1\b` matches
       the "TLSv1" inside "TLSv1.2", because the following "." is a word
       boundary. A hardened `ssl_protocols TLSv1.2 TLSv1.3` was being reported
       as offering TLS 1.0. */
    regex: /(?:ssl_protocols|SSLProtocol|MinProtocol|ssl_min_version|tls_min_version|protocols)\s*[=:]?\s*[^\n#]*\bTLSv?1(?:\.0)?(?![\d.])/i,
    severity: 'high',
    role: 'tls',
    algorithm: 'TLS',
    description: 'The TLS configuration still offers TLS 1.0, which has no forward-secure default suite set and is deprecated by RFC 8996.',
    recommendation: 'Restrict the protocol list to TLS 1.2 and TLS 1.3.',
    standards: ['RFC-8996', 'SP-800-52', 'RFC-9325'],
  },
  {
    id: 'cfg-tls-1-1',
    label: 'TLS 1.1 enabled',
    regex: /(?:ssl_protocols|SSLProtocol|MinProtocol|ssl_min_version|tls_min_version|protocols)\s*[=:]?\s*[^\n#]*\bTLSv?1\.1(?![\d.])/i,
    severity: 'high',
    role: 'tls',
    algorithm: 'TLS',
    description: 'The TLS configuration still offers TLS 1.1, deprecated by RFC 8996.',
    recommendation: 'Restrict the protocol list to TLS 1.2 and TLS 1.3.',
    standards: ['RFC-8996', 'SP-800-52', 'RFC-9325'],
  },
  {
    id: 'cfg-sslv3',
    label: 'SSL 3.0 enabled',
    regex: /(?:ssl_protocols|SSLProtocol)\s*[=:]?\s*[^\n#]*\bSSLv3\b/i,
    severity: 'critical',
    role: 'tls',
    algorithm: 'SSL (legacy)',
    description: 'SSL 3.0 is enabled. It is broken by POODLE and must not be offered under any circumstances.',
    recommendation: 'Remove SSLv3 from the protocol list immediately.',
    standards: ['RFC-8996', 'SP-800-52'],
  },
  {
    id: 'cfg-tls13-present',
    label: 'TLS 1.3 offered',
    regex: /(?:ssl_protocols|SSLProtocol|MaxProtocol|protocols)\s*[=:]?\s*[^\n#]*\bTLSv?1\.3\b/i,
    severity: 'info',
    role: 'tls',
    algorithm: 'TLS',
    positive: true,
    description: 'The configuration offers TLS 1.3, which is the prerequisite for hybrid post-quantum key agreement.',
    recommendation: 'Once the stack supports it, enable the X25519MLKEM768 group so the handshake becomes hybrid post-quantum.',
    standards: ['RFC-9325', 'SP-800-52'],
  },
  {
    id: 'cfg-hybrid-group',
    label: 'Hybrid post-quantum key-agreement group configured',
    regex: /(?:ssl_ecdh_curve|curves|groups|Groups|ssl_conf_command\s+Groups)\s*[=:]?\s*[^\n#]*\b(x25519mlkem768|X25519MLKEM768|x25519_kyber768|p256_mlkem768|SecP256r1MLKEM768)\b/i,
    severity: 'info',
    role: 'key-exchange',
    algorithm: 'ML-KEM',
    positive: true,
    description: 'A hybrid post-quantum key-agreement group is configured, so this endpoint negotiates ML-KEM alongside its classical curve.',
    recommendation: 'Keep the classical half in place until the ecosystem completes its transition.',
    standards: ['FIPS-203', 'CNSA-2.0'],
  },

  /* ── Cipher suites ───────────────────────────────────────────────────── */
  {
    id: 'cfg-null-cipher',
    cipherToken: 'aNULL',
    label: 'NULL or anonymous cipher permitted',
    regex: /(?:ssl_ciphers|SSLCipherSuite|ciphers|CipherString)\s*[=:]?\s*[^\n#]*\b(?:eNULL|aNULL|NULL-|ADH-|AECDH-)/i,
    severity: 'critical',
    role: 'tls',
    algorithm: 'TLS',
    description: 'The cipher list permits NULL encryption or anonymous key exchange, which provides no confidentiality or authentication.',
    recommendation: 'Remove eNULL, aNULL, ADH and AECDH from the cipher string.',
    standards: ['RFC-9325', 'SP-800-52'],
  },
  {
    id: 'cfg-rc4',
    cipherToken: 'RC4',
    label: 'RC4 cipher permitted',
    regex: /(?:ssl_ciphers|SSLCipherSuite|ciphers|CipherString|Ciphers)\s*[=:]?\s*[^\n#]*\bRC4\b/i,
    severity: 'high',
    role: 'tls',
    algorithm: 'RC4',
    description: 'RC4 is permitted. Its keystream biases are practically exploitable and it is prohibited by RFC 7465.',
    recommendation: 'Remove RC4 from the cipher list.',
    standards: ['RFC-7465', 'SP-800-52'],
  },
  {
    id: 'cfg-3des',
    cipherToken: '3DES',
    label: '3DES cipher permitted',
    regex: /(?:ssl_ciphers|SSLCipherSuite|ciphers|CipherString|Ciphers)\s*[=:]?\s*[^\n#]*\b(?:3DES|DES-CBC3)\b/i,
    severity: 'medium',
    role: 'tls',
    algorithm: '3DES',
    description: '3DES is permitted. Its 64-bit block size makes it vulnerable to Sweet32 birthday attacks on long-lived connections.',
    recommendation: 'Remove 3DES and DES-CBC3 suites from the cipher list.',
    standards: ['SP-800-131A', 'RFC-9325'],
  },
  {
    id: 'cfg-export-cipher',
    cipherToken: 'EXPORT',
    label: 'Export-grade cipher permitted',
    regex: /(?:ssl_ciphers|SSLCipherSuite|ciphers|CipherString)\s*[=:]?\s*[^\n#]*\b(?:EXP|EXPORT)\b/i,
    severity: 'critical',
    role: 'tls',
    algorithm: 'TLS',
    description: 'Export-grade cipher suites are permitted, reviving the FREAK and Logjam attack classes.',
    recommendation: 'Remove all EXPORT suites.',
    standards: ['RFC-9325', 'SP-800-131A'],
  },

  /* ── Key sizes and DH parameters ─────────────────────────────────────── */
  {
    id: 'cfg-weak-dh',
    label: 'Weak Diffie-Hellman parameter size',
    /* No leading \b: the group size is usually part of a filename
       (`dhparam1024.pem`), where there is no word boundary before the digits.
       The trailing (?!\d) still prevents 10240 from matching 1024. */
    regex: /(?:dhparam|ssl_dhparam|DHParameters)[^\n#]*?(?:1024|512|768)(?!\d)/i,
    severity: 'high',
    role: 'key-exchange',
    algorithm: 'Diffie-Hellman',
    description: 'A Diffie-Hellman group below 2048 bits is configured, which is within reach of precomputation attacks (Logjam).',
    recommendation: 'Generate a 3072-bit or larger group, or move to ECDHE with a named curve.',
    standards: ['SP-800-56A', 'SP-800-57', 'RFC-9325'],
  },
  {
    id: 'cfg-rsa-1024',
    label: 'RSA key size of 1024 bits or less',
    regex: /\b(?:rsa[_-]?key[_-]?(?:size|bits|length)|key[_-]?size|default_bits)\s*[=:]\s*(?:512|768|1024)\b/i,
    severity: 'critical',
    role: 'unknown',
    algorithm: 'RSA',
    description: 'An RSA key size of 1024 bits or less is configured. This is below the classical security floor, before any quantum consideration.',
    recommendation: 'Use 3072-bit RSA as an interim minimum and plan the ML-DSA / ML-KEM migration.',
    standards: ['SP-800-131A', 'SP-800-57'],
  },

  /* ── Certificate validation ──────────────────────────────────────────── */
  {
    id: 'cfg-verify-disabled',
    label: 'Certificate verification disabled',
    regex: /\b(?:ssl_verify|verify_ssl|rejectUnauthorized|SSL_VERIFY_NONE|insecure_skip_verify|InsecureSkipVerify|CURLOPT_SSL_VERIFYPEER|validate_certs|ssl_verify_mode)\s*[=:]\s*(?:false|0|none|no|SSL_VERIFY_NONE|VERIFY_NONE)\b/i,
    severity: 'critical',
    role: 'certificate',
    algorithm: 'TLS',
    description: 'Certificate verification is explicitly disabled, which removes authentication from TLS and makes the channel trivially interceptable.',
    recommendation: 'Re-enable verification and supply the correct trust anchor rather than bypassing the check.',
    standards: ['RFC-9325', 'OWASP-ASVS-V6'],
  },
  {
    id: 'cfg-tls-insecure-flag',
    label: 'Insecure TLS flag set',
    regex: /(?:--insecure\b|-k\s+https|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|PYTHONHTTPSVERIFY\s*=\s*0|GIT_SSL_NO_VERIFY\s*=\s*(?:1|true))/i,
    severity: 'high',
    role: 'certificate',
    algorithm: 'TLS',
    description: 'A flag or environment variable that disables TLS certificate validation is set.',
    recommendation: 'Remove the flag and install the required CA certificate into the trust store.',
    standards: ['RFC-9325', 'OWASP-ASVS-V6'],
  },

  /* ── Hashing and signature policy ────────────────────────────────────── */
  {
    id: 'cfg-sha1-signature',
    label: 'SHA-1 signature algorithm configured',
    regex: /(?:signature_algorithms|SignatureAlgorithms|sig_?alg|default_md|md)\s*[=:]\s*[^\n#]*\b(?:sha1|SHA1|rsa_pkcs1_sha1|ecdsa_sha1)\b/i,
    severity: 'high',
    role: 'signature',
    algorithm: 'SHA-1',
    description: 'SHA-1 is configured as a signature digest. SHA-1 collisions are practical (SHAttered) and it must not sign certificates or tokens.',
    recommendation: 'Set the digest to SHA-256 or stronger.',
    standards: ['SP-800-131A-SHA1', 'CABF-BR'],
  },
  {
    id: 'cfg-md5',
    label: 'MD5 configured as a digest',
    regex: /(?:default_md|md|hash|digest|checksum_algorithm)\s*[=:]\s*["']?md5["']?\b/i,
    severity: 'high',
    role: 'hashing',
    algorithm: 'MD5',
    description: 'MD5 is configured as a digest. It is collision-broken and unsuitable for any security purpose.',
    recommendation: 'Use SHA-256 or SHA3-256.',
    standards: ['RFC-6151', 'SP-800-131A'],
  },

  /* ── SSH ─────────────────────────────────────────────────────────────── */
  {
    id: 'cfg-ssh-weak-kex',
    appliesTo: /ssh(d)?_config$/i,
    label: 'Weak SSH key-exchange algorithm permitted',
    regex: /^\s*KexAlgorithms[^\n#]*\b(?:diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b/im,
    severity: 'high',
    role: 'key-exchange',
    algorithm: 'Diffie-Hellman',
    description: 'The SSH daemon permits a SHA-1-based or 1024-bit Diffie-Hellman key exchange.',
    recommendation: 'Restrict KexAlgorithms to curve25519-sha256 and diffie-hellman-group16-sha512 or better.',
    standards: ['SP-800-56A', 'SP-800-131A'],
  },
  {
    id: 'cfg-ssh-weak-cipher',
    appliesTo: /ssh(d)?_config$/i,
    label: 'Weak SSH cipher permitted',
    regex: /^\s*Ciphers[^\n#]*\b(?:3des-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc)\b/im,
    severity: 'medium',
    role: 'encryption',
    algorithm: '3DES',
    description: 'The SSH configuration permits a legacy cipher.',
    recommendation: 'Restrict Ciphers to chacha20-poly1305@openssh.com and the AES-GCM suites.',
    standards: ['SP-800-131A'],
  },
  {
    id: 'cfg-ssh-permit-root',
    appliesTo: /sshd_config$/i,
    label: 'SSH root login permitted with password',
    regex: /^\s*PermitRootLogin\s+yes\b/im,
    severity: 'high',
    role: 'authentication',
    description: 'PermitRootLogin is set to yes, allowing direct password authentication as root.',
    recommendation: 'Set PermitRootLogin to prohibit-password or no.',
  },

  /* ── Application-level ───────────────────────────────────────────────── */
  {
    id: 'cfg-jwt-none',
    label: 'JWT "none" algorithm permitted',
    regex: /(?:algorithms?|alg)\s*[=:]\s*\[?\s*["']none["']/i,
    severity: 'critical',
    role: 'token-signing',
    algorithm: 'JWT',
    description: 'The JWT configuration accepts the "none" algorithm, which allows an attacker to forge any token by stripping its signature.',
    recommendation: 'Pin the accepted algorithm list to the exact algorithm the issuer signs with.',
    standards: ['OWASP-ASVS-V6'],
  },
  {
    id: 'cfg-insecure-cookie',
    label: 'Session cookie without the Secure flag',
    regex: /(?:cookie[._]?secure|secure)\s*[=:]\s*(?:false|0|off)\b/i,
    severity: 'medium',
    role: 'authentication',
    description: 'A cookie is configured without the Secure attribute, so it can be transmitted over plaintext HTTP.',
    recommendation: 'Set Secure and HttpOnly on every session cookie, and SameSite where the flow allows.',
    standards: ['OWASP-ASVS-V6'],
  },
  {
    id: 'cfg-debug-production',
    label: 'Debug mode enabled',
    regex: /^\s*(?:DEBUG|APP_DEBUG|FLASK_DEBUG|DJANGO_DEBUG)\s*[=:]\s*(?:true|1|on)\b/im,
    severity: 'medium',
    role: 'unknown',
    description: 'Debug mode is enabled in a committed configuration file. Debug handlers routinely disclose secrets, key material and stack traces.',
    recommendation: 'Ensure debug is disabled for every non-development environment.',
  },
  {
    id: 'cfg-http-endpoint',
    label: 'Plaintext HTTP endpoint configured',
    regex: /\b(?:url|endpoint|host|uri|base[_-]?url)\s*[=:]\s*["']?http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/i,
    severity: 'medium',
    role: 'tls',
    algorithm: 'TLS',
    description: 'A non-loopback endpoint is configured over plaintext HTTP, so its traffic has no confidentiality, integrity or authentication.',
    recommendation: 'Move the endpoint to HTTPS and enable HSTS at the edge.',
  },
];

/* ────────────────────────────────────────────────────────────── the engine ── */

const CONFIG_CLASSES = new Set(['config', 'container', 'kubernetes', 'helm', 'iac', 'cicd']);

export const configurationEngine: ExposureEngine = {
  descriptor: {
    id: 'configuration-security',
    label: 'Configuration Security',
    description: 'Reads TLS, PKI, SSH and application configuration for cryptographic misconfiguration — the settings that decide what a deployment actually negotiates.',
    mode: 'local',
    layer: 'configuration',
    capability: 'configuration',
    dependsOn: ['file-discovery'],
    weight: 10,
  },

  appliesTo(context) {
    return context.workspace.files.some((file) => file.content && CONFIG_CLASSES.has(file.classification))
      ? { applicable: true }
      : { applicable: false, reason: 'No configuration files were found in scope.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const files = context.workspace.files.filter(
      (file) => file.content && !context.isExcluded(file.path) && CONFIG_CLASSES.has(file.classification),
    );

    const findings: ReturnType<typeof buildFinding>[] = [];
    let processed = 0;

    for (const file of files) {
      if (context.isCancelled()) break;
      processed += 1;
      if (processed % 20 === 0 || processed === files.length) {
        context.report('Reading configuration', { done: processed, total: files.length, unit: 'files' });
      }

      const content = file.content as string;
      const lines = content.split('\n');

      for (const rule of CONFIG_RULES) {
        if (rule.appliesTo && !rule.appliesTo.test(file.path)) continue;

        // Line-scoped match so the evidence can name the exact directive.
        let matchedLine = -1;
        for (let index = 0; index < lines.length; index += 1) {
          const line = lines[index];
          if (!line || line.length > 4_000) continue;
          if (/^\s*(#|;|\/\/)/.test(line)) continue; // a commented-out directive is not in force
          if (rule.regex.test(line)) {
            matchedLine = index;
            break;
          }
        }
        // Multiline rules (the `m` flag ones) may only match across the file.
        if (matchedLine === -1) {
          if (!rule.regex.flags.includes('m') || !rule.regex.test(content)) continue;
          matchedLine = 0;
        }

        /* An OpenSSL cipher string that EXCLUDES the token is a control, not a
           weakness. Re-check the parsed list before publishing, so
           `HIGH:!aNULL:!RC4` is read as the hardening it is. */
        if (rule.cipherToken) {
          const directive = lines[matchedLine] ?? '';
          const listValue = directive.split(/[=:]\s*/).slice(1).join(':').replace(/[;'"]+$/, '').trim();
          if (listValue && !cipherListPermits(listValue, rule.cipherToken)) continue;
        }

        const quantum = rule.algorithm
          ? classifyQuantum({ algorithm: rule.algorithm, role: rule.role })
          : { status: 'not-applicable' as const, rationale: 'This is a configuration control, not a cryptographic primitive.', quantumRelevant: false };

        const finding = buildFinding({
          scanId: context.scanId,
          engineId: 'configuration-security',
          mode: context.mode,
          layer: 'configuration',
          category: rule.positive ? 'Configuration Strength' : 'Configuration Weakness',
          subcategory: rule.label,
          title: `${rule.label} — ${file.path}`,
          description: `${rule.description} ${rule.positive ? '' : quantum.rationale}`.trim(),
          severity: rule.severity,
          confidence: 'high',
          detection: 'observed',
          algorithm: rule.algorithm,
          canonicalAlgorithm: rule.algorithm ? canonicalAlgorithmName(rule.algorithm) : undefined,
          role: rule.role,
          quantumStatus: rule.positive && rule.id === 'cfg-hybrid-group' ? 'hybrid' : quantum.status,
          quantumRationale: quantum.rationale,
          recommendation: rule.recommendation,
          references: (rule.standards ?? []).map((key) => citeStandard(STANDARDS[key])),
          evidence: [
            buildEvidence({
              summary: `${rule.label} at ${file.path}:${matchedLine + 1}`,
              file: file.path,
              line: matchedLine + 1,
              snippet: lines[matchedLine],
              ruleId: rule.id,
              localOnly: context.mode === 'local',
              attributes: { directive: rule.label, positive: Boolean(rule.positive) },
            }),
          ],
          identity: `${file.path}|${rule.id}`,
        });

        findings.push(finding);
        context.emit(finding);
      }
    }

    return completed(findings, { configFiles: files.length });
  },
};
