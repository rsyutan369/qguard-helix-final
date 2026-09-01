/**
 * Semantic cryptographic detection (§6, §27, §28, §29, §46, §47).
 *
 * The layer that turns a pattern match into a cryptographic FACT.
 *
 * §47 defines eight detection layers. This module implements the three that
 * operate on source text — API, AST-lite and data-flow — and returns each
 * observation tagged with the layer that produced it, so the ground-truth
 * engine can weigh independent agreement rather than counting repetitions.
 *
 * WHY "AST-LITE" AND NOT A REAL PARSER
 *
 * A full multi-language AST would need a parser per language, would not run in
 * a browser Web Worker at acceptable size, and would fail on the partial and
 * templated files a scanner routinely meets. What the rules here actually need
 * is narrower: whether a match sits inside a comment or a string, what the
 * enclosing function is called, and which identifiers the value flows into.
 * A brace-and-quote tracker answers all three, degrades safely on malformed
 * input, and states its own limits — which a half-working parser would not.
 */

import {
  CAVEATS,
  CRYPTO_APIS,
  KDF_PARAMETER_RULES,
  WEAK_RANDOM_RULES,
  apisForLanguage,
  classify,
  detectHybridPartner,
  findAlgorithm,
  roleForOperation,
  type CryptoApiDefinition,
  type CryptoClassification,
  type CryptoRole,
  type DetectionLayer,
  type EvidenceQuality,
  type GroundTruthEvidence,
} from '@/lib/crypto/knowledge-base';

/* ═══════════════════════════════════════════════════════════ source model ══ */

/** A file prepared for semantic analysis. */
export interface SourceDocument {
  path: string;
  content: string;
  language: string;
  lines: string[];
  /** 1-based line numbers wholly inside a comment. */
  commentLines: Set<number>;
  /** 1-based line numbers that are inside a string literal spanning lines. */
  stringLines: Set<number>;
  /** Enclosing function/method name per line, where one could be determined. */
  enclosing: Map<number, string>;
  /** True when the file looks generated or minified. */
  generated: boolean;
}

const COMMENT_PREFIX = /^\s*(\/\/|#(?!!)|--|;|\*|\/\*|<!--|%)/;

/**
 * Enclosing-function names that mean the hash is NOT a security control.
 *
 * §14: "SHA-1 certificate signature is materially different from SHA-1 used in
 *       a non-security legacy identifier."
 *
 * MD5 computing an ETag or a cache key is not a vulnerability, and reporting it
 * as one is how a scanner trains its reader to ignore it. The enclosing
 * function name is the cheapest reliable signal for that intent.
 */
const NON_SECURITY_HASH_CONTEXT =
  /\b(cache|etag|e_tag|fingerprint|checksum|dedup|dedupe|shard|bucket|partition|colou?r|avatar|gravatar|identicon|hashcode|hash_code|content_?id|object_?id|revision|version_?hash|cache_?key|memo|lookup)\b/i;

/** Identifiers that make a hash a security control after all. */
const SECURITY_HASH_CONTEXT =
  /\b(password|passwd|signature|sign|verify|token|hmac|integrity|certificate|cert|auth|credential|secret|digest_?auth|mac)\b/i;

const BLOCK_OPEN: Record<string, { open: RegExp; close: RegExp }> = {
  c: { open: /\/\*/, close: /\*\// },
  html: { open: /<!--/, close: /-->/ },
};

const C_LIKE = new Set([
  'javascript', 'typescript', 'java', 'kotlin', 'c', 'cpp', 'csharp', 'go', 'rust',
  'swift', 'php', 'scala', 'dart', 'objective-c',
]);

const FUNCTION_DECLARATION: Array<{ language: string[]; pattern: RegExp; group: number }> = [
  { language: ['javascript', 'typescript'], pattern: /(?:function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(|([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{)/, group: 1 },
  { language: ['python'], pattern: /^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)/, group: 1 },
  { language: ['java', 'kotlin', 'csharp'], pattern: /(?:public|private|protected|internal|static|fun)\s[\w<>,\[\]\s]*\s([A-Za-z_]\w*)\s*\(/, group: 1 },
  { language: ['go'], pattern: /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)/, group: 1 },
  { language: ['rust'], pattern: /^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)/, group: 1 },
  { language: ['php'], pattern: /^\s*(?:public|private|protected|static|\s)*function\s+([A-Za-z_]\w*)/, group: 1 },
  { language: ['ruby'], pattern: /^\s*def\s+([A-Za-z_]\w*)/, group: 1 },
];

/**
 * Prepare a file once, so every rule shares the comment map and the enclosing
 * function index rather than recomputing them.
 */
export function prepareDocument(path: string, content: string, language: string): SourceDocument {
  const lines = content.split('\n');
  const commentLines = new Set<number>();
  const stringLines = new Set<number>();
  const enclosing = new Map<number, string>();

  const cLike = C_LIKE.has(language);
  const html = ['html', 'xml', 'vue', 'svelte', 'markdown'].includes(language);
  const python = language === 'python';

  let openBlock: 'c' | 'html' | 'py-single' | 'py-double' | null = null;
  let currentFunction = '';
  const declarations = FUNCTION_DECLARATION.filter((entry) => entry.language.includes(language));

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const lineNumber = index + 1;

    /* ── block comments and multi-line strings ──────────────────────────── */
    if (openBlock) {
      if (openBlock === 'py-single' || openBlock === 'py-double') stringLines.add(lineNumber);
      else commentLines.add(lineNumber);

      if (openBlock === 'c' && BLOCK_OPEN.c.close.test(line)) openBlock = null;
      else if (openBlock === 'html' && BLOCK_OPEN.html.close.test(line)) openBlock = null;
      else if (openBlock === 'py-single' && line.includes("'''")) openBlock = null;
      else if (openBlock === 'py-double' && line.includes('"""')) openBlock = null;
    } else {
      if (cLike && BLOCK_OPEN.c.open.test(line) && !BLOCK_OPEN.c.close.test(line)) {
        openBlock = 'c';
        commentLines.add(lineNumber);
      } else if (html && BLOCK_OPEN.html.open.test(line) && !BLOCK_OPEN.html.close.test(line)) {
        openBlock = 'html';
        commentLines.add(lineNumber);
      } else if (python) {
        /* A Python triple quote is a docstring — a STRING, not a comment. The
           distinction matters: a key inside a docstring is documentation, but a
           key inside a string literal may well be a real embedded secret. */
        const doubles = (line.match(/"""/g) ?? []).length;
        const singles = (line.match(/'''/g) ?? []).length;
        if (doubles === 1) {
          openBlock = 'py-double';
          stringLines.add(lineNumber);
        } else if (singles === 1) {
          openBlock = 'py-single';
          stringLines.add(lineNumber);
        }
      }
      if (COMMENT_PREFIX.test(line)) commentLines.add(lineNumber);
    }

    /* ── enclosing function ─────────────────────────────────────────────── */
    for (const declaration of declarations) {
      const match = line.match(declaration.pattern);
      if (!match) continue;
      const name = match[1] ?? match[2] ?? match[3];
      if (name) currentFunction = name;
      break;
    }
    if (currentFunction) enclosing.set(lineNumber, currentFunction);
  }

  /* Minified or generated files produce enormous line lengths and no comments;
     matches in them are real but unreviewable, so they carry a caveat. */
  const longest = lines.reduce((max, line) => Math.max(max, line.length), 0);
  const generated =
    longest > 2_000 ||
    /^\s*(\/\/|#|\/\*)\s*(Code generated|AUTO-GENERATED|@generated|DO NOT EDIT)/im.test(content.slice(0, 4_000));

  return { path, content, language, lines, commentLines, stringLines, enclosing, generated };
}

/* ══════════════════════════════════════════════════════════ observations ═══ */

/** One semantic cryptographic observation. */
export interface CryptoObservation {
  /** The detection layer that produced it (§47). */
  layer: DetectionLayer;
  /** How good the proof is on its own (§45). */
  quality: EvidenceQuality;
  /** The rule that fired. */
  ruleId: string;
  line: number;
  /** The matched source, redacted downstream. */
  snippet: string;
  /** The algorithm string as written. */
  observedAlgorithm: string;
  /** The role, when the layer established one. */
  declaredRole?: CryptoRole;
  /** Full classification against the knowledge base. */
  classification: CryptoClassification;
  /** Everything that weakens this observation. */
  caveats: string[];
  /** Enclosing function, when known — the §28 data-flow anchor. */
  enclosingFunction?: string;
  /** Extra structured facts the rule extracted. */
  attributes?: Record<string, string | number | boolean>;
}

/* ═══════════════════════════════════════════════════════ the API layer ══════ */

/**
 * Layer 3: API semantics (§29).
 *
 * The highest-value layer, because a call shape proves BOTH the algorithm and
 * the role. `crypto.createSign('RSA-SHA256')` is not "the string RSA appears";
 * it is "RSA is used to produce a digital signature with SHA-256 here".
 */
export function detectByApi(document: SourceDocument): CryptoObservation[] {
  const observations: CryptoObservation[] = [];
  const applicable = apisForLanguage(document.language);
  if (applicable.length === 0) return observations;

  for (let index = 0; index < document.lines.length; index += 1) {
    const line = document.lines[index];
    if (!line || line.length > 4_000) continue;
    const lineNumber = index + 1;

    /* A call inside a comment is not a call. It stays a LEXICAL observation via
       the other layer rather than being promoted to API evidence. */
    const inComment = document.commentLines.has(lineNumber);

    for (const api of applicable) {
      const match = line.match(api.pattern);
      if (!match) continue;

      const observed = api.algorithmFromGroup ? match[api.algorithmFromGroup] : api.algorithm ?? '';
      if (!observed) continue;

      const parameter = api.parameterFromGroup ? match[api.parameterFromGroup] : undefined;
      const window = contextWindow(document, index, 4);

      /* Some APIs name the OPERATION rather than the role — SubtleCrypto's
         sign/encrypt/deriveKey all share one call shape. */
      let role = api.role;
      if (role === 'unknown') {
        const operation = line.match(/subtle\.(\w+)|\.(Signing|KeyAgreement)\b/)?.[1] ?? '';
        if (operation) role = roleForOperation(operation);
      }

      const caveats: string[] = [];
      let quality: EvidenceQuality = api.evidenceQuality;
      if (inComment) {
        caveats.push(CAVEATS.inComment);
        quality = 'WEAK';
      }
      if (document.generated) caveats.push(CAVEATS.minified);

      /* §14: a hash is only a security finding when it is doing security work.
         MD5 behind `cacheKey()` is an identifier, not a broken control, and
         reporting it as HIGH is how a scanner teaches its reader to ignore it.
         The enclosing function name decides, and an explicit security term
         anywhere nearby overrides the exemption. */
      let nonSecurityHash = false;
      if (role === 'hashing') {
        const enclosingName = document.enclosing.get(lineNumber) ?? '';
        const scope = `${enclosingName} ${line}`;
        if (NON_SECURITY_HASH_CONTEXT.test(scope) && !SECURITY_HASH_CONTEXT.test(window)) {
          nonSecurityHash = true;
          caveats.push(
            `the hash is computed inside "${enclosingName || 'a non-security helper'}", which indicates an identifier or cache key rather than a security control`,
          );
        }
      }

      const classification = classify({
        algorithm: observed,
        context: `${window}\n${document.path}`,
        declaredRole: role !== 'unknown' ? role : undefined,
        curve: parameter && /p-?\d{3}|curve|secp|prime|brainpool/i.test(parameter) ? parameter : undefined,
        hash: parameter && /sha|md5|blake/i.test(parameter) ? parameter : undefined,
        library: api.library,
        hybridPartner: detectHybridPartner(window, observed),
      });

      observations.push({
        layer: 'api',
        quality,
        ruleId: api.apiId,
        line: lineNumber,
        snippet: line.trim(),
        observedAlgorithm: observed,
        declaredRole: role !== 'unknown' ? role : undefined,
        classification,
        caveats,
        enclosingFunction: document.enclosing.get(lineNumber),
        attributes: {
          api: api.apiId,
          ...(parameter ? { parameter } : {}),
          ...(api.library ? { library: api.library } : {}),
          ...(nonSecurityHash ? { nonSecurityUse: true } : {}),
        },
      });
    }
  }

  return observations;
}

/* ══════════════════════════════════════════════ the data-flow layer (§28) ══ */

/**
 * Layer 6: data-flow correlation.
 *
 * Two correlations are worth the cost and are both bounded to one function:
 *
 *  1. WEAK RNG → KEY MATERIAL. §17 is explicit that weak randomness is only a
 *     cryptographic finding when its output reaches a cryptographic use. A
 *     `Math.random()` for animation jitter is not a finding; one feeding an IV
 *     is a serious one. The correlation is what separates them.
 *
 *  2. KDF PARAMETER → PASSWORD HASH. A literal iteration count is only
 *     meaningful next to the KDF it configures.
 */
export function detectByDataFlow(document: SourceDocument): CryptoObservation[] {
  const observations: CryptoObservation[] = [];

  /* ── weak randomness reaching a cryptographic use ─────────────────────── */
  for (const rule of WEAK_RANDOM_RULES) {
    if (!rule.language.includes(document.language)) continue;

    for (let index = 0; index < document.lines.length; index += 1) {
      const line = document.lines[index];
      if (!line || line.length > 4_000) continue;
      if (!rule.pattern.test(line)) continue;
      const lineNumber = index + 1;

      /* The security context must be NEARBY, not anywhere in the file. A
         window of a few lines is what distinguishes "this random value becomes
         a nonce" from "this file also happens to mention tokens somewhere". */
      const window = contextWindow(document, index, 3);
      const enclosing = document.enclosing.get(lineNumber) ?? '';
      const contextHit = rule.securityContext.test(window) || rule.securityContext.test(enclosing);
      if (!contextHit) continue;

      const caveats: string[] = [];
      if (document.commentLines.has(lineNumber)) caveats.push(CAVEATS.inComment);
      /* Stated plainly: this is a correlation, and a correlation can be a
         coincidence. A reviewer needs to know which one they are looking at. */
      caveats.push('the security context is inferred from nearby identifiers and may be coincidental');

      observations.push({
        layer: 'data-flow',
        quality: 'CIRCUMSTANTIAL',
        ruleId: rule.ruleId,
        line: lineNumber,
        snippet: line.trim(),
        observedAlgorithm: 'Non-cryptographic PRNG',
        declaredRole: 'random-generation',
        classification: classify({
          algorithm: 'random',
          context: window,
          declaredRole: 'random-generation',
        }),
        caveats,
        enclosingFunction: enclosing || undefined,
        attributes: {
          weakSource: rule.ruleId,
          replacement: rule.replacement,
          securityContext: (window.match(rule.securityContext)?.[0] ?? '').slice(0, 40),
        },
      });
    }
  }

  /* ── KDF work factors ─────────────────────────────────────────────────── */
  for (const rule of KDF_PARAMETER_RULES) {
    if (!rule.language.includes(document.language)) continue;

    for (let index = 0; index < document.lines.length; index += 1) {
      const line = document.lines[index];
      if (!line || line.length > 4_000) continue;
      const match = line.match(rule.pattern);
      if (!match) continue;

      const value = Number(match[1]);
      if (!Number.isFinite(value) || value >= rule.minimum) continue;
      const lineNumber = index + 1;

      const caveats: string[] = [];
      if (document.commentLines.has(lineNumber)) caveats.push(CAVEATS.inComment);
      if (/test|spec|fixture/i.test(document.path)) caveats.push(CAVEATS.testPath);

      observations.push({
        layer: 'ast',
        quality: 'DIRECT',
        ruleId: rule.ruleId,
        line: lineNumber,
        snippet: line.trim(),
        observedAlgorithm: rule.algorithm,
        declaredRole: 'password-derivation',
        classification: classify({
          algorithm: rule.algorithm,
          context: contextWindow(document, index, 2),
          declaredRole: 'password-derivation',
        }),
        caveats,
        enclosingFunction: document.enclosing.get(lineNumber),
        attributes: {
          parameter: rule.parameter,
          observed: value,
          minimum: rule.minimum,
          unit: rule.unit,
          guidance: rule.guidance,
        },
      });
    }
  }

  return observations;
}

/* ═════════════════════════════════════════════════ the lexical layer (§47) ══ */

/**
 * Layer 1: lexical.
 *
 * Kept deliberately weak. A bare algorithm name with no call, no assignment and
 * no configuration key proves only that someone wrote the word. It is worth
 * recording — an inventory should notice an algorithm mentioned in a config
 * comment — but it must never on its own produce a high-confidence finding, and
 * the WEAK quality is what enforces that through the ground-truth engine.
 *
 * The caller supplies the matches (from the existing 125-pattern catalogue);
 * this function's job is to CONTEXTUALISE them.
 */
export function contextualiseLexical(
  document: SourceDocument,
  matches: Array<{ line: number; algorithm: string; ruleId: string; label: string }>,
): CryptoObservation[] {
  const observations: CryptoObservation[] = [];
  const isTestPath = /(^|\/)(tests?|__tests__|spec|specs|fixtures?|testdata|mocks?|examples?|samples?|e2e)(\/|$)/i.test(document.path)
    || /\.(test|spec)\.[a-z]+$/i.test(document.path);

  for (const match of matches) {
    const index = match.line - 1;
    const line = document.lines[index] ?? '';
    const window = contextWindow(document, index, 3);

    const caveats: string[] = [];
    let quality: EvidenceQuality = 'WEAK';

    if (document.commentLines.has(match.line)) caveats.push(CAVEATS.inComment);
    if (isTestPath) caveats.push(CAVEATS.testPath);
    if (document.generated) caveats.push(CAVEATS.minified);
    if (document.stringLines.has(match.line)) caveats.push(CAVEATS.inComment);

    /* An algorithm name that occurs ONLY inside a quoted string on this line is
       a log message, an error string or prose — not a use. Checking every
       occurrence matters: `createHash('md5')` also has the name in quotes, but
       there the quotes are an API argument, and that case is caught by the API
       layer with far stronger evidence. Here the demotion only applies when the
       line has no call shape at all. */
    if (onlyInsideStringLiteral(line, match.algorithm)) {
      caveats.push('the algorithm name appears only inside a string literal, which is characteristic of a log or error message');
      quality = 'WEAK';
    }

    /* A call, assignment or configuration key raises a bare name from "the word
       appears" to "something is configured", which is the CIRCUMSTANTIAL step
       between lexical and API evidence. */
    const looksStructural = /[(.[]|::|->|=>|:\s*['"]|=\s*['"]/.test(line);
    if (!looksStructural) caveats.push(CAVEATS.noCallSite);
    else if (!document.commentLines.has(match.line)) quality = 'CIRCUMSTANTIAL';

    /* A line that DISABLES an algorithm is a control, not a use. */
    if (/\b(disable|disallow|deny|forbid|reject|block|remove|exclude|!)\s*[-_]?\w*\s*[:=]?\s*(true|1|yes)?/i.test(line)
      && new RegExp(`[!-]\\s*${escapeRegex(match.algorithm)}`, 'i').test(line)) {
      caveats.push(CAVEATS.negationContext);
      quality = 'WEAK';
    }

    const classification = classify({
      algorithm: match.algorithm,
      context: `${match.label}\n${window}\n${document.path}`,
      hybridPartner: detectHybridPartner(window, match.algorithm),
    });

    observations.push({
      layer: 'lexical',
      quality,
      ruleId: match.ruleId,
      line: match.line,
      snippet: line.trim(),
      observedAlgorithm: match.algorithm,
      classification,
      caveats,
      enclosingFunction: document.enclosing.get(match.line),
      attributes: { pattern: match.label },
    });
  }

  return observations;
}

/* ══════════════════════════════════════════════════════════ merge to truth ══ */

/**
 * Group observations by cryptographic identity so the ground-truth engine sees
 * INDEPENDENT layers rather than repetitions.
 *
 * The key is (canonical algorithm, role, file) — deliberately not the line, so
 * an API observation and a lexical observation of the same call corroborate
 * each other instead of becoming two findings.
 */
export function groupForGroundTruth(
  document: SourceDocument,
  observations: CryptoObservation[],
): Map<string, { observations: CryptoObservation[]; evidence: GroundTruthEvidence[] }> {
  const groups = new Map<string, { observations: CryptoObservation[]; evidence: GroundTruthEvidence[] }>();

  for (const observation of observations) {
    const key = `${observation.classification.canonicalName}|${observation.classification.role}|${document.path}`;
    const group = groups.get(key) ?? { observations: [], evidence: [] };
    group.observations.push(observation);
    group.evidence.push({
      engineId: 'source-crypto',
      evidenceType: observation.layer === 'api' || observation.layer === 'ast' ? 'STATIC_ANALYSIS' : observation.layer === 'data-flow' ? 'INFERENCE' : 'STATIC_ANALYSIS',
      quality: observation.quality,
      layer: observation.layer,
      summary: `${observation.classification.canonicalName} via ${observation.ruleId} at ${document.path}:${observation.line}`,
      location: { file: document.path, line: observation.line },
      ruleId: observation.ruleId,
      observedAt: new Date().toISOString(),
      caveats: observation.caveats,
    });
    groups.set(key, group);
  }

  return groups;
}

/* ─────────────────────────────────────────────────────────────── helpers ──── */

/**
 * True when every occurrence of `needle` on this line sits inside a quoted
 * string AND the line has no cryptographic call shape.
 *
 * `logger.warn('Deprecated: SHA-1 signatures ...')` is a message.
 * `createHash('sha1')` is a call — the quotes are an argument, and the API
 * layer will have already claimed it with DIRECT evidence.
 */
function onlyInsideStringLiteral(line: string, needle: string): boolean {
  if (!needle) return false;
  const lower = line.toLowerCase();
  const target = needle.toLowerCase();

  const regions: Array<[number, number]> = [];
  let quote: string | null = null;
  let start = 0;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (quote) {
      if (char === '\\') {
        // An escaped character cannot close the string.
        index += 1;
        continue;
      }
      if (char === quote) {
        regions.push([start, index]);
        quote = null;
      }
    } else if (char === '"' || char === "'" || char === '`') {
      quote = char;
      start = index + 1;
    }
  }
  if (regions.length === 0) return false;

  let found = false;
  let allInProse = true;
  let from = 0;

  for (;;) {
    const at = lower.indexOf(target, from);
    if (at === -1) break;
    found = true;
    from = at + target.length;

    const region = regions.find(([open, close]) => at >= open && at < close);
    if (!region) {
      // Outside every string: this is code, not a message.
      allInProse = false;
      continue;
    }

    /* Being inside quotes is not enough to call it prose — `createHash('md5')`
       puts the algorithm in quotes too, and that is an ARGUMENT. The
       discriminator is what else is in the string: an argument is essentially
       just the algorithm token, while a log or error message is a sentence.
       Three or more words is the line between them. */
    const contents = line.slice(region[0], region[1]).trim();
    const words = contents.split(/\s+/).filter(Boolean);
    if (words.length < 3) allInProse = false;
  }

  return found && allInProse;
}

function contextWindow(document: SourceDocument, index: number, radius: number): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(document.lines.length, index + radius + 1);
  return document.lines.slice(start, end).join('\n');
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Every API rule id, for capability disclosure. */
export function apiRuleIds(): string[] {
  return CRYPTO_APIS.map((entry) => entry.apiId);
}

/** Language inferred from a path, matching the API catalogue's vocabulary. */
export function languageOfPath(path: string): string {
  const extension = (path.split('.').pop() ?? '').toLowerCase();
  const table: Record<string, string> = {
    js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
    ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript',
    py: 'python', pyi: 'python',
    java: 'java', kt: 'kotlin', kts: 'kotlin', scala: 'scala',
    c: 'c', h: 'c', cc: 'cpp', cpp: 'cpp', cxx: 'cpp', hpp: 'cpp', hh: 'cpp',
    cs: 'csharp', fs: 'csharp', vb: 'csharp',
    go: 'go', rs: 'rust', rb: 'ruby', php: 'php',
    swift: 'swift', m: 'objective-c', mm: 'objective-c',
    sh: 'shell', bash: 'shell', zsh: 'shell', ps1: 'powershell',
    dart: 'dart',
  };
  return table[extension] ?? 'unknown';
}
