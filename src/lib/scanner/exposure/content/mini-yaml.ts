/**
 * A deliberately small YAML reader for Kubernetes, Helm, Compose and CI
 * manifests.
 *
 * WHY NOT A FULL PARSER: the platform ships no YAML dependency, this module
 * must stay isomorphic (it runs inside a browser Web Worker for LOCAL scans),
 * and the engines need three things a full parser is overkill for — the
 * document boundaries, the key path of every scalar, and the LINE NUMBER each
 * value came from. Line numbers are the reason a homegrown reader is the right
 * call here: most YAML libraries discard them, and a Kubernetes finding without
 * a line is a finding an engineer cannot act on.
 *
 * WHAT IT HANDLES: multi-document streams, block mappings, block sequences,
 * inline scalars, quoted scalars, flow sequences of scalars (`[a, b]`), block
 * scalars (`|`/`>`, captured verbatim), comments, and anchors/aliases at the
 * syntactic level (an alias resolves to the anchored node's value when the
 * anchor was a scalar; structural aliases are recorded and skipped).
 *
 * WHAT IT DOES NOT HANDLE: flow mappings spanning lines, complex keys, tags,
 * merge keys. Every engine that uses it treats an unresolved construct as
 * "not assessed" rather than as an absent control, so the limits of the reader
 * never become a false pass.
 */

export interface YamlNode {
  /** Dotted path with `[n]` for sequence entries, e.g. `spec.containers[0].image`. */
  path: string;
  key: string;
  value: string | null;
  line: number;
  indent: number;
  /** True when the value was a block scalar or a nested structure. */
  container: boolean;
}

export interface YamlDocument {
  /** Every scalar leaf in the document, in source order. */
  nodes: YamlNode[];
  /** 1-based line where the document starts. */
  startLine: number;
  endLine: number;
  /** Raw text of this document. */
  text: string;
  /** True when at least one construct could not be read. */
  degraded: boolean;
  degradedReason?: string;
}

const DOCUMENT_SEPARATOR = /^---\s*(?:#.*)?$/;
const DOCUMENT_END = /^\.\.\.\s*$/;

/** Split a YAML stream into documents, preserving line offsets. */
export function splitDocuments(content: string): YamlDocument[] {
  const lines = content.split('\n');
  const documents: YamlDocument[] = [];
  let current: string[] = [];
  let startLine = 1;

  const flush = (endLine: number) => {
    const text = current.join('\n');
    if (text.trim()) {
      documents.push({ ...parseDocument(text, startLine), text, startLine, endLine });
    }
    current = [];
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (DOCUMENT_SEPARATOR.test(line)) {
      flush(index);
      startLine = index + 2;
      continue;
    }
    if (DOCUMENT_END.test(line)) {
      flush(index);
      startLine = index + 2;
      continue;
    }
    current.push(line);
  }
  flush(lines.length);

  return documents;
}

/** Parse one document's scalars with their paths and line numbers. */
function parseDocument(text: string, lineOffset: number): Omit<YamlDocument, 'text' | 'startLine' | 'endLine'> {
  const lines = text.split('\n');
  const nodes: YamlNode[] = [];
  /** Stack of { indent, path, seqIndex }. */
  const stack: Array<{ indent: number; path: string; seqIndex: number }> = [{ indent: -1, path: '', seqIndex: -1 }];
  let degraded = false;
  let degradedReason: string | undefined;
  let blockScalarIndent: number | null = null;
  let blockScalarPath = '';
  let blockScalarLines: string[] = [];
  let blockScalarStart = 0;

  const flushBlockScalar = () => {
    if (blockScalarIndent === null) return;
    nodes.push({
      path: blockScalarPath,
      key: blockScalarPath.split('.').pop() ?? blockScalarPath,
      value: blockScalarLines.join('\n'),
      line: blockScalarStart,
      indent: blockScalarIndent,
      container: false,
    });
    blockScalarIndent = null;
    blockScalarLines = [];
  };

  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index];
    const lineNumber = lineOffset + index;

    if (blockScalarIndent !== null) {
      const indent = raw.search(/\S/);
      if (raw.trim() === '' || (indent >= blockScalarIndent && indent !== -1)) {
        blockScalarLines.push(raw.slice(Math.min(blockScalarIndent, raw.length)));
        continue;
      }
      flushBlockScalar();
    }

    if (!raw.trim() || /^\s*#/.test(raw)) continue;

    const indent = raw.search(/\S/);
    const trimmed = raw.trim();

    // Pop to the parent for this indent.
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
    const parent = stack[stack.length - 1];

    /* ── sequence entry ─────────────────────────────────────────────── */
    if (trimmed.startsWith('- ') || trimmed === '-') {
      parent.seqIndex += 1;
      const entryPath = `${parent.path}[${parent.seqIndex}]`;
      const rest = trimmed === '-' ? '' : trimmed.slice(2).trim();

      if (!rest) {
        stack.push({ indent, path: entryPath, seqIndex: -1 });
        continue;
      }

      const inlineKey = rest.match(/^([^\s:#][^:#]*?)\s*:\s*(.*)$/);
      if (inlineKey) {
        // `- name: value` — the sequence entry is a mapping whose first key is
        // on the dash line. Its siblings are indented to the text, not the dash.
        const childIndent = indent + (trimmed.indexOf(rest));
        stack.push({ indent, path: entryPath, seqIndex: -1 });
        const key = inlineKey[1].trim();
        const value = stripComment(inlineKey[2]);
        const path = `${entryPath}.${key}`;
        if (value === '' || value === undefined) {
          stack.push({ indent: childIndent - 1, path, seqIndex: -1 });
          nodes.push({ path, key, value: null, line: lineNumber, indent: childIndent, container: true });
        } else {
          nodes.push({ path, key, value: unquote(value), line: lineNumber, indent: childIndent, container: false });
          stack.push({ indent: childIndent - 1, path: entryPath, seqIndex: -1 });
        }
        continue;
      }

      nodes.push({
        path: entryPath,
        key: parent.path.split('.').pop() ?? '',
        value: unquote(stripComment(rest)),
        line: lineNumber,
        indent,
        container: false,
      });
      continue;
    }

    /* ── mapping entry ──────────────────────────────────────────────── */
    const mapping = trimmed.match(/^("[^"]*"|'[^']*'|[^\s:#][^:]*?)\s*:\s*(.*)$/);
    if (!mapping) {
      degraded = true;
      degradedReason = `Line ${lineNumber} uses a YAML construct this reader does not parse.`;
      continue;
    }

    const key = unquote(mapping[1].trim());
    const rawValue = stripComment(mapping[2]);
    const path = parent.path ? `${parent.path}.${key}` : key;

    if (rawValue === '|' || rawValue === '>' || /^[|>][-+]?\d*$/.test(rawValue)) {
      blockScalarIndent = indent + 2;
      blockScalarPath = path;
      blockScalarStart = lineNumber;
      blockScalarLines = [];
      nodes.push({ path, key, value: null, line: lineNumber, indent, container: true });
      continue;
    }

    if (rawValue === '') {
      nodes.push({ path, key, value: null, line: lineNumber, indent, container: true });
      stack.push({ indent, path, seqIndex: -1 });
      continue;
    }

    if (rawValue.startsWith('[') && rawValue.endsWith(']')) {
      const items = rawValue.slice(1, -1).split(',').map((item) => unquote(item.trim())).filter(Boolean);
      items.forEach((item, itemIndex) => {
        nodes.push({ path: `${path}[${itemIndex}]`, key, value: item, line: lineNumber, indent, container: false });
      });
      nodes.push({ path, key, value: rawValue, line: lineNumber, indent, container: false });
      continue;
    }

    if (rawValue.startsWith('&') || rawValue.startsWith('*')) {
      degraded = true;
      degradedReason = degradedReason ?? `Line ${lineNumber} uses a YAML anchor or alias, which this reader records but does not resolve.`;
    }

    nodes.push({ path, key, value: unquote(rawValue), line: lineNumber, indent, container: false });
  }

  flushBlockScalar();
  return { nodes, degraded, degradedReason };
}

function stripComment(value: string): string {
  // A `#` inside quotes is not a comment.
  let inSingle = false;
  let inDouble = false;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (char === "'" && !inDouble) inSingle = !inSingle;
    else if (char === '"' && !inSingle) inDouble = !inDouble;
    else if (char === '#' && !inSingle && !inDouble && (index === 0 || /\s/.test(value[index - 1]))) {
      return value.slice(0, index).trim();
    }
  }
  return value.trim();
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

/* ────────────────────────────────────────────────────────────── accessors ── */

/** First node whose path matches exactly. */
export function nodeAt(document: YamlDocument, path: string): YamlNode | null {
  return document.nodes.find((node) => node.path === path) ?? null;
}

/** Every node whose LAST path segment is `key`, at any depth. */
export function nodesByKey(document: YamlDocument, key: string): YamlNode[] {
  const suffix = `.${key}`;
  return document.nodes.filter((node) => node.path === key || node.path.endsWith(suffix));
}

/**
 * Every node whose path matches a wildcard pattern.
 *
 *   `**`  any prefix, at any depth (including none)
 *   `*`   exactly one path segment
 *   `[]`  any sequence index
 *
 * `**` exists because Kubernetes nests deeply: a container securityContext
 * lives at `spec.template.spec.containers[0].securityContext`, so a rule
 * written with a single-segment prefix matches NOTHING. A security rule that
 * silently matches nothing reads as a clean result, which is the most dangerous
 * failure this module can have.
 *
 * The wildcards are swapped for sentinel tokens BEFORE the regex escape pass,
 * so escaping cannot mangle them and cannot accidentally produce them. The
 * sentinels are private-use code points, which cannot occur in a YAML key.
 */
export function nodesMatching(document: YamlDocument, pattern: string): YamlNode[] {
  const ANY_DEPTH = '\uE000';
  const ONE_SEGMENT = '\uE001';
  const ANY_INDEX = '\uE002';

  const source = pattern
    .split('**').join(ANY_DEPTH)
    .split('*').join(ONE_SEGMENT)
    .split('[]').join(ANY_INDEX)
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .split(ANY_DEPTH).join('.*')
    .split(ONE_SEGMENT).join('[^.\\[\\]]+')
    .split(ANY_INDEX).join('\\[\\d+\\]');

  let regex: RegExp;
  try {
    regex = new RegExp('^' + source + '$');
  } catch {
    return [];
  }
  return document.nodes.filter((node) => regex.test(node.path));
}

/** Scalar value at a path, or null. */
export function valueAt(document: YamlDocument, path: string): string | null {
  return nodeAt(document, path)?.value ?? null;
}

/** The Kubernetes `kind` of a document, when it has one. */
export function documentKind(document: YamlDocument): string | null {
  return valueAt(document, 'kind');
}

/** The Kubernetes `apiVersion` of a document. */
export function documentApiVersion(document: YamlDocument): string | null {
  return valueAt(document, 'apiVersion');
}

/** `metadata.name`, or null. */
export function documentName(document: YamlDocument): string | null {
  return valueAt(document, 'metadata.name');
}

/** `metadata.namespace`, or null. */
export function documentNamespace(document: YamlDocument): string | null {
  return valueAt(document, 'metadata.namespace');
}

/** True when the document is a Helm template (carries Go templating). */
export function isHelmTemplate(text: string): boolean {
  return /\{\{[-\s]*[.\w$]/.test(text);
}
