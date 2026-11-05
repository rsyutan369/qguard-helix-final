import {readFileSync, writeFileSync, readdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {dirname, join, relative, extname} from 'node:path';
import {fileURLToPath} from 'node:url';
const base = dirname(fileURLToPath(import.meta.url));
const root = join(base, 'remotion');
const require = createRequire('C:/Users/ruel3/Music/qguard-helix-final/package.json');
const ts = require('typescript');
const tree = JSON.parse(readFileSync(join(base, 'remotion-dev--remotion-tree.json'), 'utf8'));
const expected = new Map(tree.tree.filter(entry => entry.type === 'blob').map(entry => [entry.path, entry]));
const files = [], diagnostics = [], mismatches = [], links = [];
function walk(dir) {
  for (const entry of readdirSync(dir, {withFileTypes: true})) {
    if (entry.name === '.git') continue;
    const path = join(dir, entry.name), rel = relative(root, path).replaceAll('\\', '/');
    if (entry.isSymbolicLink()) {links.push(rel); continue;}
    if (entry.isDirectory()) {walk(path); continue;}
    const data = readFileSync(path);
    const gitHash = raw => createHash('sha1').update(Buffer.from('blob ' + raw.length + '\x00')).update(raw).digest('hex');
    const expectedHash = expected.get(rel)?.sha;
    const normalized = Buffer.from(data.toString('utf8').replaceAll('\r\n', '\n'));
    if (expectedHash !== gitHash(data) && expectedHash !== gitHash(normalized)) mismatches.push(rel);
    files.push({path: rel, bytes: data.length, sha256: createHash('sha256').update(data).digest('hex')});
    if (['.ts', '.tsx', '.js', '.mjs', '.cjs'].includes(extname(path))) {
      const parsed = ts.createSourceFile(rel, data.toString('utf8'), ts.ScriptTarget.Latest, true);
      for (const error of parsed.parseDiagnostics) diagnostics.push({path: rel, message: ts.flattenDiagnosticMessageText(error.messageText, ' ')});
    }
  }
}
walk(root);
const skillFiles = files.filter(entry => entry.path.startsWith('packages/codex-plugin/skills/remotion-best-practices/'));
const result = {commit: '2f06c4e3166a94607c5c56d68169f3754a0ecc72', full_tree_files: expected.size, sparse_files: files.length, files, checked_skill_files: skillFiles.length, skipped_symlinks: links, git_blob_mismatches: mismatches, syntax_diagnostics: diagnostics};
writeFileSync(join(base, 'remotion-source-inventory.json'), JSON.stringify(result, null, 2));
console.log(JSON.stringify({full_tree_files: expected.size, sparse_files: files.length, checked_skill_files: skillFiles.length, skipped_symlinks: links, git_blob_mismatches: mismatches, syntax_diagnostics: diagnostics.slice(0, 15), syntax_diagnostic_total: diagnostics.length}, null, 2));
if (mismatches.length) process.exitCode = 1;
