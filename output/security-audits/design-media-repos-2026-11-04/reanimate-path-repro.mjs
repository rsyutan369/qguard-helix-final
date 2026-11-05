// Harmless regression reproduction. All writes stay inside this audit folder.
import assert from 'node:assert/strict';
import {mkdirSync, readFileSync, writeFileSync, existsSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {writeGlArtifacts} from './NiazMorshed2007--reanimate/skills/reanimate/scripts/gl.ts';

const base = join(dirname(fileURLToPath(import.meta.url)), 'reanimate-path-repro');
const out = join(base, 'capture');
mkdirSync(out, {recursive: true});
const sentinel = join(base, 'package.json');
const original = '{"name":"audit-owned-sentinel","changed":false}\n';
const replacement = '{"name":"audit-owned-sentinel","changed":true}\n';
writeFileSync(sentinel, original);
const data = {
  programs: [], textures: [], buffers: [], framebuffers: [], contexts: [], frameData: [],
  gpu: {modules: [{id: '../../../outside-capture', code: '// audit marker'}], pipelines: []},
  three: {revision: null, scenes: [{index: 'x/../../../package', _json: replacement, tree: [], objects: 0}], renderers: []},
};
let error = null;
try { writeGlArtifacts(out, data, 0, 1); } catch (cause) { error = String(cause); }
assert.equal(readFileSync(sentinel, 'utf8'), replacement);
const escapedShader = join(base, 'outside-capture.wgsl');
assert.ok(existsSync(escapedShader));
assert.equal(readFileSync(escapedShader, 'utf8'), '// audit marker');
assert.ok(!resolve(sentinel).startsWith(resolve(out) + '/'));
const result = {confirmed: true, capture_directory: out, audit_owned_files_written_outside_capture: [sentinel, escapedShader], existing_json_sentinel_overwritten: true, later_processing_error: error, scope: 'Direct call to the original unmodified trace serializer with synthetic webpage-controlled data; no remote page visited and no packages installed.'};
writeFileSync(join(base, 'result.json'), JSON.stringify(result, null, 2));
console.log(JSON.stringify(result, null, 2));
