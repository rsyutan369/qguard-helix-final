// Query public advisory services against exact public lockfile versions; install nothing.
import {readFileSync, writeFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
const base = dirname(fileURLToPath(import.meta.url));
const require = createRequire('C:/Users/ruel3/Music/qguard-helix-final/package.json');
const ts = require('typescript');
const semver = require('C:/Program Files/nodejs/node_modules/npm/node_modules/semver');

async function queryNpm(name, file) {
  const parsed = ts.parseConfigFileTextToJson(file, readFileSync(file, 'utf8'));
  if (parsed.error) throw new Error('Invalid JSONC lockfile: ' + file);
  const packages = {};
  for (const entry of Object.values(parsed.config.packages)) {
    if (!Array.isArray(entry) || typeof entry[0] !== 'string') continue;
    const index = entry[0].lastIndexOf('@');
    const pkg = entry[0].slice(0, index), version = entry[0].slice(index + 1);
    if (!semver.valid(version)) continue;
    (packages[pkg] ??= new Set()).add(version);
  }
  const names = Object.keys(packages).sort();
  const findings = [];
  for (let start = 0; start < names.length; start += 200) {
    const payload = Object.fromEntries(names.slice(start, start + 200).map(pkg => [pkg, [...packages[pkg]]]));
    const response = await fetch('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload), signal: AbortSignal.timeout(45000)});
    if (!response.ok) throw new Error('npm advisory HTTP ' + response.status);
    const advisories = await response.json();
    for (const [pkg, values] of Object.entries(advisories)) for (const advisory of values) {
      const affected = [...packages[pkg]].filter(version => semver.satisfies(version, advisory.vulnerable_versions, {includePrerelease: true}));
      if (affected.length) findings.push({package: pkg, locked_versions: affected, severity: advisory.severity, title: advisory.title, url: advisory.url, vulnerable_versions: advisory.vulnerable_versions});
    }
  }
  const result = {scope: name, source_lockfile: file, distinct_package_names_queried: names.length, exact_package_versions_queried: Object.values(packages).reduce((n, values) => n + values.size, 0), findings};
  writeFileSync(join(base, name + '-dependency-audit.json'), JSON.stringify(result, null, 2));
  const highest = {};
  const ranks = {low: 1, moderate: 2, high: 3, critical: 4};
  for (const f of findings) if (!highest[f.package] || ranks[f.severity] > ranks[highest[f.package]]) highest[f.package] = f.severity;
  console.log(JSON.stringify({scope: name, queried: result.exact_package_versions_queried, affected_package_names: Object.keys(highest).length, highest_severities_by_package: highest, advisory_matches: findings.length}));
}

async function queryPyPi() {
  const source = join(base, 'Comfy-Org--ComfyUI');
  const queries = [];
  const unpinned = [];
  for (const filename of ['requirements.txt', 'manager_requirements.txt', 'agent_requirements.txt']) {
    for (const raw of readFileSync(join(source, filename), 'utf8').split(/\r?\n/)) {
      const line = raw.split('#')[0].trim();
      if (!line) continue;
      const match = /^([A-Za-z0-9_.-]+)==([^;\s]+)$/.exec(line);
      if (match) queries.push({package: {name: match[1].replace(/_/g, '-').toLowerCase(), ecosystem: 'PyPI'}, version: match[2]});
      else unpinned.push({file: filename, requirement: line});
    }
  }
  const response = await fetch('https://api.osv.dev/v1/querybatch', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({queries}), signal: AbortSignal.timeout(45000)});
  if (!response.ok) throw new Error('OSV HTTP ' + response.status);
  const data = await response.json();
  const checked = queries.map((query, i) => ({...query, advisories: data.results[i].vulns ?? []}));
  const result = {scope: 'ComfyUI exact direct pins only; not a resolved environment or transitive audit', checked, unresolved_requirements: unpinned};
  writeFileSync(join(base, 'ComfyUI-dependency-audit.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify({scope: 'ComfyUI exact direct pins', checked: checked.length, affected_pins: checked.filter(entry => entry.advisories.length), unresolved_requirements: unpinned.length}));
}

const tasks = [
  ['reanimate-scripts', () => queryNpm('reanimate-scripts', join(base, 'NiazMorshed2007--reanimate/skills/reanimate/scripts/bun.lock'))],
  ['reanimate-site', () => queryNpm('reanimate-site', join(base, 'NiazMorshed2007--reanimate/site/bun.lock'))],
  ['remotion-monorepo', () => queryNpm('remotion-monorepo', join(base, 'remotion/bun.lock'))],
  ['ComfyUI', queryPyPi],
];
const outcomes = await Promise.allSettled(tasks.map(async ([name, task]) => {try {await task(); return name;} catch (error) {writeFileSync(join(base, name + '-dependency-audit-error.txt'), String(error)); throw error;}}));
for (let i = 0; i < outcomes.length; i++) if (outcomes[i].status === 'rejected') { console.log(JSON.stringify({scope: tasks[i][0], error: String(outcomes[i].reason)})); process.exitCode = 1; }
