/** Throwaway diagnostic: what quantum status does each algorithm actually get? */
import fs from 'node:fs';
import path from 'node:path';
import { runExposureScan } from '@/lib/scanner/exposure/orchestrator';
import { resolveProfile } from '@/lib/scanner/exposure/profiles';
import { emptyWorkspace } from '@/lib/scanner/exposure/engine-contract';
import { toWorkspaceFile } from '@/lib/scanner/exposure/content/file-discovery';
import type { WorkspaceFile } from '@/lib/scanner/exposure/engine-contract';

const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.vite', 'out']);

function walk(root: string, cap = 1500): WorkspaceFile[] {
  const files: WorkspaceFile[] = [];
  const stack = [root];
  while (stack.length && files.length < cap) {
    const dir = stack.pop()!;
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP.has(e.name)) stack.push(full); continue; }
      if (!e.isFile()) continue;
      const st = fs.statSync(full);
      if (st.size > 512 * 1024) continue;
      let content: string | null = null;
      try { content = fs.readFileSync(full, 'utf8'); } catch { content = null; }
      files.push(toWorkspaceFile(path.relative(root, full).split(path.sep).join('/'), content, st.size));
    }
  }
  return files;
}

async function main() {
  const ws = emptyWorkspace();
  ws.files = walk(path.resolve('src/lib'));
  const { engines } = resolveProfile('dev', 'deep');
  const a = await runExposureScan({
    scanId: 'diag', mode: 'dev',
    target: { kind: 'repository', url: 'u', provider: 'github', owner: 'o', repo: 'r', visibility: 'private' },
    profileId: 'deep', engineIds: engines, workspace: ws, budgetMs: 600_000, engineBudgetMs: 180_000,
  });

  // Per canonical algorithm: the DISTINCT statuses its components carry.
  const byAlg = new Map<string, Map<string, number>>();
  for (const c of a.cbom) {
    const m = byAlg.get(c.canonicalAlgorithm) ?? new Map<string, number>();
    m.set(c.quantumStatus, (m.get(c.quantumStatus) ?? 0) + 1);
    byAlg.set(c.canonicalAlgorithm, m);
  }

  console.log('\nalgorithm            statuses observed (count)');
  console.log('─'.repeat(70));
  const rows = [...byAlg.entries()].sort((x, y) => {
    const sx = [...x[1].values()].reduce((s, n) => s + n, 0);
    const sy = [...y[1].values()].reduce((s, n) => s + n, 0);
    return sy - sx;
  });
  for (const [alg, statuses] of rows) {
    const parts = [...statuses.entries()].map(([s, n]) => `${s}=${n}`).join('  ');
    const split = statuses.size > 1 ? '  <-- SPLIT' : '';
    console.log(`  ${alg.padEnd(20)} ${parts}${split}`);
  }

  // Roles, to see whether symmetric/hash are being counted as quantum-relevant.
  console.log('\nrole x status:');
  const byRole = new Map<string, Map<string, number>>();
  for (const c of a.cbom) {
    const m = byRole.get(c.usage) ?? new Map<string, number>();
    m.set(c.quantumStatus, (m.get(c.quantumStatus) ?? 0) + 1);
    byRole.set(c.usage, m);
  }
  for (const [role, statuses] of byRole) {
    console.log(`  ${role.padEnd(18)} ${[...statuses.entries()].map(([s, n]) => `${s}=${n}`).join('  ')}`);
  }

  // A few concrete components for the worst offenders.
  console.log('\nsample components for symmetric/hash algorithms:');
  for (const name of ['AES', 'SHA-1', 'MD5', '3DES', 'RC4', 'ML-KEM', 'ML-DSA', 'SLH-DSA']) {
    const sample = a.cbom.find((c) => c.canonicalAlgorithm === name);
    if (!sample) continue;
    console.log(`  ${name.padEnd(10)} status=${String(sample.quantumStatus).padEnd(16)} usage=${String(sample.usage).padEnd(14)} file=${sample.file ?? '?'}:${sample.line ?? '?'}`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
