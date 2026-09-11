/** Throwaway: do secret findings carry the quantumStatus urgentNonCrypto filters on? */
import fs from 'node:fs';
import path from 'node:path';
import { runExposureScan } from '@/lib/scanner/exposure/orchestrator';
import { resolveProfile } from '@/lib/scanner/exposure/profiles';
import { emptyWorkspace } from '@/lib/scanner/exposure/engine-contract';
import { toWorkspaceFile } from '@/lib/scanner/exposure/content/file-discovery';
import type { WorkspaceFile } from '@/lib/scanner/exposure/engine-contract';

const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.vite', 'out']);
function walk(root: string, cap = 1500): WorkspaceFile[] {
  const files: WorkspaceFile[] = []; const stack = [root];
  while (stack.length && files.length < cap) {
    const dir = stack.pop()!;
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP.has(e.name)) stack.push(full); continue; }
      if (!e.isFile()) continue;
      const st = fs.statSync(full); if (st.size > 512 * 1024) continue;
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

  const byStatus = new Map<string, number>();
  for (const f of a.findings) byStatus.set(f.quantumStatus, (byStatus.get(f.quantumStatus) ?? 0) + 1);
  console.log('finding quantumStatus distribution:');
  for (const [k, v] of byStatus) console.log(`  ${String(k).padEnd(18)} ${v}`);

  console.log('\nsecret-discovery findings:');
  for (const f of a.findings.filter((x) => x.engineId === 'secret-discovery')) {
    console.log(`  sev=${f.severity.padEnd(9)} qs=${String(f.quantumStatus).padEnd(16)} ${f.title}`);
  }

  const urgent = a.findings.filter(
    (f) => f.quantumStatus === 'not-applicable' && (f.severity === 'critical' || f.severity === 'high'),
  );
  console.log(`\nurgentNonCrypto would surface: ${urgent.length} finding(s)`);

  console.log('\ncritical findings (all engines):');
  for (const f of a.findings.filter((x) => x.severity === 'critical')) {
    console.log(`  [${f.engineId}] qs=${String(f.quantumStatus).padEnd(14)} ${f.title}`);
  }

  console.log('\nrecommendation titles (raw, before any merge):');
  for (const r of a.intelligence.recommendations) console.log(`  [${r.severity}] ${r.title}  (${r.findingIds.length} findings)`);
}

main().catch((e) => { console.error(e); process.exit(1); });
