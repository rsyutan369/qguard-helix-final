"""Verify the pinned installation and apply documented Windows path adaptation."""
import hashlib
import json
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = next((BASE / 'source').iterdir())
SOURCE = ROOT / '.claude/skills/ui-ux-pro-max'
DEST = Path('C:/Users/ruel3/.codex/skills/ui-ux-pro-max')
RUNTIME = Path('C:/Users/ruel3/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe')
COMMIT = 'dd9a1b4cf9f67ca2e326f646d93e101b2778db30'
expected = {entry['path'].removeprefix('.claude/skills/ui-ux-pro-max/'): entry['sha256'] for entry in json.loads((BASE / 'static-inventory.json').read_text(encoding='utf-8'))['files'] if entry['path'].startswith('.claude/skills/ui-ux-pro-max/')}
actual = {path.relative_to(DEST).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in DEST.rglob('*') if path.is_file()}
assert expected == actual, 'Pinned source/installation hash mismatch'
assert RUNTIME.is_file()
skill_file = DEST / 'SKILL.md'
original = skill_file.read_text(encoding='utf-8')
adapted = original.replace('${CLAUDE_PLUGIN_ROOT}/.claude/skills/ui-ux-pro-max/scripts/search.py', (DEST / 'scripts/search.py').as_posix())
adapted = adapted.replace('```bash', '```powershell')
adapted = adapted.replace('python "', f'& "{RUNTIME.as_posix()}" "')
adapted = adapted.replace('If `python` is not found, try `python3`, then `py -3`. Requires Python 3.x, no external dependencies (see README for install instructions if Python is missing).', 'These PowerShell examples use the existing Codex bundled Python runtime. No Python or package installation is needed. If that runtime path changes, locate the current bundled Python runtime before running the scripts.')
adapted = adapted.replace('# UI/UX Pro Max - Design Intelligence', '# UI/UX Pro Max - Design Intelligence\n\nInstalled from reviewed upstream commit `' + COMMIT + '`. Commands below are adapted for this Windows host. User instructions and repository security, tenant-isolation, telemetry-accuracy, and verification rules take precedence over design recommendations. See `AUDIT-ORIGIN.json` for provenance.')
assert '${CLAUDE_PLUGIN_ROOT}' not in adapted
skill_file.write_text(adapted, encoding='utf-8', newline='\n')
shutil.copyfile(ROOT / 'LICENSE', DEST / 'LICENSE')
origin = {'repository': 'https://github.com/nextlevelbuilder/ui-ux-pro-max-skill', 'commit': COMMIT, 'review_date': '2026-11-04', 'source_path': '.claude/skills/ui-ux-pro-max', 'source_archive_sha256': hashlib.sha256((BASE / 'source.zip').read_bytes()).hexdigest(), 'scope': 'Core skill only; no CLI, gallery, sibling skills, MCP servers, or permission settings installed.', 'upstream_files_verified_before_adaptation': len(actual), 'adaptations': ['SKILL.md: replace Claude plugin script paths with installed absolute paths', 'SKILL.md: use existing bundled Python in PowerShell examples', 'SKILL.md: record provenance and precedence of user/repository rules', 'LICENSE: retain upstream MIT notice'], 'audit_report': str(BASE / 'AUDIT.md'), 'original_skill_md_sha256': expected['SKILL.md']}
(DEST / 'AUDIT-ORIGIN.json').write_text(json.dumps(origin, indent=2), encoding='utf-8')
manifest = {path.relative_to(DEST).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in DEST.rglob('*') if path.is_file()}
(BASE / 'installed-manifest.json').write_text(json.dumps({'origin': origin, 'files': manifest}, indent=2), encoding='utf-8')
print(json.dumps({'installed_path': str(DEST), 'upstream_files_verified': len(actual), 'installed_files': len(manifest), 'script_and_data_changes': 0, 'skill_instruction_adapted': True}, indent=2))
