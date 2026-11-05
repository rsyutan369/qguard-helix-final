"""Verify upstream hashes, adapt the Remotion entrypoint, and install ComfyUI guidance."""
import hashlib
import json
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent
SKILLS = Path('C:/Users/ruel3/.codex/skills')
REMOTION = SKILLS / 'remotion-best-practices'
inventory = json.loads((BASE / 'remotion-source-inventory.json').read_text(encoding='utf-8'))
prefix = 'packages/codex-plugin/skills/remotion-best-practices/'
expected = {entry['path'].removeprefix(prefix): entry for entry in inventory['files'] if entry['path'].startswith(prefix)}
actual = {path.relative_to(REMOTION).as_posix(): path for path in REMOTION.rglob('*') if path.is_file()}
assert set(actual) == set(expected), 'Remotion installed file set differs from reviewed source'
for relative, path in actual.items():
    source = BASE / 'remotion' / prefix / relative
    assert path.read_bytes().replace(b'\r\n', b'\n') == source.read_bytes().replace(b'\r\n', b'\n'), relative

entrypoint = REMOTION / 'SKILL.md'
original = entrypoint.read_text(encoding='utf-8')
parts = original.split('---', 2)
assert len(parts) == 3 and 'version: 4.0.519' in parts[1]
frontmatter = '''---
name: remotion-best-practices
description: Create, edit, preview, and render React-based Remotion videos and compositions, including frame-based animation, audio, captions, maps, and player integrations. Use for Remotion video work; ordinary website or Android UI animation belongs to the web/mobile design skills.
metadata:
  upstream-version: "4.0.519"
  source-repository: https://github.com/remotion-dev/remotion
  reviewed-commit: 2f06c4e3166a94607c5c56d68169f3754a0ecc72
  reviewed-date: "2026-11-04"
---
'''
integration = '''
## Codex integration and reviewed scope

This installation contains reviewed guidance and optional local map-preparation examples. It does not install Remotion, a browser, media binaries, cloud services, or project dependencies. The full upstream monorepo has known vulnerable dependency versions; this skill installation does not approve that runtime graph.

- Resolve references relative to this skill directory. User requests and repository rules take precedence. Reuse the project's package manager, installed Remotion version, existing components, and authorized scope.
- Check the installed package APIs and current official documentation before applying examples: these references may describe APIs newer than the user's project. Pin package/tool versions chosen for the current task; do not treat upstream `@latest` examples as approval for unattended updates. Review the actual resolved runtime dependencies before installing or upgrading them. A skill update needs a fresh source review and must preserve these integration notes.
- Use available Codex tools for preview and inspection. On this Windows host, use PowerShell-compatible commands and hidden background processes; the upstream macOS Terminal fallback is not applicable.
- Copy optional geodata helpers and sample inputs into a project working directory before adapting them. Give helpers explicit project output paths where supported; do not overwrite installed skill assets. Their optional packages are not installed by loading this skill.
- Keep privileged AWS/provider credentials out of frontend bundles, render props, and browser-exposed environment variables. Cloud rendering, paid provider requests, uploads, deployment, and package installation must be within the current user's task authorization. Do not ask again for an operation already authorized.
- Treat renderable code and remote media as executable/untrusted input. Remotion's renderer uses reduced Chromium isolation; run untrusted compositions in a separately isolated environment. Keep Studio private to the intended user and do not bypass browser or deployment protections.
- Preserve actual evidence: preview and render results must be observed, and failures must be reported. The upstream license has commercial-use conditions; consult the bundled license for the intended use.

'''
entrypoint.write_text(frontmatter + integration + parts[2].lstrip(), encoding='utf-8', newline='\n')
shutil.copyfile(BASE / 'remotion/LICENSE.md', REMOTION / 'LICENSE.md')
remotion_origin = {'repository': 'https://github.com/remotion-dev/remotion', 'commit': '2f06c4e3166a94607c5c56d68169f3754a0ecc72', 'source_path': prefix.rstrip('/'), 'review_date': '2026-11-04', 'upstream_files_verified': len(actual), 'modifications': ['SKILL.md: Codex-compatible frontmatter and scope-specific integration notes', 'LICENSE.md: retained upstream license'], 'application_runtime_installed': False, 'audit_report': str(BASE / 'AUDIT.md')}
(REMOTION / 'AUDIT-ORIGIN.json').write_text(json.dumps(remotion_origin, indent=2), encoding='utf-8')

COMFY = SKILLS / 'comfyui-workflows'
assert not COMFY.exists(), 'ComfyUI skill destination already exists'
shutil.copytree(BASE / 'staged-skills/comfyui-workflows', COMFY)
comfy_origin = {'kind': 'Locally authored workflow/API guidance; not an upstream executable skill', 'repository': 'https://github.com/Comfy-Org/ComfyUI', 'commit': '56f179f6c50dad0c4c860ae4da427415c8e86415', 'review_date': '2026-11-04', 'upstream_application_code_copied': False, 'application_runtime_installed': False, 'audit_report': str(BASE / 'AUDIT.md')}
(COMFY / 'AUDIT-ORIGIN.json').write_text(json.dumps(comfy_origin, indent=2), encoding='utf-8')

manifest = {}
for skill in (REMOTION, COMFY):
    manifest[skill.name] = {path.relative_to(skill).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in skill.rglob('*') if path.is_file()}
(BASE / 'installed-skills-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
print(json.dumps({'installed': [{'name': name, 'files': len(files)} for name, files in manifest.items()], 'reanimate_installed': (SKILLS / 'reanimate').exists(), 'application_runtimes_installed': False}, indent=2))
