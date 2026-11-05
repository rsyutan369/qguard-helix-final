"""Run the trusted skill validator, check local references, and verify file manifests."""
import hashlib
import json
import re
import runpy
import sys
from pathlib import Path
from urllib.parse import unquote

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE / 'validator-deps'))
validator = runpy.run_path('C:/Users/ruel3/.codex/skills/.system/skill-creator/scripts/quick_validate.py')['validate_skill']
SKILLS = Path('C:/Users/ruel3/.codex/skills')
manifest = json.loads((BASE / 'installed-skills-manifest.json').read_text(encoding='utf-8'))
results = []
for name, files in manifest.items():
    root = SKILLS / name
    valid, message = validator(root)
    assert valid, name + ': ' + message
    actual = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}
    assert actual == set(files), name + ': installed file set changed'
    for relative, digest in files.items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == digest, relative
    checked = 0
    broken = []
    for path in root.rglob('*.md'):
        text = path.read_text(encoding='utf-8')
        text = re.sub(r'```[^\n]*\n.*?```', '', text, flags=re.S)
        for link in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', text):
            link = link.strip().split()[0].strip('<>')
            if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', link) or link.startswith('#'):
                continue
            target = unquote(link.split('#', 1)[0].split('?', 1)[0])
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.is_relative_to(root.resolve()) or not resolved.exists():
                broken.append({'file': str(path.relative_to(root)), 'link': link})
            checked += 1
    assert not broken, json.dumps(broken, indent=2)
    results.append({'skill': name, 'trusted_validator': message, 'manifest_files_verified': len(files), 'local_links_checked': checked, 'broken_local_links': broken})
assert not (SKILLS / 'reanimate').exists(), 'Reanimate was unexpectedly installed'
output = {'installed_skills': results, 'reanimate_withheld': True}
(BASE / 'skill-verification.json').write_text(json.dumps(output, indent=2), encoding='utf-8')
print(json.dumps(output, indent=2))
