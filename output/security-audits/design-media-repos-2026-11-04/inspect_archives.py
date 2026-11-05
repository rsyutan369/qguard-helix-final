"""Extract and inventory public source archives without executing upstream code."""
import ast
import collections
import hashlib
import json
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
for key in ('NiazMorshed2007--reanimate', 'Comfy-Org--ComfyUI'):
    archive = BASE / (key + '.zip')
    tree = json.loads((BASE / (key + '-tree.json')).read_text(encoding='utf-8-sig'))
    expected = {entry['path']: entry for entry in tree['tree'] if entry['type'] == 'blob'}
    target = BASE / key
    target.mkdir(exist_ok=True)
    files, links, modules, errors = [], [], [], []
    with zipfile.ZipFile(archive) as source:
        assert sum(entry.file_size for entry in source.infolist()) < 600_000_000
        for entry in source.infolist():
            if entry.is_dir():
                continue
            relative = entry.filename.split('/', 1)[1]
            dest = (target / relative).resolve()
            assert dest.is_relative_to(target.resolve()), relative
            data = source.read(entry)
            git_hash = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\x00' + data).hexdigest()
            assert git_hash == expected[relative]['sha'], relative
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                links.append({'path': relative, 'target': data.decode('utf-8')})
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                assert dest.read_bytes() == data
            else:
                dest.write_bytes(data)
            files.append({'path': relative, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            if dest.suffix == '.py':
                try:
                    parsed = ast.parse(data.decode('utf-8-sig'), filename=relative)
                    imports = []
                    for node in ast.walk(parsed):
                        if isinstance(node, ast.Import):
                            imports.extend(alias.name for alias in node.names)
                        elif isinstance(node, ast.ImportFrom):
                            imports.append(node.module or '')
                    modules.append({'path': relative, 'imports': sorted(set(imports))})
                except (SyntaxError, UnicodeDecodeError) as error:
                    errors.append({'path': relative, 'error': str(error)})
    result = {'repository': key.replace('--', '/'), 'commit': (BASE / (key + '-commit.txt')).read_text().strip(), 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'files': files, 'symlinks_skipped': links, 'python_modules': modules, 'parse_errors': errors}
    (BASE / (key + '-inventory.json')).write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'repository': result['repository'], 'commit': result['commit'], 'files': len(files), 'skipped_links': len(links), 'python_parsed': len(modules), 'parse_errors': errors, 'extensions': dict(collections.Counter(Path(entry['path']).suffix for entry in files))}, indent=2))
