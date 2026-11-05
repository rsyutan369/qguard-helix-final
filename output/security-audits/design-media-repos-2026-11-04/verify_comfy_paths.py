"""Focused checks of the original ComfyUI path/content-type helpers; no app startup."""
import json
import os
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE / 'Comfy-Org--ComfyUI'
OUT = BASE / 'comfy-security-check'
OUT.mkdir(exist_ok=True)
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
import folder_paths

def block_network_processes(event, args):
    if event.startswith('socket.') or event in {'subprocess.Popen', 'os.system'}:
        raise RuntimeError('Unexpected network/process operation: ' + event)

sys.addaudithook(block_network_processes)
checks = []
def check(name, condition):
    assert condition, name
    checks.append(name)

for kind in ('input', 'output', 'temp'):
    directory = OUT / kind
    directory.mkdir(exist_ok=True)
    getattr(folder_paths, 'set_' + kind + '_directory')(str(directory))
    (directory / 'existing.png').write_bytes(b'audit sentinel; not an image')

input_dir = OUT / 'input'
check('normal child contained', folder_paths.is_within_directory(str(input_dir), str(input_dir / 'sub/image.png')))
check('traversal not contained', not folder_paths.is_within_directory(str(input_dir), str(input_dir / '../outside.txt')))
check('prefix sibling not contained', not folder_paths.is_within_directory(str(input_dir), str(OUT / 'input-sibling/image.png')))
for kind in ('input', 'output', 'temp'):
    check(kind + ' annotation resolved', folder_paths.get_annotated_filepath('existing.png [' + kind + ']') == str(OUT / kind / 'existing.png'))
for name in ('../outside.txt', '../../outside.txt [output]', str(OUT / 'outside.txt')):
    try:
        folder_paths.get_annotated_filepath(name)
    except ValueError:
        checks.append('rejected escape: ' + name)
    else:
        raise AssertionError('Accepted escaping path: ' + name)
check('existing local file visible', folder_paths.exists_annotated_filepath('existing.png'))
check('escaping file treated absent', not folder_paths.exists_annotated_filepath('../outside.txt'))
for content_type in ('text/html', 'TEXT/HTML; charset=utf-8', 'image/svg+xml', 'text/javascript', 'application/rss+xml', 'text/xml'):
    check('dangerous MIME detected: ' + content_type, folder_paths.is_dangerous_content_type(content_type))
check('raster MIME not marked executable', not folder_paths.is_dangerous_content_type('image/png'))
check('SVG inline image context allowed', folder_paths.renders_safely_as_image('image/svg+xml', 'image'))
check('SVG document context not allowed', not folder_paths.renders_safely_as_image('image/svg+xml', 'document'))
check('SVG missing context not allowed', not folder_paths.renders_safely_as_image('image/svg+xml', None))
symlink = 'not attempted'
link = input_dir / 'outside-link'
outside = OUT / 'outside'
outside.mkdir(exist_ok=True)
try:
    os.symlink(outside, link, target_is_directory=True)
except (OSError, NotImplementedError) as error:
    symlink = 'skipped: ' + str(error)
else:
    check('symlink escape rejected', not folder_paths.is_within_directory(str(input_dir), str(link / 'image.png')))
    symlink = 'passed'
result = {'checks_passed': len(checks), 'checks': checks, 'symlink_case': symlink, 'scope': 'Original folder_paths module only; no PyTorch, server, models, custom nodes, or inference executed.'}
(OUT / 'results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result, indent=2))
