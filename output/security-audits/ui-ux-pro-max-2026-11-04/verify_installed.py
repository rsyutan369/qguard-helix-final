"""Exercise the installed skill with network/process execution denied."""
import contextlib
import hashlib
import io
import json
import runpy
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
SKILL = Path('C:/Users/ruel3/.codex/skills/ui-ux-pro-max')
OUT = BASE / 'verification-output'
OUT.mkdir(exist_ok=True)
events = []

def guard(event, args):
    if event.startswith('socket.') or event in {'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'}:
        events.append(event)
        raise RuntimeError('Disallowed network/process operation: ' + event)
    if event == 'open':
        file, mode, flags = args
        writing = (isinstance(mode, str) and any(letter in mode for letter in 'wax+')) or bool(flags & (1 | 2 | 64 | 512 | 1024))
        if writing and not isinstance(file, int):
            resolved = Path(file).resolve()
            if not resolved.is_relative_to(OUT):
                raise RuntimeError('Write outside verification directory: ' + str(resolved))

sys.dont_write_bytecode = True
sys.addaudithook(guard)

def search(*args):
    capture = io.StringIO()
    sys.argv = [str(SKILL / 'scripts/search.py'), *args, '--json']
    with contextlib.redirect_stdout(capture):
        runpy.run_path(sys.argv[0], run_name='__main__')
    return json.loads(capture.getvalue())

results = []
for stack, query in [('react', 'keyboard focus'), ('html-tailwind', 'responsive layout'), ('jetpack-compose', 'navigation'), ('flutter', 'accessibility'), ('react-native', 'accessibility'), ('swiftui', 'navigation')]:
    response = search(query, '--stack', stack)
    assert response['stack'] == stack and response['count'] > 0, response
    results.append({'stack': stack, 'count': response['count']})

response = search('keyboard focus modal', '--domain', 'ux')
assert response['count'] > 0 and response['domain'] == 'ux'
results.append({'domain': 'ux', 'count': response['count']})

response = search('cybersecurity dashboard', '--design-system', '-p', 'Audit Smoke', '--persist', '--output-dir', str(OUT))
assert response['persistence']['status'] != 'skipped_exists'
master = OUT / 'design-system/audit-smoke/MASTER.md'
master_hash = hashlib.sha256(master.read_bytes()).hexdigest()
response2 = search('ecommerce luxury', '--design-system', '-p', 'Audit Smoke', '--persist', '--output-dir', str(OUT))
assert response2['persistence']['status'] == 'skipped_exists'
assert hashlib.sha256(master.read_bytes()).hexdigest() == master_hash
page = search('cybersecurity dashboard', '--design-system', '-p', 'Audit Smoke', '--persist', '--page', '../../safe-page', '--output-dir', str(OUT))
expected_page = OUT / 'design-system/audit-smoke/pages/safe-page.md'
assert expected_page.is_file()
assert not events, events
summary = {'searches': results, 'design_system_generated': True, 'persistence_does_not_overwrite': True, 'page_name_traversal_sanitized': True, 'network_and_subprocess_attempts': events}
(OUT / 'results.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
print(json.dumps(summary, indent=2))
