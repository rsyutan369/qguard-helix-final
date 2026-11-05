"""Read-only source inventory and AST inspection; never imports upstream code."""
import ast
import collections
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = next((BASE / "source").iterdir())
inventory = []
python_files = []
signals = []
for path in sorted(ROOT.rglob("*")):
    if not path.is_file():
        continue
    rel = path.relative_to(ROOT).as_posix()
    raw = path.read_bytes()
    inventory.append({"path": rel, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    if path.suffix != ".py":
        continue
    tree = ast.parse(raw.decode("utf-8-sig"), filename=rel)
    imports = []
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
        elif isinstance(node, ast.Call):
            name = ast.unparse(node.func)
            calls.append({"line": node.lineno, "call": name})
            if any(part in name.lower() for part in ("exec", "eval", "subprocess", "socket", "urlopen", "request", "write", "unlink", "remove", "rmtree", "environ", "read_text", "open", "replace", "link", "mkdir")):
                signals.append({"path": rel, "line": node.lineno, "code": ast.unparse(node)[:350]})
    python_files.append({"path": rel, "imports": sorted(set(imports)), "calls": calls})

skill = ROOT / ".claude/skills/ui-ux-pro-max"
duplicates = []
for section in ("data", "scripts"):
    for path in sorted((skill / section).rglob("*")):
        if not path.is_file():
            continue
        counterpart = ROOT / "src/ui-ux-pro-max" / section / path.relative_to(skill / section)
        if not counterpart.is_file() or counterpart.read_bytes() != path.read_bytes():
            duplicates.append(path.relative_to(skill).as_posix())

result = {"files": inventory, "python": python_files, "signals": signals, "skill_source_differences": duplicates}
(BASE / "static-inventory.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
runtime = [entry for entry in python_files if entry["path"].startswith(".claude/skills/ui-ux-pro-max/scripts/") and "/tests/" not in entry["path"]]
print(json.dumps({"regular_files": len(inventory), "python_files_parsed": len(python_files), "extensions": dict(collections.Counter(Path(entry["path"]).suffix for entry in inventory)), "skill_source_differences": duplicates, "runtime_imports": [{"path": entry["path"], "imports": entry["imports"]} for entry in runtime], "runtime_signals": [entry for entry in signals if entry["path"] in {r["path"] for r in runtime}]}, indent=2))
