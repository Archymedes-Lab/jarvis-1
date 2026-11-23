"""The package layout is a dependency order; this keeps it one.

    core < platform < collectors < lab < intel < response < service < web < cli

A module may import from its own layer or any layer below it, never above.
Collector domains (process, telemetry, persistence, network, identity, host)
do not import each other: shared logic belongs in core or platform. A private
(leading-underscore) name is never imported across a top-level package. And
no import cycles, including ones hidden inside functions.

There are no exceptions. If a change seems to need one, the shared piece
belongs one layer down (see collectors/signatures.py for the pattern).
"""

import ast
import unittest
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "jarvis"

RANK = {"core": 0, "platform": 1, "collectors": 2, "lab": 3, "intel": 4,
        "response": 5, "service": 6, "web": 7, "cli": 8,
        # Verification harness: drives any layer through its pure functions,
        # imported by nothing at runtime (tests only), so it sits above all.
        "verify": 9,
        # Agent reference monitor: imports only core, so it sits just above it.
        "argus": 1,
        # Licence keys for premium content (Archymedes licence service): standard library only, used by cli.
        "licensing": 1}


def _modules():
    for path in sorted(PKG.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(PKG.parent).with_suffix("")
        parts = list(rel.parts)
        is_pkg = parts[-1] == "__init__"
        if is_pkg:
            parts = parts[:-1]
        yield ".".join(parts), is_pkg, path


MODULES = {name: (is_pkg, path) for name, is_pkg, path in _modules()}


def _imports(name):
    """(target module, imported name or None, lineno) for every jarvis import."""
    is_pkg, path = MODULES[name]
    tree = ast.parse(path.read_text(encoding="utf-8"))
    pkg = name.split(".") if is_pkg else name.split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                base = pkg[:len(pkg) - (node.level - 1)]
                target = ".".join(base + ([node.module] if node.module else []))
            else:
                target = node.module or ""
            if not target.startswith("jarvis"):
                continue
            for alias in node.names:
                full = f"{target}.{alias.name}"
                if full in MODULES:
                    yield full, None, node.lineno
                else:
                    yield target, alias.name, node.lineno
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("jarvis"):
                    yield alias.name, None, node.lineno


def _layer(name):
    parts = name.split(".")
    return parts[1] if len(parts) > 1 and parts[1] in RANK else None


def _domain(name):
    """The collector domain package a module sits in; None for shared modules
    directly under collectors/ (signatures), which every domain may use."""
    parts = name.split(".")
    if len(parts) > 2 and parts[1] == "collectors" and (PKG / "collectors" / parts[2]).is_dir():
        return parts[2]
    return None


class LayerTests(unittest.TestCase):
    def test_the_import_walk_sees_real_edges(self):
        # Guards the guards: a resolution bug would make every rule pass.
        edges = {t for t, _, _ in _imports("jarvis.web.server")}
        self.assertIn("jarvis.service.scheduler", edges)
        self.assertIn("jarvis.core.store", edges)
        relative = {t for t, _, _ in _imports("jarvis.cli.commands.pixel")}
        self.assertIn("jarvis.cli.output", relative)

    def test_no_module_imports_a_higher_layer(self):
        bad = []
        for name in MODULES:
            mine = _layer(name)
            if mine is None:
                continue
            for target, _, line in _imports(name):
                theirs = _layer(target)
                if theirs is None or RANK[theirs] <= RANK[mine]:
                    continue
                bad.append(f"{name}:{line} ({mine}) imports {target} ({theirs})")
        self.assertEqual(bad, [])

    def test_collector_domains_do_not_import_each_other(self):
        bad = []
        for name in MODULES:
            mine = _domain(name)
            if mine is None:
                continue
            for target, _, line in _imports(name):
                theirs = _domain(target)
                if theirs is None or theirs == mine:
                    continue
                bad.append(f"{name}:{line} ({mine}) imports {target} ({theirs})")
        self.assertEqual(bad, [])

    def test_private_names_stay_inside_their_package(self):
        bad = []
        for name in MODULES:
            for target, imported, line in _imports(name):
                if not imported or not imported.startswith("_"):
                    continue
                # Package-private: importer and target share the package that
                # defines the helper (e.g. toolchain.agents -> toolchain.common).
                owner = target if MODULES.get(target, (False,))[0] else target.rsplit(".", 1)[0]
                if name == owner or name.startswith(owner + "."):
                    continue
                bad.append(f"{name}:{line} imports {target}.{imported}")
        self.assertEqual(bad, [])

    def test_no_import_cycles(self):
        graph = {name: {t for t, _, _ in _imports(name) if t in MODULES and t != name}
                 for name in MODULES}
        # A package __init__ re-exporting its own submodules is not a cycle
        # anyone can trip over; ignore edges from a package into itself.
        for name, (is_pkg, _) in MODULES.items():
            if is_pkg:
                graph[name] = {t for t in graph[name] if not t.startswith(name + ".")}
        index, low, stack, on, cycles = {}, {}, [], set(), []
        counter = [0]

        def visit(v):
            index[v] = low[v] = counter[0]
            counter[0] += 1
            stack.append(v)
            on.add(v)
            for w in graph[v]:
                if w not in index:
                    visit(w)
                    low[v] = min(low[v], low[w])
                elif w in on:
                    low[v] = min(low[v], index[w])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                if len(comp) > 1:
                    cycles.append(sorted(comp))

        for v in graph:
            if v not in index:
                visit(v)
        self.assertEqual(cycles, [])

    def test_every_module_belongs_to_a_layer(self):
        loose = [name for name in MODULES
                 if _layer(name) is None and name not in ("jarvis", "jarvis.__main__")]
        self.assertEqual(loose, [])


if __name__ == "__main__":
    unittest.main()
