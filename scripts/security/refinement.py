"""Source-bound SMT refinement of defense._enabled, with a rejecting AST subset.

Assumptions: ordinary dict.get and Action attributes (no hostile descriptors or
monkeypatching); enable_flag is a string; autonomy is a string; ordinary Python
identity/truth semantics. Config values are abstracted by identity with True:
all non-True objects share the false identity class. No execution/ledger proof.
"""
import ast
import hashlib
import inspect
import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


class Unsupported(ValueError):
    pass


def expression(node, truth=False):
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return 'true' if node.value else 'false'
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return '(not ' + expression(node.operand, True) + ')'
    if isinstance(node, ast.BoolOp):
        operator = 'and' if isinstance(node.op, ast.And) else 'or'
        return '(' + operator + ' ' + ' '.join(expression(value, truth) for value in node.values) + ')'
    if truth and ast.unparse(node) == 'action.enable_flag':
        return 'has_flag'
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right, op = node.left, node.comparators[0], node.ops[0]
        if (ast.unparse(left) == 'action.autonomy' and ast.unparse(right) == 'base.AUTO'
                and isinstance(op, (ast.Eq, ast.NotEq))):
            return 'is_auto' if isinstance(op, ast.Eq) else '(not is_auto)'
        if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(right, ast.Constant) and right.value is True:
            if isinstance(left, ast.Call) and not left.keywords and len(left.args) == 2:
                if ast.unparse(left.func) != 'conf.get' or ast.unparse(left.args[1]) != 'False':
                    raise Unsupported('unsupported config access')
                key = ast.unparse(left.args[0])
                value = {"'autonomous_defense'": 'global_true', 'action.enable_flag': 'flag_true'}.get(key)
                if value:
                    return value if isinstance(op, ast.Is) else '(not ' + value + ')'
    raise Unsupported('unsupported expression')


def body(statements):
    if not statements:
        raise Unsupported('implicit return')
    first, *rest = statements
    if isinstance(first, ast.Return):
        return expression(first.value)
    if isinstance(first, ast.If):
        return '(ite ' + expression(first.test, True) + ' ' + body(first.body + rest) + ' ' + body(first.orelse + rest) + ')'
    raise Unsupported('unsupported control flow')


def translate(source):
    tree = ast.parse(textwrap.dedent(source))
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise Unsupported('one function required')
    function = tree.body[0]
    if ([a.arg for a in function.args.args] != ['conf', 'action'] or function.decorator_list
            or function.args.defaults or function.args.vararg or function.args.kwarg
            or function.args.kwonlyargs or function.args.posonlyargs):
        raise Unsupported('unsupported signature')
    return body(function.body)


def script(source):
    actual = translate(source)
    # Property written independently of the function's branch structure.
    spec = '(and global_true is_auto has_flag flag_true)'
    return '\n'.join([
        '(set-logic QF_UF)', '(set-option :timeout 5000)',
        *['(declare-const ' + name + ' Bool)' for name in ('global_true', 'is_auto', 'has_flag', 'flag_true')],
        '(assert (not (= ' + actual + ' ' + spec + ')))', '(check-sat)',
    ])


def prove(source, solver):
    result = subprocess.run([solver, '-in', '-smt2'], input=script(source).encode(),
                            capture_output=True, timeout=10, check=False)
    if result.returncode or result.stdout.strip() not in (b'unsat', b'sat', b'unknown'):
        raise Unsupported('malformed solver result')
    return result.stdout.strip().decode()


def main():
    from jarvis.response import defense
    solver = shutil.which('z3')
    if not solver:
        print(json.dumps({'status': 'unavailable'}))
        return 2
    source = inspect.getsource(defense._enabled)
    try:
        actual = prove(source, solver)
        # Plant a real source mutation that weakens the first authority guard.
        mutant = source.replace('is not True', 'is True', 1)
        if mutant == source:
            raise Unsupported('negative control cannot be applied')
        negative = prove(mutant, solver)
    except (Unsupported, subprocess.SubprocessError):
        print(json.dumps({'status': 'incomplete'}))
        return 2
    print(json.dumps({'function': 'jarvis.response.defense._enabled',
                      'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
                      'equivalence': actual, 'mutated_source': negative,
                      'scope': 'authority enable predicate only; assumptions in refinement.py'}))
    return 0 if actual == 'unsat' and negative == 'sat' else 1


if __name__ == '__main__':
    raise SystemExit(main())
