"""Small static script evidence probes. No interpreter, imports or execution.

The PHP probe recognizes direct request-to-global-executor syntax in PHP code,
not a full language or dataflow model. Comments, string examples and heredocs are
not evidence; unsupported indirection stays outside this narrow probe.
"""
import re

PHP_PROBE_VERSION = "php-direct/1"
PHP_EXTENSIONS = frozenset({".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".pht"})
_EXEC_REQUEST = re.compile(
    r"\b(?:system|shell_exec|passthru|popen|proc_open|pcntl_exec|exec|eval)\s*\(\s*"
    r"\$_(?:POST|GET|REQUEST|COOKIE)\s*\[", re.I)
_OPEN = re.compile(r"<\?(?:php\b|=)", re.I)


def php_code(text):
    """Mask non-code in-place in a bounded input; return None for heredoc syntax."""
    out = [" "] * len(text)
    i, active = 0, False
    while i < len(text):
        if not active:
            match = _OPEN.search(text, i)
            if match is None:
                break
            i, active = match.end(), True
            continue
        if text.startswith("?>", i):
            i, active = i + 2, False
        elif text.startswith("<<<", i):
            return None
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                break
            i = end + 2
        elif text.startswith("//", i) or text[i] == "#":
            end = text.find("\n", i)
            close = text.find("?>", i)
            if close >= 0 and (end < 0 or close < end):
                i, active = close + 2, False
            else:
                i = len(text) if end < 0 else end + 1
        elif text[i] in "\"'`":
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
        else:
            out[i] = text[i]
            i += 1
    return "".join(out)


def php_request_exec(data):
    code = php_code(data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data)
    if code is None:
        return False
    for match in _EXEC_REQUEST.finditer(code):
        at = match.start() - 1
        while at >= 0 and code[at].isspace():
            at -= 1
        if code[max(0, at - 1):at + 1] in ("->", "::") or (at >= 0 and code[at] == "$"):
            continue
        if at >= 0 and code[at] == "\\":
            if at and (code[at - 1].isalnum() or code[at - 1] in "_\\$"):
                continue  # namespaced user function, not a known global executor
        return True
    return False
