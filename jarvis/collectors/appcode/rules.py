"""Risky code patterns in server application code, one line at a time.

Dependency-free and deliberately simple: a rule names a dangerous sink
(dynamic evaluation, a shell, SQL assembled from strings, deserialisation, an
include or file read of a variable, TLS verification switched off, debug mode
on). When request input appears on the same line the match is "tainted" and is
reported at medium; otherwise it is low, a place to review. Some sinks are only
worth reporting when tainted (`open(...)` is everywhere). It is a heuristic:
input that flows through a variable is not seen, and a sanitised value still
matches. Findings name file:line only, never the code itself.
"""

import os
import re

from jarvis.core import safeio

MAX_LINE = 800
LANG = {".py": "py", ".php": "php", ".phtml": "php", ".js": "js", ".mjs": "js", ".cjs": "js",
        ".ts": "js", ".jsx": "js", ".tsx": "js", ".rb": "rb", ".go": "go", ".java": "java",
        ".kt": "java"}

TAINT = {
    # request.<field> of a web framework, not urllib.request or argparse's args.
    "py": r"(?:^|[^\w.]|\bself\.)request\.(?:args|form|values|json|data|files|cookies|headers|"
          r"GET|POST|body|query_params|params)\b|\.GET\[|\.POST\[|(?<![\w.])input\(",
    "php": r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input",
    "js": r"\breq\.(?:query|body|params|headers|cookies)\b|\brequest\.(?:query|body|params)\b|"
          r"\bctx\.(?:query|request)\b",
    "rb": r"\bparams\[|\brequest\.|\bcookies\[",
    "go": r"\.FormValue\(|\.URL\.Query\(|\br\.Body\b|\.PostForm\b|\bc\.(?:Query|Param)\(",
    "java": r"getParameter\(|getHeader\(|@RequestParam|getQueryString\(",
}

_SQL = r"(?i)\b(?:select|insert|update|delete)\b"

# id -> (title, {lang: pattern}, tainted_only)
RULES = {
    "eval-input": ("dynamic code evaluation (eval)", {
        "py": r"(?<![\w.])(?:eval|exec)\s*\(",
        "php": r"\b(?:eval|assert|create_function)\s*\(",
        "js": r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(",
        "rb": r"(?<![\w.])(?:eval|instance_eval|class_eval)\b",
    }, False),
    "shell-exec": ("shell command execution", {
        "py": r"\bos\.(?:system|popen)\s*\(|\bsubprocess\.\w+\(.*\bshell\s*=\s*True",
        "php": r"(?<![\w>:])(?:system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(",
        "js": r"(?<![\w.])exec(?:Sync)?\s*\(|\bspawn\s*\(.*\bshell\s*:\s*true",
        "rb": r"(?<![\w.])(?:system|exec|spawn)\s*[\( ]|`[^`]*#\{|%x[\(\{]|\bIO\.popen|\bOpen3\.",
        "go": r'exec\.Command\(\s*"(?:sh|bash|/bin/sh|/bin/bash)"',
        "java": r"Runtime\.getRuntime\(\)\.exec\(|new\s+ProcessBuilder\(",
    }, False),
    "sql-format": ("SQL assembled from strings", {
        "py": r"\.(?:execute|executemany|raw|extra)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+|\.format\())",
        "php": r"\b(?:mysql_query|mysqli_query|pg_query)\s*\(.*\$|->(?:query|exec)\s*\(\s*(?:\"[^\"]*\$|[\"'][^\"']*[\"']\s*\.)",
        "js": r"\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)",
        "rb": r"\b(?:find_by_sql|where|execute|exec_query)\s*\(\s*\"[^\"]*#\{",
        "go": r"\.(?:Query|Exec|QueryRow)(?:Context)?\(.*(?:fmt\.Sprintf|\"\s*\+)",
        "java": r"\.(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*\"[^\"]*\"\s*\+",
    }, False),
    "deserialise": ("unsafe deserialisation", {
        "py": r"\b(?:c?[Pp]ickle|marshal|dill)\.loads?\s*\(|\bjsonpickle\.decode\s*\(|"
              r"\byaml\.(?:load|load_all)\s*\((?![^)]*(?:Safe|BaseLoader))|\byaml\.unsafe_load",
        "php": r"\bunserialize\s*\(",
        "js": r"\bunserialize\s*\(|node-serialize",
        "rb": r"\bMarshal\.load\b|\bYAML\.(?:load|unsafe_load)\s*\((?![^)]*(?:safe|permitted))",
        "java": r"\bnew\s+ObjectInputStream\s*\(|\bXMLDecoder\s*\(",
    }, False),
    "file-include": ("file include or read of a request value", {
        "py": r"(?<![\w.])open\s*\(|\b(?:send_file|send_from_directory)\s*\(",
        "php": r"\b(?:include|require)(?:_once)?\b|\b(?:file_get_contents|fopen|readfile)\s*\(",
        "js": r"\b(?:res\.sendFile|res\.download)\s*\(|\bfs\.(?:readFile|readFileSync|createReadStream)\s*\(",
        "rb": r"\b(?:File\.(?:read|open)|send_file|render\s+file:)",
        "go": r"\bos\.(?:Open|ReadFile)\(|http\.ServeFile\(",
        "java": r"\bnew\s+File(?:InputStream|Reader)?\s*\(",
    }, True),
    "tls-off": ("TLS certificate verification disabled", {
        "py": r"\bverify\s*=\s*False\b|_create_unverified_context|\bCERT_NONE\b",
        "php": r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b",
        "js": r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED",
        "rb": r"\bVERIFY_NONE\b",
        "go": r"InsecureSkipVerify\s*:\s*true",
        "java": r"NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts",
    }, False),
    "debug-on": ("debug mode enabled", {
        "py": r"\.run\(.*\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True\b",
        "php": r"display_errors['\"]?\s*,\s*['\"]?(?:1|on|true)\b",
        "rb": r"consider_all_requests_local\s*=\s*true",
    }, False),
}

_COMPILED = {lang: [(rid, re.compile(pats[lang]), only) for rid, (_t, pats, only) in RULES.items()
                    if lang in pats] for lang in TAINT}
_TAINT = {lang: re.compile(p) for lang, p in TAINT.items()}
_SQL_RX = re.compile(_SQL)
_COMMENT = ("#", "//", "*", "/*", "<!--", "--")
# A line that opens with a quote is string content: docstrings, embedded
# samples, generated code. Its "eval" is text, not a call.
_STRING = ('"', "'", "`")


def title(rule_id):
    return RULES[rule_id][0]


def scan_text(text, ext):
    """[(rule id, line number, tainted)] in one file's text."""
    lang = LANG.get(ext.lower())
    if not lang:
        return []
    rules, taint = _COMPILED[lang], _TAINT[lang]
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > MAX_LINE:
            continue
        stripped = line.lstrip()
        if not stripped or stripped.startswith(_COMMENT) or stripped.startswith(_STRING):
            continue
        tainted = None
        for rid, rx, tainted_only in rules:
            if not rx.search(line):
                continue
            if rid == "sql-format" and not _SQL_RX.search(line):
                continue
            if tainted is None:
                tainted = bool(taint.search(line))
            if tainted_only and not tainted:
                continue
            out.append((rid, lineno, tainted))
    return out


MAX_FILE_BYTES = 512 * 1024        # discover.MAX_SOURCE_BYTES, judged again at read time


def scan_file(path):
    # The walk lstat'ed a regular file, but the repository's owner can swap it
    # for a FIFO, a device or a link before this open: refuse all three here.
    try:
        text = safeio.read_text(path, MAX_FILE_BYTES, follow=False)
    except OSError:
        return None
    if text is None:
        return None
    return scan_text(text, os.path.splitext(path)[1])
