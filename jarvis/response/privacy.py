"""Best-effort secret minimization for advisory model input, not a DLP guarantee."""
import re

from jarvis.collectors.identity.secrets.patterns import PATTERNS

_PRIVATE = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)", re.S)
_ASSIGNMENT = re.compile(
    r'''(?i)\b[\w-]*(?:password|passwd|secret|token|api[_-]?key|recovery[_-]?code)[\w-]*\s*[:=]\s*(?:"[^"\n]*"|'[^'\n]*'|[^\s,;}]+)''')
_AUTH = re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")


def redact(text):
    text = _PRIVATE.sub('[REDACTED PRIVATE KEY]', str(text))
    for _, pattern, _ in PATTERNS:
        text = pattern.sub('[REDACTED SECRET]', text)
    text = _ASSIGNMENT.sub('[REDACTED CREDENTIAL]', text)
    text = _AUTH.sub('[REDACTED AUTHORIZATION]', text)
    # URL paths/queries/fragments can carry arbitrary secrets without labels.
    from urllib.parse import urlsplit

    def origin(match):
        try:
            url = urlsplit(match.group())
            return f'{url.scheme}://{url.hostname or "unknown"}/[PATH REDACTED]'
        except ValueError:
            return '[REDACTED URL]'
    return _URL.sub(origin, text)
