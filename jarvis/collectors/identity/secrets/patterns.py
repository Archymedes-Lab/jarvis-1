"""The credential patterns now live in collectors/credentials.py, shared with
the application-code scanner (collectors/appcode); this keeps the old path."""

from jarvis.collectors.credentials import (  # noqa: F401 - re-exported
    _PRIVATE_BLOCK,
    BARE_VALUE_EXTS,
    GENERIC_BARE,
    PATTERNS,
    PLACEHOLDER,
    _entropy,
    _looks_real,
    _mask,
    _private_blocks,
    fingerprint,
    scan_file,
)
