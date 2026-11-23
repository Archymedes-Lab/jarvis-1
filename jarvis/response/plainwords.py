"""Everyday wording for the Simple level.

The assistant's deterministic answers are written for someone who knows what a
collector, a persistence entry or a Sysmon event is. For the Simple level the
same facts are re-worded, not changed: this swaps jargon for plain terms and
never adds, removes or softens a fact, a number, a path or a severity.
`simplify` is deterministic, idempotent, and leaves text it does not
recognise exactly as it was.
"""

import re

LEVELS = ("simple", "expert")

# Longest phrases first so "collectors" is not half-replaced inside a longer term.
_TERMS = (
    ("persistence", "things that start by themselves"),
    ("collectors are not reporting", "checks are not reporting"),
    ("collector", "check"),
    ("sysmon", "Windows activity log"),
    ("indicators of compromise", "signs of a break-in"),
    ("indicator", "sign"),
    ("telemetry", "activity data"),
    ("unsigned", "not digitally signed"),
    ("credentials", "passwords and keys"),
    ("credential", "password or key"),
    ("remediation", "fix"),
    ("heuristic", "rule of thumb"),
    ("ledger", "record"),
    ("evidence", "what was seen"),
    ("severity", "how serious"),
)
_PATTERN = re.compile("|".join(r"\b%s(s?)\b" % re.escape(a) for a, _ in _TERMS), re.IGNORECASE)
_BY_WORD = {a: b for a, b in _TERMS}


def _swap(m):
    word = m.group(0)
    low = word.lower()
    plural = low.endswith("s") and low[:-1] in _BY_WORD
    key = low[:-1] if plural and low not in _BY_WORD else low
    out = _BY_WORD.get(key, _BY_WORD.get(low, word))
    if plural and low not in _BY_WORD and not out.endswith("s"):
        out += "s"
    return out[0].upper() + out[1:] if word[:1].isupper() else out


_BRAND = re.compile(r"\b(?:JARVIS|Jarvis)\b")


def brand(text):
    """The product is called ARGUS-INSTINCT. Command names in lower case (`jarvis ack`) are left alone."""
    return _BRAND.sub("ARGUS-INSTINCT", text) if isinstance(text, str) and text else text


def simplify(text):
    return _PATTERN.sub(_swap, text) if isinstance(text, str) and text else text


def level_of(value):
    return value if value in LEVELS else "expert"


def simplify_result(result, level):
    """User-facing strings of an assistant result: always the ARGUS-INSTINCT name, and everyday
    wording at the Simple level. Other fields stay as they are."""
    if not isinstance(result, dict):
        return result
    fix = (lambda t: simplify(brand(t))) if level == "simple" else brand
    out = dict(result)
    for key in ("answer", "text"):
        if isinstance(out.get(key), str):
            out[key] = fix(out[key])
    if isinstance(out.get("sections"), list):
        out["sections"] = [dict(s, text=fix(s["text"])) if isinstance(s, dict) and isinstance(s.get("text"), str) else s
                           for s in out["sections"]]
    if level == "simple":
        out["level"] = "simple"
    return out


LANGUAGES = {"en": "English", "fr": "French", "de": "German", "es": "Spanish",
             "zh": "Simplified Chinese", "ja": "Japanese", "ko": "Korean",
             "pt": "Brazilian Portuguese", "hi": "Hindi", "ru": "Russian", "ar": "Arabic"}


def language_instruction(code):
    """-> text for the model's system prompt, or "" for English / unknown codes.
    Only a code from LANGUAGES is ever turned into a language name."""
    name = LANGUAGES.get(code)
    return "" if code in (None, "", "en") or not name else f" Write the whole answer in {name}."


SIMPLE_MODEL_INSTRUCTION = (
    " Write for someone who is not technical: short everyday sentences, no jargon, "
    "no file paths unless asked, and say what to do next in one step."
)
