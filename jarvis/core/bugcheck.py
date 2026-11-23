"""Windows bug checks (stop errors) named and classed for security review.

A stop error at the kernel, secure-kernel or hypervisor level is the only
trace Windows leaves when code below the operating system faults or when the
kernel's own integrity checks fire. Most are bugs or failing hardware; a few
are what tampering with protected kernel or hypervisor state looks like. A
class here says which layer failed, never that the machine was compromised:
only analysis of the dump can say what faulted.

Codes and names are from Microsoft's bug check code reference
(learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-code-reference2).
A code missing from the table is "other": named by its number, never guessed.
"""
import re

# class -> (severity of one occurrence, what failed)
CLASSES = {
    "integrity": ("high", "the kernel's protected code or data was found modified"),
    "hypervisor": ("medium", "the hypervisor or secure kernel under Windows failed"),
    "security_check": ("medium", "a kernel security check failed"),
    "hardware": ("low", "the hardware reported an uncorrectable error"),
    "other": ("low", "Windows stopped with an error"),
}
CODES = {
    0x109: ("CRITICAL_STRUCTURE_CORRUPTION", "integrity"),
    0x18C: ("HYPERGUARD_VIOLATION", "integrity"),
    0x18B: ("SECURE_KERNEL_ERROR", "hypervisor"),
    0x20001: ("HYPERVISOR_ERROR", "hypervisor"),
    0x139: ("KERNEL_SECURITY_CHECK_FAILURE", "security_check"),
    0x124: ("WHEA_UNCORRECTABLE_ERROR", "hardware"),
}
# Classes that concern the layers VBS and HVCI depend on; repeats escalate.
BELOW_KERNEL = frozenset({"integrity", "hypervisor", "security_check"})
MAX_CODE = 0xFFFFFFFF
# WER-SystemErrorReporting 1001, first property: "0x00020001 (0x11, 0x.., 0x.., 0x..)".
_WER = re.compile(r"^\s*0x([0-9A-Fa-f]{1,8})\s*\(([^)]{0,200})\)\s*$")


def describe(code):
    """(name, class) for a bug check code; unknown codes are 'other'."""
    name, kind = CODES.get(code, (f"0x{code:X}", "other"))
    return name, kind


def label(code):
    name = describe(code)[0]
    return f"0x{code:X} {name}" if not name.startswith("0x") else name


def from_wer(text):
    """(code, [params]) from a WER 1001 bugcheck string, or None if malformed."""
    match = _WER.match(str(text or ""))
    if not match:
        return None
    code = int(match.group(1), 16)
    params = [p.strip() for p in match.group(2).split(",")]
    if not code or len(params) > 4 or not all(re.fullmatch(r"0x[0-9A-Fa-f]{1,16}", p) for p in params):
        return None
    return code, params


def from_kernel_power(value):
    """Bug check code from Kernel-Power 41 BugcheckCode (decimal); None if 0 or malformed."""
    try:
        code = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return code if 0 < code <= MAX_CODE else None
