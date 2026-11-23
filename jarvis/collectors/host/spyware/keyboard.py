"""Is anything sitting between the keys and the applications? Keyboard and mouse
filter drivers and attached input devices."""

import re

from jarvis.platform.windows import aslist

from .common import _finding

# The driver stack for these two classes, on a machine nobody has inserted
# anything into. Anything else in the list is a filter driver seeing input
# before the applications do.
STOCK_KBD_FILTERS = {"kbdclass"}


STOCK_MOU_FILTERS = {"mouclass"}


# Filter drivers that legitimately ship with laptop vendor and peripheral
# software. They still see every keystroke, so they are reported — just not as
# though they were a discovery.
KNOWN_FILTERS = re.compile(
    r"^(synTP|ETDFilter|ApplePS2|LenovoRd|HpqKbFiltr|SynRMIHID|"
    r"CtrlPad|Elan|AlpsAlpine|VirtualBox|vmusbmouse|vmmouse|kbfiltr)",
    re.I,
)


# Input devices that are part of a laptop rather than something attached to it.
INTERNAL_BUS = re.compile(r"^(ACPI\\|HID\\CONVERTEDDEVICE|HID\\INTC|"
                          r"HID\\ELAN|ROOT\\|BUTTONCONVERTER\\)", re.I)


def _keyboard_findings(data):
    """Answer 'is anything sitting between the keys and the applications?'"""
    out = []

    # -- 1. filter drivers -------------------------------------------------
    for label, key, stock in (("keyboard", "kbdUpperFilters", STOCK_KBD_FILTERS),
                              ("mouse", "mouUpperFilters", STOCK_MOU_FILTERS)):
        filters = [f for f in aslist(data.get(key)) if isinstance(f, str) and f]
        extra = [f for f in filters if f.lower() not in stock]
        for f in extra:
            known = KNOWN_FILTERS.match(f)
            out.append(_finding(
                "input", "low" if known else "critical",
                f"extra {label} filter driver in the input stack",
                f"{f} — a class filter driver sees every "
                f"{'keystroke' if label == 'keyboard' else 'movement and click'} "
                f"before any application does"
                + (", and this one belongs to known vendor input software"
                   if known else
                   ". Nothing but the stock driver should be here."),
                f"{label} class UpperFilters"))
        if not extra:
            out.append(_finding(
                "input", "ok", f"{label} driver stack is stock",
                f"UpperFilters = {', '.join(filters) or '(empty)'} — nothing is "
                f"layered above the class driver", f"{label} class UpperFilters"))

    lower = [f for f in aslist(data.get("kbdLowerFilters")) if isinstance(f, str) and f]
    if lower:
        out.append(_finding(
            "input", "critical", "keyboard lower filter driver present",
            f"{', '.join(lower)} — sits below the class driver, closer to the "
            f"hardware than anything else in the stack. This position is almost "
            f"never legitimately occupied.", "keyboard class LowerFilters"))

    # -- 2. scancode remapping ---------------------------------------------
    sc = data.get("scancodeMap") or ""
    if sc:
        out.append(_finding(
            "input", "medium", "a kernel-level key remap is installed",
            f"Scancode Map is set ({len(sc.split('-'))} bytes). Legitimate if you "
            f"remapped a key yourself; otherwise a key does something other than "
            f"what is printed on it.",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout"))
    else:
        out.append(_finding("input", "ok", "no kernel key remapping",
                            "Scancode Map is not set", "Keyboard Layout"))

    # -- 3. what is physically plugged in ----------------------------------
    kbs = aslist(data.get("keyboards"))
    external = [k for k in kbs if not INTERNAL_BUS.match(k.get("id") or "")]
    for k in external:
        out.append(_finding(
            "input", "medium", "external keyboard device present",
            f"{k.get('name')} — an inline hardware keylogger must enumerate as a "
            f"keyboard to pass keystrokes through, so confirm you recognise this",
            k.get("id", "")))
    if kbs and not external:
        out.append(_finding(
            "input", "ok", "all keyboard devices are internal",
            f"{len(kbs)} keyboard device(s), all on internal buses (ACPI / "
            f"embedded HID) — nothing attached from outside", ""))

    # A hardware keylogger has to enumerate to work. Anything that ever did is
    # still recorded, so this covers devices attached once and taken away.
    usb_kb = [u for u in aslist(data.get("usbHistory"))
              if re.search(r"keyboard|keypad", u.get("desc") or "", re.I)]
    for u in usb_kb:
        out.append(_finding(
            "input", "high", "a USB keyboard was attached at some point",
            f"{u.get('desc')} ({u.get('id')}) — present in the USB enumeration "
            f"history even if it is not connected now", "USB enum history"))
    if not usb_kb:
        out.append(_finding(
            "input", "ok", "no USB keyboard has ever been attached",
            f"{len(aslist(data.get('usbHistory')))} USB devices in this "
            f"machine's history, none of them a keyboard or keypad",
            "USB enum history"))

    # -- 4. accessibility backdoor -----------------------------------------
    for h in aslist(data.get("ifeoAccessibility")):
        out.append(_finding(
            "input", "critical", "accessibility binary is hijacked",
            f"{h.get('file')} → {h.get('debugger')} — these run as SYSTEM from "
            f"the logon screen, so this is a backdoor reachable from the keyboard "
            f"before anyone signs in",
            "Image File Execution Options"))

    return out
