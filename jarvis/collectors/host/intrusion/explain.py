"""Plain-language explanation of one Defender threat name.

Defender names a detection Type:Platform/Family.Variant!suffix, for example
Trojan:Win32/Bearfoos.A!ml. The name says what kind of thing it is, what it runs on and
how it was recognised; it does not say what the program did on this machine, so the
sentence never claims more than the name supports. The family part is only repeated.
"""

import re

# Type: what kind of threat the name claims.
TYPES = {
    "trojan": "a trojan: a program that pretends to be harmless while doing something else, "
              "such as opening a way in or stealing data",
    "trojandownloader": "a downloader: a small program whose job is to fetch and start other malware",
    "trojandropper": "a dropper: a program that carries other malware inside it and installs it",
    "trojanspy": "spyware: a program that watches what you do or collects your data",
    "trojanclicker": "a clicker: a program that generates clicks or visits without you",
    "backdoor": "a backdoor: a hidden way for someone else to control the computer",
    "virus": "a virus: a program or file that copies itself into other files",
    "worm": "a worm: a program that spreads to other computers by itself",
    "ransom": "ransomware: a program that locks or encrypts files and demands payment",
    "pws": "a password stealer: a program that collects saved passwords or logins",
    "spyware": "spyware: a program that watches what you do or collects your data",
    "exploit": "an exploit: code that abuses a weakness in software to gain access",
    "hacktool": "a hacking tool: software used to attack or take over systems "
                "(it is sometimes used on purpose by security staff)",
    "tool": "a tool that is sometimes misused",
    "virtool": "a tool that helps other malware avoid detection",
    "rootkit": "a rootkit: software that hides itself and other malware deep in the system",
    "behavior": "suspicious behaviour: the program acted like malware, whatever it is called",
    "pua": "a potentially unwanted program: not clearly a virus, but something you probably "
           "did not mean to install",
    "puadlmanager": "a potentially unwanted download manager that installs extra software",
    "softwarebundler": "a bundler: an installer that adds extra software you may not want",
    "adware": "adware: a program that shows unwanted adverts",
    "ddos": "a tool used to flood other computers with traffic",
    "program": "a program Defender treats as unwanted",
    "monitoringtool": "a monitoring tool that records activity, which can be misused",
    "phish": "a phishing page or file made to steal logins",
    "malware": "malware: harmful software",
}

# Platform: what it runs on.
PLATFORMS = {
    "win32": "a Windows program", "win64": "a Windows program",
    "msil": "a Windows program written for .NET", "powershell": "a PowerShell script",
    "script": "a script", "js": "a JavaScript file", "vbs": "a VBScript file",
    "html": "a web page", "wsl": "something that runs inside the Windows Linux layer",
    "dos": "an old DOS-style file", "linux": "a Linux program",
    "macos": "a Mac program", "androidos": "an Android app", "o97m": "an Office macro",
    "x97m": "an Excel macro", "w97m": "a Word macro", "pdf": "a PDF file",
}

EICAR = ("This is the EICAR test file: a harmless, industry-standard text that every antivirus "
         "is meant to flag so you can check it is working. It cannot harm the computer. "
         "Defender flagging it means Defender is working.")

NAME = re.compile(r"^\s*(?:(?P<type>[A-Za-z]+):)?(?:(?P<platform>[A-Za-z0-9]+)/)?"
                  r"(?P<family>[^!\s]+?)?(?:!(?P<suffix>\S+))?\s*$")


def explain_threat(name):
    """One or two sentences about a Defender threat name; '' for an empty name."""
    text = str(name or "").strip()
    if not text:
        return ""
    if "eicar" in text.lower():
        return EICAR
    m = NAME.match(text)
    if not m:
        return "Defender named this threat; open Windows Security for what it found."
    kind = TYPES.get((m.group("type") or "").lower())
    where = PLATFORMS.get((m.group("platform") or "").lower())
    family = m.group("family") or ""
    parts = []
    if kind:
        parts.append(f"Defender calls this {kind}" + (f", {where}" if where else "") + ".")
    elif where:
        parts.append(f"Defender flagged {where}.")
    else:
        parts.append("Defender flagged this.")
    if family:
        parts.append(f"Its family name is {family.split('.')[0]}; "
                     "Defender's name tells you the kind of threat, not what it did on this computer.")
    suffix = (m.group("suffix") or "").lower()
    if suffix in ("ml", "mtb"):
        parts.append("It was recognised by a machine-learning model, so treat it as a strong "
                     "warning rather than a certain identification.")
    return " ".join(parts)
