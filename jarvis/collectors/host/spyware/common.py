"""Signatures and finding shape shared by the Windows and Linux spyware checks."""

import re

# Names used by consumer monitoring, parental-control and stalkerware products.
# Matching one is a prompt to look, not a verdict.
STALKERWARE = re.compile(
    r"actualspy|ardamax|blurspy|cocospy|couplevow|cerberus|clevguard|"
    r"eyezy|flexispy|flexible?spy|hoverwatch|ikeymonitor|iwantspy|"
    r"kidsguard|kidlogger|mobistealth|mspy|minspy|neatspy|netbull|"
    r"pcpandora|perfectkeylogger|refog|realtime-?spy|revealer|spyagent|"
    r"spyera|spyhuman|spyic|spyier|spytech|spyzie|snoopza|"
    r"teensafe|thetruthspy|umobix|webwatcher|wolfeye|xnspy|"
    r"keylog|keystroke|screenshot.?monitor|employee.?monitor|"
    r"activtrak|hubstaff|teramind|veriato|interguard|workpuls|"
    r"desktime|timedoctor|controlio",
    re.I,
)


# Vendor software that legitimately drives volume and media keys. Present so the
# audit can say "this is probably your keyboard" instead of leaving you guessing.
INPUT_VENDORS = re.compile(
    r"logi|logitech|lghub|icue|corsair|razer|synapse|steelseries|"
    r"nahimic|sonic ?studio|realtek|dolby|armoury|asus|msi|alienware|"
    r"gamebar|xbox|elgato|streamdeck|touchportal|autohotkey|powertoys",
    re.I,
)


CAPABILITIES = ("microphone", "webcam", "location")


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


CAT_ORDER = {"spyware": 0, "access": 1, "input": 2, "signing": 3}


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(findings):
    return sorted(findings, key=lambda f: (CAT_ORDER.get(f["category"], 9),
                                           SEV_ORDER.get(f["severity"], 9),
                                           f["title"]))
