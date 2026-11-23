"""Fixed metadata only; advisory cannot suppress a finding, authorize or pass a campaign."""
import json

from jarvis.response import jev

STATE = {
    "measured": {
        "bandit": "410 findings; medium/high reviewed: XML parsing refuses entity bombs and external entities on the bundled expat 2.6.1 (measured), SQL builds only constant identifiers and placeholder lists, one trojan-source hit was raw bidi characters inside a detector regex (fixed)",
        "semgrep_taint": "0 findings; rule controls pass",
        "pip_audit": "0 known advisories in runtime pins",
        "gitleaks": "28 history hits, each reviewed as synthetic test vectors or public values",
        "windows_installer_pe": "declares ASLR but relocations are stripped, so it always loads at its preferred base; known NSIS stub limitation with no makensis switch; installer requests user-level execution (no elevation), installs per-user under LOCALAPPDATA, reads only its own embedded payload and exits",
        "windows_binaries": "desktop app and installer have no Authenticode signature and no Control Flow Guard; desktop app has effective ASLR and DEP",
    },
    "false_positive_options": {
        "exact": "Ignore exact commit:file:rule:line fingerprints with a written reason per entry and a test that refuses globs",
        "rule_wide": "Disable the noisy scanner rules or paths in configuration",
        "none": "Leave every reviewed false positive failing the scan",
    },
    "next_options": {
        "installer_aslr": "Rebuild the installer stub with relocations or move to another installer format",
        "authenticode": "Obtain a code-signing certificate and sign the desktop app and installer",
        "vm_attack_chains": "Run synthetic attack chains against a disposable deployed VM",
        "bandit_triage": "Review the remaining medium Bandit findings line by line",
    },
}
QUESTIONS = {
    "false_positives": {"type": "choice",
                        "instructions": "Which disposition of reviewed scanner false positives keeps new real secrets or flaws visible while letting the scan report a meaningful pass?",
                        "criteria": {"exact": "Exact fingerprints with reasons and a shape test",
                                     "rule_wide": "Rule-wide or path-wide exclusions",
                                     "none": "Leave them all failing"}},
    "next": {"type": "choice",
             "instructions": "Given the measured state, which next item most reduces real risk to people installing and running this Windows security product?",
             "criteria": {k: v for k, v in STATE["next_options"].items()}},
    "installer_release_blocker": {"type": "noul",
                                  "instructions": "Should a per-user, non-elevated Windows installer whose ASLR is ineffective because relocations are stripped be fixed before the next public release, rather than only documented?",
                                  "criteria": {"true": "Yes, fix before the next public release",
                                               "false": "No, documenting it is enough for now"}},
}
if __name__ == "__main__":
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({"answers": result["answers"]}))
    except jev.JevError as exc:
        print(json.dumps({"unavailable": str(exc)}))
