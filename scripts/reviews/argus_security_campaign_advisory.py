"""Fixed metadata only; advisory cannot authorize or pass a campaign."""
import json
import sys

from jarvis.response import jev

STATE = {
    "alternatives": {
        "adapters": "Fixed installed-tool argv plus existing isolated production-path tests; explicit gaps",
        "new_scanner": "Implement a universal scanner from scratch",
        "shell": "Run arbitrary scanner shell commands and accept exit zero as complete coverage",
    },
    "invariants": ["no production probing", "no user data or secrets", "bounded time and output",
                   "missing tools and skipped tests cannot pass", "no automatic human sign-off"],
    "limits": ["finite model checks are not refinement proofs", "Python debug allocator is not native ASan",
               "manual review and deployed VM attack chains remain pending"],
    "dependency_remediation": {
        "scope": "three hosted development toolchains; no Worker source or deployment change",
        "patches": {"sharp": "0.35.5", "undici": "7.30.1"},
        "alternatives": "exact transitive patch overrides versus broad Wrangler/Miniflare upgrade",
        "validation": "frozen install without scripts, Worker tests, type checks and fresh advisory audit required",
        "unresolved": "desktop deepmerge advisory has no listed upstream patch",
    },
}
QUESTIONS = {
    "design": {"type": "choice", "instructions": "Which architecture best preserves the stated invariants?",
               "criteria": {"adapters": "Fixed bounded adapters with explicit gaps",
                            "new_scanner": "New universal scanner", "shell": "Arbitrary shell commands"}},
    "gap": {"type": "noul", "instructions": "Does this design still require manual review and isolated deployed-system validation before claiming full method coverage?",
            "criteria": {"true": "Yes, these remain necessary", "false": "No, adapters establish full coverage"}},
    "dependency_validation": {"type": "noul", "instructions": "Do these transitive patch overrides still need a real Wrangler dry-run build in addition to Worker tests, types and advisory audits before claiming the development toolchain works?",
                              "criteria": {"true": "Yes, exercise the build path too", "false": "No, the listed checks suffice"}},
}
if __name__ == "__main__":
    STATE["phase"] = "implementation" if "--implementation" in sys.argv else "design"
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({"answers": result["answers"]}))
    except jev.JevError as exc:
        print(json.dumps({"unavailable": str(exc)}))
