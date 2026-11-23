"""Artifacts of how machines actually get compromised right now.

The other modules look for things that are *running* or *installed*. This one
looks for evidence of the initial access itself, because current intrusions are
increasingly things that happen once and leave no persistent process behind:

  ClickFix          A fake CAPTCHA page copies a command to the clipboard and
                    tells you to press Win+R and paste it. It is reportedly the
                    single largest initial-access technique in circulation, and
                    it leaves a perfect fingerprint: Windows records everything
                    typed into the Run dialog in the RunMRU registry key.

  Infostealers      Modern stealers run once, harvest browser cookies, session
                    tokens and saved passwords, and exit. Behavioural rules that
                    watch for persistence miss them entirely, because there is
                    no persistence. What they leave behind is access to the
                    browser credential stores and, often, a malicious extension.

  Session theft     Stolen cookies and OAuth tokens are replayed directly, so
                    the password and the second factor never come into it. A
                    browser extension with broad host permissions is one of the
                    cheapest ways to keep harvesting them.

It also reads Defender's own detection history, which is the cheapest possible
question to ask and the one most often skipped: has the antivirus already found
something and been ignored?
"""

from .bits import _bits_hosts, _bits_is_vendor
from .common import SEV_ORDER, sort_findings
from .history import (
    SUSPICIOUS_HISTORY,
    _history_findings,
    _history_malware_hosts,
    _history_severity,
)
from .run import audit
