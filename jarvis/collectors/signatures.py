"""Detection knowledge that more than one collector domain matches against.

Kept here rather than in either collector so that neither domain imports the
other: the firewall audit and the control-surface audit both need to recognise
a remote-control agent, and neither owns that list.
"""

import re

# Commercial remote-control agents. Presence is not proof of compromise -- it is
# proof that someone can drive this machine, which is what you asked to see.
REMOTE_AGENTS = re.compile(
    r"teamviewer|anydesk|rustdesk|ultravnc|tightvnc|realvnc|vncserver|x11vnc|"
    r"screenconnect|connectwise|logmein|gotoassist|splashtop|supremo|ammyy|"
    r"radmin|dwservice|dwagent|atera|ninjarmm|ninjaone|syncro|kaseya|"
    r"chrome remote desktop|remotepc|zoho assist|action1|pulseway|"
    r"quickassist|mstsc|psexec|paexec|meshagent|tacticalrmm",
    re.I,
)
