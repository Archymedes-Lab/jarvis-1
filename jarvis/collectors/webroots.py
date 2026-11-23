"""Where a web server serves files from: its configured document roots and the
usual default locations.

Shared by the web-shell audit (network/webshell) and the application-code
scanner (appcode), so it sits directly under collectors/ like signatures.py.
"""

import glob
import os
import re
import subprocess

COMMON_ROOTS = ("/var/www", "/var/www/html", "/usr/share/nginx/html",
                "/srv/www", "/srv/http", "/var/lib/tomcat/webapps",
                "/opt/lampp/htdocs", "/home/*/public_html")


def roots_from_config():
    """Document roots the installed nginx/Apache configuration names."""
    roots = set()
    for cfg_cmd in (["nginx", "-T"], ["apache2ctl", "-S"], ["httpd", "-S"]):
        try:
            r = subprocess.run(cfg_cmd, capture_output=True, text=True, errors="replace",
                               timeout=15)
            for m in re.finditer(r"(?:^\s*root|DocumentRoot)\s+\"?([^\";\s]+)",
                                 r.stdout + r.stderr, re.M):
                roots.add(m.group(1))
        except (OSError, subprocess.SubprocessError):
            continue
    return roots


def expand(paths):
    """Existing directories among `paths`, globs expanded."""
    out = []
    for p in paths:
        out += glob.glob(p) if "*" in p else ([p] if os.path.isdir(p) else [])
    return out
