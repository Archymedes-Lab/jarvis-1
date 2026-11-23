"""BITS transfer jobs: telling vendor updaters from a download staged by an intruder."""

import re

# BITS job names Windows Update and vendor updaters use.
_BITS_BENIGN = re.compile(
    r"windows ?update|wuauclt|delivery optimization|msedge|edgeupdate|"
    r"google update|gupdate|dropbox|onedrive|office|teams|adobe|mozilla",
    re.I)


# Hosts those updaters actually fetch from. The name alone is not enough in
# either direction, and matching it against the whole URL was worse than
# useless: `https://evil.example/?ref=onedrive` contains "onedrive" and was
# therefore exempt, while OneDrive's own real job — DisplayName
# `PreSignInSettingsConfigJSON`, url `https://g.live.com/odclientsettings/ProdV2`
# — contains none of these words anywhere and was reported HIGH. So the host is
# what gets matched, parsed out of the URL rather than searched for inside it: a
# dropper can name its job anything, but it still has to serve the payload from
# somewhere, and that somewhere is never one of these.
_BITS_VENDOR_HOST = re.compile(
    r"(^|\.)("
    r"(g|go|api)\.live\.com|"
    r"(officecdn|officeclient|download|update|dl\.delivery\.mp|"
    r"[a-z0-9-]*\.?windowsupdate|au\.download\.windowsupdate)\.microsoft\.com|"
    r"[a-z0-9-]+\.windowsupdate\.com|"
    r"[a-z0-9-]*\.?dl\.delivery\.mp\.microsoft\.com|"
    r"onedrive\.live\.com|oneclient\.sfx\.ms|"
    r"dl\.google\.com|update\.googleapis\.com|"
    r"download\.mozilla\.org|[a-z0-9-]+\.cdn\.mozilla\.net|"
    r"ardownload[0-9]*\.adobe\.com|"
    r"client-update\.dropbox\.com|edgedl\.me\.gvt1\.com"
    r")$", re.I)


def _bits_hosts(url):
    """Every host named in a BITS job's file list, lowercased."""
    return [m.group(1).lower()
            for m in re.finditer(r"https?://([^/\s;:]+)", url or "", re.I)]


def _bits_is_vendor(name, url):
    """True when this job is a known updater doing its normal work.

    Requires the *hosts* to check out whenever there are any. A job with no URL
    at all falls back to the name, because there is then nothing to fetch and
    nothing to stage.
    """
    hosts = _bits_hosts(url)
    if hosts:
        return all(_BITS_VENDOR_HOST.search(h) for h in hosts)
    return bool(_BITS_BENIGN.search(name or ""))
