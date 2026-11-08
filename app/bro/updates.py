# version : 0.1
# created by : JK and CF
# last edited : 02/11/2026
# Name : bro-backup (bro/updates.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Is there a newer version? Once a day we ask GitHub for the latest release.

Only a plain GET to the GitHub API, with "bro-backup/<version>" as user agent. Nothing about this
NAS, its bros or its backups is sent. Can be turned off under Settings. Drafts and pre-releases
are never offered (GitHub's "latest release" leaves them out). The overview shows a notice, and
one notification goes out per new version.
"""

import json
import os
import re
import urllib.request

from .core import VERSION, iso, load_state, log, mutate, notify, now, parse

REPO = os.environ.get("UPDATE_REPO", "j-kest/bro-backup")
API_URL = os.environ.get("UPDATE_URL", f"https://api.github.com/repos/{REPO}/releases/latest")
RELEASES_URL = f"https://github.com/{REPO}/releases"
CHECK_SECONDS = 24 * 3600
RETRY_SECONDS = 3600
TAG_RE = re.compile(r"^v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})$")


def parse_version(text):
    """'v0.10.2' or '0.10.2' -> (0, 10, 2); anything else -> None."""
    m = TAG_RE.match(str(text or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def newer(latest, current=None):
    a, b = parse_version(latest), parse_version(current or VERSION)
    return bool(a and b and a > b)


def info():
    """What the overview and the self-check show: {} when nothing is known yet."""
    return dict(load_state().get("update") or {})


def available():
    """The newer version to show, or None. Hidden when turned off, already installed or dismissed."""
    st = load_state()
    u = st.get("update") or {}
    if not st["settings"].get("update_check", True) or not newer(u.get("latest")):
        return None
    if u.get("dismissed") == u.get("latest"):
        return None
    return {"version": u["latest"], "url": u.get("url") or RELEASES_URL}


def _due(u):
    t = parse(u.get("checked_at"))
    wait = RETRY_SECONDS if u.get("error") else CHECK_SECONDS
    return not t or (now() - t).total_seconds() >= wait


def fetch(timeout=15):
    """Ask GitHub. Returns (version, release page url). Raises on anything unexpected."""
    req = urllib.request.Request(API_URL, headers={"Accept": "application/vnd.github+json",
                                                   "User-Agent": f"bro-backup/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read(200_000).decode("utf-8", "replace"))
    tag = data.get("tag_name") if isinstance(data, dict) else None
    v = parse_version(tag)
    if not v:
        raise ValueError(f"unexpected release tag {str(tag)[:40]!r}")
    url = data.get("html_url")
    if not (isinstance(url, str) and url.startswith(f"https://github.com/{REPO}/releases/")):
        url = RELEASES_URL  # only ever link to our own release pages
    return ".".join(map(str, v)), url


def check(force=False):
    """Slow-loop task. Returns the update info after checking (or {} when turned off)."""
    st = load_state()
    if not st["settings"].get("update_check", True):
        return {}
    u = st.get("update") or {}
    if not force and not _due(u):
        return u
    try:
        latest, url = fetch()
        fields = {"checked_at": iso(now()), "latest": latest, "url": url, "error": None}
    except Exception as e:
        log.info("Checking for a new version failed: %s", e)
        fields = {"checked_at": iso(now()), "error": str(e)[:200]}
    with mutate() as st2:
        u = st2.setdefault("update", {})
        u.update(fields)
        tell = newer(u.get("latest")) and u.get("notified") != u.get("latest")
        if tell:
            u["notified"] = u["latest"]
        u = dict(u)
    if tell:
        notify(f"BRO Backup {u['latest']} is available",
               f"This NAS runs {VERSION}. What changed and how to update: {u.get('url') or RELEASES_URL}",
               priority="default")
    return u


def dismiss():
    with mutate() as st:
        u = st.setdefault("update", {})
        u["dismissed"] = u.get("latest")
