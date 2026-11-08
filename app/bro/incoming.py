# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/incoming.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""What comes in right now from the bros that back up to this NAS, measured here.

Two signs, both on this NAS, so it works whatever version the bro runs:
- a restic lock in his repository that was written or refreshed in the last 10 minutes: restic holds
  one while a backup, prune or check runs and refreshes it every 5 minutes;
- the bytes rest-server wrote for him, from its Prometheus counters. Only the user "metrics", whose
  password only this app knows, can read those; bros cannot (rest-server answers them 401).
"""

import base64
import collections
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.request

from .core import REST_PORT, RECEIVE_DIR, iso, load_state, log, mutate, now

METRICS_USER = "metrics"
LOCK_FRESH = 600          # seconds: a lock older than this is a leftover, not a running backup
WINDOW = 30               # seconds of samples the speed is taken over
LINE_RE = re.compile(r'^rest_server_blob_write_bytes_total\{([^}]*)\}\s+([0-9.eE+]+)\s*$')
USER_RE = re.compile(r'(?:^|,)user="([^"]*)"')

_lock = threading.Lock()
_samples = collections.defaultdict(collections.deque)   # user -> deque of (time, bytes written in total)
_session = {}                                           # user -> {"since", "start_bytes"}
_last = {"at": 0.0}


def metrics_password():
    """The password of the metrics user, made once and kept with the other secrets in the state."""
    st = load_state()
    if st.get("metrics_pw"):
        return st["metrics_pw"]
    with mutate() as st:
        st.setdefault("metrics_pw", secrets.token_urlsafe(24))
        return st["metrics_pw"]


def read_counters(opener=urllib.request.urlopen):
    """{user: bytes rest-server wrote for him since it started}, or None when it does not answer."""
    auth = base64.b64encode(f"{METRICS_USER}:{metrics_password()}".encode()).decode()
    req = urllib.request.Request(f"http://127.0.0.1:{REST_PORT}/metrics", headers={"Authorization": f"Basic {auth}"})
    try:
        with opener(req, timeout=5) as r:
            text = r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None
    out = {}
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        u = USER_RE.search(m.group(1))
        if u and u.group(1) != METRICS_USER:
            out[u.group(1)] = out.get(u.group(1), 0) + int(float(m.group(2)))
    return out


def lock_age(user):
    """Seconds since the newest restic lock in his repository was written, or None without a lock."""
    d = os.path.join(RECEIVE_DIR, user, "locks")
    try:
        newest = max((e.stat().st_mtime for e in os.scandir(d) if e.is_file()), default=None)
    except OSError:
        return None
    return None if newest is None else max(0.0, time.time() - newest)


def sample(force=False, opener=urllib.request.urlopen):
    """Take one measurement, at most every 4 seconds."""
    t = time.time()
    with _lock:
        if not force and t - _last["at"] < 4:
            return
        _last["at"] = t
    counters = read_counters(opener)
    if counters is None:
        return
    with _lock:
        for user, total in counters.items():
            q = _samples[user]
            if q and total < q[-1][1]:
                q.clear()  # rest-server restarted: its counters start again at 0
            q.append((t, total))
            while q and t - q[0][0] > WINDOW + 10:
                q.popleft()


def status(users):
    """{user: {"active", "speed" (bytes/s), "received" (bytes this session), "since"}} for the overview."""
    sample()
    out = {}
    with _lock:
        for user in users:
            age = lock_age(user)
            active = age is not None and age < LOCK_FRESH
            q = _samples.get(user) or collections.deque()
            speed = 0.0
            if len(q) >= 2:
                recent = [s for s in q if q[-1][0] - s[0] <= WINDOW] or list(q)
                dt = recent[-1][0] - recent[0][0]
                speed = (recent[-1][1] - recent[0][1]) / dt if dt > 0 else 0.0
            total = q[-1][1] if q else 0
            if active and user not in _session:
                _session[user] = {"since": iso(now()), "start_bytes": total}
                log.info("Incoming backup from %s started", user)
            elif not active and user in _session:
                s = _session.pop(user)
                log.info("Incoming backup from %s ended (%d bytes received)", user, max(0, total - s["start_bytes"]))
            s = _session.get(user)
            out[user] = {"active": active, "speed": max(0.0, speed),
                         "received": max(0, total - s["start_bytes"]) if s else 0, "since": s["since"] if s else None}
    return out
