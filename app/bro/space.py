# version : 0.1
# created by : JK and CF
# last edited : 03/11/2026
# Name : bro-backup (bro/space.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Is the disk under the data folder filling up?

The data folder holds the backups of the bros that back up here, plus our own restic cache and
database dumps. When it runs full, their backups fail and so may ours. We measure the file system
of the data folder (on TrueNAS with a dataset quota that is the quota, not the whole pool):
- warn from WARN_USED (ZFS slows down when a pool gets very full), critical from CRIT_USED;
- also warn when the space promised to bros (their quota minus what they use now) is more than
  what is free: then they can fill the disk before reaching their quota.
One notification when it gets worse, another after REMIND_DAYS if it stays that way.
"""

import datetime
import shutil

from .core import (
    DATA_DIR,
    GIB,
    human_bytes,
    iso,
    load_state,
    log,
    mutate,
    notify,
    now,
    parse,
    receive_stats,
)

WARN_USED = 0.90
CRIT_USED = 0.97
REMIND_DAYS = 3
LEVELS = {"ok": 0, "warn": 1, "err": 2}


def measure(path=DATA_DIR):
    """Free space and promised space. None when the folder cannot be measured."""
    try:
        du = shutil.disk_usage(path)
    except OSError as e:
        log.info("Measuring free space of %s failed: %s", path, e)
        return None
    st = load_state()
    promised = 0
    for user, r in st["receivers"].items():
        if not r.get("accepted") or r.get("quota_blocked"):
            continue
        used = (receive_stats.get(user) or {}).get("usage") or 0
        promised += max(0, int(r.get("quota_gib") or 0) * GIB - used)
    used = du.total - du.free
    share = used / du.total if du.total else 0
    level = "err" if share >= CRIT_USED else ("warn" if share >= WARN_USED else "ok")
    return {"total": du.total, "free": du.free, "used_share": share, "promised": promised,
            "overcommitted": promised > du.free, "level": level}


def describe(m):
    return f"{human_bytes(m['free'])} free of {human_bytes(m['total'])} ({m['used_share'] * 100:.0f}% used)"


def check():
    """Hourly: notify when the disk fills up or bros were promised more than is free."""
    m = measure()
    if not m:
        return None
    st = load_state()
    prev = st.get("space_alert") or {}
    worse = LEVELS[m["level"]] > LEVELS.get(prev.get("level", "ok"), 0)
    remind = m["level"] != "ok" and parse(prev.get("at")) and \
        now() - parse(prev["at"]) > datetime.timedelta(days=REMIND_DAYS)
    if m["level"] != "ok" and (worse or remind):
        if m["level"] == "err":
            notify("The disk of BRO Backup is almost full",
                   f"{describe(m)}. Backups of your bros (and maybe your own) will fail soon. Free up space, "
                   "enlarge the dataset or its quota, or give bros less space.")
        else:
            notify("The disk of BRO Backup is filling up",
                   f"{describe(m)}. Keep an eye on it: free up space or enlarge the dataset or its quota.",
                   priority="default")
    over_new = m["overcommitted"] and not prev.get("overcommitted")
    if over_new and m["level"] == "ok":
        notify("You gave bros more space than is free",
               f"Your bros may still store {human_bytes(m['promised'])}, but only {human_bytes(m['free'])} is "
               "free. Enlarge the dataset or its quota, or lower a bro's space.", priority="default")
    with mutate() as st2:
        if m["level"] == "ok" and not m["overcommitted"]:
            st2.pop("space_alert", None)
        else:
            alert = dict(st2.get("space_alert") or {})
            if (m["level"] != "ok" and (worse or remind)) or over_new:
                alert["at"] = iso(now())
            alert.update(level=m["level"], overcommitted=m["overcommitted"])
            st2["space_alert"] = alert
    return m
