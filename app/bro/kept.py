# version : 1.1.0
# created by : JK and CF
# last edited : 12/11/2026
# Name : bro-backup (bro/kept.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""What a bro deletes here is kept for a few days.

A bro cleans up his own old versions, so he must be able to delete. But whoever gets hold of his NAS (ransomware,
a thief) can delete everything the same way. So every file of a bro gets a second name (a hard link) in a folder
his login cannot reach. A hard link costs no space while the file exists. When the bro deletes the file, the
second name still holds the data: it moves to "gone" under the day it disappeared, and is really deleted
KEEP days later. Until then "Put back" on the overview links everything back into his backup.

Why this is safe: rest-server never changes a file in place. It refuses to write a name that exists, and writes
new files under a temporary name first, so a kept file cannot be damaged through the bro's login.

  kept/<user>/live/...            second names of the files that exist now
  kept/<user>/gone/<yyyy-mm-dd>/  files the bro deleted on that day

Lock files are left out: restic makes and removes those all the time."""

import datetime
import errno
import os
import shutil
import threading

from .core import DATA_DIR, RECEIVE_DIR, human_bytes, iso, load_state, log, mutate, notify, now, settings

KEPT_DIR = os.path.join(DATA_DIR, "kept")
PARTS = ("keys", "snapshots", "index", "data")
TEMP_SUFFIX = ".rest-server-temp"
DEFAULT_DAYS = 7
MAX_DAYS = 90
MASS_SHARE, MASS_MIN = 0.5, 20  # more than half of at least 20 files gone at once: tell the owner

stats = {}            # user -> {"files", "bytes", "oldest", "until"}: what is in "gone" now
unsupported = []      # the reason when hard links do not work here (then nothing is kept)
_lock = threading.Lock()


def days(s=None):
    try:
        return min(MAX_DAYS, max(0, int((s or settings()).get("keep_deleted_days", DEFAULT_DAYS))))
    except (TypeError, ValueError):
        return DEFAULT_DAYS


def _files(base):
    """The repository files under base, as {relative path: inode}."""
    out = {}
    cfg = os.path.join(base, "config")
    try:
        out["config"] = os.lstat(cfg).st_ino
    except OSError:
        pass
    for part in PARTS:
        for root, _dirs, files in os.walk(os.path.join(base, part)):
            for fn in files:
                if fn.endswith(TEMP_SUFFIX):
                    continue
                p = os.path.join(root, fn)
                try:
                    out[os.path.relpath(p, base)] = os.lstat(p).st_ino
                except OSError:
                    pass
    return out


def _move(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    os.replace(src, dst)


def _gone_days(user):
    base = os.path.join(KEPT_DIR, user, "gone")
    try:
        return sorted(d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d)))
    except OSError:
        return []


def _measure(user, keep):
    files = size = 0
    all_days = _gone_days(user)
    for day in all_days:
        for root, _dirs, names in os.walk(os.path.join(KEPT_DIR, user, "gone", day)):
            for fn in names:
                try:
                    size += os.lstat(os.path.join(root, fn)).st_size
                    files += 1
                except OSError:
                    pass
    if files:
        until = datetime.date.fromisoformat(all_days[0]) + datetime.timedelta(days=keep)
        stats[user] = {"files": files, "bytes": size, "oldest": all_days[0], "until": until.isoformat()}
    else:
        stats.pop(user, None)


def sweep(user, today=None):
    """Give new files their second name, move what the bro deleted to "gone", and drop what is old enough.
    Returns how many files were found deleted."""
    keep = days()
    today = today or datetime.date.today()
    src, base = os.path.join(RECEIVE_DIR, user), os.path.join(KEPT_DIR, user)
    live_dir = os.path.join(base, "live")
    with _lock:
        if not keep:
            shutil.rmtree(base, ignore_errors=True)
            stats.pop(user, None)
            return 0
        cur, live = _files(src), _files(live_dir)
        gone_dir = os.path.join(base, "gone", today.isoformat())
        gone = 0
        for rel, ino in live.items():
            if cur.get(rel) != ino:  # deleted, or deleted and sent again: the old data is kept either way
                _move(os.path.join(live_dir, rel), os.path.join(gone_dir, rel))
                gone += 1
        for rel, ino in cur.items():
            if live.get(rel) == ino:
                continue
            dst = os.path.join(live_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                os.link(os.path.join(src, rel), dst)
            except FileNotFoundError:
                continue  # deleted while we were looking
            except OSError as e:
                if e.errno in (errno.EXDEV, errno.EPERM, errno.ENOTSUP, errno.EMLINK):
                    if not unsupported:
                        log.warning("Deleted files of bros cannot be kept: hard links do not work between %s and %s (%s)",
                                    RECEIVE_DIR, KEPT_DIR, e.strerror)
                    unsupported[:] = [e.strerror or str(e)]
                    return gone
                raise
        unsupported.clear()
        limit = (today - datetime.timedelta(days=keep)).isoformat()
        for day in _gone_days(user):
            if day <= limit:
                shutil.rmtree(os.path.join(base, "gone", day), ignore_errors=True)
        _measure(user, keep)
    if gone >= MASS_MIN and gone > MASS_SHARE * len(live):
        _mass_deletion(user, gone, len(live))
    return gone


def _mass_deletion(user, gone, before):
    r = load_state()["receivers"].get(user) or {}
    name = r.get("bro_name") or r.get("name") or user
    k = stats.get(user) or {}
    log.warning("%s deleted %s of %s files of his backup here at once", name, gone, before)
    notify(f"{name} deleted most of his backup on your NAS",
           f"{gone} of {before} files were deleted with {name}'s login. That happens after a big clean-up, but also "
           f"when someone else got hold of his NAS. Everything is kept until {k.get('until', '?')}: ask {name} whether "
           "he meant it. If not, click Put back next to his name on the overview.")


def users():
    out = set()
    for d in (RECEIVE_DIR, KEPT_DIR):
        try:
            out |= {x for x in os.listdir(d) if not x.startswith(".") and os.path.isdir(os.path.join(d, x))}
        except OSError:
            pass
    return sorted(out)


def sweep_all():
    for user in users():
        if os.path.isdir(os.path.join(RECEIVE_DIR, user)):
            sweep(user)
        else:
            forget(user)  # his folder was deleted here on purpose: nothing to keep it for


def restore(user):
    """Put back everything the bro deleted in the last days. Files that exist again are left alone:
    rest-server checked those when they arrived. Returns (files, bytes)."""
    src, base = os.path.join(RECEIVE_DIR, user), os.path.join(KEPT_DIR, user)
    if not os.path.isdir(src):
        raise ValueError("This bro has no backup folder here any more.")
    files = size = 0
    with _lock:
        for day in reversed(_gone_days(user)):  # newest first: the same name on an older day is the same data
            day_dir = os.path.join(base, "gone", day)
            for root, _dirs, names in os.walk(day_dir):
                for fn in names:
                    p = os.path.join(root, fn)
                    rel = os.path.relpath(p, day_dir)
                    dst = os.path.join(src, rel)
                    if not os.path.lexists(dst):
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        os.link(p, dst)
                        files += 1
                        size += os.lstat(p).st_size
                        _move(p, os.path.join(base, "live", rel))
            shutil.rmtree(day_dir, ignore_errors=True)
        stats.pop(user, None)
    log.warning("Put back %s deleted files (%s) of %s", files, human_bytes(size), user)
    with mutate() as st:
        if user in st["receivers"]:
            st["receivers"][user]["put_back"] = iso(now())
    return files, size


def forget(user):
    """The owner of this NAS deletes this bro's backups for good: the kept copies go too."""
    with _lock:
        shutil.rmtree(os.path.join(KEPT_DIR, user), ignore_errors=True)
        stats.pop(user, None)


def total_bytes():
    return sum(v["bytes"] for v in stats.values())
