# version : 0.2
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/urbackup.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""PCs and servers through UrBackup: find its storage, send it offsite, and watch every client.

UrBackup (AGPLv3, urbackup.org) backs up Windows, macOS and Linux machines to the NAS, like
Synology's Active Backup for Business. BRO Backup then takes that storage to the bros. Layout of
the UrBackup storage folder (administration manual):
- one folder per client, named after the client;
- file backups in folders named YYMMDD-HHMM, with `current` linking to the newest complete one;
- image backups as Image_<volume>_<YYMMDD_HHMM>.vhd or .vhdz (plus .mbr and similar files);
- `urbackup` (automatic database backup) and `urbackup_tmp_files` (incoming data) at the top.
Unchanged files are hard links: restic stores their content once. urbackup_tmp_files is skipped.

Every hour the storage is looked up again (cheap: folder names only) and every client is checked:
when its newest backup is older than the notification limit, you hear it, at most every 72 h.
"""

import datetime
import os
import re

from .core import NAS_DIR, SKIP_DIRS, iso, load_state, local_time, log, mutate, notify, now, parse

FILE_RE = re.compile(r"^(\d{2})(\d{2})(\d{2})-(\d{2})(\d{2})$")
IMAGE_RE = re.compile(r"^Image_(.{1,40}?)_(\d{2})(\d{2})(\d{2})[_-](\d{2})(\d{2})\.(vhdz?|raw)$")
MARKERS = ("urbackup", "urbackup_tmp_files")
NOT_CLIENTS = set(MARKERS) | {"clients", "lost+found"}
SCAN_DEPTH = 3
REMIND_HOURS = 72
MAX_ENTRIES = 5000   # a client folder with more entries than this is read partly: enough for "newest"


def _stamp(m, first):
    yy, mm, dd, hh, mi = (int(m.group(i)) for i in range(first, first + 5))
    try:
        return datetime.datetime(2000 + yy, mm, dd, hh, mi).astimezone()  # UrBackup names use its local time
    except ValueError:
        return None


def read_client(path):
    """Newest file backup, newest image per volume, and counts, from folder and file names only."""
    newest_file, images, n_files, n_images = None, {}, 0, 0
    try:
        with os.scandir(path) as it:
            for i, e in enumerate(it):
                if i >= MAX_ENTRIES:
                    break
                m = FILE_RE.match(e.name)
                if m and e.is_dir(follow_symlinks=False):
                    t = _stamp(m, 1)
                    if t:
                        n_files += 1
                        newest_file = max(filter(None, [newest_file, t]))
                    continue
                m = IMAGE_RE.match(e.name)
                if m and e.is_file(follow_symlinks=False):
                    t = _stamp(m, 2)
                    if t:
                        n_images += 1
                        vol = m.group(1)
                        images[vol] = max(filter(None, [images.get(vol), t]))
    except OSError:
        return None
    if not n_files and not n_images:
        return None
    newest = max(filter(None, [newest_file, *images.values()]))
    return {"name": os.path.basename(path), "last_file": iso(newest_file) if newest_file else None,
            "last_image": iso(max(images.values())) if images else None, "volumes": sorted(images),
            "file_backups": n_files, "image_backups": n_images, "last": iso(newest)}


def is_storage(path):
    """UrBackup storage has its folder urbackup_tmp_files (there by default), or its folder urbackup
    (database backup) next to at least one computer. A folder that only contains a folder named
    "urbackup" (the storage itself, often called that) is not storage."""
    try:
        names = {e.name for e in os.scandir(path) if e.is_dir(follow_symlinks=False)}
    except OSError:
        return False
    if "urbackup_tmp_files" in names:
        return True
    return "urbackup" in names and any(read_client(os.path.join(path, n)) for n in names - NOT_CLIENTS
                                       if not n.startswith("."))


def read_storage(path):
    clients = []
    try:
        subs = sorted(e.path for e in os.scandir(path) if e.is_dir(follow_symlinks=False)
                      and e.name not in NOT_CLIENTS and not e.name.startswith("."))
    except OSError:
        return []
    for sub in subs:
        c = read_client(sub)
        if c:
            clients.append(c)
    return clients


def find_storages(base=NAS_DIR, depth=SCAN_DEPTH):
    found = []

    def walk(path, d):
        if d < 0:
            return
        if is_storage(path):
            found.append(path)
            return  # never look for another storage inside one
        try:
            subs = [e.path for e in os.scandir(path) if e.is_dir(follow_symlinks=False)
                    and e.name not in SKIP_DIRS and not e.name.startswith((".", "-"))]  # "-": never option-like
        except OSError:
            return
        for s in sorted(subs):
            walk(s, d - 1)
    if os.path.isdir(base):
        walk(base, depth)
    return found


def included(path, sources):
    real = os.path.realpath(path)
    return any(real == os.path.realpath(s) or real.startswith(os.path.realpath(s) + os.sep) for s in sources)


def status(st=None):
    """Every UrBackup storage with its clients, as found by the last hourly scan."""
    st = st or load_state()
    s = st["settings"]
    hours = int(s.get("alert_hours") or 72)
    out = []
    for x in (st.get("urbackup") or {}).get("storages") or []:
        clients = []
        for c in x.get("clients") or []:
            t = parse(c.get("last"))
            age_h = (now() - t).total_seconds() / 3600 if t else None
            clients.append({**c, "age_h": age_h, "ok": age_h is not None and age_h <= hours})
        out.append({"path": x["path"], "rel": os.path.relpath(x["path"], NAS_DIR), "clients": clients,
                    "included": included(x["path"], s.get("sources") or []), "hours": hours})
    return out


def scan():
    """Look up the storages and their clients, and remember the result for the pages."""
    storages = [{"path": p, "clients": read_storage(p)} for p in find_storages()]
    with mutate() as st:
        st["urbackup"] = {"at": iso(now()), "storages": storages}
    return storages


def check():
    """Hourly: scan, and notify about clients that went silent (at most every REMIND_HOURS each)."""
    scan()
    st = load_state()
    alerts = dict(st.get("urbackup_alerts") or {})
    changed = False
    for x in status(st):
        for c in x["clients"]:
            key = f"{x['path']}|{c['name']}"
            if c["ok"]:
                if alerts.pop(key, None):
                    changed = True
                continue
            last = parse(alerts.get(key))
            if last and (now() - last).total_seconds() < REMIND_HOURS * 3600:
                continue
            days = f"{c['age_h'] / 24:.0f} days" if c["age_h"] is not None else "a long time"
            notify(f"{c['name']} has not been backed up for {days}",
                   f"UrBackup has no backup of {c['name']} since {local_time(c['last'])}. Is the computer on, and "
                   "is the UrBackup client running? Check the UrBackup web interface.", priority="default")
            log.info("UrBackup client %s silent since %s", c["name"], c["last"])
            alerts[key] = iso(now())
            changed = True
        if not x["included"] and x["clients"]:
            key = f"{x['path']}|not-included"
            if not alerts.get(key):
                notify("UrBackup storage is not sent offsite",
                       f"BRO Backup found UrBackup backups of {len(x['clients'])} computer(s) in {x['rel']}, but that "
                       "folder is not selected. Include it in Settings, otherwise a fire or theft takes them along.",
                       priority="default")
                alerts[key] = iso(now())
                changed = True
    if changed:
        with mutate() as st2:
            st2["urbackup_alerts"] = alerts
