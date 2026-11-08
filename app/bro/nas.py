# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/nas.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Folders on the NAS, and first backups on an external disk (seeds)."""

import json
import os
import re
import shutil
import stat

from . import scheduler
from .core import (
    clean_name,
    DATA_DIR,
    IMPORT_DIR,
    NAS_DIR,
    RECEIVE_DIR,
    SEED_MARKER,
    SEED_MOUNT,
    SKIP_DIRS,
    dir_size,
    human_bytes,
    iso,
    load_state,
    mutate,
    notify,
    now,
    recv_activity,
)


# ---------------------------------------------------------------- folders on the NAS
def same_dir(a, b):
    try:
        sa, sb = os.stat(a), os.stat(b)
        return (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino)
    except OSError:
        return False


def find_self_in_nas(max_depth=4):
    """Find where our own /data folder sits under /nas, so it is never backed up."""
    found = []

    def walk(path, depth):
        if depth > max_depth:
            return
        try:
            entries = [e for e in os.scandir(path) if e.is_dir(follow_symlinks=False)]
        except OSError:
            return
        for e in entries:
            if e.name in SKIP_DIRS:
                continue
            if same_dir(e.path, DATA_DIR) or same_dir(e.path, SEED_MOUNT):
                found.append(e.path)
                continue
            walk(e.path, depth + 1)
    walk(NAS_DIR, 1)
    return found


MOUNTINFO = "/proc/self/mountinfo"


def writable_mounts(base=None):
    """Mounts at or below /nas that are not read-only, from the mount table (nothing is written to test).
    ZFS snapshots are skipped: they cannot be changed anyway. On TrueNAS the pools are mounted with rslave
    so snapshots show up; a dataset mounted after the app started then arrives without the read-only flag."""
    base = os.path.realpath(base or NAS_DIR).rstrip("/")
    out = []
    try:
        with open(MOUNTINFO) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                mnt = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), parts[4])
                if (mnt == base or mnt.startswith(base + "/")) and "/.zfs/" not in mnt + "/" \
                        and "ro" not in parts[5].split(","):
                    out.append(mnt)
    except OSError:
        return []
    return sorted(set(out))


def sub_datasets(path):
    """File systems mounted below this path: on TrueNAS, its child datasets. A ZFS snapshot holds only its
    own dataset, so in a snapshot these folders are empty."""
    path = os.path.realpath(path).rstrip("/")
    found = set()
    try:
        with open(MOUNTINFO) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                mnt = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), parts[4])  # \040 is a space
                if mnt.startswith(path + "/") and "/.zfs/" not in mnt + "/":
                    found.add(mnt)
    except OSError:
        return []
    return sorted(found)


def list_folders():
    """Folders at level 1 and 2 under /nas, plus the child datasets of level 2, for the folder picker."""
    out = []
    if not os.path.isdir(NAS_DIR):
        return out

    def subdirs(path):
        try:
            items = [e for e in os.scandir(path) if e.is_dir(follow_symlinks=False)]
        except OSError:
            return []
        return [e for e in sorted(items, key=lambda x: x.name.lower())
                if not e.name.startswith((".", "@", "#")) and e.name not in SKIP_DIRS  # @eaDir, #recycle: Synology
                and not same_dir(e.path, DATA_DIR) and not same_dir(e.path, SEED_MOUNT)]
    for e in subdirs(NAS_DIR):
        out.append({"path": e.path, "label": e.name, "depth": 1})
        for s in subdirs(e.path):
            out.append({"path": s.path, "label": s.name, "depth": 2})
            real = os.path.realpath(s.path)
            for c in sub_datasets(real):  # child datasets: ticked one by one, each is read from its own snapshot
                if os.path.dirname(c) == real and not os.path.basename(c).startswith("."):
                    out.append({"path": os.path.join(s.path, os.path.basename(c)), "label": os.path.basename(c),
                                "depth": 3})
    return out


def clean_sources(paths):
    real_nas = os.path.realpath(NAS_DIR)
    ok = []
    for p in paths:
        rp = os.path.realpath(p)
        if (rp == real_nas or rp.startswith(real_nas + os.sep)) and os.path.isdir(rp) and rp not in ok:
            ok.append(rp)
    return ok


# ---------------------------------------------------------------- external disk
def seed_root():
    """The external disk when mounted and writable, otherwise our own bro-backup folder."""
    if os.path.isdir(SEED_MOUNT) and os.access(SEED_MOUNT, os.W_OK):
        return SEED_MOUNT, True
    return os.path.join(DATA_DIR, "seed"), False


def free_space(path):
    try:
        os.makedirs(path, exist_ok=True)
        return shutil.disk_usage(path).free
    except OSError:
        return None


def is_restic_repo(path):
    return os.path.isfile(os.path.join(path, "config")) and all(
        os.path.isdir(os.path.join(path, x)) for x in ("data", "keys", "snapshots", "index"))


def scan_seeds():
    """Find seed folders from bros on the external disk, in the import folder and under /nas."""
    found, seen = [], set()
    roots = [(IMPORT_DIR, 2), (SEED_MOUNT, 2), (NAS_DIR, 3)]
    st = load_state()
    receivers = st["receivers"]
    own = {os.path.realpath(d["seed_path"]) for d in st["destinations"] if d.get("seed_path")}

    def walk(path, depth):
        if depth < 0:
            return
        marker = os.path.join(path, SEED_MARKER)
        if os.path.isfile(marker) and not os.path.islink(marker):
            real = os.path.realpath(path)
            if real in seen or real in own:
                return
            seen.add(real)
            try:
                with open(marker) as f:
                    m = json.load(f)
                if not isinstance(m, dict):
                    return
            except Exception:
                return
            user = m.get("for_user")
            found.append({"path": real, "from": clean_name(m.get("from")) or "?", "user": user,
                          "known": user in receivers, "created": m.get("created"),
                          "complete": m.get("complete", False) and is_restic_repo(path),
                          "receiver_name": (receivers.get(user) or {}).get("bro_name")
                          or (receivers.get(user) or {}).get("name")})
            return
        try:
            subs = [e.path for e in os.scandir(path) if e.is_dir(follow_symlinks=False)
                    and e.name not in SKIP_DIRS and not e.name.startswith(".")
                    and not same_dir(e.path, RECEIVE_DIR)]
        except OSError:
            return
        for s in subs:
            walk(s, depth - 1)
    for root, depth in roots:
        if os.path.isdir(root):
            walk(root, depth)
    return found


REPO_DIRS = {"data", "index", "keys", "snapshots", "locks"}
HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def check_seed_layout(path):
    """A seed must be a plain restic repository: regular files with restic's names, nothing else.
    A link would make the import copy whatever it points to (state.json, your own files) into a
    folder the other bro can download, so links and unknown files refuse the whole import."""
    for root, dirs, files in os.walk(path):  # os.walk does not descend into linked folders
        rel = os.path.relpath(root, path)
        parts = [] if rel == "." else rel.split(os.sep)
        for name in dirs + files:
            st = os.lstat(os.path.join(root, name))
            if stat.S_ISLNK(st.st_mode):
                raise RuntimeError(f"The seed contains a link ({os.path.join(rel, name)}). Import refused.")
        for name in dirs:
            ok = (not parts and name in REPO_DIRS) or \
                (parts == ["data"] and len(name) == 2 and all(c in "0123456789abcdef" for c in name))
            if not ok:
                raise RuntimeError(f"Unexpected folder in the seed: {os.path.join(rel, name)}. Import refused.")
        for name in files:
            if not stat.S_ISREG(os.lstat(os.path.join(root, name)).st_mode):
                raise RuntimeError(f"Not a regular file in the seed: {os.path.join(rel, name)}. Import refused.")
            ok = (not parts and name in ("config", SEED_MARKER)) or (parts and HEX_RE.match(name))
            if not ok:
                raise RuntimeError(f"Unexpected file in the seed: {os.path.join(rel, name)}. Import refused.")


def run_import(path, user, replace):
    """Move a bro's seed into his receive folder. The data stays encrypted."""
    target = os.path.join(RECEIVE_DIR, user)
    tmp = os.path.join(RECEIVE_DIR, f".import-{user}")
    try:
        if os.path.isdir(os.path.join(target, "snapshots")) and os.listdir(os.path.join(target, "snapshots")) \
                and not replace:
            raise RuntimeError("This bro already has backups here. Tick 'replace existing' to overwrite them.")
        check_seed_layout(path)
        total = dir_size(path)
        done = 0
        shutil.rmtree(tmp, ignore_errors=True)
        for root, _dirs, files in os.walk(path):
            rel = os.path.relpath(root, path)
            os.makedirs(os.path.join(tmp, rel), exist_ok=True)
            for fn in files:
                if rel == "." and fn == SEED_MARKER:
                    continue
                src, dst = os.path.join(root, fn), os.path.join(tmp, rel, fn)
                if not stat.S_ISREG(os.lstat(src).st_mode):  # changed since the check: refuse
                    raise RuntimeError(f"Not a regular file in the seed: {os.path.join(rel, fn)}. Import refused.")
                shutil.copyfile(src, dst, follow_symlinks=False)  # checked above: regular files only
                done += os.path.getsize(dst)
                recv_activity[user] = f"Importing: {done * 100 // max(total, 1)}% ({human_bytes(done)} of {human_bytes(total)})"
        if not is_restic_repo(tmp):
            raise RuntimeError("The copied folder is not a complete backup. Was the seed finished?")
        if os.path.exists(target):
            shutil.rmtree(target)
        os.replace(tmp, target)
        scheduler.refresh_receive_stats(only=user)
        notify("Seed imported", f"{human_bytes(total)} for {user}. Their backups now continue over the internet.",
               priority="default")
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        with mutate() as st:
            if user in st["receivers"]:
                st["receivers"][user]["import_error"] = str(e)
        notify(f"Import for {user} failed", str(e))
    else:
        with mutate() as st:
            if user in st["receivers"]:
                st["receivers"][user].pop("import_error", None)
                st["receivers"][user]["imported"] = iso(now())
    finally:
        recv_activity.pop(user, None)


