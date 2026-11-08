# version : 0.1
# created by : JK and CF
# last edited : 03/11/2026
# Name : bro-backup (bro/pickup.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Picking up your backup at your bro's, on a disk: the reverse of a seed.

After a fire or a theft, getting terabytes back over the internet takes days. Your bro lives
nearby: he copies your backup to a disk, you take it home. His side (make_pickup): your restic
repository and your key copy, both encrypted, go to the disk as they are. He never needs or sees
a key. Your side: with only your recovery code and that disk you get everything back, without
network:
- on a (new) NAS, through Setup ("From a disk your bro made") or, on a NAS that already runs,
  under Restore ("Restore from the disk");
- on any PC with Docker, with `python main.py restore-from-disk` (see install/restore-from-disk.ps1).

The pickup folder holds the repository (config, keys, snapshots, index, data), `escrow.json` (the
key copy, sealed with your recovery code) and the marker PICKUP_MARKER. The repository is copied
in this order: config, keys, snapshots, index, data. A snapshot is written after its data, so every
snapshot on the disk finds its data there, even if your NAS was still backing up during the copy.
"""

import getpass
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading

from . import recovery
from .core import (
    tag_dec,
    ESCROW_DIR,
    IMPORT_DIR,
    NAS_DIR,
    RECEIVE_DIR,
    RESTIC,
    SEED_MOUNT,
    SKIP_DIRS,
    clean_name,
    dir_size,
    human_bytes,
    iso,
    load_state,
    log,
    mutate,
    notify,
    now,
    recv_activity,
    settings,
    slug,
    update_dest,
)

PICKUP_MARKER = "bro-pickup.json"
ESCROW_FILE = "escrow.json"
ORDER = ("config", "keys", "snapshots", "index", "data")
USER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
GREEN, RED, END = "\033[32m", "\033[31m", "\033[0m"


# ---------------------------------------------------------------- the bro's side: copy to a disk
def pickup_target(user):
    from . import nas  # late: nas imports the scheduler, which imports a lot
    root, external = nas.seed_root()
    r = load_state()["receivers"].get(user) or {}
    who = slug(r.get("bro_name") or r.get("name") or user)
    return os.path.join(root, f"backup-of-{who}-{now().strftime('%Y%m%d')}"), external


def _copy_tree(src, dst, user, done, total):
    for root, dirs, files in os.walk(src):  # os.walk does not follow linked folders
        dirs[:] = [x for x in dirs if not os.path.islink(os.path.join(root, x))]
        rel = os.path.relpath(root, src)
        os.makedirs(os.path.join(dst, rel), exist_ok=True)
        for fn in sorted(files):
            s = os.path.join(root, fn)
            if not stat.S_ISREG(os.lstat(s).st_mode):
                continue  # rest-server only writes regular files: skip anything else
            shutil.copyfile(s, os.path.join(dst, rel, fn), follow_symlinks=False)
            done[0] += os.path.getsize(s)
            recv_activity[user] = f"Copying to disk: {done[0] * 100 // max(total, 1)}% " \
                                  f"({human_bytes(done[0])} of {human_bytes(total)})"


def make_pickup(user):
    """Copy the backup of the bro `user` (and his key copy) to the disk. Runs in the background."""
    if not USER_RE.match(user or "") or user not in load_state()["receivers"]:
        raise ValueError("Unknown bro.")
    repo = os.path.join(RECEIVE_DIR, user)
    if not os.path.isfile(os.path.join(repo, "config")):
        raise ValueError("This bro has no backup here yet.")
    target, external = pickup_target(user)
    total = dir_size(repo)
    from . import nas
    free = nas.free_space(os.path.dirname(target))
    if free is not None and free < total * 1.02 + 64 * 1024 ** 2:
        raise ValueError(f"Not enough space on the disk: {human_bytes(total)} needed, {human_bytes(free)} free.")

    def work():
        part = target + ".part"
        r = load_state()["receivers"].get(user) or {}
        name = r.get("bro_name") or r.get("name") or user
        try:
            shutil.rmtree(part, ignore_errors=True)
            os.makedirs(part)
            done = [0]
            for x in ORDER:
                src = os.path.join(repo, x)
                if os.path.isfile(src):
                    shutil.copyfile(src, os.path.join(part, x), follow_symlinks=False)
                elif os.path.isdir(src):
                    _copy_tree(src, os.path.join(part, x), user, done, total)
            esc = os.path.join(ESCROW_DIR, f"{user}.json")
            if os.path.isfile(esc):
                shutil.copyfile(esc, os.path.join(part, ESCROW_FILE))
            with open(os.path.join(part, PICKUP_MARKER), "w") as f:
                json.dump({"v": 1, "from": settings().get("name"), "for": name, "user": user,
                           "created": iso(now()), "size": done[0], "escrow": os.path.isfile(esc),
                           "complete": True}, f, indent=2)
            if os.path.exists(target):
                shutil.rmtree(target)
            os.replace(part, target)
            with mutate() as st:
                if user in st["receivers"]:
                    st["receivers"][user]["pickup"] = {"at": iso(now()), "path": target, "size": done[0], "ok": True}
            log.info("Backup of %s copied to %s (%s)", name, target, human_bytes(done[0]))
            notify(f"Backup of {name} is on the disk",
                   f"{human_bytes(done[0])} in {target}. Give the disk to {name}: with his recovery code he gets "
                   "everything back. The data stays encrypted, nobody else can read it.", priority="default")
        except Exception as e:
            shutil.rmtree(part, ignore_errors=True)
            with mutate() as st:
                if user in st["receivers"]:
                    st["receivers"][user]["pickup"] = {"at": iso(now()), "ok": False, "error": str(e)[:300]}
            notify(f"Copying the backup of {name} to the disk failed", str(e))
        finally:
            recv_activity.pop(user, None)
    threading.Thread(target=work, daemon=True).start()
    return target, external, total


# ---------------------------------------------------------------- your side: find a disk, use it
def is_pickup(path):
    return os.path.isfile(os.path.join(path, PICKUP_MARKER)) and os.path.isfile(os.path.join(path, "config")) \
        and os.path.isdir(os.path.join(path, "snapshots"))


def read_marker(path):
    p = os.path.join(path, PICKUP_MARKER)
    if os.path.islink(p):
        return None
    try:
        with open(p) as f:
            m = json.load(f)
    except Exception:
        return None
    if not isinstance(m, dict) or not USER_RE.match(str(m.get("user") or "")):
        return None
    return {"path": os.path.realpath(path), "from": clean_name(m.get("from")) or "?", "for": clean_name(m.get("for")),
            "user": m["user"], "created": str(m.get("created") or "")[:25], "size": m.get("size") or 0,
            "escrow": os.path.isfile(os.path.join(path, ESCROW_FILE))}


def scan(roots=None):
    """Pickup folders on the disk, in the import folder and under /nas."""
    found, seen = [], set()

    def walk(path, depth):
        if depth < 0 or path in seen:
            return
        seen.add(path)
        if is_pickup(path):
            m = read_marker(path)
            if m:
                found.append(m)
            return
        try:
            subs = [e.path for e in os.scandir(path) if e.is_dir(follow_symlinks=False)
                    and e.name not in SKIP_DIRS and not e.name.startswith(".") and not e.name.endswith(".part")]
        except OSError:
            return
        for s in sorted(subs):
            walk(s, depth - 1)
    for root, depth in roots or [(SEED_MOUNT, 2), (IMPORT_DIR, 2), (NAS_DIR, 3)]:
        if os.path.isdir(root):
            walk(root, depth)
    return found


def open_escrow(path, code):
    """Decrypt the key copy on the disk. Returns (bundle, key, salt). The seal is authenticated:
    a changed file or a wrong code fails here."""
    p = os.path.join(path, ESCROW_FILE)
    if os.path.islink(p) or not os.path.isfile(p):
        raise ValueError("There is no key copy on this disk. Recover with a help code from your bro instead, "
                         "then restore from the disk.")
    with open(p) as f:
        blob = json.load(f)
    if isinstance(blob, dict) and isinstance(blob.get("blob"), dict):
        blob = blob["blob"]  # the bro stores {"blob": ..., "stored": ...}, as received from /bro/escrow
    try:
        bundle, key = recovery.unseal(blob, code)
    except Exception:
        raise ValueError("The recovery code is not correct. Check that you typed it correctly.")
    return bundle, key, blob["salt"]


def recover_from_disk(path, code):
    """Setup on a new NAS: everything back from the disk and the recovery code, without network."""
    m = read_marker(path) if is_pickup(path) else None
    if not m:
        raise ValueError("That folder is not a backup your bro copied to a disk.")
    bundle, key, salt = open_escrow(path, code)
    recovery.apply_bundle(bundle, key.hex(), salt)
    d = next((x for x in load_state()["destinations"] if x.get("user") == m["user"]), None)
    if d:
        update_dest(d["id"], restore_from=m["path"])
    return bundle, m, d


def use_for_restore(dest_id, path):
    """On a NAS that already runs: restore from this disk from now on (until switched back)."""
    m = read_marker(path) if is_pickup(path) else None
    d = next((x for x in load_state()["destinations"] if x["id"] == dest_id), None)
    if m and m["path"] not in {x["path"] for x in scan()}:
        m = None  # only disks where BRO Backup looks for them, never an arbitrary folder from the form
    if not m or not d or m["user"] != d.get("user"):
        raise ValueError("This disk does not hold your backup at this bro.")
    update_dest(dest_id, restore_from=m["path"])
    return m


def for_dest(d):
    """Pickups on the disk that belong to this destination."""
    return [m for m in scan() if m["user"] == d.get("user")]


# ---------------------------------------------------------------- restore on any PC, no NAS needed
def _say(ok, msg):
    print(f"{GREEN if ok else RED}{msg}{END}", flush=True)


def restore_from_disk_cli(args):
    """python main.py restore-from-disk [--path DIR] [--to DIR] [--code -]

    Restores the newest version of every folder from a pickup disk to --to (default /out),
    with only the recovery code. Changes nothing else: no state, no network, no keys left behind."""
    opts = {"--path": None, "--to": "/out", "--code": None}
    it = iter(args)
    for a in it:
        if a in opts:
            opts[a] = next(it, None)
        else:
            _say(False, f"Unknown option {a}")
            return 2
    if opts["--path"]:
        picks = [read_marker(opts["--path"])] if is_pickup(opts["--path"]) else []
    else:
        picks = scan([(SEED_MOUNT, 3), ("/mnt", 3)])
    picks = [p for p in picks if p]
    if not picks:
        _say(False, f"No backup from a bro found under {opts['--path'] or SEED_MOUNT}. "
                    "Mount the disk there, or give the folder with --path.")
        return 1
    if len(picks) > 1:
        print("Several backups found:")
        for n, p in enumerate(picks, 1):
            print(f"  {n}. {p['path']}: copied by {p['from']} on {p['created'][:10]}")
        choice = input("Which one (number)? ").strip()
        if not choice.isdigit() or not 1 <= int(choice) <= len(picks):
            _say(False, "No valid choice.")
            return 1
        pick = picks[int(choice) - 1]
    else:
        pick = picks[0]
    print(f"Backup copied by {pick['from']} on {pick['created'][:10]} ({human_bytes(pick['size'])})")
    code = sys.stdin.readline().strip() if opts["--code"] == "-" else getpass.getpass("Your recovery code: ")
    try:
        bundle, _key, _salt = open_escrow(pick["path"], code)
    except ValueError as e:
        _say(False, str(e))
        return 1
    d = next((x for x in bundle.get("destinations") or [] if x.get("user") == pick["user"]), None)
    if not d or not d.get("repo_password"):
        _say(False, "The key copy does not contain the key for this backup.")
        return 1
    env = dict(os.environ, RESTIC_REPOSITORY=pick["path"], RESTIC_PASSWORD=d["repo_password"],
               RESTIC_CACHE_DIR=os.path.join(opts["--to"], ".restic-cache"))
    p = subprocess.run([RESTIC, "--no-lock", "snapshots", "--json"], env=env, capture_output=True, text=True)
    if p.returncode != 0:
        _say(False, "Could not read the backup on the disk:\n" + p.stderr[-800:])
        return 1
    newest = {}
    for s in json.loads(p.stdout or "[]"):
        src = tag_dec(next((t[4:] for t in s.get("tags") or [] if t.startswith("src:")), None)) or "all"
        if src not in newest or s["time"] > newest[src]["time"]:
            newest[src] = s
    ok_all = True
    for src, s in sorted(newest.items()):
        target = os.path.join(opts["--to"], slug(src.replace("/", "-"), 64))
        os.makedirs(target, exist_ok=True)
        print(f"Restoring {src} (version {s['short_id']} of {s['time'][:16].replace('T', ' ')}) to {target} ...",
              flush=True)
        r = subprocess.run([RESTIC, "--no-lock", "restore", s["id"], "--target", target], env=env,
                           capture_output=True, text=True)
        if r.returncode == 0:
            _say(True, f"  {src}: done")
        else:
            ok_all = False
            _say(False, f"  {src}: failed\n{r.stderr[-800:]}")
    shutil.rmtree(env["RESTIC_CACHE_DIR"], ignore_errors=True)
    if ok_all:
        _say(True, f"All {len(newest)} folder(s) restored to {opts['--to']}.")
        return 0
    _say(False, "Some folders could not be restored, see above.")
    return 1
