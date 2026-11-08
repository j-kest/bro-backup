# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/checks.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Restore test, full integrity check and repair."""

import datetime
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import threading

from . import backup
from .core import (
    tag_dec,
    ANSI_RE,
    CONFIG_DIR,
    NAS_DIR,
    PACK_REPAIR_RE,
    RESTIC,
    RESTORE_TEST_FILES,
    RESTORE_TEST_MAX_BYTES,
    activity,
    get_dest,
    iso,
    job_locks,
    last_lines,
    log,
    notify,
    now,
    settings,
    slug,
    update_dest,
)


# ---------------------------------------------------------------- restore test
def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def pick_files(d, snap_id, k, max_bytes):
    """Pick k random files from a snapshot (reservoir sampling over restic ls), within a size budget."""
    p = subprocess.Popen([RESTIC, "ls", "--json", snap_id], env=backup.restic_env(d), stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
    picked, seen = [], 0
    for line in p.stdout:
        try:
            n = json.loads(line)
        except ValueError:
            continue
        if n.get("type") != "file" or not n.get("size") or n["size"] > max_bytes:
            continue
        seen += 1
        if len(picked) < k:
            picked.append(n)
        else:
            j = random.randrange(seen)
            if j < k:
                picked[j] = n
    p.wait()
    total, out = 0, []
    for n in sorted(picked, key=lambda x: x["size"]):
        if total + n["size"] <= max_bytes:
            out.append(n)
            total += n["size"]
    return out


def restore_test(d):
    """Run a restore test. Never raises: a failing test is reported, it never marks a backup as failed."""
    try:
        return _restore_test(d)
    except Exception as e:
        return {"at": iso(now()), "files": 0, "bytes": 0, "compared": 0, "identical": 0, "changed": 0,
                "ok": False, "error": str(e)}


def _restore_test(d):
    """Restore a few random files from the newest version of each folder, let restic verify them,
    and compare them with the originals where those did not change since. Returns the result."""
    host = slug(settings()["name"])
    p = backup.restic(d, "snapshots", "--json", "--host", host, "--tag", "bro", "--group-by", "host,tags", "--latest", "1",
               timeout=300)
    if p.returncode != 0:
        raise backup.JobError("Could not list versions:\n" + last_lines(p.stderr))
    groups = json.loads(p.stdout or "[]")
    snaps = [s for g in groups for s in (g.get("snapshots") or [])] if groups and "snapshots" in groups[0] else groups
    snaps = [x for x in snaps if any(t.startswith("src:") for t in x.get("tags") or [])]
    if not snaps:
        raise backup.JobError("No versions to test yet")
    per = max(1, RESTORE_TEST_FILES // len(snaps))
    budget = RESTORE_TEST_MAX_BYTES // len(snaps)
    tmp = os.path.join(CONFIG_DIR, "restore-test")
    shutil.rmtree(tmp, ignore_errors=True)
    res = {"at": iso(now()), "files": 0, "bytes": 0, "compared": 0, "identical": 0, "changed": 0, "ok": True}
    try:
        for n, snap in enumerate(snaps, 1):
            tags = snap.get("tags") or []
            root = tag_dec(next((t[5:] for t in tags if t.startswith("root:")), None))
            activity[d["id"]] = f"Restore test {n}/{len(snaps)}: choosing files"
            files = pick_files(d, snap["id"], per, budget)
            if not files:
                continue
            target = os.path.join(tmp, str(n))
            includes = []
            for f in files:
                includes += ["--include", f["path"]]
            activity[d["id"]] = f"Restore test {n}/{len(snaps)}: restoring and verifying {len(files)} file(s)"
            r = backup.restic(d, "restore", snap["id"], "--target", target, "--verify", *includes, timeout=3600)
            if r.returncode != 0:
                raise backup.JobError("restic could not restore or verify the files:\n" + last_lines(r.stderr))
            for f in files:
                restored = os.path.join(target, f["path"].lstrip("/"))
                if not os.path.isfile(restored) or os.path.getsize(restored) != f["size"]:
                    raise backup.JobError(f"Restored file is missing or has the wrong size: {f['path']}")
                res["files"] += 1
                res["bytes"] += f["size"]
                live = os.path.join(NAS_DIR, root, f["path"].lstrip("/")) if root else None
                if not live or not os.path.isfile(live):
                    continue
                st = os.stat(live)
                same_meta = st.st_size == f["size"] and abs(st.st_mtime - parse_restic_time(f.get("mtime"))) < 2
                if not same_meta:
                    res["changed"] += 1
                    continue
                res["compared"] += 1
                if file_sha256(live) == file_sha256(restored):
                    res["identical"] += 1
                else:
                    raise backup.JobError(f"Restored file differs from the original: {f['path']}")
    except Exception as e:
        res.update(ok=False, error=str(e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return res


def parse_restic_time(s):
    if not s:
        return 0
    s = re.sub(r"(\.\d{6})\d+", r"\1", s).replace("Z", "+00:00")
    try:
        return datetime.datetime.fromisoformat(s).timestamp()
    except ValueError:
        return 0


def record_restore_test(d, res):
    update_dest(d["id"], restore_test=res)
    if res["ok"]:
        log.info("Restore test from %s: %s file(s) restored and verified, %s identical to the original",
                 d["name"], res["files"], res["identical"])
    else:
        notify(f"Restore test from {d['name']} failed", res.get("error", "unknown error"))


def run_restore_test(dest_id):
    lock = job_locks.setdefault(dest_id, threading.Lock())
    if not lock.acquire(blocking=False):
        return
    d = get_dest(dest_id)
    try:
        record_restore_test(d, restore_test(d))
    finally:
        activity.pop(dest_id, None)
        lock.release()


# ---------------------------------------------------------------- full integrity check and repair
def record_check(dest_id, p, full=True):
    """Store the outcome of restic check. Damaged packs are remembered so Repair knows what to remove."""
    out = backup.scrub(get_dest(dest_id), (p.stdout or "") + "\n" + (p.stderr or ""))
    packs = sorted({x for m in PACK_REPAIR_RE.finditer(out) for x in m.group(1).split()})
    res = {"at": iso(now()), "full": full, "ok": p.returncode == 0, "packs": packs,
           "hardware": "ciphertext verification failed" in out,
           "error": None if p.returncode == 0 else last_lines(ANSI_RE.sub("", out), 8)}
    update_dest(dest_id, full_check=res)
    return res


def run_full_check(dest_id):
    lock = job_locks.setdefault(dest_id, threading.Lock())
    if not lock.acquire(blocking=False):
        return
    d = get_dest(dest_id)
    try:
        activity[dest_id] = "Full integrity check: reading all your data at your bro"
        backup.clear_stale_locks(d)
        p = backup.restic(d, "--retry-lock", "2m", "check", "--read-data")
        if p.returncode != 0 and "already locked" in (p.stderr or ""):
            raise backup.JobError("The check could not start: the repository was busy for more than 2 minutes. Try again later.")
        res = record_check(dest_id, p)
        if res["ok"]:
            update_dest(dest_id, last_check=iso(now()))
            log.info("Full integrity check at %s: no errors", d["name"])
            notify(f"Full check at {d['name']}: all good", "Every byte of your backup at your bro was read and verified.",
                   priority="default")
        else:
            notify(f"Full check at {d['name']} found damage",
                   f"{len(res['packs'])} damaged data file(s). Open Restore in BRO Backup for what to do.")
    except Exception as e:  # the check did not run: keep the last real result
        log.error("Full check at %s did not run: %s", d["name"], e)
        notify(f"Full check at {d['name']} did not run", str(e), priority="default")
    finally:
        activity.pop(dest_id, None)
        lock.release()


def run_repair(dest_id):
    """restic's own repair procedure (troubleshooting guide): remove the damaged packs, send the
    missing data again from your NAS, drop what cannot be recovered, then verify everything."""
    lock = job_locks.setdefault(dest_id, threading.Lock())
    if not lock.acquire(blocking=False):
        return
    d = get_dest(dest_id)
    log_lines = []
    try:
        packs = (d.get("full_check") or {}).get("packs") or []
        if not packs:
            raise backup.JobError("Nothing to repair: run a full check first")

        # "repair packs" saves a copy of every damaged file in the current folder: keep those out of the app
        work = os.path.join(CONFIG_DIR, "repair-work")
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work)

        def step(n, text, *args, ok_codes=(0,)):
            activity[dest_id] = f"Repair {n}/4: {text}"
            p = backup.restic(d, *args, cwd=work)
            log_lines.append(f"{n}. {text}: exit {p.returncode}")
            if p.returncode not in ok_codes:
                err = p.stderr or ""
                if "append-only" in err.lower() or "403" in err:
                    raise backup.JobError("Your bro has append-only switched on, so nothing can be removed there. "
                                   "Ask him to switch it off for the repair.")
                raise backup.JobError(f"Repair step {n} ({text}) failed:\n" + last_lines(err))
            return p
        backup.clear_stale_locks(d)
        step(1, "removing the damaged data files", "--retry-lock", "2m", "repair", "packs", *packs)
        activity[dest_id] = "Repair 2/4: sending the missing data again"
        backup.restic_backup(get_dest(dest_id), "Repair 2/4: sending the missing data again", force=True)
        log_lines.append("2. backup with --force: done")
        step(3, "removing what could not be recovered from old versions", "--retry-lock", "2m", "repair", "snapshots", "--forget")
        activity[dest_id] = "Repair 4/4: checking everything"
        p = backup.restic(d, "--retry-lock", "2m", "check", "--read-data")
        res = record_check(dest_id, p)
        res["repaired"] = iso(now())
        update_dest(dest_id, full_check=res, repair_log=log_lines)
        if res["ok"]:
            update_dest(dest_id, last_check=iso(now()), restore_test=None, last_error=None)
            notify(f"Backup at {d['name']} repaired", "The full check after the repair found no errors.",
                   priority="default")
        else:
            notify(f"Repair at {d['name']} did not fix everything", res["error"] or "")
        shutil.rmtree(work, ignore_errors=True)
    except Exception as e:
        update_dest(dest_id, repair_log=log_lines + [f"stopped: {e}"],
                    full_check={**(get_dest(dest_id).get("full_check") or {}), "repair_error": str(e)})
        notify(f"Repair at {d['name']} failed", str(e))
    finally:
        activity.pop(dest_id, None)
        lock.release()


