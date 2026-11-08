# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/backup.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""restic: backing up, seeding and restoring."""

import datetime
import json
import os
import re
import signal
import subprocess
import threading
import time

from . import alarm, checks, dumps, nas, procs
from .core import (
    version_or_none,
    int_or_none,
    clean_name,
    tag_enc,
    tag_dec,
    CONFIG_DIR,
    DATA_MARKER,
    DEFAULT_EXCLUDES,
    GIB,
    NAS_DIR,
    PAUSED_MODES,
    backups_paused,
    RESTIC,
    RESTORE_DIR,
    RESTORE_TEST_DAYS,
    RETENTION_PRESETS,
    SEED_MARKER,
    SNAP_TIME_RE,
    activity,
    dest_ports,
    dir_size,
    get_dest,
    human_bytes,
    human_secs,
    iso,
    job_locks,
    last_lines,
    load_state,
    local_time,
    log,
    mutate,
    notify,
    now,
    parse,
    settings,
    slug,
    update_dest,
)


# ---------------------------------------------------------------- restic (sending)
class JobError(Exception):
    pass


class Paused(Exception):
    """The user paused backups while one was running."""


class WindowClosed(Exception):
    """The backup window closed during a backup. Not an error: the next run continues."""


def restic_env(d, repo_path=None):
    env = os.environ.copy()
    if repo_path:
        env["RESTIC_REPOSITORY"] = repo_path
    else:
        port = dest_ports.get(d["id"])
        if not port:
            raise JobError("The tunnel to your bro has not started yet")
        env["RESTIC_REPOSITORY"] = f"rest:http://{d['user']}:{d['password']}@127.0.0.1:{port}/{d['user']}/"
    env["RESTIC_PASSWORD"] = d["repo_password"]
    env["RESTIC_CACHE_DIR"] = os.path.join(CONFIG_DIR, "cache")
    return env


def scrub(d, text):
    for s in (d["password"], d["repo_password"]):
        text = (text or "").replace(s, "***")
    return text


def exclude_args(s=None):
    s = s or settings()
    pats = (DEFAULT_EXCLUDES if s.get("exclude_defaults", True) else []) + list(s.get("excludes") or [])
    out = []
    for pat in pats:
        out += ["--exclude", pat]
    gb = float(s.get("exclude_larger_gb") or 0)
    if gb > 0:
        out += ["--exclude-larger-than", f"{int(gb * 1024)}M"]
    return out


def is_night(s, t=None):
    a, b = int(s.get("night_start", 22)), int(s.get("night_end", 7))
    h = (t or datetime.datetime.now()).hour
    return a <= h < b if a < b else (h >= a or h < b)


def limit_kib(s=None, t=None):
    """Upload limit in KiB/s right now (or at time t): the night limit at night, if one is set."""
    s = s or settings()
    night = int(s.get("limit_night_kib", -1))
    if night >= 0 and is_night(s, t):
        return night
    return int(s.get("limit_upload_kib") or 0)


def next_limit_change(s, t=None):
    """When the upload limit changes next (start or end of the night), or None if day and night are equal."""
    night = int(s.get("limit_night_kib", -1))
    if night < 0 or night == int(s.get("limit_upload_kib") or 0):
        return None
    t = (t or datetime.datetime.now()).astimezone()
    out = []
    for h in (int(s.get("night_start", 22)), int(s.get("night_end", 7))):
        c = t.replace(hour=h, minute=0, second=0, microsecond=0)
        out.append(c if c > t else c + datetime.timedelta(days=1))
    return min(out)


def limit_args(local):
    lim = limit_kib()
    return ["--limit-upload", str(lim)] if lim > 0 and not local else []


def restore_source(d):
    """The disk to restore from, when the user chose one (see pickup.py) and it is still there."""
    p = (d or {}).get("restore_from")
    return p if p and os.path.isfile(os.path.join(p, "config")) and os.path.isdir(os.path.join(p, "snapshots")) else None


def restic(d, *args, timeout=None, repo_path=None, cwd=None, read=False):
    """read=True: a read-only call for restoring. It goes to the disk from the bro when one is chosen,
    without a lock (the disk may be read-only)."""
    if read and not repo_path and restore_source(d):
        repo_path = restore_source(d)
        args = ("--no-lock",) + tuple(a for a in args if a != "--no-lock")
    p = subprocess.run([RESTIC, *limit_args(repo_path), *args], env=restic_env(d, repo_path),
                       capture_output=True, text=True, timeout=timeout, cwd=cwd)
    p.stderr = scrub(d, p.stderr)
    return p


def locked(p):
    """restic stopped because another restic holds a lock on the repository at the bro."""
    return p is not None and p.returncode != 0 and "already locked" in (p.stderr or "")


def clear_stale_locks(d):
    """Remove locks that a restic which is gone left behind at the bro, before anything that needs the repository
    to itself (cleanup, check, repair). restic leaves its lock when it is stopped hard: the app restarted during a
    backup, or the bro could not be reached when it wanted to remove it. restic never skips such a lock by itself,
    not even after hours. `restic unlock` removes only stale locks: not refreshed for 30 minutes (a running restic
    refreshes every 5), or made in this container by a process that no longer runs. A restic that still runs,
    here or anywhere else, keeps its lock."""
    try:
        p = restic(d, "unlock", timeout=300)
    except subprocess.TimeoutExpired:
        return False
    if p.returncode == 0 and "removed" in (p.stdout or "") + (p.stderr or ""):
        log.warning("Removed a lock at %s that a stopped restic had left behind", d["name"])
        return True
    return False


def lock_note(p):
    """The line of restic's lock message that says who holds it, for the overview."""
    line = next((x.strip() for x in (p.stderr or "").splitlines() if "locked by" in x), "")
    return line[line.find("locked by"):] if line else "another restic is using it"


# ---------------------------------------------------------------- what to back up, and from where
def zfs_root(path):
    """The root of the ZFS dataset that holds this path (it has a .zfs folder), or None."""
    p, nas = os.path.realpath(path), os.path.realpath(NAS_DIR)
    while True:
        if os.path.isdir(os.path.join(p, ".zfs", "snapshot")):
            return p
        if p in (nas, "/") or not p.startswith(nas):
            return None
        p = os.path.dirname(p)


sub_datasets = nas.sub_datasets


def _looks_empty(snap_path, live_path, tries=3):
    """True when the snapshot folder stays empty while the live folder has something in it.
    A snapshot is mounted on first access, which can take a moment: look again before deciding."""
    for i in range(tries):
        if os.listdir(snap_path):
            return False
        try:
            if not [n for n in os.listdir(live_path) if n != ".zfs"]:  # .zfs shows up with snapdir=visible
                return False  # empty both ways: nothing wrong
        except OSError:
            return False
        if i < tries - 1:
            time.sleep(1)
    return True


def snapshot_time(base, name):
    m = SNAP_TIME_RE.search(name)
    if m:
        try:
            y, mo, dd, hh, mi = (int(x) for x in m.groups())
            return datetime.datetime(y, mo, dd, hh, mi).astimezone()
        except ValueError:
            pass
    try:
        return datetime.datetime.fromtimestamp(os.stat(os.path.join(base, name)).st_mtime).astimezone()
    except OSError:
        return None


def newest_snapshot(root):
    """Newest readable snapshot of a dataset: (name, time) or (None, reason)."""
    base = os.path.join(root, ".zfs", "snapshot")
    try:
        names = os.listdir(base)
    except OSError as e:
        return None, f"snapshots not readable from the app ({e.strerror})"
    dated = sorted(((snapshot_time(base, n), n) for n in names), key=lambda x: x[0] or datetime.datetime.min.astimezone())
    if not dated:
        return None, "no ZFS snapshots of this dataset (add a periodic snapshot task in TrueNAS)"
    when, name = dated[-1]
    return (name, when), None


def backup_plan():
    """One item per selected folder: where restic reads it (live folder or ZFS snapshot) and how it is named."""
    s = settings()
    nas = os.path.realpath(NAS_DIR)
    sources = sorted({os.path.realpath(p) for p in s["sources"] if os.path.isdir(p)})
    # a folder inside another selected folder is already covered
    sources = [p for p in sources if not any(p != q and p.startswith(q + os.sep) for q in sources)]
    plan = []
    for src in sources:
        key = os.path.relpath(src, nas)
        root = zfs_root(src) if s["use_zfs_snapshots"] else None
        item = {"key": key, "cwd": src, "target": ".", "root": key, "origin": "live", "note": None}
        subs = sub_datasets(src) if root else []
        if subs:  # a snapshot of this dataset would leave the child datasets out: read the whole folder live
            first = os.path.relpath(subs[0], src)
            item["note"] = (f"holds {len(subs)} child dataset(s), such as {first}, that a ZFS snapshot of this "
                            "dataset leaves out, so read live. Tick the child datasets one by one to read each "
                            "from its own snapshot")
            root = None
        if root:
            rel = os.path.relpath(src, root)
            item.update(root=os.path.relpath(root, nas), cwd=root, target=rel)
            snap, why = newest_snapshot(root)
            if snap:
                name, when = snap
                age_h = (now() - when).total_seconds() / 3600 if when else None
                snap_dir = os.path.join(root, ".zfs", "snapshot", name)
                if age_h is not None and age_h > s["snapshot_max_age_h"]:
                    item["note"] = f"newest snapshot {name} is {age_h:.0f} h old, read live instead"
                elif not os.path.isdir(os.path.join(snap_dir, rel)):
                    item["note"] = f"folder is newer than snapshot {name}, read live instead"
                else:
                    try:
                        if _looks_empty(os.path.join(snap_dir, rel), src):
                            # ZFS mounts a snapshot when it is first opened, and that mount does not always
                            # reach a container: then the snapshot looks empty while the folder is not
                            item["note"] = (f"snapshot {name} looks empty in the app while the folder is not, "
                                            "read live instead")
                        else:
                            item.update(cwd=snap_dir, origin=f"zfs:{name}")
                    except OSError as e:
                        item["note"] = f"snapshot {name} not readable ({e.strerror}), read live instead"
            else:
                item["note"] = why + ", read live instead"
        plan.append(item)
    if s.get("sqlite_dbs") or dumps.dumps_present():  # database dumps travel as their own "folder"
        plan.append({"key": "@databases", "cwd": dumps.DUMP_DIR, "target": ".", "root": "@databases",
                     "origin": "dump", "note": None})
    return plan


def restic_backup(d, label, repo_path=None, deadline=None, force=False):
    """Back up every selected folder with live progress in the UI. Returns (totals, warning, plan).

    restic runs once per folder, from a fixed base folder with a relative path. That keeps the
    paths inside the backup identical whether restic reads the live folder or a ZFS snapshot,
    so unchanged files are recognised and not read again.

    With a deadline (backup window), restic is stopped gracefully when the window closes. restic
    writes its index every few minutes, so the next run continues where this one stopped.
    """
    s = settings()
    plan = backup_plan()
    if not plan:
        raise JobError("No folders selected to back up (Settings)")
    host = slug(s["name"])
    totals = {"data_added": 0, "total_bytes_processed": 0, "files_new": 0, "files_changed": 0, "files_unmodified": 0}
    warnings = [f"{i['key']}: {i['note']}" for i in plan if i["note"]]
    for n, item in enumerate(plan, 1):
        step = f"{label} {n}/{len(plan)} ({item['key']})" if len(plan) > 1 else f"{label} ({item['key']})"
        while True:  # runs again when the upload limit changes halfway (day/night)
            rc, err, stop_reason, item_sum = _run_restic_item(d, item, step, totals, s, host, repo_path, deadline,
                                                              force)
            if stop_reason != "limit":
                break
            log.info("Upload limit changes now (%s), restic continues with it", f"{limit_kib()} KiB/s" if limit_kib() else "no limit")
        if stop_reason == "window":
            raise WindowClosed(f"{item['key']} ({n} of {len(plan)})")
        if stop_reason == "pause":
            raise Paused(f"{item['key']} ({n} of {len(plan)})")
        if rc not in (0, 3):  # 3 = snapshot created, some files unreadable
            raise JobError(f"{step} failed:\n" + last_lines(err))
        if rc == 3:
            warnings.append(f"{item['key']}: some files could not be read\n" + last_lines(err, 3))
        item["sum"] = item_sum
        log.info("%s read from %s", item["key"], item["origin"])
    sources_info = []
    for i in plan:  # per folder what was read from where, and the counts the ransomware check needs
        x = {"key": i["key"], "origin": i["origin"], "note": i["note"]}
        x.update({k: (i.get("sum") or {}).get(k) or 0 for k in ("files_new", "files_changed", "files_unmodified")})
        x["snapshot_id"] = (i.get("sum") or {}).get("snapshot_id")
        sources_info.append(x)
    return totals, ("\n".join(warnings) or None), sources_info


def _run_restic_item(d, item, step, totals, s, host, repo_path, deadline, force):
    """One restic run for one folder. Returns (exit code, stderr, why it was stopped: None|window|limit|pause, summary)."""
    switch_at = None if repo_path else next_limit_change(s)
    args = [RESTIC, *limit_args(repo_path), "backup", "--json", "--host", host,
            "--tag", "bro", "--tag", f"src:{tag_enc(item['key'])}", "--tag", f"root:{tag_enc(item['root'])}",
            "--group-by", "host,tags", "--ignore-inode", "--exclude-caches",
            "--exclude-if-present", DATA_MARKER, "--exclude-if-present", SEED_MARKER, *exclude_args(s),
            *(["--force"] if force else []), "--", item["target"]]  # "--": a folder named "--x" is a path, never an option
    p = subprocess.Popen(args, cwd=item["cwd"], env=restic_env(d, repo_path), stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, bufsize=1)
    errs = []
    reader = threading.Thread(target=lambda: errs.extend(p.stderr), daemon=True)
    reader.start()
    stopped, summary = [], None
    pausable = repo_path is None  # a seed to disk is not paused: it uses no internet

    def stopper():
        while p.poll() is None:
            t = now()
            why = "window" if deadline and t >= deadline else ("limit" if switch_at and t >= switch_at else None)
            if not why and pausable and backups_paused():
                why = "pause"
            if why:
                stopped.append(why)
                log.info("Stopping restic for %s (%s)", item["key"], {"window": "backup window closed",
                         "limit": "upload limit changes", "pause": "backups paused"}[why])
                p.send_signal(signal.SIGINT)
                try:
                    p.wait(120)
                except subprocess.TimeoutExpired:
                    p.kill()
                return
            time.sleep(2)
    threading.Thread(target=stopper, daemon=True).start()
    for line in p.stdout:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("message_type") == "status":
            pct = int((msg.get("percent_done") or 0) * 100)
            txt = f"{step}: {pct}%"
            if msg.get("total_bytes"):
                txt += f" ({human_bytes(msg.get('bytes_done'))} of {human_bytes(msg['total_bytes'])})"
            if msg.get("seconds_remaining"):
                txt += f", about {human_secs(msg['seconds_remaining'])} left"
            activity[d["id"]] = txt
        elif msg.get("message_type") == "summary":
            summary = msg
            for k in totals:
                totals[k] += msg.get(k) or 0
    rc = p.wait()
    reader.join(timeout=5)
    err = scrub(d, "".join(errs))
    return rc, err, (stopped[0] if stopped else None), summary


UNAUTHORIZED_RE = re.compile(r"\(401\)|\b401 Unauthorized")  # not a bare "401": the tunnel port can contain it


def ensure_repo(d, repo_path=None):
    for _ in range(1 if repo_path else 5):
        p = restic(d, "cat", "config", timeout=180, repo_path=repo_path)
        if not UNAUTHORIZED_RE.search(p.stderr):
            break
        activity[d["id"]] = "Waiting for your bro to activate your login"
        time.sleep(15)
        d = get_dest(d["id"])  # the password may have been rotated meanwhile
    if p.returncode == 0:
        return
    err = p.stderr.lower()
    if UNAUTHORIZED_RE.search(err):
        from . import peers  # late import: peers is not needed for anything else here
        peers.hello(d)
        if (get_dest(d["id"]) or {}).get("mode") == "revoked":
            raise JobError(get_dest(d["id"])["last_error"])
        raise JobError("Login refused by your bro. Was his NAS recovered, or your access revoked? "
                       "Then ask him for a new code.\n" + last_lines(p.stderr))
    if p.returncode == 10 or "does not exist" in err or "is there a repository" in err or "no such file" in err:
        activity[d["id"]] = "Creating the repository"
        p = restic(d, "init", timeout=300, repo_path=repo_path)
        if p.returncode != 0:
            raise JobError("restic init failed:\n" + last_lines(p.stderr))
        return
    raise JobError("Bro not reachable:\n" + last_lines(p.stderr))


def bro_status(d, timeout=60):
    """The bro's answer, kept to known fields of the right type: a bro is not trusted for types or sizes."""
    info = procs.pair_call(d["pair_ticket"], "GET", "/bro/status", auth=(d["user"], d["password"]), timeout=timeout)
    if not isinstance(info, dict):
        raise RuntimeError("Bro sent an answer that is not an object")
    return {"usage": int_or_none(info.get("usage")) or 0,
            "snapshots": int_or_none(info.get("snapshots"), 0, 10 ** 9) or 0,
            "quota_gib": int_or_none(info.get("quota_gib"), 0, 10 ** 9) or 0,
            "disk": info.get("disk") if info.get("disk") in ("ok", "warn", "err") else None,
            "name": clean_name(info.get("name")) if isinstance(info.get("name"), str) else None,
            "blocked": info.get("blocked") is True, "escrow": info.get("escrow") is True,
            "v": version_or_none(info.get("v"))}


def check_quota(d):
    try:
        info = bro_status(d)
    except Exception as e:
        log.info("Quota check at %s failed (%s), backing up anyway", d["name"], e)
        return None
    disk = info["disk"]
    update_dest(d["id"], remote_usage=info["usage"], remote_quota_gib=info["quota_gib"], remote_disk=disk)
    if disk == "err" and d.get("remote_disk") != "err":
        notify(f"The NAS of {d['name']} is almost full",
               f"Your backups to {d['name']} may start failing because his disk is almost full. Let him know.",
               priority="default")
    q = info["quota_gib"]
    if q and info["usage"] >= q * GIB:
        raise JobError(f"Quota at {d['name']} reached ({human_bytes(info['usage'])} of {q} GiB). "
                       "Ask your bro for more space or select fewer folders.")
    return info


def window_deadline(s, start=None):
    """When a scheduled backup that starts now must stop, or None without a backup window."""
    end = int(s.get("backup_end_hour", -1))
    if end < 0 or end == int(s["backup_hour"]):
        return None
    start = (start or datetime.datetime.now()).astimezone()
    dl = start.replace(hour=end, minute=0, second=0, microsecond=0)
    if dl <= start:
        dl += datetime.timedelta(days=1)
    return dl


def in_window(s, t=None):
    """Is t (local time) inside the backup window? Always True without a window."""
    end = int(s.get("backup_end_hour", -1))
    start = int(s["backup_hour"])
    if end < 0 or end == start:
        return True
    h = (t or datetime.datetime.now()).hour
    return start <= h < end if start < end else (h >= start or h < end)


HISTORY_MAX = 400  # about a year of nightly backups


def record_history(dest_id, entry):
    with mutate() as st:
        for x in st["destinations"]:
            if x["id"] == dest_id:
                x["history"] = (x.get("history") or [])[-(HISTORY_MAX - 1):] + [entry]


def run_backup(dest_id, scheduled=False):
    lock = job_locks.setdefault(dest_id, threading.Lock())
    if not lock.acquire(blocking=False):
        return
    d = get_dest(dest_id)
    try:
        if not d or d.get("mode") in PAUSED_MODES or d.get("accepting") or backups_paused():
            return
        update_dest(dest_id, last_run=iso(now()))
        started = time.time()
        d = get_dest(dest_id)  # details may have changed during pairing
        procs.ensure_tunnel(d)

        activity[dest_id] = "Checking space at your bro"
        check_quota(d)
        activity[dest_id] = "Checking connection and repository"
        ensure_repo(d)
        d = get_dest(dest_id)

        deadline = window_deadline(settings()) if scheduled else None
        try:
            activity[dest_id] = "Dumping databases"
            dump_warn = dumps.run_dumps() if settings().get("sqlite_dbs") else []
            summary, warning, sources_info = restic_backup(d, "Backup", deadline=deadline)
            if dump_warn:
                warning = "\n".join(dump_warn + ([warning] if warning else []))
        except WindowClosed as w:
            update_dest(dest_id, last_error=None, window_stop=iso(now()),
                        last_warning=f"Backup window closed during {w}. It continues in the next window, "
                                     "without sending again what was already uploaded.")
            log.info("Backup to %s paused by the backup window", d["name"])
            return
        except Paused as w:
            update_dest(dest_id, last_error=None, pause_stop=iso(now()),
                        last_warning=f"Paused during {w}. It continues when you resume, "
                                     "without sending again what was already uploaded.")
            log.info("Backup to %s paused", d["name"])
            return
        activity[dest_id] = "Looking for signs of ransomware"
        reasons, examples = alarm.inspect(d, sources_info, env=restic_env(d))
        if reasons:
            alarm.raise_alarm(d, reasons, examples, sources_info)
        update_dest(dest_id, last_sources=sources_info, window_stop=None)

        s = settings()
        activity[dest_id] = "Forgetting old versions"
        keep = RETENTION_PRESETS.get(s["retention"], RETENTION_PRESETS["standard"])
        last_prune = parse(d.get("last_prune"))
        prune = not last_prune or now() - last_prune >= datetime.timedelta(days=7)
        extra = ["--prune", "--max-unused", "10%"] if prune else []
        if prune:
            activity[dest_id] = "Cleaning up (weekly)"
        if alarm.active():  # keep every version until the user has looked
            p = None
            warning = (warning + "\n" if warning else "") + \
                "Old versions are kept and nothing is cleaned up: the ransomware alarm is on."
        else:
            clear_stale_locks(d)
            p = restic(d, "--retry-lock", "2m", "forget", "--host", slug(s["name"]), "--tag", "bro",
                       "--group-by", "host,tags", *keep, *extra)
        if p is None:
            pass
        elif locked(p):  # the backup itself is fine: cleaning up waits for the next backup
            warning = (warning + "\n" if warning else "") + \
                f"Cleanup postponed to the next backup: your bro's copy is in use ({lock_note(p)})."
            log.warning("Cleanup at %s postponed: %s", d["name"], lock_note(p))
        elif p.returncode != 0:
            if "append-only" in p.stderr.lower() or "403" in p.stderr:
                warning = (warning + "\n" if warning else "") + "Cleanup not allowed (append-only at your bro)."
            else:
                raise JobError("Cleanup failed:\n" + last_lines(p.stderr))
        elif prune:
            update_dest(dest_id, last_prune=iso(now()))

        last_check = parse(d.get("last_check"))
        if not last_check or now() - last_check >= datetime.timedelta(days=7):
            activity[dest_id] = "Integrity check (2% sample)"
            p = restic(d, "--retry-lock", "2m", "check", "--read-data-subset=2%")
            if locked(p):  # not a result: check again next time
                warning = (warning + "\n" if warning else "") + \
                    f"Integrity check postponed to the next backup: your bro's copy is in use ({lock_note(p)})."
            elif p.returncode != 0:
                checks.record_check(dest_id, p, full=False)
                raise JobError("Integrity check found problems:\n" + last_lines(p.stderr))
            update_dest(dest_id, last_check=iso(now()))

        update_dest(dest_id, last_ok=iso(now()), last_error=None, last_warning=warning, pause_stop=None,
                    last_added=summary.get("data_added"), last_files={k: summary.get(k) for k in
                                                                      ("files_new", "files_changed", "files_unmodified")},
                    last_processed=summary.get("total_bytes_processed"))
        log.info("Backup to %s succeeded", d["name"])
        record_history(dest_id, {"at": iso(now()), "added": summary.get("data_added") or 0,
                                 "processed": summary.get("total_bytes_processed") or 0,
                                 "seconds": round(time.time() - started),
                                 "files_new": summary.get("files_new") or 0,
                                 "files_changed": summary.get("files_changed") or 0,
                                 "usage": (get_dest(dest_id) or {}).get("remote_usage"),
                                 "src": {x["key"]: [x["files_new"], x["files_changed"], x["files_unmodified"],
                                                    any(y.get("key") == x["key"] for y in d.get("last_sources") or [])]
                                         for x in sources_info},
                                 "alarm": bool(reasons)})

        prev = d.get("restore_test") or {}
        last_test = parse(prev.get("at"))
        due = not last_test or not prev.get("ok") or now() - last_test >= datetime.timedelta(days=RESTORE_TEST_DAYS)
        if s["restore_test"] and due and not backups_paused():  # monthly, and after a failed test at every next successful backup
            checks.record_restore_test(d, checks.restore_test(get_dest(dest_id)))
    except Exception as e:
        update_dest(dest_id, last_error=str(e))
        notify(f"BRO Backup to {d['name'] if d else dest_id} failed", str(e))
    finally:
        activity.pop(dest_id, None)
        lock.release()


def seed_path_for(d):
    root, _ = nas.seed_root()
    return os.path.join(root, f"{slug(settings()['name'])}-for-{slug(d['name'])}")


def run_seed(dest_id):
    """First backup to a local folder (external disk). Your bro imports it afterwards."""
    lock = job_locks.setdefault(dest_id, threading.Lock())
    if not lock.acquire(blocking=False):
        return
    d = get_dest(dest_id)
    try:
        path = seed_path_for(d)
        os.makedirs(path, exist_ok=True)
        update_dest(dest_id, mode="seeding", seed_path=path, seed_error=None)
        marker = {"app": "bro-backup", "v": 1, "from": settings()["name"], "for_user": d["user"],
                  "created": iso(now()), "complete": False}
        with open(os.path.join(path, SEED_MARKER), "w") as f:
            json.dump(marker, f)
        activity[dest_id] = "Preparing the seed"
        ensure_repo(d, repo_path=path)
        if settings().get("sqlite_dbs"):
            dumps.run_dumps()
        summary, warning, _ = restic_backup(d, "Writing seed", repo_path=path)
        marker.update(complete=True, finished=iso(now()))
        with open(os.path.join(path, SEED_MARKER), "w") as f:
            json.dump(marker, f)
        size = dir_size(path)
        update_dest(dest_id, mode="seed_ready", seed_size=size, seed_done=iso(now()), last_warning=warning)
        notify(f"Seed for {d['name']} ready", f"{human_bytes(size)} in {path}. Take the disk to your bro.",
               priority="default")
    except Exception as e:
        update_dest(dest_id, mode="seed_error", seed_error=str(e))
        notify(f"Seed for {d['name'] if d else dest_id} failed", str(e))
    finally:
        activity.pop(dest_id, None)
        lock.release()


def check_seed_imports():
    """Check whether bros imported our seed; then we continue over the internet."""
    for d in load_state()["destinations"]:
        if d.get("mode") != "seed_ready":
            continue
        try:
            info = bro_status(d, timeout=60)
        except Exception:
            continue
        if info.get("snapshots", 0) > 0:
            update_dest(d["id"], mode=None, seed_imported=iso(now()), last_run=None)
            notify(f"{d['name']} imported your seed",
                   "From now on only changes go over the internet.", priority="default")
            threading.Thread(target=run_backup, args=(d["id"],), daemon=True).start()


def restic_pattern(path):
    """A path from restic ls as an --include pattern that matches only itself (wildcards escaped)."""
    return re.sub(r"([*?\[\]\\])", r"\\\1", path)


def run_restore(dest_id, snapshot_id, paths=None):
    lock = job_locks.setdefault(dest_id, threading.Lock())
    if not lock.acquire(blocking=False):
        return
    d = get_dest(dest_id)
    try:
        target = os.path.join(RESTORE_DIR, slug(d["name"]),
                              f"{snapshot_id[:8]}-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}")
        os.makedirs(target, exist_ok=True)
        activity[dest_id] = f"Restoring version {snapshot_id[:8]}"
        info = restic(d, "snapshots", "--json", snapshot_id, timeout=180, read=True)
        tags = (json.loads(info.stdout or "[]") or [{}])[0].get("tags") or [] if info.returncode == 0 else []
        src = tag_dec(next((t[4:] for t in tags if t.startswith("src:")), None))
        if src:  # v0.6+: one snapshot per folder, stored with relative paths
            target = os.path.join(target, slug(src.replace("/", "-"), 64))
            os.makedirs(target, exist_ok=True)
            inc = [a for pth in (paths or []) for a in ("--include", restic_pattern(pth))]
            p = restic(d, "restore", snapshot_id, "--target", target, *inc, read=True)
        else:    # v0.5 and older: absolute paths under /nas
            if paths:  # absolute paths: restore from the snapshot root, so they land under <target>/nas/...
                inc = [a for pth in paths for a in ("--include", restic_pattern(pth))]
                p = restic(d, "restore", snapshot_id, "--target", target, *inc, read=True)
            else:
                p = restic(d, "restore", f"{snapshot_id}:{NAS_DIR}", "--target", target, read=True)
        if p.returncode != 0:
            raise JobError("Restore failed:\n" + last_lines(p.stderr))
        what = f"{len(paths)} selected item(s) of version" if paths else "version"
        if restore_source(d):
            what += " (from the disk)"
        update_dest(dest_id, last_restore=f"{local_time(now())}: {what} {snapshot_id[:8]} to {target}")
        notify(f"Restore from {d['name']} done", target, priority="default")
    except Exception as e:
        update_dest(dest_id, last_error=f"Restore: {e}")
        notify(f"Restore from {d['name']} failed", str(e))
    finally:
        activity.pop(dest_id, None)
        lock.release()


