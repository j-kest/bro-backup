# version : 0.10
# created by : JK and CF
# last edited : 01/11/2026
# Name : bro-backup (bro/dumps.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Database dumps before a backup.

SQLite (Vaultwarden, Home Assistant, many small apps): a consistent copy through SQLite's online
backup API, the same thing `sqlite3 db ".backup file"` does, which is what Vaultwarden recommends.
PostgreSQL in Immich: Immich makes its own daily dumps in UPLOAD_LOCATION/backups. We only check
that those exist and are recent, so they travel along with the folder that holds them.
"""

import datetime
import fnmatch
import glob
import os
import shutil
import sqlite3
import tempfile
import threading

from .core import DATA_DIR, NAS_DIR, iso, log, mutate, now, settings, slug

DUMP_DIR = os.path.join(DATA_DIR, "dumps")
SQLITE_MAGIC = b"SQLite format 3\x00"
SQLITE_EXT = (".sqlite3", ".sqlite", ".db")
IMMICH_GLOB = "immich-db-backup-*.sql.gz"
IMMICH_MAX_AGE_H = 48
SCAN_MAX_FILES = 200_000
_lock = threading.Lock()  # two backups to two bros at once share the dump folder


def is_sqlite(path):
    try:
        with open(path, "rb") as f:
            return f.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def find_databases(roots=None, limit=100):
    """SQLite files and Immich dump folders inside the selected folders, for the Settings page."""
    roots = roots if roots is not None else settings()["sources"]
    found, immich, seen = [], [], 0
    for root in roots:
        for dirpath, dirnames, files in os.walk(root):
            dirnames[:] = [x for x in dirnames if not x.startswith(".zfs") and x not in ("@eaDir", "#recycle")]
            seen += len(files)
            if seen > SCAN_MAX_FILES or len(found) >= limit:
                break
            for fn in files:
                p = os.path.join(dirpath, fn)
                if fn.lower().endswith(SQLITE_EXT) and is_sqlite(p):
                    try:
                        found.append({"path": p, "size": os.path.getsize(p)})
                    except OSError:
                        pass
            if os.path.basename(dirpath) == "backups" and any(fnmatch.fnmatch(f, IMMICH_GLOB) for f in files):
                immich.append(dirpath)
    return found, immich


def immich_status(folders):
    """For every Immich dump folder (found by the last scan): the newest dump and its age."""
    out = []
    for folder in folders:
        dumps = sorted(glob.glob(os.path.join(folder, IMMICH_GLOB)), key=os.path.getmtime)
        newest = dumps[-1] if dumps else None
        age_h = (datetime.datetime.now().timestamp() - os.path.getmtime(newest)) / 3600 if newest else None
        out.append({"folder": folder, "count": len(dumps), "newest": os.path.basename(newest) if newest else None,
                    "age_h": age_h, "ok": age_h is not None and age_h <= IMMICH_MAX_AGE_H})
    return out


def _snapshot_copy(path, workdir):
    """Copy the database and its WAL from the newest ZFS snapshot (or live, as a last resort)."""
    from . import backup  # late import: backup imports this module
    src_dir = os.path.dirname(path)
    root = backup.zfs_root(path)
    if root:
        snap, _ = backup.newest_snapshot(root)
        if snap:
            cand = os.path.join(root, ".zfs", "snapshot", snap[0], os.path.relpath(src_dir, root))
            if os.path.isfile(os.path.join(cand, os.path.basename(path))):
                src_dir = cand
    dst = os.path.join(workdir, os.path.basename(path))
    for suffix in ("", "-wal"):
        if os.path.exists(os.path.join(src_dir, os.path.basename(path) + suffix)):
            shutil.copy2(os.path.join(src_dir, os.path.basename(path) + suffix), dst + suffix)
    return dst, ("snapshot" if src_dir != os.path.dirname(path) else "live copy")


def dump_sqlite(path, target):
    """Write a consistent copy of the SQLite database at `path` to `target`. Returns how it was read."""
    tmp_target = target + ".tmp"
    if os.path.exists(tmp_target):
        os.remove(tmp_target)
    method = "online backup"
    try:  # the normal way: a read transaction on the live database
        src = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
        try:
            dst = sqlite3.connect(tmp_target)
            src.backup(dst)
            dst.close()
        finally:
            src.close()
    except sqlite3.Error as e:
        # A WAL database on a read-only mount cannot always be opened live. Then work on a copy,
        # preferably taken from a ZFS snapshot (consistent like after a power cut; SQLite recovers that).
        log.info("Live dump of %s not possible (%s), using a copy", path, e)
        with tempfile.TemporaryDirectory(dir=DUMP_DIR) as work:
            copy, method = _snapshot_copy(path, work)
            src = sqlite3.connect(copy, timeout=30)
            try:
                dst = sqlite3.connect(tmp_target)
                src.backup(dst)
                dst.close()
            finally:
                src.close()
    con = sqlite3.connect(tmp_target)
    try:
        result = con.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        con.close()
    if result != "ok":
        os.remove(tmp_target)
        raise sqlite3.DatabaseError(f"integrity check of the dump failed: {result}")
    os.replace(tmp_target, target)
    return method


def run_dumps():
    """Dump every configured database. Returns warnings (a failed dump never stops the backup)."""
    with _lock:
        return _run_dumps()


def _run_dumps():
    dbs = settings().get("sqlite_dbs") or []
    os.makedirs(DUMP_DIR, exist_ok=True)
    results, warnings, keep = {}, [], set()
    for path in dbs:
        rel = os.path.splitext(os.path.relpath(path, NAS_DIR))[0]  # tank/apps/vaultwarden/db
        name = slug(rel.replace("/", "-"), 80) + ".sqlite3"
        keep.add(name)
        target = os.path.join(DUMP_DIR, name)
        try:
            if not os.path.isfile(path):
                raise FileNotFoundError("the database file is gone")
            method = dump_sqlite(path, target)
            results[path] = {"at": iso(now()), "ok": True, "size": os.path.getsize(target), "method": method,
                             "file": name}
        except Exception as e:
            results[path] = {"at": iso(now()), "ok": False, "error": str(e), "file": name}
            warnings.append(f"Database dump of {os.path.relpath(path, NAS_DIR)} failed: {e}")
            log.warning(warnings[-1])
    for fn in os.listdir(DUMP_DIR):  # dumps of databases no longer selected
        if fn.endswith(".sqlite3") and fn not in keep:
            os.remove(os.path.join(DUMP_DIR, fn))
    with mutate() as st:
        st["dump_results"] = results
    return warnings


def dumps_present():
    try:
        return any(f.endswith(".sqlite3") for f in os.listdir(DUMP_DIR))
    except OSError:
        return False


def scan_in_background():
    def work():
        try:
            found, immich = find_databases()
            res = {"at": iso(now()), "sqlite": found, "immich": immich, "running": False}
        except Exception as e:
            res = {"at": iso(now()), "sqlite": [], "immich": [], "running": False, "error": str(e)}
        with mutate() as st:
            st["db_scan"] = res
    with mutate() as st:
        st["db_scan"] = {**(st.get("db_scan") or {}), "running": True}
    threading.Thread(target=work, daemon=True).start()
