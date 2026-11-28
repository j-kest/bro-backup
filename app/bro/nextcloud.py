# version : 1.6.1
# created by : JK and CF
# last edited : 28/11/2026
# Name : bro-backup (bro/nextcloud.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Nextcloud: find the parts of an installation, so the self-check can tell whether a backup holds all of it.

Nextcloud's backup guide names the config, (custom) apps, data and theme folders and the database. In the
TrueNAS app those live in three folders: "html" (the installation with config/ and custom_apps/), "data" (the
users' files) and the database (PostgreSQL). A backup with only the users' files restores the files, but not
the shares, calendars, contacts, versions or who has access to what.

How the parts are recognised, without touching Nextcloud itself:
  html      a folder with the `occ` program and config/config.php
  data      a folder with the `.ocdata` file Nextcloud puts there
  database  a PostgreSQL data folder (PG_VERSION) or a MariaDB/MySQL one (ibdata1), next to the other parts
html and data belong together when config.php's instanceid matches the data folder's appdata_<instanceid>.

Only folder names and a few small files are read: no file contents of the users, no database contents.
The app cannot switch on Nextcloud's maintenance mode or make a database dump: that would need access to
the Nextcloud containers (the Docker socket), which is root on the NAS. A ZFS snapshot of the database
folder is a usable backup instead: PostgreSQL treats it like a restart after a power cut."""

import os
import re

DEPTH = 3                      # how deep below a selected folder, and below the folder that holds a part
PREVIEW_EXCLUDE = "appdata_*/preview"   # thumbnails Nextcloud makes again by itself
INSTANCE_RE = re.compile(r"""['"]instanceid['"]\s*=>\s*['"]([A-Za-z0-9]+)['"]""")
DBTYPE_RE = re.compile(r"""['"]dbtype['"]\s*=>\s*['"]([A-Za-z0-9]+)['"]""")
SKIP = {".zfs", "@eaDir", "#recycle", "#snapshot", "node_modules"}


def _kind(path, files):
    if "occ" in files and os.path.isfile(os.path.join(path, "config", "config.php")):
        return "html"
    if ".ocdata" in files:
        return "data"
    if "PG_VERSION" in files and "postgresql.conf" in files:
        return "postgres"
    if "ibdata1" in files:
        return "mariadb"
    return None


def _walk(top, depth=DEPTH):
    """(folder, kind) for every part up to `depth` levels below top. Does not go into a part: a data folder
    can hold millions of files."""
    top = os.path.normpath(top)
    base = top.count(os.sep)
    for cur, dirs, files in os.walk(top):
        kind = _kind(cur, files)
        if kind:
            dirs[:] = []
            yield cur, kind
            continue
        if cur.count(os.sep) - base >= depth:
            dirs[:] = []
        else:
            dirs[:] = [x for x in dirs if x not in SKIP and not x.startswith(".")]


def _config(html):
    try:
        with open(os.path.join(html, "config", "config.php"), encoding="utf-8", errors="replace") as f:
            text = f.read(200_000)
    except OSError:
        return None, None
    iid, db = INSTANCE_RE.search(text), DBTYPE_RE.search(text)
    return (iid.group(1) if iid else None), (db.group(1).lower() if db else None)


def _instance_of_data(data):
    try:
        names = [x for x in os.listdir(data) if x.startswith("appdata_")]
    except OSError:
        return None
    return names[0][len("appdata_"):] if len(names) == 1 else None


def find(roots, nas_dir):
    """Every Nextcloud installation with a part inside the selected folders (roots), with the other parts found
    next to it. Returns [{"html", "data", "db", "dbtype", "instance"}]; a part not found is None."""
    nas = os.path.realpath(nas_dir)
    parts = {}
    for root in roots:
        if os.path.isdir(root):
            for p, kind in _walk(root):
                parts[os.path.realpath(p)] = kind
    found = [p for p, k in parts.items() if k in ("html", "data")]
    for p in found:  # look around: the other parts are usually siblings, or one level up
        for up in (os.path.dirname(p), os.path.dirname(os.path.dirname(p))):
            if up == nas or not up.startswith(nas + os.sep):
                continue
            for q, kind in _walk(up):
                parts.setdefault(os.path.realpath(q), kind)
    htmls = [p for p, k in parts.items() if k == "html"]
    datas = [p for p, k in parts.items() if k == "data"]
    dbs = [p for p, k in parts.items() if k in ("postgres", "mariadb")]
    out, used = [], set()
    for h in sorted(htmls):
        iid, dbtype = _config(h)
        data = next((x for x in datas if iid and _instance_of_data(x) == iid), None)
        if data is None:  # no instanceid to match: a data folder that is the only one next to it
            near = [x for x in datas if os.path.dirname(x) == os.path.dirname(h)]
            data = near[0] if len(near) == 1 else None
        used.add(data)
        out.append({"html": h, "data": data, "instance": iid, "dbtype": dbtype})
    for x in sorted(datas):
        if x not in used:
            out.append({"html": None, "data": x, "instance": _instance_of_data(x), "dbtype": None})
    for inst in out:
        if inst["dbtype"] == "sqlite":
            inst["db"] = inst["data"]  # the database is a file in the data folder
            continue
        anchor = inst["html"] or inst["data"]
        want = "mariadb" if inst["dbtype"] == "mysql" else ("postgres" if inst["dbtype"] == "pgsql" else None)
        near = [d for d in dbs if (want is None or parts[d] == want) and _distance(d, anchor) <= 2]
        near.sort(key=lambda d: (_distance(d, anchor), "nextcloud" not in d.lower(), d))
        inst["db"] = near[0] if near else None
    return [i for i in out if any(_inside_any(r, i) for r in roots)]


def _distance(a, b):
    """Folder levels from a and b up to the folder that holds both: siblings are 1 apart, cousins 2."""
    common = os.path.commonpath([a, b])
    return max(len(os.path.relpath(a, common).split(os.sep)), len(os.path.relpath(b, common).split(os.sep)))


def _covered(inst):
    return {p for p in (inst.get("html"), inst.get("data"), inst.get("db")) if p}


def _inside_any(root, inst):
    r = os.path.realpath(root)
    return any(p == r or p.startswith(r + os.sep) or r.startswith(p + os.sep) for p in _covered(inst))


PARTS = (("data", "the users' files"), ("html", "the installation (config and apps)"), ("db", "the database"))


def status(st, s, nas_dir):
    """Every Nextcloud in what any bro gets, with what each bro misses:
    [{"inst", "where", "missing": {bro name: [part labels]}}]."""
    from .core import dest_sources  # core is light, but keep this module free of it at import
    bros = [d for d in st["destinations"] if d.get("mode") != "revoked"]
    choices = {}
    for d in bros:
        choices.setdefault(tuple(sorted(dest_sources(d, s))), []).append(d["name"])
    if not bros:
        choices[tuple(sorted(s["sources"]))] = []
    seen = {}
    for sources, names in choices.items():
        for inst in find(list(sources), nas_dir):
            key = inst["html"] or inst["data"]
            v = seen.setdefault(key, {"inst": inst, "where": os.path.relpath(os.path.dirname(key), nas_dir),
                                      "rel": {k: os.path.relpath(inst[k], nas_dir) if inst[k] else None
                                              for k, _label in PARTS},
                                      "missing": {}})
            for part, label in PARTS:
                path = inst[part]
                if path and included(path, sources):
                    continue
                what = label if path else f"{label} (not found next to the other parts)"
                for n in names or ["your bros"]:
                    v["missing"].setdefault(n, []).append(what)
    return list(seen.values())


def included(path, sources):
    """True when a backup of these folders holds all of path."""
    p = os.path.realpath(path)
    return any(p == os.path.realpath(s) or p.startswith(os.path.realpath(s) + os.sep) for s in sources)
