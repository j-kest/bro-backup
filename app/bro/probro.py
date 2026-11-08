# version : 0.1
# created by : JK and CF
# last edited : 05/11/2026
# Name : bro-backup (bro/probro.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Storing backups for many bros: a reference per bro, usage per month for billing, space requests.

Useful between friends too, but made for a "Pro bro": someone (an IT company, for example) who
stores backups for customers that have no friend with a NAS, or want a second copy.

- reference: your own name or customer number for a bro, shown in the list and in the export;
- usage per month: the highest usage of each bro per calendar month (UTC), kept 25 months;
- export: one CSV row per bro per month (GET /receivers.csv);
- space requests: a bro asks for more space from his own BRO Backup; you grant or decline it.
"""

import csv
import io

from . import procs
from .core import clean_name, GIB, iso, load_state, log, mutate, notify, now

MAX_GIB = 1_000_000
MONTHS_KEPT = 25


# ---------------------------------------------------------------- usage per month
def record_usage(user, usage):
    """Called after measuring a bro's folder. Writes only when the month's peak goes up."""
    month = now().strftime("%Y-%m")
    st = load_state()
    r = st["receivers"].get(user)
    if not r or (r.get("usage_months") or {}).get(month, -1) >= usage:
        return
    with mutate() as st2:
        r = st2["receivers"].get(user)
        if not r:
            return
        months = r.setdefault("usage_months", {})
        months[month] = max(months.get(month, 0), int(usage))
        for old in sorted(months)[:-MONTHS_KEPT]:
            del months[old]


def _cell(v):
    """Never let a name become a formula in a spreadsheet (CSV injection)."""
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def usage_csv():
    st = load_state()
    out = io.StringIO()
    w = csv.writer(out, delimiter=";")  # ; opens correctly in Excel with Belgian and Dutch settings
    w.writerow(["month", "login", "bro", "reference", "space_gib", "peak_used_bytes", "peak_used_gib", "paired_on"])
    for user, r in sorted(st["receivers"].items(), key=lambda x: (x[1].get("ref") or "", x[0])):
        if not r.get("accepted"):
            continue
        for month, used in sorted((r.get("usage_months") or {}).items()):
            w.writerow([month, user, _cell(r.get("bro_name") or r.get("name")), _cell(r.get("ref")),
                        r.get("quota_gib"), used, f"{used / GIB:.2f}", (r.get("accepted_at") or r.get("created") or "")[:10]])
    return out.getvalue()


# ---------------------------------------------------------------- reference
def set_ref(user, ref):
    with mutate() as st:
        r = st["receivers"].get(user)
        if not r:
            raise LookupError(user)
        r["ref"] = clean_name(ref, 60) or None


# ---------------------------------------------------------------- space requests
def receive_space_request(user, p):
    """A bro that backs up here asks for more space (pair API, authenticated as that bro)."""
    try:
        gib = int(p.get("gib"))
    except (TypeError, ValueError):
        return None
    if not 1 <= gib <= MAX_GIB:
        return None
    note = clean_name(p.get("note"), 200)
    with mutate() as st:
        r = st["receivers"].get(user)
        if not r or not r.get("accepted"):
            return None
        r["space_request"] = {"gib": gib, "note": note, "at": iso(now())}
        name, quota = r.get("bro_name") or r["name"], r["quota_gib"]
    notify(f"{name} asks for more space",
           f"{name} asks for {gib} GiB more (he has {quota} GiB now)." + (f' His note: "{note}"' if note else "")
           + " Grant or decline it on the overview.", priority="default")
    return {"ok": True}


def answer_request(user, grant):
    """Grant (space += asked) or decline the open request. Returns (name, old quota, new quota)."""
    with mutate() as st:
        r = st["receivers"].get(user)
        if not r or not r.get("space_request"):
            raise LookupError("There is no open request.")
        req = r.pop("space_request")
        name, old = r.get("bro_name") or r["name"], r["quota_gib"]
        if grant:
            r["quota_gib"] = min(MAX_GIB, old + req["gib"])
        r["space_answer"] = {"granted": bool(grant), "at": iso(now()), "gib": req["gib"]}
        new = r["quota_gib"]
    log.info("Space request of %s %s (%s -> %s GiB)", name, "granted" if grant else "declined", old, new)
    return name, old, new


def ask_space(d, gib, note=""):
    """From our side: ask the bro we back up to for more space."""
    if not 1 <= int(gib) <= MAX_GIB:
        raise ValueError(f"Ask for 1 to {MAX_GIB} GiB.")
    procs.pair_call(d["pair_ticket"], "POST", "/bro/space-request", {"gib": int(gib), "note": clean_name(note, 200)},
                    auth=(d["user"], d["password"]), timeout=60)
