# version : 1.3.0
# created by : JK and CF
# last edited : 13/11/2026
# Name : bro-backup (bro/stats.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Statistics: totals, growth per folder, when space runs out, reliability, what bros send here, what
compression and deduplication save, and how the connection went.

Everything comes from what the app already records: the history of successful backups, every run with its
outcome, a daily sample of the space each bro uses here and of our own data folder, and a weekly `restic stats`."""

import datetime
import json
import shutil

from .core import DATA_DIR, GIB, iso, load_state, log, mutate, notify, now, parse, receive_stats, sources_size

SAMPLES_MAX = 400          # about a year of daily samples
SAMPLE_EVERY = datetime.timedelta(hours=20)
TREND_DAYS = 30            # growth is measured over this many days
SOON_DAYS = 30             # tell the owner when space runs out within this many days


# ---------------------------------------------------------------- daily samples
def _add_sample(series, value, t):
    last = parse(series[-1]["at"]) if series else None
    if last and t - last < SAMPLE_EVERY:
        return series
    return (series + [{"at": iso(t), "v": value}])[-SAMPLES_MAX:]


def sample_daily():
    """Once a day: the space each bro uses here, and how full our own data folder is."""
    t = now()
    try:
        du = shutil.disk_usage(DATA_DIR)
    except OSError:
        du = None
    with mutate() as st:
        hist = st.setdefault("recv_history", {})
        for user in st["receivers"]:
            usage = (receive_stats.get(user) or {}).get("usage")
            if usage is not None:
                hist[user] = _add_sample(hist.get(user) or [], usage, t)
        for user in list(hist):
            if user not in st["receivers"]:
                hist.pop(user)
        if du:
            st["space_history"] = _add_sample(st.get("space_history") or [], du.total - du.free, t)
            st["space_total"] = du.total


# ---------------------------------------------------------------- growth and forecast
def growth_per_day(points, days=TREND_DAYS):
    """Bytes per day over the last `days`, from [(datetime, value)], by least squares. None with too little data."""
    if not points:
        return None
    cut = points[-1][0] - datetime.timedelta(days=days)
    pts = [(t, v) for t, v in points if t >= cut]
    if len(pts) < 3 or (pts[-1][0] - pts[0][0]) < datetime.timedelta(days=3):
        return None
    t0 = pts[0][0]
    xs = [(t - t0).total_seconds() / 86400 for t, _ in pts]
    ys = [v for _, v in pts]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    var = sum((x - mx) ** 2 for x in xs)
    if not var:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var


def full_in(points, limit):
    """(days until `limit` is reached at the current growth, growth per day), or (None, growth)."""
    if not points or not limit:
        return None, None
    g = growth_per_day(points)
    if g is None:
        return None, None
    current = points[-1][1]
    if current >= limit:
        return 0, g
    if g <= 0:
        return None, g
    return (limit - current) / g, g


def _pts(entries, key="v"):
    out = []
    for e in entries or []:
        t, v = parse(e.get("at")), e.get(key)
        if t and isinstance(v, (int, float)):
            out.append((t, v))
    return out


def forecasts(st=None):
    """Every place where space can run out, with how long it still lasts."""
    st = st or load_state()
    out = []
    for d in st["destinations"]:
        if d.get("mode") == "revoked":
            continue
        q = int(d.get("remote_quota_gib") or 0) * GIB
        days, g = full_in(_pts(d.get("history"), "usage"), q)
        out.append({"kind": "dest", "id": d["id"], "name": d["name"], "used": d.get("remote_usage"), "limit": q,
                    "days": days, "per_day": g, "what": f"Your space at {d['name']}"})
    for user, r in st["receivers"].items():
        if not r.get("accepted"):
            continue
        q = int(r.get("quota_gib") or 0) * GIB
        days, g = full_in(_pts((st.get("recv_history") or {}).get(user)), q)
        name = r.get("bro_name") or r["name"]
        out.append({"kind": "receiver", "id": user, "name": name, "used": (receive_stats.get(user) or {}).get("usage"),
                    "limit": q, "days": days, "per_day": g, "what": f"The space you gave {name}"})
    total = st.get("space_total")
    days, g = full_in(_pts(st.get("space_history")), total)
    hist = st.get("space_history") or []
    out.append({"kind": "own", "id": "own", "name": "This NAS", "used": hist[-1]["v"] if hist else None,
                "limit": total, "days": days, "per_day": g, "what": "The bro-backup folder on this NAS"})
    return out


def check_running_out():
    """Hourly: tell the owner once when a space will be full within SOON_DAYS at the current growth."""
    soon = [f for f in forecasts() if f["days"] is not None and f["days"] < SOON_DAYS]
    with mutate() as st:
        told = st.setdefault("full_soon_told", {})
        new = [f for f in soon if f"{f['kind']}:{f['id']}" not in told]
        keep = {f"{f['kind']}:{f['id']}" for f in soon}
        for k in list(told):
            if k not in keep:
                told.pop(k)  # not soon any more: tell again when it comes back
        for f in new:
            told[f"{f['kind']}:{f['id']}"] = iso(now())
    for f in new:
        when = (now() + datetime.timedelta(days=f["days"])).astimezone().strftime("%d/%m/%Y")
        log.warning("%s is full in about %.0f days", f["what"], f["days"])
        notify(f"{f['what']} is full in about {max(1, round(f['days']))} days",
               f"At the growth of the last {TREND_DAYS} days it is full around {when}. "
               + ("Ask your bro for more space, or leave something out." if f["kind"] == "dest" else
                  "Give him more space or talk to him." if f["kind"] == "receiver" else
                  "Enlarge the dataset or its quota, or give bros less space."), priority="default")


# ---------------------------------------------------------------- per bro
def reliability(d, days=30):
    cut = now() - datetime.timedelta(days=days)
    runs = [r for r in d.get("runs") or [] if (parse(r.get("at")) or cut) >= cut]
    counted = [r for r in runs if r.get("outcome") in ("ok", "failed", "no_room")]
    ok = sum(1 for r in counted if r["outcome"] == "ok")
    hist = [h for h in d.get("history") or [] if (parse(h.get("at")) or cut) >= cut]
    secs = [h.get("seconds") or 0 for h in hist]
    fails = [r for r in d.get("runs") or [] if r.get("outcome") in ("failed", "no_room")]
    return {"runs": len(counted), "ok": ok, "share": ok / len(counted) if counted else None,
            "failed": len(counted) - ok, "interrupted": sum(1 for r in runs if r.get("outcome") == "interrupted"),
            "avg_seconds": sum(secs) / len(secs) if secs else None,
            "since_failure": fails[-1]["at"] if fails else None}


def paths(d, days=30):
    cut = now() - datetime.timedelta(days=days)
    hist = [h for h in d.get("history") or [] if (parse(h.get("at")) or cut) >= cut]
    counts = {}
    for h in hist:
        counts[h.get("path") or "unknown"] = counts.get(h.get("path") or "unknown", 0) + 1
    return counts, len(hist)


def speeds(d):
    """Average upload speed per backup (bits per second), for backups that sent enough to measure."""
    out = []
    for h in d.get("history") or []:
        if (h.get("seconds") or 0) >= 30 and (h.get("added") or 0) >= 50 * 1024 * 1024:
            out.append({"at": h["at"], "bps": h["added"] * 8 / h["seconds"]})
    return out


def savings(d):
    rs = d.get("repo_stats") or {}
    files, stored = rs.get("files") or 0, rs.get("stored") or 0
    if not files or not stored:
        return None
    return {"files": files, "stored": stored, "saved": max(0, files - stored), "share": max(0.0, 1 - stored / files),
            "at": rs.get("at")}


# ---------------------------------------------------------------- per folder
def folder_growth(st=None, days=30):
    """Bytes each folder sent in the last `days`, over all bros (the same data goes to every bro: the largest
    is taken, not the sum)."""
    st = st or load_state()
    cut = now() - datetime.timedelta(days=days)
    per_dest = []
    for d in st["destinations"]:
        tot = {}
        for h in d.get("history") or []:
            if (parse(h.get("at")) or cut) < cut:
                continue
            for k, v in (h.get("src_added") or {}).items():
                tot[k] = tot.get(k, 0) + (v or 0)
        per_dest.append(tot)
    keys = {k for t in per_dest for k in t}
    rows = [{"key": k, "bytes": max(t.get(k, 0) for t in per_dest)} for k in keys]
    return sorted(rows, key=lambda r: -r["bytes"])


# ---------------------------------------------------------------- totals
def totals(st=None):
    st = st or load_state()
    month = now().astimezone().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    sent = 0
    for d in st["destinations"]:
        sent += sum(h.get("added") or 0 for h in d.get("history") or [] if (parse(h.get("at")) or month) >= month)
    received = 0
    for user, series in (st.get("recv_history") or {}).items():
        pts = [p for p in _pts(series) if p[0] >= month]
        before = [p for p in _pts(series) if p[0] < month]
        start = before[-1][1] if before else (pts[0][1] if pts else 0)
        now_v = (receive_stats.get(user) or {}).get("usage") or (pts[-1][1] if pts else start)
        received += max(0, now_v - start)
    key = sorted(st["settings"].get("sources") or [])
    cached = sources_size.get(json.dumps(key))
    protected = cached["bytes"] if cached else max(((d.get("repo_stats") or {}).get("files") or 0
                                                    for d in st["destinations"]), default=0) or None
    return {"protected": protected,
            "at_bros": sum(d.get("remote_usage") or 0 for d in st["destinations"] if d.get("mode") != "revoked"),
            "for_others": sum((receive_stats.get(u) or {}).get("usage") or 0 for u in st["receivers"]),
            "sent_month": sent, "received_month": received, "month": month}
