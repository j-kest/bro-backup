# version : 1.1.0
# created by : JK and CF
# last edited : 12/11/2026
# Name : bro-backup (bro/speed.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Speed test through the tunnel to a bro."""

import base64
import datetime
import http.client
import json
import os
import threading
import time

from . import backup, procs
from .core import (
    SPEED_MAX_BYTES,
    SPEED_PART,
    SPEED_SECONDS,
    activity,
    conn_paths,
    dir_size,
    get_dest,
    iso,
    job_locks,
    log,
    now,
    settings,
    sources_size,
    update_dest,
)


DOWNLOAD_GRACE = 15  # seconds a bro may send longer than asked before we stop reading


# ---------------------------------------------------------------- speed test
def basic_auth(d):
    return "Basic " + base64.b64encode(f"{d['user']}:{d['password']}".encode()).decode()


def speed_upload(port, d, seconds):
    """Send parts of SPEED_PART for about this many seconds, one after the other on one connection.
    The bro answers a part only once all of it arrived, so the time until the last answer is the upload time,
    measured here: what the bro reports is only checked, never used as a speed."""
    block = os.urandom(1024 * 1024)
    per_part = SPEED_PART // len(block)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    try:
        start = time.monotonic()
        end, sent, busy_waits = start + seconds, 0, 0
        while time.monotonic() < end and sent < SPEED_MAX_BYTES:
            conn.putrequest("POST", "/bro/speedtest")
            conn.putheader("Authorization", basic_auth(d))
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(per_part * len(block)))
            conn.endheaders()
            for _ in range(per_part):
                conn.send(block)
            resp = conn.getresponse()
            body = resp.read(65536)  # a few numbers: never read an unlimited answer from a bro
            if resp.status == 429 and sent and busy_waits < 10:  # another bro took the test slot between two parts
                busy_waits += 1
                time.sleep(1)
                continue
            if resp.status == 413:
                raise RuntimeError("Your bro runs an older version that cannot take this test. Ask him to update.")
            if resp.status != 200:
                raise RuntimeError(f"Bro refused the upload test ({resp.status})")
            try:
                got = json.loads(body).get("bytes")
            except (ValueError, AttributeError):
                got = None
            if got != per_part * len(block):
                raise RuntimeError("The bro did not receive the whole test part")
            sent += got
        secs = time.monotonic() - start
    finally:
        conn.close()
    if not sent or secs <= 0:
        raise RuntimeError("Too little data arrived to measure the upload speed")
    return sent * 8 / secs


def speed_download(port, d, seconds):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    conn.request("GET", f"/bro/speedtest?seconds={seconds}", headers={"Authorization": basic_auth(d)})
    resp = conn.getresponse()
    if resp.status != 200:
        raise RuntimeError(f"Bro refused the download test ({resp.status})")
    total, first, first_len, last = 0, None, 0, None
    stop = time.monotonic() + seconds + DOWNLOAD_GRACE  # the bro sends for `seconds`: never read longer, nor more than the cap
    while time.monotonic() < stop and total < SPEED_MAX_BYTES + SPEED_PART:
        chunk = resp.read(1024 * 1024)
        if not chunk:
            break
        t = time.monotonic()
        if first is None:
            first, first_len = t, len(chunk)
        total, last = total + len(chunk), t
    conn.close()
    if first is None or last <= first:
        raise RuntimeError("Too little data arrived to measure the download speed")
    return (total - first_len) * 8 / (last - first)


def selected_size():
    """Total size of the selected folders, cached for 6 hours (walking a big pool takes a while)."""
    s = settings()
    key = json.dumps(sorted(s["sources"]))
    cached = sources_size.get(key)
    if cached and time.time() - cached["at"] < 6 * 3600:
        return cached["bytes"]
    total = sum(dir_size(p) for p in s["sources"] if os.path.isdir(p))
    sources_size[key] = {"bytes": total, "at": time.time()}
    return total


def run_speedtest(dest_id):
    lock = job_locks.setdefault(dest_id, threading.Lock())
    if not lock.acquire(blocking=False):
        update_dest(dest_id, speed_error="A backup is running to this bro. Try again when it is done.")
        return
    d = get_dest(dest_id)
    try:
        update_dest(dest_id, speed_error=None)
        seen = {}

        def record(line):
            found = procs.parse_path(line)
            if found:
                seen["path"] = found
                conn_paths[dest_id] = {"type": found[0], "detail": found[1], "at": iso(now())}
        activity[dest_id] = "Speed test: connecting"
        with procs.pair_tunnel(d["pair_ticket"], on_line=record) as port:
            last = None
            for _ in range(5):  # the first connection (hole punching) can take a moment
                try:
                    with procs.pair_opener.open(f"http://127.0.0.1:{port}/bro/ping", timeout=30) as r:
                        r.read(4096)
                    last = None
                    break
                except Exception as e:
                    last = e
                    time.sleep(3)
            if last:
                raise RuntimeError(f"Bro not reachable: {last}")
            time.sleep(1)
            activity[dest_id] = f"Speed test: upload ({SPEED_SECONDS} s)"
            up = speed_upload(port, d, SPEED_SECONDS)
            activity[dest_id] = f"Speed test: download ({SPEED_SECONDS} s)"
            down = speed_download(port, d, SPEED_SECONDS)
        activity[dest_id] = "Measuring the size of your folders"
        src = selected_size()
        s = settings()  # backups run at the backup hour: estimate with the limit that applies then
        at = datetime.datetime.now().replace(hour=int(s["backup_hour"]), minute=30)
        d = get_dest(dest_id)
        lims = [x for x in (backup.limit_kib(s, at), backup.bro_limit(d)) if x > 0]  # ours at that hour, his as it is now
        lim = min(lims) * 1024 * 8 if lims else 0
        eff_up = min(up, lim) if lim else up
        remote = d.get("remote_usage") or src
        path = seen.get("path") or (None, None)
        result = {"at": iso(now()), "up_bps": up, "down_bps": down, "eff_up_bps": eff_up,
                  "limited": bool(lim and lim < up), "path": path[0], "path_detail": path[1],
                  "src_bytes": src, "first_s": src * 8 / eff_up if eff_up else None,
                  "daily_s": (d.get("last_added") or 0) * 8 / eff_up if eff_up and d.get("last_added") else None,
                  "restore_bytes": remote, "restore_s": remote * 8 / down if down else None}
        update_dest(dest_id, speed=result)
        log.info("Speed test to %s: up %.1f Mbit/s, down %.1f Mbit/s, path %s",
                 d["name"], up / 1e6, down / 1e6, path[0])
    except Exception as e:
        update_dest(dest_id, speed_error=str(e))  # keep the previous result
    finally:
        activity.pop(dest_id, None)
        lock.release()


