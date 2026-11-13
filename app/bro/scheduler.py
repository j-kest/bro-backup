# version : 1.3.0
# created by : JK and CF
# last edited : 13/11/2026
# Name : bro-backup (bro/scheduler.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""The loop that starts backups, checks and reports on time."""

import datetime
import os
import threading
import time

from . import alarm, backup, kept, nas, stats, pairing, peers, probro, procs, receiving, recovery, reports, space, updates, urbackup
from .core import (
    CODE_DAYS,
    PAUSED_MODES,
    backups_paused,
    RECEIVE_DIR,
    SLOW_LOOP_SECONDS,
    dest_ports,
    iso,
    load_state,
    local_time,
    log,
    mutate,
    my_tickets,
    notify,
    now,
    parse,
    receive_stats,
    settings,
    setup_done,
    update_dest,
)


# ---------------------------------------------------------------- scheduler
def backup_due(d, hour):
    if d.get("mode") in PAUSED_MODES or d.get("accepting") or not backup.in_window(settings()) or backups_paused():
        return False  # outside the backup window nothing starts by itself ("Back up now" still works)
    if d.get("pause_stop"):
        return True  # stopped by a pause that has ended: continue where it stopped
    last_run = parse(d.get("last_run"))
    if not last_run:
        return True
    if d.get("last_error") and not d.get("no_room"):  # no room at the bro: an hour later changes nothing
        return now() - last_run >= datetime.timedelta(hours=1)
    local_now = datetime.datetime.now().astimezone()
    slot = local_now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if local_now < slot:
        slot -= datetime.timedelta(days=1)
    return last_run.astimezone() < slot


def m365_secret_check():
    """Warn 30 and 7 days before the Microsoft 365 client secret stops working (once each)."""
    s = settings()
    if s.get("mail_method") != "m365" or not s.get("m365_secret_expires"):
        return
    try:
        days = (datetime.date.fromisoformat(s["m365_secret_expires"]) - datetime.date.today()).days
    except ValueError:
        return
    level = 7 if days <= 7 else 30 if days <= 30 else None
    mark = f"{s['m365_secret_expires']}/{level}"
    if not level or load_state().get("m365_secret_warned") == mark:
        return
    with mutate() as st:
        st["m365_secret_warned"] = mark
    notify("The Microsoft 365 mail secret expires soon",
           f"The client secret stops working on {s['m365_secret_expires']} ({max(days, 0)} days). Make a new one for "
           "the app registration in Entra ID, paste it under Settings, Email, and change the expiry date.")


def readonly_check():
    """Warn when a folder under /nas became writable for the app (a dataset mounted after it started)."""
    rw = nas.writable_mounts()
    key = ",".join(rw)
    if load_state().get("rw_warned", "") == key:
        return
    with mutate() as st:
        st["rw_warned"] = key
    if rw:
        log.warning("Writable mounts under /nas: %s", key)
        notify("A folder is writable for BRO Backup",
               "These folders are not read-only for the app: " + ", ".join(rw[:4]) + ". Restart the app so it gets "
               "them read-only again. BRO Backup never writes there, but read-only keeps a mistake or an attacker "
               "inside the app away from your data.")


def slow_tasks():
    for fn in (pairing.retry_pending, peers.keep_in_touch, backup.check_seed_imports, recovery.push_escrow,
               refresh_receive_stats, updates.check):
        try:
            fn()
        except Exception as e:
            log.exception("%s: %s", fn.__name__, e)


def scheduler():
    last_usage = last_slow = 0.0
    while True:
        try:
            if setup_done():
                procs.supervise_once()
                st = load_state()
                s = st["settings"]
                if st.get("pause") and not backups_paused(st):
                    with mutate() as st2:
                        st2.pop("pause", None)
                    log.info("Backups resumed: the pause has ended")
                for d in st["destinations"]:
                    if dest_ports.get(d["id"]) and backup_due(d, int(s["backup_hour"])):
                        threading.Thread(target=backup.run_backup, args=(d["id"], True), daemon=True).start()
                    if d.get("mode") in PAUSED_MODES:
                        continue
                    ref = parse(d.get("last_ok")) or parse(d.get("created"))
                    last_alert = parse(d.get("last_stale_alert"))
                    if ref and now() - ref > datetime.timedelta(hours=int(s["alert_hours"])) and \
                            (not last_alert or now() - last_alert > datetime.timedelta(hours=24)):
                        notify(f"BRO Backup to {d['name']} is falling behind",
                               f"Last successful backup: {local_time(d.get('last_ok'))}")
                        update_dest(d["id"], last_stale_alert=iso(now()))
                if time.time() - last_slow > SLOW_LOOP_SECONDS and my_tickets.get("pair"):
                    last_slow = time.time()
                    threading.Thread(target=slow_tasks, daemon=True).start()
                if time.time() - last_usage > 3600:
                    last_usage = time.time()
                    kept.sweep_all()
                    refresh_receive_stats()
                    stats.sample_daily()
                    stats.check_running_out()
                    reports.check_silent_bros(s)
                    space.check()
                    alarm.remind()
                    urbackup.check()
                    m365_secret_check()
                    readonly_check()
                if reports.report_due(s):
                    with mutate() as st2:
                        st2["settings"]["last_report"] = iso(now())
                    threading.Thread(target=reports.send_report, daemon=True).start()
                expire_codes()
        except Exception as e:
            log.exception("Scheduler error: %s", e)
        time.sleep(10)


def refresh_receive_stats(only=None, max_age=0):
    """Measure the folders of the bros that back up here, and enforce their quota."""
    users = [only] if only else list(load_state()["receivers"])
    for user in users:
        if max_age and time.time() - (receive_stats.get(user) or {}).get("t", 0) < max_age:
            continue  # measured a moment ago: walking a large repository on every call costs too much
        path = os.path.join(RECEIVE_DIR, user)
        total, newest, snaps = 0, 0.0, 0
        for root, _dirs, files in os.walk(path):
            for fn in files:
                try:
                    stt = os.lstat(os.path.join(root, fn))
                    total += stt.st_size
                    if os.path.basename(root) == "snapshots":
                        newest = max(newest, stt.st_mtime)
                        snaps += 1
                except OSError:
                    pass
        receive_stats[user] = {"usage": total, "snapshots": snaps, "t": time.time(), "last_seen": iso(
            datetime.datetime.fromtimestamp(newest, datetime.timezone.utc)) if newest else None}
        receiving.enforce_quota(user, total)
        probro.record_usage(user, total)


def expire_codes():
    limit = now() - datetime.timedelta(days=CODE_DAYS)
    gone = []
    with mutate() as st:
        for user, r in list(st["receivers"].items()):
            if not r.get("accepted") and parse(r["created"]) < limit:
                gone.append(user)
                del st["receivers"][user]
            elif r.get("help_token") and parse(r["help_created"]) < limit:
                r.pop("help_token", None)
    for user in gone:
        receiving.remove_rest_user(user)
    peers.expire_tombstones()


