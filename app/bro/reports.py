# version : 0.10.6
# created by : JK and CF
# last edited : 05/11/2026
# Name : bro-backup (bro/reports.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Weekly report and alerts about silent bros."""

import datetime

from . import scheduler, web
from .core import (
    PAUSED_MODES,
    REPORT_HOUR,
    human_bytes,
    iso,
    load_state,
    local_time,
    mutate,
    notification_channels,
    notify,
    now,
    parse,
    receive_stats,
)


# ---------------------------------------------------------------- weekly report and silent bros
def status_report():
    """Plain-text overview of every bro, for the weekly report."""
    st = load_state()
    lines = []
    for d in st["destinations"]:
        rt = d.get("restore_test") or {}
        state = "PAUSED" if d.get("mode") in PAUSED_MODES else ("FAILED" if d.get("last_error") else "ok")
        lines.append(f"Backup to {d['name']}: {state}")
        lines.append(f"  last successful backup: {local_time(d.get('last_ok')) if d.get('last_ok') else 'never'}")
        if d.get("remote_quota_gib"):
            lines.append(f"  space used: {human_bytes(d.get('remote_usage'))} of {d['remote_quota_gib']} GiB")
        lines.append(f"  restore test: {('passed' if rt.get('ok') else 'FAILED') + ' on ' + local_time(rt.get('at')) if rt else 'not run yet'}")
        if d.get("last_error"):
            lines.append(f"  problem: {web.friendly_error(d['last_error'])}")
        if d.get("full_check") and not d["full_check"].get("ok"):
            lines.append(f"  integrity: damaged data found on {local_time(d['full_check'].get('at'))}, open Restore to repair")
    scheduler.refresh_receive_stats()
    for user, r in st["receivers"].items():
        if not r.get("accepted"):
            continue
        stats = receive_stats.get(user) or {}
        lines.append(f"{r.get('bro_name') or r['name']} backs up to you: last data "
                     f"{local_time(stats.get('last_seen')) if stats.get('last_seen') else 'never'}, "
                     f"{human_bytes(stats.get('usage'))} of {r['quota_gib']} GiB")
    problems = sum(1 for d in st["destinations"] if d.get("last_error") or not (d.get("restore_test") or {"ok": True}).get("ok")
                   or not (d.get("full_check") or {"ok": True}).get("ok"))
    a = st.get("alarm")
    if a:
        problems += 1
        lines.insert(0, f"RANSOMWARE ALARM since {local_time(a['at'])}: {a['reasons'][0]}. Nothing is cleaned up at your "
                        "bros until you clear it on the overview.")
    from . import safety  # late import: safety is only needed here
    lines.insert(0, safety.report_line(st))
    title = f"BRO Backup weekly: {'all good' if not problems else f'{problems} problem(s)'}"
    return title, "\n".join(lines) or "No bros yet."


def send_report():
    with mutate() as st:  # first, so the scheduler never sends the same report twice
        st["settings"]["last_report"] = iso(now())
    title, body = status_report()
    return notify(title, body, priority="default")


def report_due(s):
    day = int(s.get("report_day", 0))
    if day < 0 or not notification_channels(s):
        return False
    local = datetime.datetime.now().astimezone()
    if local.weekday() != day or local.hour < REPORT_HOUR:
        return False
    last = parse(s.get("last_report"))
    return not last or last.astimezone().date() < local.date()


def check_silent_bros(s):
    """Warn when a bro that backs up here has sent nothing for a while: his NAS may be off."""
    if not s.get("alert_receivers", True):
        return
    hours = int(s["alert_hours"])
    st = load_state()
    for user, r in st["receivers"].items():
        if not r.get("accepted"):
            continue
        stats = receive_stats.get(user) or {}
        ref = max(filter(None, [parse(stats.get("last_seen")), parse(r.get("accepted_at") or r.get("created"))]),
                  default=None)
        last_alert = parse(r.get("silent_alert"))
        if ref and now() - ref > datetime.timedelta(hours=hours) and \
                (not last_alert or now() - last_alert > datetime.timedelta(hours=72)):
            name = r.get("bro_name") or r["name"]
            notify(f"{name} has not backed up to you for a while",
                   f"Nothing came in from {name} since {local_time(iso(ref))}. His NAS may be off or offline, "
                   "unless he is sending his first backup on a disk. Maybe let him know.", priority="default")
            with mutate() as st2:
                if user in st2["receivers"]:
                    st2["receivers"][user]["silent_alert"] = iso(now())


