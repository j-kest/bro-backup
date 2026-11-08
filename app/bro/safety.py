# version : 0.10.8
# created by : JK and CF
# last edited : 05/11/2026
# Name : bro-backup (bro/safety.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""How safe is your data? One score out of 100, and what to do to make it higher.

Based on the 3-2-1 rule (three copies, on two kinds of storage, one far away): your NAS is one
copy, every bro with a recent backup is another one far away. On top of that: is a restore known
to work, is the backup undamaged, can you get back in after a crash, and would you hear it when
something goes wrong. Some problems cap the score whatever else is fine: without a recent copy at
a bro, or with the ransomware alarm on, your data is not safe.
"""


from .core import PAUSED_MODES, load_state, notification_channels, now, parse

FRESH_DAYS = 2          # a backup older than this does not count as a current copy
RESTORE_TEST_MAX_DAYS = 35
LEVELS = ((90, "Very safe", "ok"), (70, "Safe", "ok"), (40, "At risk", "warn"), (0, "Not safe", "err"))


def _age_days(stamp):
    t = parse(stamp)
    return (now() - t).total_seconds() / 86400 if t else None


def compute(st=None):
    st = st or load_state()
    s = st["settings"]
    dests = [d for d in st["destinations"] if not d.get("accepting")]
    fresh = [d for d in dests if d.get("mode") not in PAUSED_MODES and _age_days(d.get("last_ok")) is not None
             and _age_days(d["last_ok"]) <= FRESH_DAYS and not d.get("last_error")]
    items = []

    def item(points, ok, text, fix=None, link=None):
        items.append({"points": points, "ok": ok, "text": text, "fix": None if ok else fix,
                      "link": None if ok else link})

    if not dests:
        item(30, False, "No bro yet: your data exists only on this NAS", "Pair with a bro", "index")
    else:
        item(30, bool(fresh), f"A recent copy at {fresh[0]['name']}" if fresh else "No bro has a backup of the last two days",
             "Check the problems with your bros below", "index")
    item(15, len(fresh) >= 2, "A second bro with a recent copy" if len(fresh) >= 2 else "Only one copy away from home",
         "Add a second bro: if one is gone, the other still has everything", "index")
    tested = [d for d in fresh if (d.get("restore_test") or {}).get("ok")
              and (_age_days(d["restore_test"].get("at")) or 99) <= RESTORE_TEST_MAX_DAYS]
    item(15, bool(fresh) and len(tested) == len(fresh),
         "Restore test passed this month" if fresh and len(tested) == len(fresh) else "No passed restore test this month",
         "Run a restore test under Restore" if s.get("restore_test", True) else "Turn on the monthly restore test",
         "settings_page")
    damaged = [d for d in dests if d.get("full_check") and not d["full_check"].get("ok")]
    item(10, not damaged, "No damage found in your backups" if not damaged else f"Damaged data at {damaged[0]['name']}",
         "Open Restore next to that bro and repair", "index")
    item(10, bool(st["recovery"].get("key")), "Recovery code set" if st["recovery"].get("key") else "No recovery code",
         "Create one: without it you cannot get anything back after a crash", "settings_page")
    keys = [d for d in dests if d.get("escrow_at")]
    item(5, bool(keys), f"Key copy at {keys[0]['name']}" if keys else "No key copy at a bro yet",
         "Set a recovery code; the key copy follows by itself", "settings_page")
    ch = notification_channels(s)
    item(10, bool(ch), f"Notifications by {', '.join(ch)}" if ch else "No notifications: you would not hear about problems",
         "Set up ntfy or email", "settings_page")
    watch, alarm = s.get("ransomware_watch", True), st.get("alarm")
    item(5, watch and not alarm, "Ransomware alarm watching" if watch and not alarm else
         ("Ransomware alarm is ON" if alarm else "Ransomware alarm is off"),
         "Check your files, see the red banner" if alarm else "Turn it on in Settings", "index" if alarm else "settings_page")

    from . import urbackup  # late import: only needed when UrBackup is there
    ub = [x for x in urbackup.status(st) if x["clients"]]
    if ub:  # computers backed up by UrBackup count too; the score stays out of 100
        out = [x for x in ub if not x["included"]]
        item(10, not out, "UrBackup storage goes offsite" if not out else f"UrBackup storage {out[0]['rel']} stays at home",
             "Include the UrBackup folder in Settings", "settings_page")
        silent = [c for x in ub for c in x["clients"] if not c["ok"]]
        item(10, not silent, "Every computer backed up recently" if not silent else
             f"{len(silent)} computer(s) without a recent backup, such as {silent[0]['name']}",
             "Check the computers without a recent backup in UrBackup", "index")

    total = sum(i["points"] for i in items)
    score = round(sum(i["points"] for i in items if i["ok"]) * 100 / total)
    if not fresh:
        score = min(score, 20)
    if alarm:
        score = min(score, 40)
    label, level = next((lab, lev) for limit, lab, lev in LEVELS if score >= limit)
    todo = sorted([i for i in items if not i["ok"]], key=lambda i: -i["points"])
    return {"score": score, "label": label, "level": level, "checks": items, "todo": todo}


def report_line(st=None):
    r = compute(st)
    line = f"Safety: {r['score']}/100 ({r['label']})"
    if r["todo"]:
        line += ". To do: " + "; ".join(i["fix"] for i in r["todo"][:3])
    return line
