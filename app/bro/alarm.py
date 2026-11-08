# version : 0.1
# created by : JK and CF
# last edited : 03/11/2026
# Name : bro-backup (bro/alarm.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Ransomware alarm: notice a backup that looks like files were encrypted or wiped, and keep old versions.

Ransomware often encrypts files days or weeks after getting in. The nightly backup then sends the
encrypted files to the bros, and cleaning up old versions would slowly throw away the last good
ones. So after every backup each folder is compared with its own past:

- share: far more files new or changed than this folder normally has (encrypted in place, or
  written as new files);
- deleted: far fewer files than in the previous backup (wiped, or replaced by renamed copies);
- renamed: many files that came back with an extra extension (photo.jpg -> photo.jpg.locked);
- notes: ransom notes (HOW_TO_DECRYPT.txt and the like) appearing in several places.

The last three need the list of changes between the previous and the new snapshot (`restic diff`).
The very first backup of a folder is never judged: everything is new then.

When something is found, the alarm goes on for this NAS: a notification with high priority, a red
banner, and NO cleanup of old versions at any bro until you look. Backups keep running: the old
versions stay anyway. Clearing the alarm ("This was me") needs your password.
"""

import json
import os
import re
import subprocess
import threading

from .core import RESTIC, iso, load_state, log, mutate, notify, now, parse, settings

MIN_FILES = 100          # never judge fewer touched files than this: small folders change a lot
SHARE = 0.25             # at least a quarter of the folder new or changed...
FACTOR = 5               # ...and at least 5 times what is normal for this folder
BASELINE_FLOOR = 0.01    # "normal" is never taken as less than 1%
BASELINE_RUNS = 10
DELETE_SHARE = 0.25      # a quarter of the files gone since the previous backup
RENAME_MIN = 50          # files that came back with an extra extension
NOTE_MIN = 3             # ransom notes in at least this many places
DIFF_TIMEOUT = 900
DIFF_MAX_PATHS = 300_000  # beyond this the rename check works on a part: enough to see a pattern
EXAMPLES = 10
REMIND_HOURS = 24
NOTE_RE = re.compile(r"(?i)(decrypt|ransom|(recover|restore)[_ .-]*((my|your|all)[_ .-]*)?(files|data)"
                     r"|how[_ .-]*to[_ .-]*(back|get)[_ .-]*(your[_ .-]*)?files)[^/]*\.(txt|html?|hta|url|rtf)$")
EXT_RE = re.compile(r"^(.+\.[^./]{1,12})\.([^./]{1,24})$")


def enabled():
    return settings().get("ransomware_watch", True)


def active():
    return load_state().get("alarm")


# ---------------------------------------------------------------- judging one folder
def baseline(history, key):
    """The usual share of touched files for a folder, from earlier backups (its first one left out)."""
    shares = []
    for e in history:
        v = (e.get("src") or {}).get(key)
        if not v or not v[3]:  # v = [new, changed, unmodified, had a previous backup]
            continue
        total = v[0] + v[1] + v[2]
        if total:
            shares.append((v[0] + v[1]) / total)
    shares = sorted(shares[-BASELINE_RUNS:])
    if not shares:
        return BASELINE_FLOOR
    mid = len(shares) // 2
    med = shares[mid] if len(shares) % 2 else (shares[mid - 1] + shares[mid]) / 2
    return max(BASELINE_FLOOR, med)


def judge_counts(key, cur, prev, base):
    """cur/prev: {"files_new", "files_changed", "files_unmodified"} of this and the previous backup."""
    reasons = []
    touched = cur["files_new"] + cur["files_changed"]
    total = touched + cur["files_unmodified"]
    if total and touched >= MIN_FILES:
        share = touched / total
        if share >= SHARE and share >= FACTOR * base:
            reasons.append(f"{key}: {touched} of {total} files new or changed ({share:.0%}, normally about {base:.0%})")
    prev_total = prev["files_new"] + prev["files_changed"] + prev["files_unmodified"]
    gone = prev_total - total
    if prev_total and gone >= MIN_FILES and gone / prev_total >= DELETE_SHARE:
        reasons.append(f"{key}: {gone} of {prev_total} files gone since the previous backup ({gone / prev_total:.0%})")
    return reasons


def judge_diff(key, added, removed):
    """added/removed: paths from restic diff. Returns (reasons, examples)."""
    reasons, examples = [], []
    gone = set(removed)
    renamed = []
    for p in added:
        m = EXT_RE.match(p)
        if m and m.group(1) in gone:
            renamed.append((m.group(1), p))
    if len(renamed) >= RENAME_MIN and len(renamed) >= 0.5 * max(1, len(gone)):
        ext = max({p.rsplit(".", 1)[1] for _, p in renamed}, key=lambda e: sum(p.endswith("." + e) for _, p in renamed))
        reasons.append(f"{key}: {len(renamed)} files came back with an extra extension, mostly .{ext}")
        examples += [f"{a} -> {b}" for a, b in renamed[:EXAMPLES]]
    notes = [p for p in added if NOTE_RE.search(p.rsplit("/", 1)[-1])]
    places = {os.path.dirname(p) for p in notes}
    if len(places) >= NOTE_MIN:
        reasons.append(f"{key}: files that look like ransom notes in {len(places)} folders")
        examples += notes[:EXAMPLES]
    return reasons, examples


def snapshot_diff(env, prev_id, cur_id):
    """Run restic diff (streamed: it can be long). Returns (added, removed) paths, or None when it did not work."""
    try:
        p = subprocess.Popen([RESTIC, "--no-lock", "diff", "--json", prev_id, cur_id], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, env=env)
    except OSError as e:
        log.info("Comparing snapshots failed: %s", e)
        return None
    added, removed, n = [], [], 0
    watchdog = threading.Timer(DIFF_TIMEOUT, p.kill)  # also stops a diff that hangs while we read
    watchdog.start()
    try:
        for line in p.stdout:  # noqa: SIM115 (closed below)
            if not line.startswith('{"message_type":"change"'):
                continue
            n += 1
            if n > DIFF_MAX_PATHS:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            mod, path = msg.get("modifier") or "", msg.get("path") or ""
            if mod == "+":
                added.append(path)
            elif mod == "-":
                removed.append(path)
        p.wait(DIFF_TIMEOUT)
    except subprocess.TimeoutExpired:
        p.kill()
        return None
    finally:
        watchdog.cancel()
        p.stdout.close()
    return (added, removed) if p.returncode == 0 else None


# ---------------------------------------------------------------- after a backup
def inspect(d, items, env=None):
    """Judge every folder of the backup that just finished. items: per folder its counts and snapshot id.
    Returns (reasons, examples). Never raises: a failing check must not fail the backup."""
    if not enabled():
        return [], []
    reasons, examples = [], []
    prev_items = {x["key"]: x for x in d.get("last_sources") or [] if x.get("snapshot_id")}
    history = d.get("history") or []
    for it in items:
        try:
            prev = prev_items.get(it["key"])
            if not prev or not it.get("snapshot_id"):
                continue  # first backup of this folder (or of this version): nothing to compare with
            r = judge_counts(it["key"], it, prev, baseline(history, it["key"]))
            if env and prev["snapshot_id"] != it["snapshot_id"]:
                diff = snapshot_diff(env, prev["snapshot_id"], it["snapshot_id"])
                if diff:
                    r2, ex = judge_diff(it["key"], *diff)
                    r += r2
                    examples += ex
            reasons += r
        except Exception as e:  # noqa: BLE001
            log.warning("Ransomware check of %s failed: %s", it.get("key"), e)
    return reasons, examples[:EXAMPLES * 2]


def raise_alarm(d, reasons, examples, items):
    """Turn the alarm on (or add to it), and notify. The snapshots of this backup are marked suspicious."""
    snaps = [it["snapshot_id"][:8] for it in items if it.get("snapshot_id")]
    before = [x["snapshot_id"][:8] for x in d.get("last_sources") or [] if x.get("snapshot_id")]
    with mutate() as st:
        a = st.get("alarm")
        new = not a
        if new:
            a = st["alarm"] = {"at": iso(now()), "dest": d["name"], "reasons": [], "examples": [],
                               "snaps": {}, "before": {}}
        a["last_at"] = iso(now())
        a["reasons"] = (a["reasons"] + [x for x in reasons if x not in a["reasons"]])[:20]
        a["examples"] = (a["examples"] + [x for x in examples if x not in a["examples"]])[:20]
        a["snaps"].setdefault(d["id"], [])
        a["snaps"][d["id"]] = (a["snaps"][d["id"]] + snaps)[-50:]
        a["before"].setdefault(d["id"], before)  # the snapshots right before the first suspicious one
        due = new or not parse(a.get("notified_at")) or \
            (now() - parse(a["notified_at"])).total_seconds() >= REMIND_HOURS * 3600
        if due:
            a["notified_at"] = iso(now())
        a = dict(a)
    log.warning("Ransomware alarm (backup to %s): %s", d["name"], "; ".join(reasons))
    if due:
        name = settings().get("name") or "your NAS"
        notify(f"Possible ransomware on {name}",
               "The backup that just ran looks like files were encrypted or deleted:\n- " + "\n- ".join(a["reasons"][:6])
               + ("\nFor example: " + ", ".join(a["examples"][:5]) if a["examples"] else "")
               + "\nNothing is cleaned up at your bros until you look: older versions stay. Check your files. "
                 "Did you do this yourself (a big reorganisation, for example)? Then click 'This was me' on the overview.")
    return a


def remind():
    """Hourly: a reminder every REMIND_HOURS while the alarm is on."""
    a = active()
    if not a or not parse(a.get("notified_at")):
        return
    if (now() - parse(a["notified_at"])).total_seconds() >= REMIND_HOURS * 3600:
        with mutate() as st:
            if st.get("alarm"):
                st["alarm"]["notified_at"] = iso(now())
        notify(f"Ransomware alarm still on for {settings().get('name') or 'your NAS'}",
               f"Since {a['at'][:16].replace('T', ' ')} UTC nothing is cleaned up at your bros. "
               "Check your files, then clear the alarm on the overview.")


def clear():
    with mutate() as st:
        a = st.pop("alarm", None)
        if a:
            st["alarm_cleared"] = {"at": iso(now()), "since": a.get("at")}
    if a:
        log.info("Ransomware alarm cleared by the user (on since %s)", a.get("at"))
    return a
