# version : 0.1
# created by : JK and CF
# last edited : 03/11/2026
# Name : bro-backup (tests/lab/ransomware.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ransomware alarm on the lab: alice gets "encrypted", her next backup raises the alarm.

1. alice gets 300 extra documents (in a fresh simulated ZFS snapshot), pairs with bob, backs up twice.
2. A new snapshot holds the attack: every document rewritten as <name>.locked, the originals gone,
   ransom notes in three folders. The next backup must raise the alarm.
3. While the alarm is on, old versions are kept: the number of versions at bob grows with every backup.
4. The version from before the attack restores the original documents.
5. Clearing the alarm needs the password; after that the next backup cleans up again.

Start a fresh lab first:  cd lab && pwsh ./lab.ps1 -Action Reset -Force && pwsh ./lab.ps1 -SizeMB 40
Then:                     python3 tests/lab/ransomware.py
"""

import datetime
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402
from e2e import LAB, Bro, backup_now, fail, flash, ok, setup, step, wait  # noqa: E402

TANK = os.path.join(LAB, "alice", "nas", "tank")
DOCS = 300


def new_snapshot(minutes):
    """A new simulated ZFS snapshot of tank, named a few minutes ahead so it is the newest."""
    when = datetime.datetime.now() + datetime.timedelta(minutes=minutes)
    snap = os.path.join(TANK, ".zfs", "snapshot", when.strftime("auto-%Y-%m-%d_%H-%M"))
    if os.path.exists(snap):
        shutil.rmtree(snap)
    shutil.copytree(TANK, snap, ignore=shutil.ignore_patterns(".zfs"))
    return snap


def versions(b):
    page = b.get(f"/dest/{b.dest()['id']}/snapshots")
    return re.findall(r'<td><code>([0-9a-f]{8})</code>(.*?)</td>.*?<span class="muted">([^<]*)</span>', page, re.S)


def main():
    a, b = Bro("alice", 8481), Bro("bob", 8482)

    step("1. 300 documents, pairing, two normal backups")
    work = os.path.join(TANK, "documents", "work")
    os.makedirs(work, exist_ok=True)
    for i in range(DOCS):
        with open(os.path.join(work, f"offer-{i:03d}.docx"), "w") as f:
            f.write(f"Offer {i} for a customer\n" * 20)
    new_snapshot(1)
    setup(a, "Alice", "alice-password-1")
    setup(b, "Bob", "bob-password-12")
    wait(lambda: "Setting up the connection" not in a.get("/") + b.get("/"), 90, "tickets ready")
    code = re.search(r"(BRO1\.[A-Za-z0-9_-]{30,})", a.post("/invite", {"name": "Bob", "quota": "5", "mutual_ok": "1"})).group(1)
    flash(b.post("/add", {"code": code, "mutual": "1", "quota": "5"}))
    wait(lambda: a.dest().get("last_ok"), 400, "first backup of alice")
    with open(os.path.join(work, "offer-000.docx"), "a") as f:
        f.write("one small change\n")
    new_snapshot(2)
    (ok if backup_now(a) else fail)("a normal second backup")
    (ok if not a.state().get("alarm") else fail)("no alarm after a normal day")
    before = len(versions(a))

    step("2. The attack")
    snap = new_snapshot(3)
    swork = os.path.join(snap, "documents", "work")
    for i in range(DOCS):
        src = os.path.join(swork, f"offer-{i:03d}.docx")
        with open(src + ".locked", "wb") as f:
            f.write(os.urandom(600))
        os.remove(src)
    for d in ("documents", "documents/work", "photos"):
        with open(os.path.join(snap, d, "HOW_TO_DECRYPT.txt"), "w") as f:
            f.write("Your files are encrypted. Pay to get them back.\n")
    backup_now(a)
    st = a.state()
    al = st.get("alarm")
    (ok if al else fail)("the backup after the attack raised the alarm")
    if al:
        print(f"{e2e.DIM}        " + "\n        ".join(al["reasons"]) + e2e.END)
        joined = " ".join(al["reasons"])
        for what in ("extra extension, mostly .locked", "ransom notes in 3 folders", "new or changed"):
            (ok if what in joined else fail)(f"reason found: {what}")
    page = a.get("/")
    (ok if "Possible ransomware" in page else fail)("alice's overview shows the alarm")
    (ok if "ransomware alarm is on" in (a.dest().get("last_warning") or "") else fail)("no cleanup in that backup")
    logs = subprocess.run(["docker", "compose", "logs", "alice"], cwd=LAB, capture_output=True, text=True).stdout
    (ok if "Possible ransomware on Alice" in logs else fail)("notification sent")
    (ok if not b.state().get("alarm") else fail)("bob has no alarm: his files did not change")

    step("3. Old versions are kept while the alarm is on")
    n1 = len(versions(a))
    backup_now(a)
    n2 = len(versions(a))
    (ok if n2 > n1 >= before else fail)(f"versions at bob keep growing: {before}, {n1}, {n2}")
    rows = versions(a)
    (ok if any("suspicious" in m for _v, m, _f in rows) else fail)("Restore marks the suspicious version")
    good = [v for v, m, f in rows if "last before the alarm" in m and f.strip() == "tank"]
    (ok if good else fail)("Restore marks the last version before the alarm")

    step("4. Restore the version from before the attack")
    if good:
        flash(a.post(f"/dest/{a.dest()['id']}/restore", {"snapshot": good[0]}))
        out = os.path.join(LAB, "alice", "data", "restore")

        def restored():
            for root, _d, files in os.walk(out):
                if "offer-123.docx" in files:
                    return open(os.path.join(root, "offer-123.docx")).read()
            return None
        if wait(lambda: restored(), 300, "restore of the good version"):
            (ok if restored().startswith("Offer 123 for a customer") else fail)("restored document is the original")

    step("5. Clearing needs the password, then cleanup starts again")
    a.post("/alarm/clear", {"current_pw": "wrong-password"})
    (ok if a.state().get("alarm") else fail)("a wrong password leaves the alarm on")
    kind, msg = flash(a.post("/alarm/clear", {"current_pw": "alice-password-1"}))
    (ok if kind == "ok" and not a.state().get("alarm") else fail)(f"cleared: {msg[:60]}")
    n3 = len(versions(a))
    backup_now(a)
    n4 = len(versions(a))
    (ok if n4 < n3 else fail)(f"old versions cleaned up again: {n3} -> {n4}")

    step("6. Logs")
    for x in ("alice", "bob"):
        logs = subprocess.run(["docker", "compose", "logs", x], cwd=LAB, capture_output=True, text=True).stdout
        n = logs.count("Traceback")
        (ok if n == 0 else fail)(f"{x}: {n} traceback(s) in the log")

    print()
    if e2e.failures:
        print(f"{e2e.RED}{len(e2e.failures)} check(s) failed{e2e.END}")
        return 1
    print(f"{e2e.GREEN}All checks passed{e2e.END}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
