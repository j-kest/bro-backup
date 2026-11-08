# version : 0.1
# created by : JK and CF
# last edited : 05/11/2026
# Name : bro-backup (tests/lab/probro.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Safety score and space requests on the lab.

1. alice and bob pair both ways and back up: alice's overview shows a safety score.
2. alice asks bob for 10 GiB more; bob sees the request, grants it; alice's next backup sees 15 GiB.
3. bob gives alice a reference and exports the usage per month.

Start a fresh lab first:  cd lab && pwsh ./lab.ps1 -Action Reset -Force && pwsh ./lab.ps1 -SizeMB 40
Then:                     python3 tests/lab/probro.py
"""

import csv
import io
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402
from e2e import LAB, Bro, backup_now, fail, flash, ok, setup, step, wait  # noqa: E402


def main():
    a, b = Bro("alice", 8481), Bro("bob", 8482)

    step("1. Pairing, first backups, safety score")
    setup(a, "Alice", "alice-password-1")
    setup(b, "Bob", "bob-password-12")
    wait(lambda: "Setting up the connection" not in a.get("/") + b.get("/"), 90, "tickets ready")
    code = re.search(r"(BRO1\.[A-Za-z0-9_-]{30,})", a.post("/invite", {"name": "Bob", "quota": "5", "mutual_ok": "1"})).group(1)
    flash(b.post("/add", {"code": code, "mutual": "1", "quota": "5"}))
    wait(lambda: a.dest().get("last_ok") and (a.dest().get("restore_test") or {}).get("ok") and a.dest().get("escrow_at"),
         500, "backup, restore test and key copy of alice")
    m = re.search(r'class="safety-score (\w+)"[^>]*>(\d+)<small>', a.get("/"))
    (ok if m else fail)(f"alice's overview shows a safety score: {m.group(2) if m else '-'} ({m.group(1) if m else '-'})")
    if m:
        (ok if int(m.group(2)) == 75 else fail)("75: one bro, tested, recovery code and key copy, but no notifications")
    (ok if "Add a second bro" in a.get("/") else fail)("to do: add a second bro")

    step("2. alice asks bob for more space")
    kind, msg = flash(a.post(f"/dest/{a.dest()['id']}/ask-space", {"gib": "10", "note": "photos keep growing"}))
    (ok if kind == "ok" else fail)(f"asked: {msg[:70]}")
    user = next(iter(b.state()["receivers"]))
    (ok if "asks for 10 GiB more" in b.get("/") and "photos keep growing" in b.get("/") else fail)(
        "bob's overview shows the request with the note")
    kind, msg = flash(b.post(f"/receiver/{user}/space/grant", {}))
    (ok if kind == "ok" and b.state()["receivers"][user]["quota_gib"] == 15 else fail)(f"granted: {msg[:70]}")
    backup_now(a)
    (ok if a.dest().get("remote_quota_gib") == 15 else fail)(f"alice now sees {a.dest().get('remote_quota_gib')} GiB at bob")

    step("3. Reference and export at bob")
    b.post(f"/receiver/{user}/ref", {"ref": "Klant 0042"})
    (ok if "Klant 0042" in b.get("/") else fail)("reference shown in the list")
    rows = list(csv.reader(io.StringIO(b.get("/receivers.csv")), delimiter=";"))
    row = next((r for r in rows[1:] if r[1] == user), None)
    (ok if row and row[3] == "Klant 0042" and float(row[6]) > 0 else fail)(
        f"CSV row: {';'.join(row) if row else 'missing'}")

    step("4. Logs")
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
