# version : 0.1
# created by : JK and CF
# last edited : 06/11/2026
# Name : bro-backup (tests/lab/pause.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pausing backups on the lab: a running restic stops within seconds, nothing new starts, and after
resuming the backup continues without sending again what was already uploaded.

Start a fresh lab first:  cd lab && pwsh ./lab.ps1 -Action Reset -Force && pwsh ./lab.ps1 -SizeMB 120
Then:                     python3 tests/lab/pause.py
"""

import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402
from e2e import LAB, Bro, fail, flash, ok, setup, step, wait  # noqa: E402


def in_alice(code):
    return subprocess.run(["docker", "compose", "exec", "-T", "alice", "python", "-c",
                           "import sys; sys.path.insert(0, '/app')\n" + code],
                          cwd=LAB, capture_output=True, text=True).stdout


def restic_running():
    return "restic" in in_alice("import os\nfor p in os.listdir('/proc'):\n"
                                "    if p.isdigit():\n"
                                "        try: print(open(f'/proc/{p}/cmdline','rb').read().split(b'\\0')[0].decode())\n"
                                "        except OSError: pass")


def main():
    a, b = Bro("alice", 8481), Bro("bob", 8482)

    step("1. Pairing, with a slow upload so the first backup takes a while")
    setup(a, "Alice", "alice-password-1")
    setup(b, "Bob", "bob-password-12")
    in_alice("from bro import core\nwith core.mutate() as st: st['settings']['limit_upload_kib'] = 400")
    wait(lambda: "Setting up the connection" not in a.get("/") + b.get("/"), 90, "tickets ready")
    code = re.search(r"(BRO1\.[A-Za-z0-9_-]{30,})", a.post("/invite", {"name": "Bob", "quota": "5", "mutual_ok": "1"})).group(1)
    flash(b.post("/add", {"code": code, "mutual": "1", "quota": "5"}))
    wait(lambda: re.search(r"Backup[^<]*: \d+%", a.get("/")), 300, "alice's first backup running")

    def incoming():
        return list(json.loads(b.get("/live.json"))["incoming"].values())
    wait(lambda: any(v["active"] and v["speed"] > 0 for v in incoming()), 90, "bob sees the backup coming in")
    v = next((v for v in incoming() if v["active"]), {})
    (ok if v.get("speed", 0) > 0 and "Receiving now" in v.get("text", "") else fail)(
        f"bob shows it: {v.get('text', '')}")
    (ok if v.get("speed", 0) < 2 * 400 * 1024 else fail)("the speed fits the 400 KiB/s upload limit")
    (ok if "data-incoming=" in b.get("/") else fail)("bob's overview has the live line")

    step("2. Pause while it runs")
    kind, msg = flash(a.post("/pause", {"hours": "0"}))
    (ok if kind == "ok" and "stops in a few seconds" in msg else fail)(f"paused: {msg[:90]}")
    wait(lambda: not restic_running(), 60, "restic stopped")
    (ok if not restic_running() else fail)("restic is no longer running")
    wait(lambda: "Paused during" in (a.dest().get("last_warning") or ""), 60, "the bro row says it was paused")
    d = a.dest()
    (ok if d.get("pause_stop") and not d.get("last_error") and not d.get("last_ok") else fail)(
        "marked as interrupted, not as failed")
    page = a.get("/")
    (ok if "Backups are paused until you resume them" in page and ">Now</button>" not in page else fail)(
        "banner shown, no Now button")
    kind, msg = flash(a.post(f"/dest/{d['id']}/run", {}))
    (ok if kind == "err" and "paused" in msg else fail)("Back up now is refused while paused")
    time.sleep(25)  # two scheduler rounds
    (ok if not restic_running() else fail)("nothing started by itself during the pause")
    sc = a.get("/selfcheck.json?run=1")
    (ok if "Paused until you resume them" in sc else fail)("self-check shows the pause")

    step("3. Resume: the backup continues and finishes")
    kind, msg = flash(a.post("/resume", {}))
    (ok if kind == "ok" and "continues now" in msg else fail)(f"resumed: {msg[:80]}")
    in_alice("from bro import core\nwith core.mutate() as st: st['settings']['limit_upload_kib'] = 0")
    wait(lambda: a.dest().get("last_ok"), 400, "backup finished after resuming")
    d = a.dest()
    (ok if d.get("last_ok") and not d.get("pause_stop") and not d.get("last_error") else fail)(
        "backup OK, interruption cleared")

    for x in ("alice", "bob"):
        n = subprocess.run(["docker", "compose", "logs", x], cwd=LAB, capture_output=True, text=True).stdout.count("Traceback")
        (ok if n == 0 else fail)(f"{x}: {n} traceback(s) in the log")

    print()
    if e2e.failures:
        print(f"{e2e.RED}{len(e2e.failures)} check(s) failed{e2e.END}")
        return 1
    print(f"{e2e.GREEN}All checks passed{e2e.END}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
