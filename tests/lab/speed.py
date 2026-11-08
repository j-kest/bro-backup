# version : 0.1
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (tests/lab/speed.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The speed test on the lab, both ways, through the real pair server (waitress with its request limits).
The upload goes in parts the pair server accepts; the sender times it.

Start a fresh lab first:  cd lab && pwsh ./lab.ps1 -Action Reset -Force && pwsh ./lab.ps1 -SizeMB 20
Then:                     python3 tests/lab/speed.py
"""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402
from e2e import Bro, fail, flash, ok, setup, step, wait  # noqa: E402
from pause import in_alice  # noqa: E402


def main():
    a, b = Bro("alice", 8481), Bro("bob", 8482)
    step("1. Pairing")
    setup(a, "Alice", "alice-password-1")
    setup(b, "Bob", "bob-password-12")
    wait(lambda: "Setting up the connection" not in a.get("/") + b.get("/"), 90, "tickets ready")
    code = re.search(r"(BRO1\.[A-Za-z0-9_-]{30,})", a.post("/invite", {"name": "Bob", "quota": "5"})).group(1)
    flash(b.post("/add", {"code": code, "quota": "5"}))
    wait(lambda: b.dest(), 60, "bob knows alice")
    server = in_alice("import importlib.util\nprint('waitress' if importlib.util.find_spec('waitress') else '')").strip()
    (ok if server == "waitress" else fail)(f"the image has waitress, like the real one ({server or 'missing'})")

    step("2. Speed test from bob to alice")
    did = b.dest()["id"]
    wait(lambda: b.dest().get("last_ok") and not b.dest().get("accepting"), 300, "bob's first backup finished")
    started = {}

    def start():  # a backup that the pairing started can still be busy: then the test is refused, try again
        started["kind"], started["msg"] = flash(b.post(f"/dest/{did}/speed", {}))
        return started["kind"] != "err"  # started: the speed page, without a message
    wait(start, 300, "speed test accepted")
    (ok if started.get("kind") != "err" else fail)("speed test started")
    res = {}

    def done():
        d = b.dest()
        res.update(speed=d.get("speed"), err=d.get("speed_error"))
        return (res.get("speed") or {}).get("up_bps") or res.get("err")
    wait(done, 240, "speed test finished")
    sp = res.get("speed") or {}
    (ok if not res.get("err") else fail)(f"no error ({res.get('err')})")
    (ok if (sp.get("up_bps") or 0) > 1e6 else fail)(f"upload measured: {(sp.get('up_bps') or 0) / 1e6:.0f} Mbit/s")
    (ok if (sp.get("down_bps") or 0) > 1e6 else fail)(f"download measured: {(sp.get('down_bps') or 0) / 1e6:.0f} Mbit/s")
    for x in ("alice", "bob"):
        n = subprocess.run(["docker", "compose", "logs", x], cwd=e2e.LAB, capture_output=True, text=True).stdout.count("Traceback")
        (ok if n == 0 else fail)(f"{x}: {n} traceback(s) in the log")
    print()
    if e2e.failures:
        print(f"{e2e.RED}{len(e2e.failures)} check(s) failed{e2e.END}")
        return 1
    print(f"{e2e.GREEN}All checks passed{e2e.END}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
