# version : 0.1
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (tests/lab/stale_lock.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A restic that is killed during a backup leaves its lock at the bro. The next backup removes that stale lock
first, so the weekly cleanup runs instead of failing with "repository is already locked".

Start a fresh lab first:  cd lab && pwsh ./lab.ps1 -Action Reset -Force && pwsh ./lab.ps1 -SizeMB 80
Then:                     python3 tests/lab/stale_lock.py
"""

import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402
from e2e import LAB, Bro, fail, flash, ok, setup, step, wait  # noqa: E402
from pause import in_alice  # noqa: E402


def in_bob(code):
    return subprocess.run(["docker", "compose", "exec", "-T", "bob", "python", "-c",
                           "import sys; sys.path.insert(0, '/app')\n" + code],
                          cwd=LAB, capture_output=True, text=True).stdout


def locks_at_alice():
    return in_alice("import glob\nprint(len(glob.glob('/data/receive/*/locks/*')))").strip()


def main():
    a, b = Bro("alice", 8481), Bro("bob", 8482)
    step("1. Pair, bob uploads slowly")
    setup(a, "Alice", e2e.A_PW); setup(b, "Bob", e2e.B_PW)
    in_bob("from bro import core\nwith core.mutate() as st: st['settings']['limit_upload_kib'] = 400")
    wait(lambda: "Setting up the connection" not in a.get("/") + b.get("/"), 90, "tickets ready")
    code = re.search(r"(BRO1\.[A-Za-z0-9_-]{30,})", a.post("/invite", {"name": "Bob", "quota": "5"})).group(1)
    flash(b.post("/add", {"code": code, "quota": "5"}))
    wait(lambda: locks_at_alice() not in ("", "0"), 300, "bob's backup holds a lock at alice")
    step("2. Kill bob's restic hard")
    in_bob("import os,signal\nfor p in os.listdir('/proc'):\n if p.isdigit():\n  try:\n   c=open(f'/proc/{p}/cmdline','rb').read().split(b'\\0')\n   if c[0].endswith(b'restic') and b'backup' in c: os.kill(int(p), signal.SIGKILL); print('killed', p)\n  except OSError: pass")
    time.sleep(8)
    n = locks_at_alice()
    (ok if n not in ("", "0") else fail)(f"its lock is left behind at alice ({n})")
    step("3. Next backup with the weekly cleanup")
    in_bob("from bro import core\nwith core.mutate() as st:\n st['settings']['limit_upload_kib']=0\n for d in st['destinations']: d['last_prune']=None")
    def run_now():
        kind, msg = flash(b.post(f"/dest/{b.dest()['id']}/run", {}))
        return kind == "ok"
    wait(run_now, 300, "backup started")
    t0 = b.dest().get("last_ok")
    wait(lambda: b.dest().get("last_ok") != t0 and b.dest().get("last_prune"), 900, "backup and cleanup finished")
    d = b.dest()
    (ok if d.get("last_prune") and not d.get("last_error") else fail)(f"backup and weekly cleanup OK (error: {d.get('last_error')}, warning: {d.get('last_warning')})")
    # the restore test may still run right after the backup, with a lock of its own: wait for it
    wait(lambda: locks_at_alice() == "0", 300, "no lock left at alice")
    n = locks_at_alice()
    (ok if n == "0" else fail)(f"no lock left at alice ({n})")
    logs = subprocess.run(["docker","compose","logs","bob"],cwd=LAB,capture_output=True,text=True).stdout
    (ok if "left behind" in logs else fail)("bob's log says it removed the stale lock")
    print()
    if e2e.failures:
        print(f"{e2e.RED}{len(e2e.failures)} check(s) failed{e2e.END}")
        sys.exit(1)
    print(f"{e2e.GREEN}All checks passed{e2e.END}")


if __name__ == "__main__":
    main()
