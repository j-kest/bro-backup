# version : 0.1
# created by : JK and CF
# last edited : 05/11/2026
# Name : bro-backup (tests/lab/urbackup.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""UrBackup storage on the lab: found, included, sent to bob, restored with its hard links intact.

The storage is laid out like UrBackup's (administration manual): a folder per computer, file
backups in YYMMDD-HHMM folders with unchanged files hard-linked to the previous backup, a
`current` link, image files Image_C_YYMMDD_HHMM.vhdz, and urbackup / urbackup_tmp_files at the top.
A real UrBackup server is not part of the lab.

Start a fresh lab first:  cd lab && pwsh ./lab.ps1 -Action Reset -Force && pwsh ./lab.ps1 -SizeMB 40
Then:                     python3 tests/lab/urbackup.py
"""

import datetime
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402
from e2e import LAB, Bro, backup_now, fail, flash, ok, setup, step, wait  # noqa: E402

STORE = os.path.join(LAB, "alice", "nas", "pcbackup", "urbackup")


def stamp(hours_ago, sep="-"):
    return (datetime.datetime.now() - datetime.timedelta(hours=hours_ago)).strftime(f"%y%m%d{sep}%H%M")


def make_storage():
    os.makedirs(os.path.join(STORE, "urbackup_tmp_files"), exist_ok=True)
    os.makedirs(os.path.join(STORE, "urbackup"), exist_ok=True)
    with open(os.path.join(STORE, "urbackup_tmp_files", "incoming.tmp"), "wb") as f:
        f.write(os.urandom(2048))  # must never go offsite
    for name, hours in (("PC-ANNE", 3), ("LAPTOP-TOM", 240)):
        older, newer = os.path.join(STORE, name, stamp(hours + 24)), os.path.join(STORE, name, stamp(hours))
        os.makedirs(os.path.join(older, "C", "Users", "doc"))
        os.makedirs(os.path.join(newer, "C", "Users", "doc"))
        for i in range(20):
            a = os.path.join(older, "C", "Users", "doc", f"offer-{i}.docx")
            with open(a, "w") as f:
                f.write(f"{name} offer {i}\n" * 50)
            os.link(a, os.path.join(newer, "C", "Users", "doc", f"offer-{i}.docx"))  # unchanged: a hard link
        os.symlink(os.path.basename(newer), os.path.join(STORE, name, "current"))
        with open(os.path.join(STORE, name, f"Image_C_{stamp(hours, '_')}.vhdz"), "wb") as f:
            f.write(os.urandom(512 * 1024))


def main():
    a, b = Bro("alice", 8481), Bro("bob", 8482)

    step("1. UrBackup storage on alice's NAS, pairing")
    make_storage()
    setup(a, "Alice", "alice-password-1")
    setup(b, "Bob", "bob-password-12")
    wait(lambda: "Setting up the connection" not in a.get("/") + b.get("/"), 90, "tickets ready")
    code = re.search(r"(BRO1\.[A-Za-z0-9_-]{30,})", a.post("/invite", {"name": "Bob", "quota": "5", "mutual_ok": "1"})).group(1)
    flash(b.post("/add", {"code": code, "mutual": "1", "quota": "5"}))
    wait(lambda: a.dest().get("last_ok"), 400, "first backup of alice")

    step("2. Found, not yet sent offsite")
    a.post("/urbackup/scan", {}, "/settings")
    page = a.get("/")
    (ok if "PCs and servers (UrBackup)" in page and "PC-ANNE" in page and "LAPTOP-TOM" in page else fail)(
        "the overview lists both computers")
    (ok if "is not sent offsite" in page else fail)("the overview says the storage is not sent offsite")
    (ok if re.search(r"LAPTOP-TOM</strong></td>\s*<td class=\"err\"", page) else fail)("LAPTOP-TOM shown as silent")
    st = a.state()
    path = st["urbackup"]["storages"][0]["path"]
    kind, msg = flash(a.post("/urbackup/include", {"path": path}))
    (ok if kind == "ok" and path in a.state()["settings"]["sources"] else fail)(f"included: {msg[:70]}")

    step("3. Sent to bob, restored with hard links")
    backup_now(a)
    snaps = a.get(f"/dest/{a.dest()['id']}/snapshots")
    rows = re.findall(r'<span class="muted">([^<]*)</span>.*?name="snapshot" value="([0-9a-f]{64})"', snaps, re.S)
    snap = next((full for src, full in rows if "pcbackup" in src), None)
    (ok if snap else fail)("a version of the UrBackup storage is listed")
    if snap:
        flash(a.post(f"/dest/{a.dest()['id']}/restore", {"snapshot": snap}))
        wait(lambda: "pcbackup" in (a.dest().get("last_restore") or "") or snap[:8] in (a.dest().get("last_restore") or ""),
             300, "restore of the UrBackup storage")
        out = subprocess.run(["docker", "compose", "exec", "-T", "alice", "python", "-c", """
import os, glob
base = glob.glob('/data/restore/bob/*/*urbackup*')[0]
anne = os.path.join(base, 'PC-ANNE')
dirs = sorted(d for d in os.listdir(anne) if d[:6].isdigit() and '-' in d)
a = os.stat(os.path.join(anne, dirs[0], 'C/Users/doc/offer-1.docx'))
b = os.stat(os.path.join(anne, dirs[1], 'C/Users/doc/offer-1.docx'))
print('hardlink', a.st_ino == b.st_ino, 'nlink', a.st_nlink)
print('current', os.path.islink(os.path.join(anne, 'current')), os.readlink(os.path.join(anne, 'current')) == dirs[1])
print('image', any(f.startswith('Image_C_') for f in os.listdir(anne)))
print('tmp', os.path.exists(os.path.join(base, 'urbackup_tmp_files', 'incoming.tmp')))
"""], cwd=LAB, capture_output=True, text=True)
        res = out.stdout + out.stderr
        print(e2e.DIM + "        " + res.strip().replace("\n", "\n        ") + e2e.END)
        (ok if "hardlink True" in res else fail)("unchanged files come back as hard links (stored once)")
        (ok if "current True True" in res else fail)("the current link comes back and points to the newest backup")
        (ok if "image True" in res else fail)("image files come back")
        (ok if "tmp False" in res else fail)("urbackup_tmp_files was left out")

    step("4. Self-check, notification, logs")
    sc = a.get("/selfcheck.json?run=1")
    (ok if "Computer LAPTOP-TOM" in sc and "Computer PC-ANNE" in sc else fail)("self-check has a row per computer")
    subprocess.run(["docker", "compose", "exec", "-T", "alice", "python", "-c",
                    "import sys; sys.path.insert(0, '/app'); from bro import urbackup; urbackup.check()"],
                   cwd=LAB, capture_output=True)
    logs = subprocess.run(["docker", "compose", "logs", "alice"], cwd=LAB, capture_output=True, text=True).stdout
    exec_log = subprocess.run(["docker", "compose", "exec", "-T", "alice", "python", "-c",
                               "import json; print(json.load(open('/data/config/state.json')).get('urbackup_alerts'))"],
                              cwd=LAB, capture_output=True, text=True).stdout
    (ok if "LAPTOP-TOM" in exec_log else fail)("LAPTOP-TOM's silence was notified")
    (ok if "PC-ANNE" not in exec_log else fail)("PC-ANNE (backed up 3 h ago) was not")
    for x in ("alice", "bob"):
        n = subprocess.run(["docker", "compose", "logs", x], cwd=LAB, capture_output=True, text=True).stdout.count("Traceback")
        (ok if n == 0 else fail)(f"{x}: {n} traceback(s) in the log")
    del logs

    print()
    if e2e.failures:
        print(f"{e2e.RED}{len(e2e.failures)} check(s) failed{e2e.END}")
        return 1
    print(f"{e2e.GREEN}All checks passed{e2e.END}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
