# version : 0.1
# created by : JK and CF
# last edited : 03/11/2026
# Name : bro-backup (tests/lab/pickup.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Disaster on the lab: alice loses her NAS and gets everything back from a disk that bob made.

1. alice and bob pair both ways and back up; alice's key copy reaches bob.
2. bob clicks Copy to disk next to alice: her encrypted backup and key copy go to the shared "usb" folder.
3. On a "PC" (a container without network, through install/restore-from-disk.ps1): only the disk and
   alice's recovery code bring back her files, identical to the originals.
4. alice's NAS is wiped. bob goes offline. The new alice is set up from the disk with only the recovery
   code, and restores from the disk: identical files again, without bob.

Start a fresh lab first:  cd lab && pwsh ./lab.ps1 -Action Reset -Force && pwsh ./lab.ps1 -SizeMB 40
Then:                     python3 tests/lab/pickup.py [--image bro-backup:lab]
"""

import argparse
import filecmp
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402
from e2e import LAB, Bro, fail, flash, ok, step, wait  # noqa: E402

ROOT = os.path.join(LAB, "..")
TANK = os.path.join(LAB, "alice", "nas", "tank")


def setup_rc(b, name, pw):
    """Like e2e.setup, but returns the recovery code."""
    page = b.post("/setup", [("name", name), ("pw", pw), ("pw2", pw), ("src", "/nas/tank"), ("src", "/nas/media")],
                  "/setup")
    rc = re.search(r"([A-Z2-9]{4}(?:-[A-Z2-9]{4}){7})", page).group(1)
    b.post("/recovery-code", {"last": rc[-4:]}, "/recovery-code")
    return rc


def same_tree(a, b, sub):
    """Every file under a/sub is in b/sub with the same content. Returns the number compared."""
    n = 0
    for root, _d, files in os.walk(os.path.join(a, sub)):
        for fn in files:
            rel = os.path.relpath(os.path.join(root, fn), a)
            other = os.path.join(b, rel)
            if not os.path.isfile(other) or not filecmp.cmp(os.path.join(a, rel), other, shallow=False):
                fail(f"different or missing after restore: {rel}")
                return -1
            n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default=os.environ.get("BRO_IMAGE", "bro-backup:lab"))
    args = ap.parse_args()
    a, b = Bro("alice", 8481), Bro("bob", 8482)

    step("1. Pairing, backups, alice's key copy at bob")
    rc = setup_rc(a, "Alice", "alice-password-1")
    setup_rc(b, "Bob", "bob-password-12")
    wait(lambda: "Setting up the connection" not in a.get("/") + b.get("/"), 90, "tickets ready")
    code = re.search(r"(BRO1\.[A-Za-z0-9_-]{30,})", a.post("/invite", {"name": "Bob", "quota": "5", "mutual_ok": "1"})).group(1)
    flash(b.post("/add", {"code": code, "mutual": "1", "quota": "5"}))
    if wait(lambda: a.dest().get("last_ok") and a.dest().get("escrow_at"), 400, "alice's backup and key copy at bob"):
        ok("alice backed up to bob, her key copy is there")

    step("2. bob copies alice's backup to the disk")
    user = next(iter(b.state()["receivers"]))
    kind, msg = flash(b.post(f"/receiver/{user}/pickup", {}))
    (ok if kind == "ok" else fail)(f"copy started: {msg[:80]}")
    wait(lambda: (b.state()["receivers"][user].get("pickup") or {}).get("ok"), 300, "copy to disk done")
    path = b.state()["receivers"][user]["pickup"]["path"]        # as bob's container sees it: /seed/...
    disk = os.path.join(LAB, "usb", os.path.relpath(path, "/seed"))
    (ok if os.path.isfile(os.path.join(disk, "bro-pickup.json")) and os.path.isfile(os.path.join(disk, "escrow.json"))
     else fail)(f"on the disk: {os.path.basename(disk)} with marker and key copy")

    step("3. Restore on a PC without NAS and without network")
    out = tempfile.mkdtemp(prefix="bro-pc-")
    pwsh = os.environ.get("PWSH") or shutil.which("pwsh")
    p = subprocess.run([pwsh, "-NoProfile", "-File", os.path.join(ROOT, "install", "restore-from-disk.ps1"),
                        "-Disk", disk, "-To", out, "-Image", args.image, "-CodeFromInput"],
                       input=rc + "\n", capture_output=True, text=True, timeout=900)
    print(e2e.DIM + "        " + "\n        ".join(re.sub(r"\x1b\[[0-9;]*m", "", p.stdout).strip().splitlines()[-4:]) + e2e.END)
    (ok if p.returncode == 0 else fail)("restore-from-disk.ps1 finished" + ("" if p.returncode == 0 else f": {p.stderr[-300:]}"))
    n = same_tree(TANK, os.path.join(out, "tank"), "documents")
    (ok if n > 0 else fail)(f"{n} documents restored on the PC, identical to the originals")
    p = subprocess.run([pwsh, "-NoProfile", "-File", os.path.join(ROOT, "install", "restore-from-disk.ps1"),
                        "-Disk", disk, "-To", out, "-Image", args.image, "-CodeFromInput"],
                       input="AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH\n", capture_output=True, text=True, timeout=300)
    (ok if p.returncode != 0 and "not correct" in p.stdout else fail)("a wrong recovery code restores nothing")

    step("4. alice's NAS is gone; bob goes offline; the new alice recovers from the disk")
    subprocess.run(["docker", "compose", "stop", "alice", "bob"], cwd=LAB, check=True, capture_output=True)
    data = os.path.join(LAB, "alice", "data")
    for x in os.listdir(data):
        p2 = os.path.join(data, x)
        shutil.rmtree(p2) if os.path.isdir(p2) and not os.path.islink(p2) else os.remove(p2)
    subprocess.run(["docker", "compose", "up", "-d", "--no-build", "alice"], cwd=LAB, check=True, capture_output=True,
                   env=dict(os.environ, BRO_IMAGE=args.image))
    a = Bro("alice", 8481)
    wait(lambda: a.get("/healthz") is not None, 90, "the new alice answers")
    page = a.get("/setup")
    (ok if "Copied by <strong>Bob</strong>" in page else fail)("setup offers the disk from bob")
    kind, msg = flash(a.post("/setup", {"pw": "alice-new-pass1", "pw2": "alice-new-pass1", "disk": path,
                                        "disk_code": rc}, "/setup"))
    (ok if kind == "ok" and "Recovered from the disk" in msg else fail)(f"recovered: {msg[:90]}")
    d = a.dest()
    (ok if d and d.get("mode") == "hold" and d.get("restore_from") == path else fail)(
        "bob is back, paused, restoring from the disk")
    snaps = a.get(f"/dest/{d['id']}/snapshots")
    (ok if "Restoring from the <strong>disk</strong>" in snaps else fail)("Restore reads the disk, bob is offline")
    rows = re.findall(r'<td><code>([0-9a-f]{8})</code>.*?<span class="muted">([^<]*)</span>.*?name="snapshot" value="([0-9a-f]{64})"',
                      snaps, re.S)
    tank = next((full for _s, src, full in rows if src.strip() == "tank"), None)
    (ok if tank else fail)("a version of tank is listed")
    if tank:
        flash(a.post(f"/dest/{d['id']}/restore", {"snapshot": tank}))
        if wait(lambda: "from the disk" in (a.dest().get("last_restore") or "") or
                str(a.dest().get("last_error") or "").startswith("Restore"), 300, "restore from the disk"):
            (ok if not a.dest().get("last_error") else fail)(f"restored: {a.dest().get('last_restore', '')[:90]}")
            base = next((r for r, dirs, _f in os.walk(os.path.join(data, "restore"))
                         if os.path.basename(r) == "tank" and "documents" in dirs), None)
            n = same_tree(TANK, base, "documents") if base else -1
            (ok if n > 0 else fail)(f"{n} documents restored on the new NAS from the disk, identical")

    step("5. Logs")
    logs = subprocess.run(["docker", "compose", "logs", "alice"], cwd=LAB, capture_output=True, text=True).stdout
    nt = logs.count("Traceback")
    (ok if nt == 0 else fail)(f"alice: {nt} traceback(s) in the log")
    shutil.rmtree(out, ignore_errors=True)

    print()
    if e2e.failures:
        print(f"{e2e.RED}{len(e2e.failures)} check(s) failed{e2e.END}")
        return 1
    print(f"{e2e.GREEN}All checks passed{e2e.END}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
