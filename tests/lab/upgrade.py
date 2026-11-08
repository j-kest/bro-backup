# version : 0.1
# created by : JK and CF
# last edited : 02/11/2026
# Name : bro-backup (tests/lab/upgrade.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Upgrade test on the lab: two bros paired on an older version, then upgraded one at a time.

1. alice and bob start on the OLD image, pair both ways and make their first backups.
2. Only alice moves to the NEW image: backups still work both ways (a new bro next to an old one).
3. bob moves to the NEW image too: both sides say hello, exchange link keys and link the two directions.
4. alice gets another IP address: bob learns it and keeps backing up.
5. bob stops storing alice's backups: alice is told.

Start a fresh lab first:  cd lab && pwsh ./lab.ps1 -Action Reset -Force && pwsh ./lab.ps1 -Image <old> -SizeMB 40
Then:                     python3 tests/lab/upgrade.py --old <old image> --new <new image>
For example --old ghcr.io/j-kest/bro-backup:0.9.0 --new bro-backup:lab
"""

import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402
from e2e import LAB, Bro, backup_now, change_address, fail, flash, ok, setup, step, wait  # noqa: E402


def switch(bro, image):
    """Recreate one bro on another image. Its data folder stays."""
    env = dict(os.environ, BRO_IMAGE=image)
    subprocess.run(["docker", "compose", "up", "-d", "--no-build", "--force-recreate", bro], cwd=LAB, env=env,
                   check=True, capture_output=True)


def version(b):
    out = subprocess.run(["docker", "compose", "exec", "-T", b.name, "python", "-c",
                          "from bro.core import VERSION; print(VERSION)"], cwd=LAB, capture_output=True, text=True)
    return out.stdout.strip()


def login(b, pw):
    """A new image means a new session store: log in again."""
    b.web = Bro(b.name, int(b.base.rsplit(":", 1)[1])).web
    page = b.post("/login", {"pw": pw}, "/login")
    return "Log out" in page or "logout" in page


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", required=True, help="image of the old version, already running in the lab")
    ap.add_argument("--new", required=True, help="image of the new version")
    args = ap.parse_args()
    a, b = Bro("alice", 8481), Bro("bob", 8482)
    pw = {"alice": "alice-password-1", "bob": "bob-password-12"}

    step(f"1. Both on the old version ({version(a)}): setup, mutual pairing, first backups")
    setup(a, "Alice", pw["alice"])
    setup(b, "Bob", pw["bob"])
    wait(lambda: "Setting up the connection" not in a.get("/") + b.get("/"), 90, "tickets ready")
    code = re.search(r"(BRO1\.[A-Za-z0-9_-]{30,})", a.post("/invite", {"name": "Bob", "quota": "5", "mutual_ok": "1"})).group(1)
    kind, msg = flash(b.post("/add", {"code": code, "mutual": "1", "quota": "5"}))
    (ok if kind == "ok" else fail)(f"pairing on the old version: {msg[:80]}")
    if wait(lambda: a.dest().get("last_ok") and b.dest().get("last_ok"), 400, "first backups both ways"):
        ok("first backups on the old version, both ways")
    old_dest = {x.name: dict(x.dest()) for x in (a, b)}

    step("2. Only alice upgrades: a new bro next to an old one")
    switch("alice", args.new)
    wait(lambda: a.get("/healthz") is not None, 90, "alice answers after the upgrade")
    v = version(a)
    (ok if v and v != version(b) else fail)(f"alice runs {v}, bob still runs {version(b)}")
    (ok if login(a, pw["alice"]) else fail)("alice: logging in again works")
    st = a.state()
    (ok if all(k in st for k in ("revoked", "pending_goodbyes", "pending_deletes")) else fail)(
        "alice's state has the new fields")
    (ok if a.dest()["id"] == old_dest["alice"]["id"] and a.state()["receivers"] else fail)(
        "alice kept her bro and his login")
    if wait(lambda: a.dest().get("peer_version") is None and a.dest().get("hello_at"), 120,
            "alice's hello to the old bob (he does not know hello yet)"):
        ok("alice's hello to old bob is tolerated (no hello on his side yet)")
    (ok if backup_now(a) else fail)("alice (new) backs up to bob (old)")
    (ok if backup_now(b) else fail)("bob (old) backs up to alice (new)")

    step("3. bob upgrades too")
    switch("bob", args.new)
    wait(lambda: b.get("/healthz") is not None, 90, "bob answers after the upgrade")
    (ok if version(b) == version(a) else fail)(f"bob runs {version(b)}")
    (ok if login(b, pw["bob"]) else fail)("bob: logging in again works")
    if wait(lambda: a.dest().get("link_key") and b.dest().get("link_key"), 180, "hello and link keys"):
        ok("both sides said hello and exchanged link keys")
    if wait(lambda: all(r.get("peer_pt") for x in (a, b) for r in x.state()["receivers"].values()), 120,
            "receivers know the pair address of their bro"):
        ok("both receivers know how to reach their bro")
    if wait(lambda: a.dest().get("receiver_user") and b.dest().get("receiver_user"), 240,
            "the two directions linked after the upgrade"):
        ok("the two directions are linked (paired before the upgrade)")
    (ok if backup_now(a) else fail)("alice backs up to bob")
    (ok if backup_now(b) else fail)("bob backs up to alice")
    for x in (a, b):  # snapshots made on the old version are still there, next to the new ones
        n = len(set(re.findall(r"<td><code>([0-9a-f]{8})</code></td>", x.get(f"/dest/{x.dest()['id']}/snapshots"))))
        (ok if n >= 3 else fail)(f"{x.name}: {n} snapshots listed, old and new")

    step("4. Alice gets another IP address")
    old_ticket = b.dest()["data_ticket"]
    change_address("alice")
    if wait(lambda: b.dest()["data_ticket"] != old_ticket, 240, "bob receives alice's new address"):
        ok("bob received alice's new address")
    wait(lambda: a.get("/healthz") is not None, 60, "alice answers again")
    (ok if backup_now(b) else fail)("bob backs up to alice at her new address")

    step("5. Bob stops storing alice's backups")
    user = next(iter(b.state()["receivers"]))
    kind, msg = flash(b.post(f"/receiver/{user}/remove", {"confirm": "Alice"}))
    (ok if kind == "ok" else fail)(f"bob stopped storing alice's backups: {msg[:70]}")
    if wait(lambda: a.dest().get("mode") == "revoked", 120, "alice learns that bob stopped"):
        ok("alice shows: stopped by Bob")

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
