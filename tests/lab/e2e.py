# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (tests/lab/e2e.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end test on the lab: two real bros in Docker.

Pairs alice and bob both ways, waits for the first backups, gives alice another IP address,
checks that bob learns it and that backups keep working, then unpairs and checks both sides,
pairs again, and lets alice stop storing bob's backups only.

Start a fresh lab first:  cd lab && pwsh ./lab.ps1 -Action Reset -Force && pwsh ./lab.ps1 -SizeMB 40
Then:                     python3 tests/lab/e2e.py
Exit code 0 when everything passed. Works on Linux, macOS and Windows (Python 3.9+, no packages).
"""

import argparse
import http.cookiejar
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request

GREEN, RED, DIM, END = ("\033[32m", "\033[31m", "\033[2m", "\033[0m") if sys.stdout.isatty() or os.environ.get("CI") \
    else ("", "", "", "")
LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "lab")
failures = []


def ok(msg):
    print(f"{GREEN}  OK    {msg}{END}", flush=True)


def fail(msg):
    failures.append(msg)
    print(f"{RED}  FAIL  {msg}{END}", flush=True)


def step(msg):
    print(f"\n{msg}", flush=True)


A_PW, B_PW = "alice-password-1", "bob-password-12"


class Bro:
    def __init__(self, name, port):
        self.name, self.base = name, f"http://127.0.0.1:{port}"
        self.web = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                               urllib.request.ProxyHandler({}))

    def get(self, path):
        with self.web.open(self.base + path, timeout=200) as r:
            return r.read().decode()

    def post(self, path, data, token_page="/"):
        data = list(data.items()) if isinstance(data, dict) else list(data)
        data.append(("csrf", re.search(r'name="csrf" value="([^"]+)"', self.get(token_page)).group(1)))
        req = urllib.request.Request(self.base + path, data=urllib.parse.urlencode(data).encode())
        with self.web.open(req, timeout=200) as r:
            return r.read().decode()

    def state(self):
        out = subprocess.run(["docker", "compose", "exec", "-T", self.name, "cat", "/data/config/state.json"],
                             cwd=LAB, capture_output=True, text=True, check=True).stdout
        return json.loads(out)

    def dest(self):
        ds = self.state()["destinations"]
        return ds[0] if ds else None


def wait(pred, secs, what):
    end = time.time() + secs
    while time.time() < end:
        try:
            if pred():
                return True
        except Exception:
            pass
        time.sleep(2)
    fail(f"timeout after {secs} s: {what}")
    return False


def flash(page):
    m = re.search(r'<div class="flash (\w+)">(.*?)</div>', page, re.S)
    return (m.group(1), re.sub(r"\s+", " ", m.group(2)).strip()) if m else (None, "")


def setup(b, name, pw):
    page = b.post("/setup", [("name", name), ("pw", pw), ("pw2", pw), ("src", "/nas/tank"), ("src", "/nas/media")],
                  "/setup")
    rc = re.search(r"([A-Z2-9]{4}(?:-[A-Z2-9]{4}){7})", page).group(1)
    b.post("/recovery-code", {"last": rc[-4:]}, "/recovery-code")


def change_address(bro):
    pwsh = os.environ.get("PWSH") or shutil.which("pwsh")
    if pwsh:
        subprocess.run([pwsh, "-NoProfile", "-File", os.path.join(LAB, "lab.ps1"), "-Action", "ChangeAddress",
                        "-Bro", bro], cwd=LAB, check=True)
        return
    cid = subprocess.run(["docker", "compose", "ps", "-q", bro], cwd=LAB, capture_output=True, text=True).stdout.strip()
    net = subprocess.run(["docker", "inspect", "-f", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}", cid],
                         capture_output=True, text=True).stdout.strip()
    subprocess.run(["docker", "network", "disconnect", net, cid], check=True)
    subprocess.run(["docker", "network", "connect", "--ip", "172.29.71.21", net, cid], check=True)


def backup_now(b):
    """Click Now; when another job for this bro is still running (the restore test after a first backup,
    for example), the app says so: wait for it and click again."""
    before = (b.dest() or {}).get("last_ok")
    end = time.time() + 600
    while True:
        kind, msg = flash(b.post(f"/dest/{b.dest()['id']}/run", {}))
        if kind == "ok" or time.time() > end:
            break
        print(f"{DIM}        {b.name}: {msg[:100]}{END}", flush=True)
        time.sleep(10)
    return wait(lambda: b.dest().get("last_ok") not in (None, before) and not b.dest().get("last_error"), 300,
                f"backup of {b.name} after the change")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-address", action="store_true", help="skip the IP address change")
    ap.add_argument("--stop-after-address", action="store_true", help="stop after the address change (debugging)")
    args = ap.parse_args()
    a, b = Bro("alice", 8481), Bro("bob", 8482)

    step("1. Setup and mutual pairing")
    setup(a, "Alice", A_PW)
    setup(b, "Bob", B_PW)
    wait(lambda: "Setting up the connection" not in a.get("/") + b.get("/"), 90, "tickets ready")
    code = re.search(r"(BRO1\.[A-Za-z0-9_-]{30,})", a.post("/invite", {"name": "Bob", "quota": "5", "mutual_ok": "1"})).group(1)
    kind, msg = flash(b.post("/add", {"code": code, "mutual": "1", "quota": "5"}))
    (ok if kind == "ok" else fail)(f"pairing: {msg[:90]}")
    if wait(lambda: a.dest().get("last_ok") and b.dest().get("last_ok"), 400, "first backups both ways"):
        ok("first backups: alice to bob and bob to alice")
    for x in (a, b):
        if x.dest() and x.dest().get("last_error"):
            fail(f"{x.name}: {x.dest()['last_error'][:200]}")

    # what a bro deletes is kept: on the real data folder every file of bob must get its second name at alice
    out = subprocess.run(["docker", "compose", "exec", "-T", "alice", "python", "-c",
                          "import sys, os; sys.path.insert(0, '/app')\nfrom bro import kept\nkept.sweep_all()\n"
                          "n = sum(len(f) for u in kept.users() for _r, _d, f in os.walk(os.path.join(kept.KEPT_DIR, u, 'live')))\n"
                          "print(n, kept.unsupported)"], cwd=LAB, capture_output=True, text=True).stdout.strip()
    (ok if out.split(" ")[0].isdigit() and int(out.split(" ")[0]) > 3 and out.endswith("[]") else fail)(
        f"alice keeps a second name for bob's files ({out})")

    step("2. Hello: both sides know how to reach each other")
    if wait(lambda: a.dest().get("link_key") and b.dest().get("link_key") and
            all(r.get("peer_pt") for r in a.state()["receivers"].values()), 120, "link keys and addresses exchanged"):
        ok("link keys exchanged, receivers know the pair address of their bro")
    if a.dest().get("receiver_user") and b.dest().get("receiver_user"):
        ok("both directions linked")
    else:
        fail("the two directions are not linked")

    if not args.skip_address:
        step("3. Alice gets another IP address")
        old_ticket = b.dest()["data_ticket"]
        change_address("alice")
        if wait(lambda: b.dest()["data_ticket"] != old_ticket and b.dest().get("address_changed"), 240,
                "bob receives alice's new address"):
            ok("bob received alice's new address")
        wait(lambda: a.get("/healthz") is not None, 60, "alice answers again")
        if backup_now(b):
            ok("bob backs up to alice at her new address")
        if backup_now(a):
            ok("alice still backs up to bob")
        if "new address received" in b.get("/"):
            ok("bob's overview shows the new address")
        else:
            fail("bob's overview does not mention the new address")

    if args.stop_after_address:
        return 1 if failures else 0

    step("4. Bob stops backing up to alice, asks to delete, and stops storing hers")
    bdest = b.dest()
    page = b.get(f"/dest/{bdest['id']}/remove")
    (ok if "Also stop storing Alice" in page else fail)("remove page offers to stop the other direction too")
    kind, msg = flash(b.post(f"/dest/{bdest['id']}/remove",
                             {"confirm": "Alice", "ask_delete": "1", "also_receiver": "1"}))
    (ok if kind == "err" and b.dest() else fail)(f"without the password nothing happens: {msg[:60]}")
    kind, msg = flash(b.post(f"/dest/{bdest['id']}/remove",
                             {"confirm": "Alice", "ask_delete": "1", "also_receiver": "1", "current_pw": B_PW}))
    (ok if kind == "ok" else fail)(f"removed at bob: {msg[:90]}")
    sb = b.state()
    (ok if not sb["destinations"] and not sb["receivers"] else fail)("bob has no destination and no receiver left")
    (ok if sb["revoked"] else fail)("bob keeps a tombstone for alice's login")
    if wait(lambda: a.dest().get("mode") == "revoked", 120, "alice learns that bob stopped"):
        ok("alice shows: stopped by Bob")
    sa = a.state()
    (ok if not sa["receivers"] else fail)("alice no longer stores bob's backups")
    (ok if sa["pending_deletes"] else fail)("bob's data at alice is scheduled for deletion")
    (ok if "Backups of bros that stopped" in a.get("/") else fail)("alice's overview lists bob's leftover data")
    (ok if "Backups of bros that stopped" in b.get("/") else fail)("bob's overview lists alice's leftover data")

    step("5. Alice cleans up")
    kind, msg = flash(a.post(f"/dest/{a.dest()['id']}/remove", {"confirm": "bob", "current_pw": A_PW}))
    (ok if kind == "ok" and not a.state()["destinations"] else fail)(f"alice removed bob: {msg[:80]}")
    user = next(iter(a.state()["pending_deletes"]), None)
    if user:
        a.post(f"/leftover/{user}/delete", {"current_pw": A_PW})
        (ok if "Backups of bros that stopped" not in a.get("/") else fail)("bob's leftover data deleted at alice")

    step("6. Pairing again, then alice only stops storing bob's backups")
    code = re.search(r"(BRO1\.[A-Za-z0-9_-]{30,})", a.post("/invite", {"name": "Bob", "quota": "5", "mutual_ok": "1"})).group(1)
    kind, msg = flash(b.post("/add", {"code": code, "mutual": "1", "quota": "5"}))
    (ok if kind == "ok" else fail)(f"paired again: {msg[:80]}")
    for x in (a, b):  # each side still has a tombstone (and bob still has alice's old data): never reuse those names
        st = x.state()
        clash = set(st["revoked"]) & set(st["receivers"])
        (ok if st["revoked"] and not clash else fail)(f"{x.name}: the bro got a new login, not his old one")
    if wait(lambda: a.dest().get("last_ok") and b.dest().get("last_ok") and not b.dest().get("last_error"), 400,
            "backups after pairing again"):
        ok("backups work again both ways")
    user = next(iter(a.state()["receivers"]))
    kind, msg = flash(a.post(f"/receiver/{user}/remove", {"confirm": "Bob"}))
    (ok if kind == "ok" else fail)(f"alice stopped storing bob's backups: {msg[:70]}")
    if wait(lambda: b.dest().get("mode") == "revoked", 120, "bob learns that alice stopped"):
        ok("bob shows: stopped by Alice")
    (ok if backup_now(a) else fail)("alice still backs up to bob")

    step("7. Logs")
    for x in ("alice", "bob"):
        logs = subprocess.run(["docker", "compose", "logs", x], cwd=LAB, capture_output=True, text=True).stdout
        n = logs.count("Traceback")
        (ok if n == 0 else fail)(f"{x}: {n} traceback(s) in the log")

    print()
    if failures:
        print(f"{RED}{len(failures)} check(s) failed{END}")
        return 1
    print(f"{GREEN}All checks passed{END}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
