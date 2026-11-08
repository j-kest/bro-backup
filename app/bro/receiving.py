# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/receiving.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Logins on our rest-server for the bros that back up here."""

import os
import secrets

import bcrypt

from .core import GIB, HTPASSWD, RECEIVE_DIR, human_bytes, iso, load_state, log, mutate, notify, now, sha256, slug, state_lock


# ---------------------------------------------------------------- htpasswd (receiving)
def read_htpasswd():
    users = {}
    if os.path.exists(HTPASSWD):
        with open(HTPASSWD) as f:
            for line in f:
                if ":" in line:
                    u, h = line.strip().split(":", 1)
                    users[u] = h
    return users


def write_htpasswd(users):
    tmp = HTPASSWD + ".tmp"
    with open(tmp, "w") as f:
        for u, h in users.items():
            f.write(f"{u}:{h}\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, HTPASSWD)


def set_rest_user(user, pw):
    h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=10)).decode().replace("$2b$", "$2y$", 1)
    with state_lock:
        users = read_htpasswd()
        users[user] = h
        write_htpasswd(users)


_metrics_checked = {"hash": None}


def ensure_metrics_user():
    """The rest-server login that reads its counters (incoming.py). Bros never get this name."""
    from . import incoming
    pw = incoming.metrics_password()
    with state_lock:
        users = read_htpasswd()
        h = users.get(incoming.METRICS_USER)
        if h and h == _metrics_checked["hash"]:
            return
        if not h or not bcrypt.checkpw(pw.encode(), h.replace("$2y$", "$2b$", 1).encode()):
            users[incoming.METRICS_USER] = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=10)).decode().replace(
                "$2b$", "$2y$", 1)
            write_htpasswd(users)
        _metrics_checked["hash"] = users[incoming.METRICS_USER]


def remove_rest_user(user):
    with state_lock:
        users = read_htpasswd()
        users.pop(user, None)
        write_htpasswd(users)


def new_receiver(name, quota_gib, invite=True, seed_back=False, mutual_ok=True):
    """A login on our rest-server for a bro. Returns (user, password, token)."""
    with mutate() as st:
        base = slug(name)
        user, i = base, 2
        # never reuse a name that still has a folder or a tombstone: a bro who pairs again must not
        # land in his old repository (other password) or in someone else's leftover data
        while user in st["receivers"] or user in read_htpasswd() or user in (st.get("revoked") or {}) \
                or user == "metrics" \
                or os.path.exists(os.path.join(RECEIVE_DIR, user)):
            user, i = f"{base}-{i}", i + 1
        pw = secrets.token_urlsafe(24)
        tok = secrets.token_urlsafe(16) if invite else None
        st["receivers"][user] = {"name": name, "quota_gib": quota_gib, "created": iso(now()),
                                 "pw_sha": sha256(pw), "token": tok, "accepted": not invite,
                                 "seed_back": seed_back, "mutual_ok": bool(mutual_ok)}
    if not invite:
        set_rest_user(user, pw)
    # An invite gets no rest-server login yet: /bro/accept makes one with a new password. So a code that
    # leaks before it is used cannot be used to store data here (and an unused code has no quota to skip).
    return user, pw, tok


def drop_unaccepted_logins():
    """Logins that older versions made for invites that were never accepted: remove them."""
    st = load_state()
    waiting = {u for u, r in st["receivers"].items() if not r.get("accepted")}
    with state_lock:
        users = read_htpasswd()
        gone = [u for u in users if u in waiting]
        if gone:
            for u in gone:
                users.pop(u)
            write_htpasswd(users)
            log.info("Removed the rest-server login of %d unused invite(s)", len(gone))




# ---------------------------------------------------------------- quota, enforced here
# The bro that sends checks his quota before each backup, but a bro that wants to can skip that.
# rest-server's --max-size only limits all bros together. So this side measures every bro's folder and
# takes his login away while he is over (the bcrypt line is kept, so nothing has to be exchanged again).
QUOTA_MARGIN = 1.05  # a little room: a backup that started under the quota may finish


def enforce_quota(user, usage):
    st = load_state()
    r = st["receivers"].get(user)
    if not r or not r.get("accepted"):
        return
    over = usage > int(r.get("quota_gib") or 0) * GIB * QUOTA_MARGIN
    name = r.get("bro_name") or r.get("name") or user
    if over and not r.get("quota_blocked"):
        with state_lock:
            users = read_htpasswd()
            line = users.pop(user, None)
            write_htpasswd(users)
        with mutate() as st2:
            if user in st2["receivers"]:
                st2["receivers"][user].update(quota_blocked=iso(now()), htpasswd=line)
        log.warning("%s is over his quota (%s of %s GiB): backups to this NAS are blocked", name,
                    human_bytes(usage), r.get("quota_gib"))
        notify(f"{name} is over his quota", f"He uses {human_bytes(usage)} of {r.get('quota_gib')} GiB. His "
               "backups to you are blocked until you give him more space (next to his name on the overview).",
               priority="default")
    elif not over and r.get("quota_blocked"):
        with state_lock:
            users = read_htpasswd()
            if r.get("htpasswd"):
                users[user] = r["htpasswd"]
            write_htpasswd(users)
        with mutate() as st2:
            if user in st2["receivers"]:
                st2["receivers"][user].pop("quota_blocked", None)
                st2["receivers"][user].pop("htpasswd", None)
        log.info("%s is under his quota again: backups to this NAS work again", name)
