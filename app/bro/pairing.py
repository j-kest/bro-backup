# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/pairing.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Pairing codes and the pairing handshake."""

import json
import os
import re
import secrets
import threading

from . import backup, lan, procs, receiving
from .core import (
    clean_name,
    ESCROW_DIR,
    b64d,
    b64e,
    get_dest,
    iso,
    load_state,
    log,
    mutate,
    my_tickets,
    now,
    settings,
    update_dest,
)


# ---------------------------------------------------------------- codes
def encode_code(prefix, payload):
    return prefix + b64e(json.dumps(payload, separators=(",", ":")).encode())


def decode_code(code, prefix, fields):
    code = re.sub(r"\s+", "", code or "")
    if not code.startswith(prefix):
        raise ValueError(f"Not a valid code (it should start with {prefix})")
    data = json.loads(b64d(code[len(prefix):]))
    for k in fields:
        if not data.get(k):
            raise ValueError(f"Code is missing field '{k}'")
    return data


def make_invite(name, quota_gib, seed_back, mutual_ok=True):
    if not my_tickets.get("data") or not my_tickets.get("pair"):
        raise RuntimeError("The connection is not ready yet. Wait half a minute and try again.")
    user, pw, tok = receiving.new_receiver(name, quota_gib, seed_back=seed_back, mutual_ok=mutual_ok)
    # m: whether we also back up to him when he offers space back. Decided here, by whoever makes the code:
    # otherwise a bro who uses the code could make our NAS send its backups to him without being asked.
    return encode_code("BRO1.", {"v": 1, "n": settings()["name"], "dt": lan.advertised("data"),
                                 "pt": lan.advertised("pair"), "u": user, "pw": pw, "tok": tok, "q": quota_gib,
                                 "m": bool(mutual_ok)})


def make_help_code(user):
    """Help code for a bro whose NAS crashed: gives access to his key copy."""
    if not my_tickets.get("pair"):
        raise RuntimeError("The connection is not ready yet.")
    if not os.path.exists(os.path.join(ESCROW_DIR, f"{user}.json")):
        raise RuntimeError("There is no key copy of this bro here yet. He needs to set a recovery code first.")
    tok = secrets.token_urlsafe(16)
    with mutate() as st:
        st["receivers"][user].update(help_token=tok, help_created=iso(now()))
    return encode_code("BROH1.", {"v": 1, "n": settings()["name"], "pt": lan.advertised("pair"), "tok": tok})


# ---------------------------------------------------------------- pairing
PW_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")  # what secrets.token_urlsafe makes: nothing that changes a URL


def check_peer_fields(name, dt, pt, user, pw):
    """Everything here came from another bro (a code or a pair call) and ends up in restic's repository
    URL and in dumbpipe's arguments. Refuse anything that is not exactly what BRO Backup itself sends."""
    from . import peers  # late import: peers imports this module's neighbours
    if not (peers.valid_ticket(dt) and peers.valid_ticket(pt)):
        raise ValueError("The code holds an invalid address.")
    if not (isinstance(user, str) and peers.USER_RE.match(user)) or not (isinstance(pw, str) and PW_RE.match(pw)):
        raise ValueError("The code holds an invalid login.")
    return clean_name(name) or user


def add_destination(name, dt, pt, user, pw, seed=False, accepting=False, receiver_user=None):
    name = check_peer_fields(name, dt, pt, user, pw)
    # accepting: the bro is about to rotate the password from the code. No backup may start before
    # that: rest-server keeps accepting the old password for up to 30 s, and a backup that started
    # with it would fail halfway.
    dt, pt = lan.clean_peer_ticket(dt), lan.clean_peer_ticket(pt)
    d = {"id": secrets.token_hex(4), "name": name, "data_ticket": dt, "pair_ticket": pt,
         "user": user, "password": pw, "repo_password": secrets.token_urlsafe(32),
         "created": iso(now()), "mode": "seeding" if seed else None, "accepting": accepting,
         "receiver_user": receiver_user}
    with mutate() as st:
        st["destinations"].append(d)
    if seed:
        threading.Thread(target=backup.run_seed, args=(d["id"],), daemon=True).start()
    return d


def accept_code(code, mutual, quota_gib, seed):
    """Use someone else's bro code. With mutual, we give space back right away."""
    data = decode_code(code, "BRO1.", ("n", "dt", "pt", "u", "pw", "tok"))
    if not isinstance(data.get("tok"), str):
        raise ValueError("Code is missing field 'tok'")
    mutual = bool(mutual) and data.get("m") is not False  # the bro said no to backing up to us
    d = add_destination(data["n"], data["dt"], data["pt"], data["u"], data["pw"], seed=seed, accepting=True)
    # pt always: the bro needs it to tell us when his address changes
    payload = {"tok": data["tok"], "n": settings()["name"], "mutual": bool(mutual), "pt": lan.advertised("pair")}
    if mutual:
        user, pw, _ = receiving.new_receiver(d["name"], quota_gib, invite=False)
        payload.update({"dt": lan.advertised("data"), "u": user, "pw": pw, "q": quota_gib})
        update_dest(d["id"], receiver_user=user)
    try:
        finish_accept(d["id"], payload)
        result = "ok"
    except RuntimeError as e:
        if "(403)" in str(e):  # code already used or revoked: leave nothing half done
            with mutate() as st:
                st["destinations"] = [x for x in st["destinations"] if x["id"] != d["id"]]
                if mutual:
                    st["receivers"].pop(payload["u"], None)
            if mutual:
                receiving.remove_rest_user(payload["u"])
            raise ValueError("This code was already used or revoked. Ask for a new one.")
        log.warning("Confirming the pairing failed, will retry later: %s", e)
        with mutate() as st:
            st["pending_accepts"].append({"dest_id": d["id"], "payload": payload, "error": str(e)})
        # accepting stays on: since 0.10.11 an invite has no login at the bro until he confirms, so a backup
        # now would only fail. retry_pending starts the first backup once he has confirmed.
        result = str(e)
    if not seed and result == "ok":
        threading.Thread(target=backup.run_backup, args=(d["id"],), daemon=True).start()
    return dict(d, mutual=mutual, mutual_refused=data.get("m") is False), result


def finish_accept(dest_id, payload):
    d = get_dest(dest_id)
    resp = procs.pair_call(d["pair_ticket"], "POST", "/bro/accept", payload)
    # The bro rotates the password from the code: an intercepted code is worthless afterwards
    fields = {"accepting": False, "last_contact": iso(now())}
    if not isinstance(resp, dict):
        resp = {}
    if isinstance(resp.get("pw"), str) and PW_RE.match(resp["pw"]):  # it ends up in the restic URL
        fields["password"] = resp["pw"]
    if isinstance(resp.get("lk"), str) and PW_RE.match(resp["lk"]):
        fields["link_key"] = resp["lk"]
    user = payload.get("u")
    if user and resp.get("mutual") is False:  # he made the code without backing up to us: no login needed here
        fields["receiver_user"] = None
        with mutate() as st:
            st["receivers"].pop(user, None)
        receiving.remove_rest_user(user)
        log.info("%s does not back up to us: the login made for him is removed again", d["name"])
    update_dest(dest_id, **fields)


def retry_pending():
    st = load_state()
    for item in list(st["pending_accepts"]):
        try:
            if not get_dest(item["dest_id"]):
                raise LookupError("destination removed")
            finish_accept(item["dest_id"], item["payload"])
            ok = True
            if (get_dest(item["dest_id"]) or {}).get("mode") is None:  # confirmed: the first backup can start
                threading.Thread(target=backup.run_backup, args=(item["dest_id"],), daemon=True).start()
        except LookupError:
            ok = True
        except Exception as e:
            ok = "(403)" in str(e)  # the bro no longer knows the code: do not retry forever
            item["error"] = str(e)
            if ok:
                update_dest(item["dest_id"], last_error="Your bro refused the pairing. Ask him for a new code.")
        with mutate() as st2:
            st2["pending_accepts"] = [x for x in st2["pending_accepts"] if x["dest_id"] != item["dest_id"]]
            if not ok:
                st2["pending_accepts"].append(item)


