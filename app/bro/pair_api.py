# version : 1.2.0
# created by : JK and CF
# last edited : 13/11/2026
# Name : bro-backup (bro/pair_api.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""The API bros talk to, only reachable through dumbpipe."""

import json
import os
import secrets
import threading
import time

from flask import Flask, Response, jsonify, request

from . import lan, pairing, peers, probro, receiving, scheduler, space
from .core import (
    clean_name,
    ESCROW_DIR,
    SPEED_MAX_BYTES,
    SPEED_PART,
    SPEED_SECONDS,
    VERSION,
    iso,
    load_state,
    log,
    mutate,
    now,
    receive_stats,
    settings,
    sha256,
)

# ---------------------------------------------------------------- pair API (only via dumbpipe)
APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the app folder, with templates/
pair_app = Flask("bro-pair", root_path=APP_ROOT)
pair_app.config["MAX_CONTENT_LENGTH"] = 512 * 1024


def pair_auth():
    auth = request.authorization
    r = load_state()["receivers"].get(auth.username if auth else "")
    # an invite that was never accepted has no login: the password in an intercepted code opens nothing here
    if not auth or not r or not r.get("accepted") or \
            not secrets.compare_digest(r.get("pw_sha", ""), sha256(auth.password or "")):
        return None
    return auth.username


def refused():
    """401, or 410 with an explanation for a bro whose login we removed on purpose."""
    auth = request.authorization
    t = peers.tombstone_auth(auth.username, auth.password) if auth else None
    if t:
        why = "left" if t.get("reason") == "left" else "revoked"
        return jsonify(error=f"Access {why} on {t['at'][:10]}", revoked=True), 410
    return jsonify(error="Not allowed"), 401


@pair_app.post("/bro/accept")
def bro_accept():
    p = request.get_json(force=True, silent=True) or {}
    tok = p.get("tok", "")
    with mutate() as st:
        user = next((u for u, r in st["receivers"].items()
                     if r.get("token") and secrets.compare_digest(r["token"], tok)), None)
        if not user:
            return jsonify(error="Unknown or already used code"), 403
        r = st["receivers"][user]
        new_pw = secrets.token_urlsafe(24)
        r.update(accepted=True, accepted_at=iso(now()), token=None, pw_sha=sha256(new_pw), bro_name=clean_name(p.get("n")) or None,
                 link_key=secrets.token_urlsafe(24))
        pt = lan.clean_peer_ticket(p.get("pt")) if peers.valid_ticket(p.get("pt")) else None
        if pt:
            r["peer_pt"] = pt
        seed_back, lk, mutual_ok = r.get("seed_back"), r["link_key"], r.get("mutual_ok", True)
    receiving.set_rest_user(user, new_pw)
    mutual = False
    if p.get("mutual") and not mutual_ok:
        log.info("%s offered space back; not used: this invite was made without backing up to him", user)
    elif p.get("mutual") and p.get("dt") and p.get("pt") and p.get("u") and p.get("pw"):
        try:
            d = pairing.add_destination(clean_name(p.get("n")) or user, p["dt"], p["pt"], p["u"], p["pw"],
                                        seed=bool(seed_back), receiver_user=user)
            log.info("Mutual pairing with %s: destination %s added", d["name"], d["id"])
            mutual = True
        except ValueError as e:
            log.warning("Mutual pairing from %s refused: %s", user, e)
    return jsonify(ok=True, n=settings()["name"], pw=new_pw, lk=lk, mutual=mutual)


@pair_app.get("/bro/status")
def bro_status_api():
    user = pair_auth()
    if not user:
        return refused()
    scheduler.refresh_receive_stats(only=user, max_age=60)
    stats = receive_stats.get(user) or {}
    r = load_state()["receivers"][user]
    disk = (space.measure() or {}).get("level", "ok")  # only ok, warn or err: no sizes of our disk
    lim, lim_for = receiving.limit_for_bros()
    return jsonify(usage=stats.get("usage", 0), disk=disk, snapshots=stats.get("snapshots", 0),
                   limit_kib=lim, limit_for=lim_for,
                   quota_gib=r.get("quota_gib", 0), name=settings()["name"], blocked=bool(r.get("quota_blocked")),
                   escrow=os.path.exists(os.path.join(ESCROW_DIR, f"{user}.json")), v=VERSION)


@pair_app.post("/bro/hello")
def bro_hello():
    """A bro that backs up here checks in: his current address in, ours out."""
    user = pair_auth()
    if not user:
        return refused()
    return jsonify(peers.receive_hello(user, request.get_json(force=True, silent=True) or {}))


@pair_app.post("/bro/address")
def bro_address():
    """A bro we back up to has a new address. Proven with the link key from pairing."""
    time.sleep(0.3)
    d = peers.receive_address(request.get_json(force=True, silent=True) or {})
    if not d:
        return jsonify(error="Unknown bro or another identity"), 403
    return jsonify(ok=True)


@pair_app.post("/bro/link")
def bro_link():
    """A bro asks us to prove that his login and our login belong to one pairing (pairs made before v0.10)."""
    user = pair_auth()
    if not user:
        return refused()
    time.sleep(0.3)
    resp = peers.receive_link(user, request.get_json(force=True, silent=True) or {})
    if not resp:
        return jsonify(error="No matching pairing"), 403
    return jsonify(resp)


@pair_app.post("/bro/space-request")
def bro_space_request():
    """A bro that backs up here asks for more space."""
    user = pair_auth()
    if not user:
        return refused()
    resp = probro.receive_space_request(user, request.get_json(force=True, silent=True) or {})
    if not resp:
        return jsonify(error="Not a valid request"), 400
    return jsonify(resp)


@pair_app.post("/bro/goodbye")
def bro_goodbye():
    """A bro stops backing up here, and/or stopped storing our backups."""
    user = pair_auth()
    if not user:
        return refused()
    return jsonify(peers.receive_goodbye(user, request.get_json(force=True, silent=True) or {}))


@pair_app.post("/bro/escrow")
def bro_escrow_put():
    user = pair_auth()
    if not user:
        return jsonify(error="Not allowed"), 401
    blob = (request.get_json(force=True, silent=True) or {}).get("blob")
    if not isinstance(blob, dict) or not {"salt", "nonce", "ct"} <= set(blob):
        return jsonify(error="Invalid key copy"), 400
    os.makedirs(ESCROW_DIR, exist_ok=True)
    path = os.path.join(ESCROW_DIR, f"{user}.json")
    with open(path + ".tmp", "w") as f:
        json.dump({"blob": blob, "stored": iso(now())}, f)
    os.chmod(path + ".tmp", 0o600)
    os.replace(path + ".tmp", path)
    return jsonify(ok=True)


@pair_app.post("/bro/recover")
def bro_recover():
    tok = (request.get_json(force=True, silent=True) or {}).get("tok", "")
    time.sleep(0.5)
    st = load_state()
    user = next((u for u, r in st["receivers"].items()
                 if r.get("help_token") and secrets.compare_digest(r["help_token"], tok)), None)
    path = os.path.join(ESCROW_DIR, f"{user}.json") if user else None
    if not user or not os.path.exists(path):
        return jsonify(error="Unknown or expired help code"), 403
    with open(path) as f:
        return jsonify(blob=json.load(f)["blob"], n=st["settings"]["name"])


_speed_slot = threading.Semaphore(1)  # one speed test at a time: it may take a pair API thread for 30 s
SPEED_BUDGET = 2 * SPEED_MAX_BYTES     # what one bro may move through speed tests ...
SPEED_WINDOW = 3600                    # ... per hour, up and down together: a real test uses at most half
_speed_used = {}                       # user -> [(time, bytes)]
_speed_lock = threading.Lock()


def _speed_allowed(user, size, force=False):
    """Count `size` bytes of speed test for this bro, or refuse when that would go over his budget for this
    hour. force: count it anyway (what was already sent)."""
    t = time.monotonic()
    with _speed_lock:
        used = [x for x in _speed_used.get(user, []) if t - x[0] < SPEED_WINDOW]
        if not force and sum(b for _, b in used) + max(size, 1) > SPEED_BUDGET:
            _speed_used[user] = used
            return False
        _speed_used[user] = used + ([(t, size)] if size else [])
        return True


@pair_app.post("/bro/speedtest")
def bro_speed_upload():
    """Receive test data from a bro and throw it away. Measures how fast it arrives."""
    user = pair_auth()
    if not user:
        return jsonify(error="Not allowed"), 401
    if not _speed_allowed(user, request.content_length or SPEED_PART):
        return jsonify(error="Enough speed tests for this hour. Try again later."), 429
    if not _speed_slot.acquire(blocking=False):
        return jsonify(error="Another speed test is running. Try again in a minute."), 429
    try:
        return _speed_upload()
    finally:
        _speed_slot.release()


def _speed_upload():
    """One part of the upload test. The web server has the whole part before this runs, so timing here would
    only measure reading a buffer: the bro that sends measures the time until our answer instead."""
    request.max_content_length = SPEED_PART + (64 << 10)
    total = 0
    while True:
        chunk = request.stream.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
    return jsonify(bytes=total)


@pair_app.get("/bro/speedtest")
def bro_speed_download():
    """Send test data to a bro for a few seconds, so he can measure his download speed."""
    user = pair_auth()
    if not user:
        return jsonify(error="Not allowed"), 401
    try:
        secs = min(max(int(request.args.get("seconds", SPEED_SECONDS)), 1), 30)
    except ValueError:
        secs = SPEED_SECONDS
    if not _speed_allowed(user, 0):  # what is really sent is counted when the test ends
        return jsonify(error="Enough speed tests for this hour. Try again later."), 429
    if not _speed_slot.acquire(blocking=False):
        return jsonify(error="Another speed test is running. Try again in a minute."), 429
    block = os.urandom(1024 * 1024)

    sent = [0]

    def stream():
        end = time.monotonic() + secs
        while time.monotonic() < end and sent[0] < SPEED_MAX_BYTES:
            yield block
            sent[0] += len(block)

    def done():
        _speed_slot.release()
        _speed_allowed(user, sent[0], force=True)  # what was sent counts, even over the budget: the next test waits
    resp = Response(stream(), mimetype="application/octet-stream")
    resp.call_on_close(done)  # also when the bro hangs up halfway
    return resp


@pair_app.get("/bro/ping")
def bro_ping():
    return jsonify(ok=True, v=VERSION)


