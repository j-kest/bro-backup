# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/peers.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Staying in touch with bros: fresh addresses, saying goodbye, and data that bros left behind.

Addresses. A ticket holds an endpoint id (who) and addresses (where). iroh normally finds a bro
whose IP changed by itself, through the n0 DNS and the relays. Without those (relays blocked, a
LAN without internet) the addresses in the ticket are all there is. So:
- every bro that backs up somewhere says hello there every HELLO_SECONDS, sending its own current
  tickets and getting the other side's current tickets back;
- a bro whose own tickets change pushes them to every bro that backs up to it;
- a new ticket is only accepted with the same endpoint id as before: the address may change, the
  identity may not.

Goodbye. Removing a bro tells him (or retries for GOODBYE_DAYS). Whoever stops storing a bro's
backups keeps a tombstone, so that bro gets a clear answer instead of a bare 401. Data that a bro
asked to delete is deleted after DELETE_GRACE_DAYS, never automatically in append-only mode.
"""

import base64
import datetime
import hashlib
import hmac
import os
import re
import secrets
import shutil
import threading

from . import lan, procs, receiving
from .core import (
    version_or_none,
    clean_name,
    ESCROW_DIR,
    RECEIVE_DIR,
    VERSION,
    dest_ports,
    get_dest,
    human_bytes,
    iso,
    load_state,
    local_time,
    log,
    mutate,
    my_tickets,
    notify,
    now,
    parse,
    settings,
    sha256,
    update_dest,
)

HELLO_SECONDS = 6 * 3600
OLD_PEER_SECONDS = 3600  # a bro without hello (v0.9 or older) is asked again every hour: he may have updated
RETRY_SECONDS = 600
GOODBYE_DAYS = 30
TOMBSTONE_DAYS = 90
DELETE_GRACE_DAYS = 7
USER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
KEY_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")  # link keys are made by secrets.token_urlsafe


# ---------------------------------------------------------------- tickets
TICKET_RE = re.compile(r"^endpoint[a-z2-7]{50,2000}$")


def valid_ticket(ticket):
    return isinstance(ticket, str) and bool(TICKET_RE.match(ticket)) and ticket_id(ticket) is not None


def _ticket_bytes(ticket):
    if not isinstance(ticket, str) or not TICKET_RE.match(ticket):
        return None
    s = ticket[len("endpoint"):].upper()
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except (ValueError, base64.binascii.Error):
        return None


def ticket_id(ticket):
    """The endpoint id (hex) in a dumbpipe ticket: byte 0 is the format variant, 1..32 the id."""
    raw = _ticket_bytes(ticket)
    if not raw or len(raw) < 33 or raw[0] != 0:
        return None
    return raw[1:33].hex()


def _varint(raw, i):
    val = shift = 0
    while True:
        b = raw[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def ticket_addrs(ticket):
    """Relays and direct addresses in a ticket, for the self-check. Never raises."""
    out = {"relays": [], "direct": []}
    raw = _ticket_bytes(ticket)
    try:
        n, i = _varint(raw, 33)
        for _ in range(n):
            kind, i = raw[i], i + 1
            if kind == 0:  # relay url
                ln, i = _varint(raw, i)
                out["relays"].append(raw[i:i + ln].decode())
                i += ln
            elif kind == 1:  # ip address
                fam, i = raw[i], i + 1
                size = 4 if fam == 0 else 16
                ip = raw[i:i + size]
                i += size
                port, i = _varint(raw, i)
                host = ".".join(map(str, ip)) if fam == 0 else \
                    "[" + ":".join(ip[k:k + 2].hex() for k in range(0, 16, 2)) + "]"
                out["direct"].append(f"{host}:{port}")
            else:
                break
    except (TypeError, IndexError, UnicodeDecodeError):
        pass
    return out


def same_identity(old, new):
    a, b = ticket_id(old), ticket_id(new)
    return bool(a) and a == b


def current_tickets():
    """Our tickets as bros get them, with the addresses on your network (lan.py) added."""
    dt, pt = lan.advertised("data"), lan.advertised("pair")
    return [dt, pt] if dt and pt else None


# ---------------------------------------------------------------- links between the two directions
def linked_receiver(d, st=None):
    """The bro's login on our side when we back up to each other (mutual pairing).
    Only the link made at pairing counts, never a matching name: names come from the other side."""
    st = st or load_state()
    u = d.get("receiver_user")
    return u if u and u in st["receivers"] else None


def linked_dest(user, st=None):
    st = st or load_state()
    return next((d for d in st["destinations"] if user and d.get("receiver_user") == user), None)


def _link_proof(lk, side, nonce, target_id):
    msg = f"bro-link|{side}|{nonce}|{target_id}".encode()
    return hmac.new(str(lk).encode(), msg, hashlib.sha256).hexdigest()


def try_link(user):
    """Link the two directions of a pairing made before v0.10, when nothing recorded that they belong together.

    The bro that backs up here as `user` claims (in hello) that his pair address is X. A claim is not
    enough, so we ask the bro behind X, over our own login there, to prove that he holds the link key of
    `user`. Both proofs are bound to X's endpoint id, so a third bro cannot pass them on. Returns True
    when linked."""
    st = load_state()
    r = st["receivers"].get(user)
    if not r or not r.get("link_key") or not valid_ticket(r.get("peer_pt")) or linked_dest(user, st):
        return False
    pid = ticket_id(r["peer_pt"])
    with mutate() as st2:
        if user in st2["receivers"]:
            st2["receivers"][user]["link_tried"] = iso(now())
    for d in st["destinations"]:
        if d.get("receiver_user") or d.get("mode") == "revoked" or ticket_id(d.get("pair_ticket")) != pid:
            continue
        nonce = secrets.token_hex(16)
        try:
            resp = procs.pair_call(d["pair_ticket"], "POST", "/bro/link",
                                   {"u": user, "nonce": nonce, "proof": _link_proof(r["link_key"], "b", nonce, pid)},
                                   auth=(d["user"], d["password"]), timeout=60)
        except Exception as e:
            log.info("Linking with %s not possible yet: %s", d["name"], e)
            continue
        if not hmac.compare_digest(str(resp.get("proof") or ""), _link_proof(r["link_key"], "a", nonce, pid)):
            log.warning("%s could not prove the link, not linked", d["name"])
            continue
        with mutate() as st3:
            if not any(x.get("receiver_user") == user for x in st3["destinations"]):
                for x in st3["destinations"]:
                    if x["id"] == d["id"] and not x.get("receiver_user"):
                        x["receiver_user"] = user
        log.info("Both directions with %s linked", d["name"])
        return True
    return False


def receive_link(caller, p):
    """The other side of try_link. `caller` is the bro's login here; `u` is our login at his NAS."""
    u, nonce, proof = p.get("u"), p.get("nonce"), p.get("proof")
    if not all(isinstance(x, str) and 0 < len(x) <= 128 for x in (u, nonce, proof)):
        return None
    me = ticket_id(my_tickets.get("pair"))
    if not me:
        return None
    st = load_state()
    for d in st["destinations"]:
        if d.get("user") != u or not d.get("link_key") or d.get("receiver_user") not in (None, caller):
            continue
        if not hmac.compare_digest(proof, _link_proof(d["link_key"], "b", nonce, me)):
            continue
        other = linked_dest(caller, st)
        if other and other["id"] != d["id"]:
            return None
        if not d.get("receiver_user"):
            update_dest(d["id"], receiver_user=caller)
            log.info("Both directions with %s linked", d["name"])
        return {"ok": True, "proof": _link_proof(d["link_key"], "a", nonce, me)}
    return None


# ---------------------------------------------------------------- hello (we back up there)
def _refused(e, code):
    return f"({code})" in str(e)


def hello(d):
    """Say hello to a bro we back up to. Returns True when he answered."""
    payload = {"n": settings()["name"], "v": VERSION}
    cur = current_tickets()
    if cur:
        payload.update(dt=cur[0], pt=cur[1])
    try:
        resp = procs.pair_call(d["pair_ticket"], "POST", "/bro/hello", payload,
                               auth=(d["user"], d["password"]), timeout=60)
    except RuntimeError as e:
        if _refused(e, 410):
            mark_revoked(d["id"])
            return True
        if _refused(e, 404):  # a bro on v0.9 or older: no hello yet, try again much later
            update_dest(d["id"], hello_at=iso(now()), helloed=cur, last_contact=iso(now()))
            return True
        update_dest(d["id"], hello_fail_at=iso(now()))
        log.info("Hello to %s failed: %s", d["name"], e)
        return False
    if not isinstance(resp, dict):
        resp = {}
    fields = {"hello_at": iso(now()), "helloed": cur, "last_contact": iso(now()), "hello_fail_at": None,
              "peer_version": version_or_none(resp.get("v"))}
    if isinstance(resp.get("lk"), str) and KEY_RE.match(resp["lk"]):
        fields["link_key"] = resp["lk"]
    for key, field in (("dt", "data_ticket"), ("pt", "pair_ticket")):
        new = lan.clean_peer_ticket(resp.get(key))
        if new and new != d.get(field):
            if same_identity(d.get(field), new):
                fields[field] = new
                fields["address_changed"] = iso(now())
                log.info("%s has a new address (%s)", d["name"], field)
            else:
                log.warning("%s sent a %s with another identity, ignored", d["name"], field)
    update_dest(d["id"], **fields)
    if "data_ticket" in fields:
        procs.supervise_once()  # the tunnel moves to the new address now, not at the next loop
    return True


def receive_hello(user, p):
    """The other side of hello: remember how to reach this bro, and answer with our own tickets."""
    with mutate() as st:
        r = st["receivers"][user]
        if valid_ticket(p.get("pt")) and (not r.get("peer_pt") or same_identity(r["peer_pt"], p["pt"])):
            r["peer_pt"] = lan.clean_peer_ticket(p["pt"])
        r.update(last_hello=iso(now()), peer_version=version_or_none(p.get("v")))
        if clean_name(p.get("n")):
            r["bro_name"] = clean_name(p.get("n"))
        if not r.get("link_key"):
            r["link_key"] = secrets.token_urlsafe(24)
        lk = r["link_key"]
    cur = current_tickets()
    if cur:  # he gets our current tickets in this answer: no separate push needed
        with mutate() as st:
            if user in st["receivers"]:
                st["receivers"][user]["pushed"] = cur
    cur = cur or [None, None]
    _hello_back(p.get("pt"))
    return {"ok": True, "n": settings()["name"], "v": VERSION, "dt": cur[0], "pt": cur[1], "lk": lk}


def _hello_back(pt):
    """A bro that did not know hello yet (we only got 404s) just said hello himself: he updated.
    Say hello back now instead of within the hour. Only a hint: hello itself checks everything."""
    pid = ticket_id(pt) if valid_ticket(pt) else None
    if not pid:
        return
    for d in load_state()["destinations"]:
        if not d.get("peer_version") and d.get("mode") != "revoked" and not d.get("accepting") \
                and ticket_id(d.get("pair_ticket")) == pid:
            threading.Thread(target=hello, args=(d,), daemon=True).start()


# ---------------------------------------------------------------- our address changed
def push_address(user):
    st = load_state()
    r, cur = st["receivers"].get(user), current_tickets()
    if not r or not cur or not r.get("peer_pt") or not r.get("link_key"):
        return False
    try:
        procs.pair_call(r["peer_pt"], "POST", "/bro/address",
                        {"u": user, "lk": r["link_key"], "dt": cur[0], "pt": cur[1]}, timeout=60)
    except Exception as e:
        log.info("Telling %s about our new address failed: %s", user, e)
        with mutate() as st2:
            if user in st2["receivers"]:
                st2["receivers"][user]["push_fail_at"] = iso(now())
        return False
    with mutate() as st2:
        if user in st2["receivers"]:
            st2["receivers"][user].update(pushed=cur, push_fail_at=None)
    log.info("Told %s about our new address", user)
    return True


def receive_address(p):
    """A bro we back up to has a new address. Returns the destination or None."""
    u, lk = p.get("u") or "", p.get("lk") or ""
    if not u or not lk or not p.get("dt") or not p.get("pt"):
        return None
    for d in load_state()["destinations"]:
        if d.get("user") == u and d.get("link_key") and secrets.compare_digest(d["link_key"], lk):
            if not (same_identity(d["data_ticket"], p["dt"]) and same_identity(d["pair_ticket"], p["pt"])):
                log.warning("New address for %s refused: another identity", d["name"])
                return None
            dt, pt = lan.clean_peer_ticket(p["dt"]), lan.clean_peer_ticket(p["pt"])
            if (dt, pt) != (d["data_ticket"], d["pair_ticket"]):
                update_dest(d["id"], data_ticket=dt, pair_ticket=pt, address_changed=iso(now()),
                            last_contact=iso(now()))
                log.info("%s has a new address", d["name"])
                procs.supervise_once()  # the tunnel moves to the new address now, not at the next loop
            else:
                update_dest(d["id"], last_contact=iso(now()))
            return d
    return None


def _due(stamp, seconds):
    t = parse(stamp)
    return not t or (now() - t).total_seconds() >= seconds


def keep_in_touch():
    """Slow-loop task: hellos, address pushes, queued goodbyes, scheduled deletions."""
    cur = current_tickets()
    if not cur:
        return
    st = load_state()
    for d in st["destinations"]:
        if d.get("mode") == "revoked" or d.get("accepting") or not _due(d.get("hello_fail_at"), RETRY_SECONDS):
            continue
        if d.get("helloed") != cur or _due(d.get("hello_at"), HELLO_SECONDS if d.get("peer_version")
                                           else OLD_PEER_SECONDS):
            hello(d)
    for user, r in st["receivers"].items():
        if r.get("accepted") and r.get("peer_pt") and r.get("link_key") and r.get("pushed") != cur \
                and _due(r.get("push_fail_at"), RETRY_SECONDS):
            push_address(user)
    st = load_state()
    for user, r in st["receivers"].items():
        if r.get("accepted") and r.get("peer_pt") and r.get("link_key") and not linked_dest(user, st) \
                and _due(r.get("link_tried"), RETRY_SECONDS):
            try_link(user)
    retry_goodbyes()
    run_scheduled_deletes()


# ---------------------------------------------------------------- they stopped storing our backups
def mark_revoked(dest_id):
    d = get_dest(dest_id)
    if not d or d.get("mode") == "revoked":
        return
    update_dest(dest_id, mode="revoked", revoked_at=iso(now()),
                last_error=f"{d['name']} stopped storing your backups. You can no longer back up there, and probably "
                           "not restore either. Remove this bro and pair with someone else.")
    procs.stop_proc(f"tunnel-{dest_id}")
    notify(f"{d['name']} stopped storing your backups",
           "Your backups there are no longer available. Pair with another bro so your data stays safe.")


def tombstone_auth(user, password):
    """For a login we removed: the matching tombstone, so the bro gets a clear answer."""
    t = (load_state().get("revoked") or {}).get(user or "")
    if t and password and secrets.compare_digest(t.get("pw_sha", ""), sha256(password)):
        return t
    return None


# ---------------------------------------------------------------- receivers: revoke and data
def receiver_dir(user):
    if not USER_RE.match(user or ""):
        raise ValueError("not a bro login")
    path = os.path.realpath(os.path.join(RECEIVE_DIR, user))
    if os.path.dirname(path) != os.path.realpath(RECEIVE_DIR):
        raise ValueError("not a bro folder")
    return path


def dir_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for fn in files:
            try:
                total += os.lstat(os.path.join(root, fn)).st_size
            except OSError:
                pass
    return total


def revoke_receiver(user, delete_data=False, reason="revoked"):
    """Stop storing a bro's backups: login gone, key copy gone, a tombstone for a clear answer."""
    with mutate() as st:
        r = st["receivers"].pop(user, None)
        if r and r.get("accepted"):
            st.setdefault("revoked", {})[user] = {"name": r.get("bro_name") or r.get("name"),
                                                  "pw_sha": r.get("pw_sha"), "at": iso(now()), "reason": reason}
        st.setdefault("pending_deletes", {}).pop(user, None)
    receiving.remove_rest_user(user)
    try:
        os.remove(os.path.join(ESCROW_DIR, f"{user}.json"))
    except FileNotFoundError:
        pass
    if delete_data:
        delete_data_now(user)
    return r


def delete_data_now(user):
    st = load_state()
    if user in st["receivers"]:
        raise ValueError("This bro still backs up here. Stop storing his backups first.")
    path = receiver_dir(user)
    size = dir_size(path) if os.path.isdir(path) else 0
    shutil.rmtree(path, ignore_errors=True)
    with mutate() as st2:
        st2.setdefault("pending_deletes", {}).pop(user, None)
    log.info("Deleted the data of %s (%s)", user, human_bytes(size))
    return size


def leftover_data():
    """Folders of bros that no longer back up here, for the overview."""
    st = load_state()
    out = []
    try:
        names = sorted(os.listdir(RECEIVE_DIR))
    except OSError:
        return out
    for user in names:
        path = os.path.join(RECEIVE_DIR, user)
        if user in st["receivers"] or not os.path.isdir(path) or not USER_RE.match(user):
            continue
        t = (st.get("revoked") or {}).get(user) or {}
        pdel = (st.get("pending_deletes") or {}).get(user)
        out.append({"user": user, "name": t.get("name") or user, "size": dir_size(path), "since": t.get("at"),
                    "reason": t.get("reason"), "delete_after": pdel["after"] if pdel else None})
    return out


def cancel_delete(user):
    with mutate() as st:
        st.setdefault("pending_deletes", {}).pop(user, None)


def run_scheduled_deletes():
    for user, item in list((load_state().get("pending_deletes") or {}).items()):
        if parse(item["after"]) <= now():
            try:
                size = delete_data_now(user)
                notify(f"Deleted the backups of {item.get('name') or user}",
                       f"As he asked, {human_bytes(size)} was deleted from your NAS.", priority="default")
            except Exception as e:
                log.warning("Scheduled delete of %s failed: %s", user, e)


def receive_goodbye(user, p):
    """A bro that backs up here says goodbye (leave), and/or tells us he stopped storing ours."""
    st = load_state()
    r = st["receivers"].get(user) or {}
    name = r.get("bro_name") or r.get("name") or user
    msgs = []
    if p.get("revoked"):
        d = linked_dest(user, st)
        if d:
            mark_revoked(d["id"])
    if p.get("leave"):
        revoke_receiver(user, reason="left")
        size = dir_size(receiver_dir(user)) if os.path.isdir(receiver_dir(user)) else 0
        if p.get("delete") and size:
            if st["settings"].get("append_only"):
                msgs.append(f"He asked to delete his backups ({human_bytes(size)}). Because this NAS keeps backups "
                            "append-only, nothing is deleted by itself: delete them on the overview when you agree.")
            else:
                after = now() + datetime.timedelta(days=DELETE_GRACE_DAYS)
                with mutate() as st2:
                    st2.setdefault("pending_deletes", {})[user] = {"after": iso(after), "name": name}
                msgs.append(f"As he asked, his backups ({human_bytes(size)}) will be deleted on "
                            f"{local_time(iso(after))[:10]}. You can keep them or delete them sooner on the overview.")
        elif size:
            msgs.append(f"His backups ({human_bytes(size)}) stay on your NAS until you delete them on the overview.")
        notify(f"{name} stopped backing up to you", " ".join(msgs) or "He had no data here.", priority="default")
    return {"ok": True}


# ---------------------------------------------------------------- removing a bro we back up to
def send_goodbye(item):
    procs.pair_call(item["pair_ticket"], "POST", "/bro/goodbye", item["payload"],
                    auth=(item["user"], item["password"]), timeout=60)


def _goodbye_in_background(item):
    def work():
        try:
            send_goodbye(item)
            log.info("Said goodbye to %s", item["name"])
        except Exception as e:
            if _refused(e, 401) or _refused(e, 410):
                return  # he already removed us
            log.info("Goodbye to %s failed, will retry: %s", item["name"], e)
            with mutate() as st:
                st.setdefault("pending_goodbyes", []).append(item)
    threading.Thread(target=work, daemon=True).start()


def retry_goodbyes():
    st = load_state()
    items = list(st.get("pending_goodbyes") or [])
    if not items:
        return
    keep = []
    for item in items:
        if parse(item["created"]) < now() - datetime.timedelta(days=GOODBYE_DAYS):
            continue
        try:
            send_goodbye(item)
        except Exception as e:
            if not (_refused(e, 401) or _refused(e, 410)):
                keep.append(item)
    with mutate() as st2:
        st2["pending_goodbyes"] = keep + [x for x in st2.get("pending_goodbyes") or [] if x not in items]


def remove_destination(dest_id, ask_delete=True, also_receiver=False, tell=True):
    """Stop backing up to a bro. Tells him (in the background, retried for GOODBYE_DAYS)."""
    st = load_state()
    d = get_dest(dest_id)
    if not d:
        raise LookupError("This bro is already gone.")
    linked = linked_receiver(d, st) if also_receiver else None
    with mutate() as st2:
        st2["destinations"] = [x for x in st2["destinations"] if x["id"] != dest_id]
        st2["pending_accepts"] = [p for p in st2["pending_accepts"] if p["dest_id"] != dest_id]
    procs.stop_proc(f"tunnel-{dest_id}")
    dest_ports.pop(dest_id, None)
    if linked:
        revoke_receiver(linked)
    if tell and d.get("mode") != "revoked":
        _goodbye_in_background({"name": d["name"], "pair_ticket": d["pair_ticket"], "user": d["user"],
                                "password": d["password"], "created": iso(now()),
                                "payload": {"leave": True, "delete": bool(ask_delete), "revoked": bool(linked)}})
    return d, linked


def stop_receiving(user, delete_data=False):
    """Stop storing a bro's backups. When we also back up to him, tell him right away."""
    st = load_state()
    d = linked_dest(user, st)
    r = revoke_receiver(user, delete_data=delete_data)
    if d and d.get("mode") != "revoked":
        _goodbye_in_background({"name": d["name"], "pair_ticket": d["pair_ticket"], "user": d["user"],
                                "password": d["password"], "created": iso(now()),
                                "payload": {"leave": False, "delete": False, "revoked": True}})
    return r


def expire_tombstones():
    limit = now() - datetime.timedelta(days=TOMBSTONE_DAYS)
    with mutate() as st:
        for user, t in list((st.get("revoked") or {}).items()):
            if parse(t["at"]) < limit:
                del st["revoked"][user]
