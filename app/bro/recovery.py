# version : 0.10
# created by : JK and CF
# last edited : 01/11/2026
# Name : bro-backup (bro/recovery.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Recovery code, encrypted key copies at your bros, and recovering after a crash."""

import datetime
import hashlib
import json
import os
import re
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import backup, procs
from .core import (
    HTPASSWD,
    RC_ALPHABET,
    b64d,
    b64e,
    iso,
    load_state,
    log,
    mutate,
    now,
    parse,
    sha256,
    update_dest,
)


# ---------------------------------------------------------------- recovery code and key copies
def new_recovery_code():
    raw = "".join(secrets.choice(RC_ALPHABET) for _ in range(32))  # 32 x 5 bit = 160 bit
    return "-".join(raw[i:i + 4] for i in range(0, 32, 4))


def norm_recovery_code(code):
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


def derive_key(code, salt):
    return hashlib.scrypt(norm_recovery_code(code).encode(), salt=salt, n=2 ** 15, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def set_recovery_code(code):
    salt = secrets.token_bytes(16)
    with mutate() as st:
        st["recovery"] = {"salt": salt.hex(), "key": derive_key(code, salt).hex(),
                          "created": iso(now())}
        for d in st["destinations"]:
            d.pop("escrow_hash", None)  # resend with the new key


def recovery_bundle(st):
    """Everything a new NAS needs to find your backups again."""
    s = {k: v for k, v in st["settings"].items() if k not in ("pw_hash", "ntfy_token")}
    dests = [{k: v for k, v in d.items() if not k.startswith(("last_", "escrow_", "remote_"))}
             for d in st["destinations"]]
    htp = open(HTPASSWD).read() if os.path.exists(HTPASSWD) else ""
    return {"v": 1, "settings": s, "identity": st["identity"], "destinations": dests,
            "receivers": st["receivers"], "htpasswd": htp}


def seal(bundle, key_hex, salt_hex):
    nonce = secrets.token_bytes(12)
    ct = AESGCM(bytes.fromhex(key_hex)).encrypt(nonce, json.dumps(bundle).encode(), b"bro-backup-v1")
    return {"v": 1, "salt": salt_hex, "nonce": nonce.hex(), "ct": b64e(ct)}


def unseal(blob, code):
    key = derive_key(code, bytes.fromhex(blob["salt"]))
    pt = AESGCM(key).decrypt(bytes.fromhex(blob["nonce"]), b64d(blob["ct"]), b"bro-backup-v1")
    return json.loads(pt), key


def push_escrow():
    """Send an encrypted copy of your keys to every bro (only when something changed)."""
    st = load_state()
    rec = st["recovery"]
    if not rec.get("key"):
        return
    bundle = recovery_bundle(st)
    h = sha256(json.dumps(bundle, sort_keys=True) + rec["key"])
    for d in st["destinations"]:
        if d.get("escrow_hash") == h:
            # Once a day, check the copy is still there (the bro may have been recovered himself)
            checked = parse(d.get("escrow_checked"))
            if checked and now() - checked < datetime.timedelta(hours=24):
                continue
            try:
                present = backup.bro_status(d).get("escrow")
            except Exception:
                continue
            update_dest(d["id"], escrow_checked=iso(now()))
            if present:
                continue
        try:
            procs.pair_call(d["pair_ticket"], "POST", "/bro/escrow", {"blob": seal(bundle, rec["key"], rec["salt"])},
                      auth=(d["user"], d["password"]), timeout=60)
            update_dest(d["id"], escrow_hash=h, escrow_at=iso(now()))
            log.info("Key copy at %s updated", d["name"])
        except Exception as e:
            log.info("Key copy to %s not delivered yet: %s", d["name"], e)


def apply_bundle(bundle, key_hex, salt_hex):
    with mutate() as st:
        name, pw_hash = st["settings"].get("name"), st["settings"].get("pw_hash")
        st["settings"].update(bundle.get("settings") or {})
        st["settings"]["pw_hash"] = pw_hash
        st["settings"]["name"] = st["settings"].get("name") or name
        st["identity"] = bundle["identity"]
        st["destinations"] = bundle.get("destinations") or []
        for d in st["destinations"]:
            # Never back up automatically after a recovery: an empty new NAS would push out your good versions
            d["mode"] = "hold"
        st["receivers"] = bundle.get("receivers") or {}
        if key_hex:
            st["recovery"] = {"salt": salt_hex, "key": key_hex, "created": iso(now())}
    if bundle.get("htpasswd") is not None:
        with open(HTPASSWD + ".tmp", "w") as f:
            f.write(bundle["htpasswd"])
        os.chmod(HTPASSWD + ".tmp", 0o600)
        os.replace(HTPASSWD + ".tmp", HTPASSWD)


