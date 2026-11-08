# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/server.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Startup."""

import logging
import os
import secrets
import threading
from logging.handlers import RotatingFileHandler

from . import backup, pair_api, receiving, scheduler, web
from .core import (
    CONFIG_DIR,
    DATA_DIR,
    DATA_MARKER,
    ESCROW_DIR,
    HTPASSWD,
    IMPORT_DIR,
    LOG_FORMAT,
    PAIR_PORT,
    RECEIVE_DIR,
    RESTORE_DIR,
    SPEED_PART,
    UI_PORT,
    VERSION,
    load_state,
    log,
    redact_text,
)


# ---------------------------------------------------------------- startup
def _redact_record(r):
    try:
        r.msg, r.args = redact_text(r.getMessage()), ()
    except Exception:  # a badly formatted log call must never stop the app
        r.msg, r.args = redact_text(str(r.msg)), ()
    return True


def init():
    for p in (CONFIG_DIR, RECEIVE_DIR, RESTORE_DIR, IMPORT_DIR, ESCROW_DIR, os.path.join(CONFIG_DIR, "cache")):
        os.makedirs(p, exist_ok=True)
    fh = RotatingFileHandler(os.path.join(CONFIG_DIR, "bro-backup.log"), maxBytes=1024 * 1024, backupCount=3)
    fh.setFormatter(logging.Formatter(LOG_FORMAT))
    fh.addFilter(_redact_record)  # the whole message, arguments included
    logging.getLogger().addHandler(fh)
    if not os.path.exists(HTPASSWD):
        receiving.write_htpasswd({})
    with open(os.path.join(DATA_DIR, DATA_MARKER), "w") as f:
        f.write("BRO Backup data folder: contains keys and encrypted data of bros. Never backed up.\n")
    secret_file = os.path.join(CONFIG_DIR, ".flask_secret")
    if not os.path.exists(secret_file):
        with open(secret_file, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(secret_file, 0o600)
    with open(secret_file) as f:
        web.app.secret_key = f.read().strip()
    # Seeds interrupted halfway (restart) simply start again
    for d in load_state()["destinations"]:
        if d.get("mode") == "seeding":
            threading.Thread(target=backup.run_seed, args=(d["id"],), daemon=True).start()


def serve():
    init()
    threading.Thread(target=scheduler.scheduler, daemon=True).start()
    try:
        from waitress import create_server
        ui = create_server(web.app, host="0.0.0.0", port=UI_PORT, threads=8)
        # Waitress reads a whole request before a thread gets it (it buffers the body, on disk when it is large),
        # so a slow sender holds a connection, not a thread. The limits cap what bros can hold open: 64
        # connections, one upload speed test part plus 1 MiB per request, 60 s without any data.
        pair = create_server(pair_api.pair_app, host="127.0.0.1", port=PAIR_PORT, threads=16,
                             channel_timeout=60, connection_limit=64, max_request_body_size=SPEED_PART + (1 << 20),
                             max_request_header_size=64 << 10)
        threading.Thread(target=pair.run, daemon=True).start()
        log.info("BRO Backup %s: web UI on port %s", VERSION, UI_PORT)
        ui.run()
    except ImportError:  # only for local testing without waitress
        from werkzeug.serving import make_server
        pair = make_server("127.0.0.1", PAIR_PORT, pair_api.pair_app, threaded=True)
        threading.Thread(target=pair.serve_forever, daemon=True).start()
        log.info("BRO Backup %s (dev server): web UI on port %s", VERSION, UI_PORT)
        make_server("0.0.0.0", UI_PORT, web.app, threaded=True).serve_forever()



def cli(args):
    """Emergency commands, run inside the container: python main.py reset-two-step | reset-password | restore-from-disk"""
    import secrets as _secrets

    from .core import hash_ui_password, mutate
    if args == ["reset-two-step"]:
        with mutate() as st:
            st["settings"].update(totp_secret="", totp_last=-1)
        print("Two-step login is off. Log in with your password and set it up again under Security.")
        return 0
    if args == ["reset-password"]:
        pw = "-".join(_secrets.token_hex(3) for _ in range(4))
        with mutate() as st:
            st["settings"]["pw_hash"] = hash_ui_password(pw)
        print(f"Temporary password: {pw}\nLog in with it and change it under Security.")
        return 0
    if args[:1] == ["restore-from-disk"]:
        from . import pickup
        return pickup.restore_from_disk_cli(args[1:])
    print("Usage: python main.py [reset-two-step | reset-password | restore-from-disk [--path DIR] [--to DIR]]")
    return 2
