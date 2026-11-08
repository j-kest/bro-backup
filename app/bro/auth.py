# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/auth.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Logging in: password, optional two-step login (TOTP), lockout after failed attempts, session expiry."""

import base64
import hashlib
import hmac
import secrets
import struct
import threading
import time
import urllib.parse

from .core import log, notify, settings

MAX_FAILS = 5                 # failed logins per address ...
FAIL_WINDOW = 15 * 60         # ... within this many seconds lock that address for the same time
IDLE_TIMEOUT = 60 * 60        # log out after an hour without activity
MAX_SESSION = 12 * 60 * 60    # and always after 12 hours
TOTP_STEP = 30
TOTP_DIGITS = 6

_fails = {}                   # address -> [timestamps of failed attempts]
_fails_lock = threading.Lock()


# ---------------------------------------------------------------- lockout
def locked_for(addr):
    """Seconds this address still has to wait, or 0."""
    with _fails_lock:
        recent = [t for t in _fails.get(addr, []) if time.time() - t < FAIL_WINDOW]
        _fails[addr] = recent
        if len(recent) >= MAX_FAILS:
            return int(FAIL_WINDOW - (time.time() - recent[-MAX_FAILS])) + 1
    return 0


def register_fail(addr):
    with _fails_lock:
        _fails.setdefault(addr, []).append(time.time())
        n = len([t for t in _fails[addr] if time.time() - t < FAIL_WINDOW])
    log.warning("Failed login from %s (%s in the last %s minutes)", addr, n, FAIL_WINDOW // 60)
    if n == MAX_FAILS:
        notify("BRO Backup: login blocked",
               f"{MAX_FAILS} wrong logins from {addr}. That address is blocked for {FAIL_WINDOW // 60} minutes. "
               "Was this not you? Change your password and turn on two-step login.")


def clear_fails(addr):
    with _fails_lock:
        _fails.pop(addr, None)


# ---------------------------------------------------------------- TOTP (RFC 6238)
def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** TOTP_DIGITS
    return str(code).zfill(TOTP_DIGITS)


def totp_counter_for(secret, code, last_used=-1, at=None):
    """The time step this code belongs to (one step of clock drift allowed either way), or None.
    A step at or before last_used is refused, so a code can never be used twice."""
    code = "".join(c for c in str(code) if c.isdigit())
    if len(code) != TOTP_DIGITS or not secret:
        return None
    now_step = int((at or time.time()) // TOTP_STEP)
    for step in (now_step - 1, now_step, now_step + 1):
        if step > last_used and hmac.compare_digest(_totp(secret, step), code):
            return step
    return None


def totp_uri(secret, account):
    label = urllib.parse.quote(f"BRO Backup:{account or 'NAS'}")
    return f"otpauth://totp/{label}?secret={secret}&issuer=BRO%20Backup&digits={TOTP_DIGITS}&period={TOTP_STEP}"


def qr_svg(text):
    """The QR code as inline SVG, or None when segno is not installed."""
    try:
        import segno
    except ImportError:
        return None
    return segno.make(text, error="m").svg_inline(scale=5, dark="#000", light="#fff", border=2)


def two_step_on():
    return bool(settings().get("totp_secret"))
