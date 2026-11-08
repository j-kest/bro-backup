# SPDX-License-Identifier: AGPL-3.0-or-later
"""Imported first by every unit test: points the app at a throwaway data folder."""

import os
import shutil
import sys
import tempfile

ROOT = tempfile.mkdtemp(prefix="bro-test-")
os.environ.update(DATA_DIR=os.path.join(ROOT, "data"), NAS_DIR=os.path.join(ROOT, "nas"), TZ="UTC")
for sub in ("data/config/escrow", "data/receive", "nas"):
    os.makedirs(os.path.join(ROOT, sub), exist_ok=True)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "app"))

from bro import core  # noqa: E402


def reset():
    """A fresh, empty state and receive folder for the next test."""
    for p in (core.STATE_FILE, core.HTPASSWD):
        if os.path.exists(p):
            os.remove(p)
    for d in (core.RECEIVE_DIR, core.ESCROW_DIR):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    core.my_tickets.clear()


def ticket(endpoint_hex, ip="0a000001", port_varint="8008"):
    """A dumbpipe ticket for an endpoint id, with one direct IPv4 address."""
    import base64
    raw = bytes.fromhex("00" + endpoint_hex + "01" + "01" + "00" + ip + port_varint)
    return "endpoint" + base64.b32encode(raw).decode().rstrip("=").lower()


class SyncThread:
    """Stands in for threading.Thread so background work runs inside the test."""

    def __init__(self, target, args=(), daemon=None):
        self.target, self.args = target, args

    def start(self):
        self.target(*self.args)
