# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/procs.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Background processes (rest-server, dumbpipe) and connection paths."""

import base64
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager

from . import receiving

from .core import (
    ANSI_RE,
    DUMBPIPE,
    GIB,
    IROH_DATA_PORT,
    IROH_PAIR_PORT,
    PAIR_PORT,
    PATH_LOG,
    PATH_RE,
    RECEIVE_DIR,
    REST_PORT,
    REST_SERVER,
    conn_paths,
    dest_ports,
    iso,
    load_state,
    log,
    my_tickets,
    now,
    setup_done,
)


# ---------------------------------------------------------------- connection paths
def parse_path(line):
    """Turn an iroh 'path selected' log line into (type, detail): direct, lan or relay."""
    m = PATH_RE.search(ANSI_RE.sub("", line))
    if not m:
        return None
    kind, detail = m.groups()
    if kind == "Relay":
        url = detail.split(",")[0].strip()
        return "relay", url
    remote = detail.split("->")[-1].strip()
    host = remote.rsplit(":", 1)[0].strip("[]")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_link_local or ip.is_loopback:
            return "lan", remote
    except ValueError:
        pass
    return "direct", remote


def path_recorder(dest_id):
    def record(line):
        found = parse_path(line)
        if found:
            conn_paths[dest_id] = {"type": found[0], "detail": found[1], "at": iso(now())}
    return record


# ---------------------------------------------------------------- processes
class Proc:
    TICKET_RE = re.compile(r"\b(endpoint[a-z0-9]{20,})\b")

    def __init__(self, key, args, env=None, ticket_key=None, on_line=None):
        self.key, self.args, self.env, self.ticket_key = key, args, env or {}, ticket_key
        self.on_line = on_line
        self.p = None
        self.lines = []
        self.started = 0.0
        self.fails = 0

    def signature(self):
        return json.dumps([self.args, sorted(self.env.items())])

    def start(self):
        env = os.environ.copy()
        env.update(self.env)
        self.p = subprocess.Popen(self.args, env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.started = time.time()
        threading.Thread(target=self._read, daemon=True).start()
        log.info("Started: %s", self.key)

    def _read(self):
        for line in self.p.stdout:
            line = ANSI_RE.sub("", line.rstrip())
            if "secret key" in line.lower():
                continue
            if self.on_line:
                self.on_line(line)
                if "_events::path" in line:
                    continue  # path events are parsed, not kept as output
            if self.ticket_key:
                m = self.TICKET_RE.search(line)
                if m:
                    my_tickets[self.ticket_key] = m.group(1)
            self.lines = (self.lines + [line if len(line) <= 300 else line[:300] + " …"])[-20:]

    def alive(self):
        return self.p is not None and self.p.poll() is None

    def stop(self):
        if self.alive():
            self.p.terminate()
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.kill()


procs = {}


def ensure_proc(key, args, env=None, ticket_key=None, on_line=None):
    new = Proc(key, args, env, ticket_key, on_line)
    old = procs.get(key)
    if old and old.signature() != new.signature():
        old.stop()
        old = None
    if old and old.alive():
        return old
    if old and time.time() - old.started < min(60, 5 * (old.fails + 1)):
        return old  # back off after a crash
    if old:
        new.fails = old.fails + 1
        log.warning("%s stopped, restarting. Last output:\n%s", key, "\n".join(old.lines[-5:]))
    procs[key] = new
    new.start()
    return new


def stop_proc(key):
    p = procs.pop(key, None)
    if p:
        p.stop()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


# ---------------------------------------------------------------- fresh tickets
# dumbpipe prints its ticket once, at start. The addresses in it go stale when an IP changes.
TICKET_REFRESH_SECONDS = 24 * 3600
_listen_ips = {"ips": None}


def local_ips():
    """IPv4 addresses of this container, from /proc (no `ip` tool needed). None if unreadable."""
    try:
        with open("/proc/net/fib_trie") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    ips = set()
    for i, line in enumerate(lines):
        if "/32 host LOCAL" in line and i:
            ip = lines[i - 1].strip().split()[-1]
            if not ip.startswith("127."):
                ips.add(ip)
    return sorted(ips)


def port_busy(port):
    """Is anything connected to this local port right now (an incoming backup, a pairing call)?"""
    try:
        with open("/proc/net/tcp") as f:
            rows = f.read().splitlines()[1:]
    except OSError:
        return True  # unknown: assume busy, never cut a transfer
    for row in rows:
        cols = row.split()
        if len(cols) > 3 and cols[3] == "01" and int(cols[1].rsplit(":", 1)[1], 16) == port:
            return True
    return False


def refresh_listeners(reason):
    log.info("Restarting the listeners for a fresh address (%s)", reason)
    for key, ticket in (("listen-data", "data"), ("listen-pair", "pair")):
        stop_proc(key)
        my_tickets.pop(ticket, None)


def check_addresses():
    ips = local_ips()
    if ips:  # an empty list is a network that is gone for a moment: wait for the new address
        old, _listen_ips["ips"] = _listen_ips["ips"], ips
        if old is not None and ips != old:
            refresh_listeners(f"local address changed from {', '.join(old)} to {', '.join(ips)}")
            return
    lp = procs.get("listen-data")
    if lp and lp.alive() and time.time() - lp.started > TICKET_REFRESH_SECONDS \
            and not port_busy(REST_PORT) and not port_busy(PAIR_PORT):
        refresh_listeners("daily refresh")


_supervise_lock = threading.Lock()  # the scheduler, a backup and the pair API can all call supervise_once


def supervise_once():
    with _supervise_lock:
        _supervise()


def ensure_tunnel(d, timeout=20):
    """The tunnel to this bro must run with his current ticket before restic uses it.
    Without this a backup started right after an address change would dial the old address."""
    p = procs.get(f"tunnel-{d['id']}")
    if not (p and p.alive() and d["data_ticket"] in p.args):
        supervise_once()
    return wait_port(dest_ports.get(d["id"], 0) or 1, timeout)


def _supervise():
    if not setup_done():
        return
    check_addresses()
    st = load_state()
    ident = st["identity"]
    rest_args = [REST_SERVER, "--path", RECEIVE_DIR, "--listen", f"127.0.0.1:{REST_PORT}",
                 "--private-repos", "--prometheus"]  # counters for the incoming view, only for user "metrics"
    receiving.ensure_metrics_user()
    receiving.drop_unaccepted_logins()
    total_quota = sum(int(r.get("quota_gib") or 0) for r in st["receivers"].values())
    if total_quota:  # hard limit for all bros together, 10% headroom for pruning
        rest_args += ["--max-size", str(int(total_quota * GIB * 1.1))]
    if st["settings"]["append_only"]:
        rest_args.append("--append-only")
    ensure_proc("rest-server", rest_args)
    ensure_proc("listen-data", [DUMBPIPE, "listen-tcp", "--host", f"127.0.0.1:{REST_PORT}",
                                "--ipv4-addr", f"0.0.0.0:{IROH_DATA_PORT}"],
                {"IROH_SECRET": ident["data_secret"]}, ticket_key="data")
    ensure_proc("listen-pair", [DUMBPIPE, "listen-tcp", "--host", f"127.0.0.1:{PAIR_PORT}",
                                "--ipv4-addr", f"0.0.0.0:{IROH_PAIR_PORT}"],
                {"IROH_SECRET": ident["pair_secret"]}, ticket_key="pair")
    wanted = set()
    for d in st["destinations"]:
        if d.get("mode") == "revoked":
            continue
        key = f"tunnel-{d['id']}"
        wanted.add(key)
        port = dest_ports.get(d["id"]) or free_port()
        dest_ports[d["id"]] = port
        ensure_proc(key, [DUMBPIPE, "connect-tcp", "--addr", f"127.0.0.1:{port}", d["data_ticket"]],
                    {"RUST_LOG": PATH_LOG}, on_line=path_recorder(d["id"]))
    for key in [k for k in procs if k.startswith("tunnel-") and k not in wanted]:
        stop_proc(key)


@contextmanager
def pair_tunnel(ticket, on_line=None):
    port = free_port()
    env = dict(os.environ, RUST_LOG=PATH_LOG)
    p = subprocess.Popen([DUMBPIPE, "connect-tcp", "--addr", f"127.0.0.1:{port}", ticket], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE if on_line else subprocess.DEVNULL,
                         text=True, bufsize=1)
    if on_line:
        threading.Thread(target=lambda: [on_line(x) for x in p.stderr], daemon=True).start()
    try:
        if not wait_port(port):
            raise RuntimeError("The local tunnel to your bro does not start")
        yield port
    finally:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # a bro never redirects: a 3xx is an error, never a request to somewhere else


pair_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
PAIR_MAX_ANSWER = 1 << 20  # the largest real answer (a key copy) is a few kB


class PairAnswerError(RuntimeError):
    """The bro answered, but with something we do not accept: no point in asking again."""


def pair_call(ticket, method, path, payload=None, auth=None, timeout=90):
    with pair_tunnel(ticket) as port:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        if auth:
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode())
        last = None
        for _ in range(3):  # the first connection (hole punching) can take a moment
            try:
                with pair_opener.open(req, timeout=timeout) as r:
                    raw = r.read(PAIR_MAX_ANSWER + 1)
                if len(raw) > PAIR_MAX_ANSWER:
                    raise PairAnswerError("Bro sent an answer larger than 1 MiB")
                try:
                    return json.loads(raw or b"{}")
                except ValueError:
                    raise PairAnswerError("Bro sent an answer that is not JSON") from None
            except PairAnswerError:
                raise
            except urllib.error.HTTPError as e:
                body = e.read(2000).decode(errors="replace")
                raise RuntimeError(f"Bro refused ({e.code}): {body[:200]}")
            except Exception as e:
                last = e
                time.sleep(3)
        raise RuntimeError(f"Bro not reachable: {last}")


