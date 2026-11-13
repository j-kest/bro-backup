# version : 1.2.0
# created by : JK and CF
# last edited : 13/11/2026
# Name : bro-backup (bro/lan.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Direct connections between bros on the same network.

BRO Backup runs in a Docker network of its own, so it only sees its internal address (172.x) and never
the address of the NAS itself. Two bros on the same LAN, or on VLANs that reach each other, then fall
back to a relay: they hand each other addresses the other cannot reach, and a router rarely sends
traffic for its own public address back inside.

With the addresses of the NAS on your network filled in (Settings, or BRO_LAN_ADDRS from the installer),
they are added to the tickets this NAS hands out, with the UDP ports the app listens on (7841 data,
7842 pairing). The bro then tries those first. For that to work the app must publish those UDP ports
on the same port numbers ("7841:7841/udp", "7842:7842/udp")."""

import base64
import ipaddress
import os
import re


from .core import IROH_DATA_PORT, IROH_PAIR_PORT, IROH_RELAYS, my_tickets, settings

ENV = "BRO_LAN_ADDRS"
MAX_ADDRS = 4
PORTS = {"data": IROH_DATA_PORT, "pair": IROH_PAIR_PORT}


def parse_addrs(text):
    """'192.168.1.50, 192.168.20.50' -> (["192.168.1.50", "192.168.20.50"], [what was not usable])."""
    good, bad = [], []
    for part in str(text or "").replace(",", " ").replace(";", " ").split():
        try:
            ip = ipaddress.ip_address(part.strip("[]"))
        except ValueError:
            bad.append(part)
            continue
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            bad.append(part)
        elif str(ip) not in good:
            good.append(str(ip))
    if len(good) > MAX_ADDRS:
        bad += good[MAX_ADDRS:]
        good = good[:MAX_ADDRS]
    return good, bad


def configured(s=None):
    """The addresses to hand out: the setting when it was saved, else what the installer passed in."""
    s = s or settings()
    if s.get("lan_addrs") is not None:
        return list(s["lan_addrs"])
    return parse_addrs(os.environ.get(ENV, ""))[0]


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _read_varint(raw, i):
    val = shift = 0
    while True:
        b = raw[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def _entries(raw):
    """The address entries of a ticket as raw byte strings, or None when the layout is not the one we know."""
    try:
        if raw[0] != 0 or len(raw) < 34:
            return None
        n, i = _read_varint(raw, 33)
        entries = []
        for _ in range(n):
            start, kind = i, raw[i]
            i += 1
            if kind == 0:  # relay url
                ln, i = _read_varint(raw, i)
                i += ln
            elif kind == 1:  # ip address and port
                fam = raw[i]
                if fam not in (0, 1):
                    return None
                i += 1 + (4 if fam == 0 else 16)
                _, i = _read_varint(raw, i)
            else:
                return None
            if i > len(raw):
                return None
            entries.append(bytes(raw[start:i]))
        return entries if i == len(raw) else None
    except IndexError:
        return None


def _entry(ip, port):
    ip = ipaddress.ip_address(ip)
    return bytes([1, 0 if ip.version == 4 else 1]) + ip.packed + _varint(port)


def with_addrs(ticket, ips, port):
    """The same ticket with these direct addresses added. Anything unexpected: the ticket unchanged."""
    if not ticket or not ips or not ticket.startswith("endpoint"):
        return ticket
    s = ticket[len("endpoint"):].upper()
    try:
        raw = base64.b32decode(s + "=" * (-len(s) % 8))
    except ValueError:
        return ticket
    entries = _entries(raw)
    if entries is None:
        return ticket
    for ip in ips:
        e = _entry(ip, port)
        if e not in entries:
            entries.append(e)
    new = raw[:33] + _varint(len(entries)) + b"".join(entries)
    return "endpoint" + base64.b32encode(new).decode().rstrip("=").lower()


def advertised(kind):
    """This NAS's ticket as bros get it: dumbpipe's own ticket plus the addresses on your network."""
    t = my_tickets.get(kind)
    return with_addrs(t, configured(), PORTS[kind]) if t else t


RELAY_SUFFIX = ".relay.n0.iroh.link"  # n0's relays; the list in core may grow, the domain stays theirs
LOW_PORTS = 1024


RELAY_URL_RE = re.compile(r"^https?://([a-z0-9-]+(?:\.[a-z0-9-]+)+)\.?(?::[0-9]{1,5})?/?$")


def _relay_ok(entry):
    """Only a plain relay URL: scheme, host name, an optional port, nothing else. Parsers disagree on URLs with
    a backslash, user info or a path (Python and dumbpipe could see a different host), so those are refused."""
    ln, i = _read_varint(entry, 1)
    try:
        url = entry[i:i + ln].decode("ascii").lower()
    except UnicodeDecodeError:
        return False
    m = RELAY_URL_RE.match(url)
    if not m:
        return False
    host = m.group(1)
    return host in IROH_RELAYS or host.endswith(RELAY_SUFFIX)


def _direct_ok(entry):
    fam = entry[1]
    size = 4 if fam == 0 else 16
    ip = ipaddress.ip_address(bytes(entry[2:2 + size]))
    port, _ = _read_varint(entry, 2 + size)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return port >= LOW_PORTS and not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
                                      or ip.is_reserved)


def clean_peer_ticket(ticket):
    """A bro's ticket with only addresses we are willing to send packets to. A bro could otherwise make our
    dumbpipe connect to any address he likes: a relay of his own choosing, or a service on this NAS or our
    network (localhost, ports below 1024). Addresses on your network stay: bros on the same LAN need them.
    A ticket we cannot read entry by entry is refused (None): what we cannot check, we do not use."""
    if not ticket or not isinstance(ticket, str) or not ticket.startswith("endpoint"):
        return None
    s = ticket[len("endpoint"):].upper()
    try:
        raw = base64.b32decode(s + "=" * (-len(s) % 8))
    except ValueError:
        return None
    entries = _entries(raw)
    if entries is None:
        return None
    keep = [e for e in entries if (_relay_ok(e) if e[0] == 0 else _direct_ok(e))]
    if len(keep) == len(entries):
        return ticket
    new = raw[:33] + _varint(len(keep)) + b"".join(keep)
    return "endpoint" + base64.b32encode(new).decode().rstrip("=").lower()
