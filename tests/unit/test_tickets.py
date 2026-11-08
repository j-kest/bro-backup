# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import unittest

import _env  # noqa: F401

from bro import peers

# The test vector from iroh-tickets (src/endpoint.rs, test_ticket_base32): variant 0, the endpoint id,
# two addresses: relay "http://derp.me./" and 127.0.0.1:1024.
ID = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6"
VECTOR = "00" + ID + "02" + "00" + "10" + "687474703a2f2f646572702e6d652e2f" + "01" + "00" + "7f0000018008"


def ticket(hexbytes):
    return "endpoint" + base64.b32encode(bytes.fromhex(hexbytes)).decode().rstrip("=").lower()


class Tickets(unittest.TestCase):
    def test_id(self):
        self.assertEqual(peers.ticket_id(ticket(VECTOR)), ID)

    def test_addresses(self):
        a = peers.ticket_addrs(ticket(VECTOR))
        self.assertEqual(a["relays"], ["http://derp.me./"])
        self.assertEqual(a["direct"], ["127.0.0.1:1024"])

    def test_same_identity_other_address(self):
        other_addr = VECTOR[:-12] + "c0a801028008"  # 192.168.1.2 instead of 127.0.0.1
        self.assertTrue(peers.same_identity(ticket(VECTOR), ticket(other_addr)))

    def test_other_identity(self):
        other = "00" + "11" * 32 + VECTOR[66:]
        self.assertFalse(peers.same_identity(ticket(VECTOR), ticket(other)))

    def test_garbage(self):
        for bad in (None, "", "endpoint", "endpoint!!!", "blob" + ticket(VECTOR)[8:], ticket("01" + ID)):
            self.assertIsNone(peers.ticket_id(bad))
            self.assertFalse(peers.same_identity(bad, bad))
        self.assertEqual(peers.ticket_addrs("endpointaaaa"), {"relays": [], "direct": []})


if __name__ == "__main__":
    unittest.main()
