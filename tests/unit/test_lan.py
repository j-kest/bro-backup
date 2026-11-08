# SPDX-License-Identifier: AGPL-3.0-or-later
"""Addresses on your network: added to the tickets bros get, so bros on the same LAN connect directly."""
import os
import re
import unittest
from unittest import mock

import _env

from bro import core, lan, pairing, peers, web

PW = "a-long-test-password"
ID = "ab" * 32


class Tickets(unittest.TestCase):
    def setUp(self):
        _env.reset()
        core.my_tickets.update(data=_env.ticket(ID, port_varint="f13d"), pair=_env.ticket(ID, port_varint="f23d"))
        self.addCleanup(core.my_tickets.clear)

    def test_parse(self):
        self.assertEqual(lan.parse_addrs("192.168.1.50, 192.168.20.50;10.0.0.1"),
                         (["192.168.1.50", "192.168.20.50", "10.0.0.1"], []))
        self.assertEqual(lan.parse_addrs("127.0.0.1 nas.local 0.0.0.0 169.254.1.1")[1],
                         ["127.0.0.1", "nas.local", "0.0.0.0", "169.254.1.1"])
        good, bad = lan.parse_addrs("10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 10.0.0.1")
        self.assertEqual((len(good), bad), (4, ["10.0.0.5"]))

    def test_added_to_the_ticket_identity_unchanged(self):
        with mock.patch.dict(os.environ, {lan.ENV: "192.168.1.50,fd00::5"}):
            dt = lan.advertised("data")
        self.assertEqual(peers.ticket_id(dt), ID)
        self.assertTrue(peers.valid_ticket(dt))
        self.assertEqual(peers.ticket_addrs(dt)["direct"], ["10.0.0.1:7921", "192.168.1.50:7841",
                                                             "[fd00:0000:0000:0000:0000:0000:0000:0005]:7841"])
        self.assertTrue(peers.same_identity(core.my_tickets["data"], dt))

    def test_nothing_set_ticket_unchanged(self):
        self.assertEqual(lan.advertised("pair"), core.my_tickets["pair"])
        self.assertEqual(lan.with_addrs("endpointnotaticket", ["10.0.0.1"], 7841), "endpointnotaticket")

    def test_setting_wins_over_installer_and_can_be_emptied(self):
        with mock.patch.dict(os.environ, {lan.ENV: "192.168.1.50"}):
            self.assertEqual(lan.configured(), ["192.168.1.50"])
            with core.mutate() as st:
                st["settings"]["lan_addrs"] = []
            self.assertEqual(lan.advertised("data"), core.my_tickets["data"])

    def test_bros_get_it_in_codes_and_hellos(self):
        with core.mutate() as st:
            st["settings"].update(name="Alice", lan_addrs=["192.168.1.50"])
        code = pairing.make_invite("Bob", 10, False)
        data = pairing.decode_code(code, "BRO1.", ("dt", "pt"))
        self.assertIn("192.168.1.50:7842", peers.ticket_addrs(data["pt"])["direct"])
        self.assertIn("192.168.1.50:7841", peers.ticket_addrs(peers.current_tickets()[0])["direct"])


class Page(unittest.TestCase):
    def setUp(self):
        _env.reset()
        with core.mutate() as st:
            st["settings"].update(name="Alice", pw_hash=core.hash_ui_password(PW), sources=[])
        web.auth.clear_fails("127.0.0.1")
        web.app.secret_key = "unit-test"
        self.c = web.app.test_client()
        mock.patch.object(web.time, "sleep").start()
        mock.patch.object(web.peers, "keep_in_touch").start()
        self.addCleanup(mock.patch.stopall)
        self.tok = lambda p: re.search(r'name="csrf" value="([^"]+)"', self.c.get(p).get_data(as_text=True)).group(1)
        self.c.post("/login", data={"pw": PW, "csrf": self.tok("/login")})

    def save(self, value):
        return self.c.post("/settings", data={"csrf": self.tok("/settings"), "lan_addrs": value,
                                              "backup_hour": "2", "alert_hours": "72", "default_quota_gib": "500",
                                              "retention": "standard", "ransomware_watch": "1", "alert_receivers": "1", "restore_test": "1", "report_day": "0"},  # unchanged: no password needed
                           follow_redirects=True).get_data(as_text=True)

    def test_font_without_login(self):
        c = web.app.test_client()
        r = c.get("/static/fonts/montserrat-latin-wght.woff")
        self.assertEqual((r.status_code, r.data[:4]), (200, b"wOFF"))
        self.assertEqual(c.get("/static/../bro/core.py").status_code, 404)

    def test_save_and_refuse(self):
        with mock.patch.dict(os.environ, {lan.ENV: "192.168.1.50"}):
            self.assertIn('value="192.168.1.50"', self.c.get("/settings").get_data(as_text=True))
            self.save("192.168.1.50")
            self.assertIsNone(core.settings()["lan_addrs"])  # unchanged: the installer's value stays in charge
            page = self.save("my-nas")
            self.assertIn("not a usable address", page)
            self.save("192.168.1.50, 192.168.20.50")
            self.assertEqual(core.settings()["lan_addrs"], ["192.168.1.50", "192.168.20.50"])


if __name__ == "__main__":
    unittest.main()
