# SPDX-License-Identifier: AGPL-3.0-or-later
"""The overview and the self-check show which version each bro runs."""
import unittest
from unittest import mock

import _env  # noqa: F401

from bro import core, selfcheck, web
from test_peers import mk_dest, mk_receiver
from test_security import WebBase


class Badge(unittest.TestCase):
    def test_older_same_newer_unknown(self):
        with mock.patch.object(web, "VERSION", "1.1.0"):
            self.assertEqual(web.bro_version("1.0.1")["cls"], "warn")
            self.assertEqual(web.bro_version("1.0.1")["text"], "v1.0.1 · older")
            self.assertEqual(web.bro_version("v1.1.0")["text"], "v1.1.0")
            self.assertEqual(web.bro_version("1.2.0")["text"], "v1.2.0 · newer")
            self.assertEqual(web.bro_version(None)["text"], "version unknown")
            self.assertEqual(web.bro_version("<b>")["text"], "version unknown")


class Pages(WebBase):
    def test_overview_and_selfcheck(self):
        self.login()
        d = mk_dest("Bob")
        core.update_dest(d["id"], peer_version="0.10.13")
        user, _ = mk_receiver("Carol")
        with core.mutate() as st:
            st["receivers"][user]["peer_version"] = core.VERSION
        page = self.c.get("/").get_data(as_text=True)
        self.assertIn("v0.10.13 · older", page)
        self.assertIn(f">v{core.VERSION}</span>", page)
        row = selfcheck.versions_row(core.load_state())
        self.assertEqual(row[2], "warn")
        self.assertIn("Bob (0.10.13)", row[3])
        core.update_dest(d["id"], peer_version=core.VERSION)
        self.assertEqual(selfcheck.versions_row(core.load_state())[2], "ok")


if __name__ == "__main__":
    unittest.main()
