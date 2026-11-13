# SPDX-License-Identifier: AGPL-3.0-or-later
"""The folder picker opens deeper than two levels, and a folder chosen deep down is kept."""
import os
import shutil

import _env  # noqa: F401

from bro import core
from test_security import WebBase


def mk(*parts):
    p = os.path.join(core.NAS_DIR, *parts)
    os.makedirs(p, exist_ok=True)
    return p


class Tree(WebBase):
    def setUp(self):
        super().setUp()
        shutil.rmtree(core.NAS_DIR, ignore_errors=True)
        os.makedirs(core.NAS_DIR)
        self.deep = mk("data", "share", "shows", "Series A")
        mk("data", "share", "movies")
        mk("data", "share", "@eaDir", "x")
        mk("data", "share", "#recycle")
        self.addCleanup(shutil.rmtree, core.NAS_DIR, True)

    def test_children_and_limits(self):
        self.login()
        j = self.c.get("/folders.json?path=" + os.path.join(core.NAS_DIR, "data", "share")).get_json()
        self.assertEqual([(f["label"], f["has_sub"]) for f in j["folders"]], [("movies", False), ("shows", True)])
        self.assertEqual(self.c.get("/folders.json?path=/etc").status_code, 404)
        self.assertEqual(self.c.get("/folders.json?path=" + core.NAS_DIR + "/../../etc").status_code, 404)
        os.symlink("/etc", os.path.join(core.NAS_DIR, "data", "out"))
        self.assertEqual(self.c.get("/folders.json?path=" + os.path.join(core.NAS_DIR, "data", "out")).status_code, 404)
        self.c.post("/logout", data={"csrf": self.csrf("/")})
        self.assertEqual(self.c.get("/folders.json?path=" + core.NAS_DIR).status_code, 302)  # login needed

    def test_a_deep_folder_is_saved_and_shown(self):
        self.login()
        page = self.c.get("/settings").get_data(as_text=True)
        self.assertIn('aria-label="Open share"', page)
        data = {"csrf": self.csrf("/settings"), "backup_hour": "2", "alert_hours": "72", "default_quota_gib": "500",
                "retention": "standard", "ransomware_watch": "1", "alert_receivers": "1", "restore_test": "1",
                "report_day": "0", "src": self.deep}
        self.assertIn("Settings saved", self.c.post("/settings", data=data, follow_redirects=True).get_data(as_text=True))
        self.assertEqual(core.settings()["sources"], [os.path.realpath(self.deep)])
        page = self.c.get("/settings").get_data(as_text=True)
        self.assertIn("Also selected, deeper down:", page)
        self.assertRegex(page, r'name="src" value="[^"]*Series A" checked')
        # saving again without touching it keeps it (no password needed: nothing was left out)
        data["csrf"] = self.csrf("/settings")
        self.assertIn("Settings saved", self.c.post("/settings", data=data, follow_redirects=True).get_data(as_text=True))
