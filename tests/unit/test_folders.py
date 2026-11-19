# SPDX-License-Identifier: AGPL-3.0-or-later
"""The folder picker opens deeper than two levels, and a folder chosen deep down is kept."""
import os
import shutil
import time
from unittest import mock

import _env  # noqa: F401

from bro import core
from test_security import WebBase

from bro import nas  # after web: nas and backup import each other


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

def put(path, n):
    with open(path, "wb") as f:
        f.write(b"x" * n)


class Sizes(WebBase):
    """The folder picker shows how big each folder is."""
    def setUp(self):
        super().setUp()
        shutil.rmtree(core.NAS_DIR, ignore_errors=True)
        os.makedirs(core.NAS_DIR)
        self.addCleanup(shutil.rmtree, core.NAS_DIR, True)
        nas._sizes.clear()
        share = mk("data", "share")
        put(os.path.join(share, "a"), 1000)
        put(os.path.join(mk("data", "share", "photos", "2025", "summer", "deep"), "p"), 5000)
        put(os.path.join(mk("data", "share", "docs"), "d"), 300)
        bro = mk("data", "share", "bro-data")  # a folder a backup skips
        put(os.path.join(bro, core.DATA_MARKER), 0)
        put(os.path.join(bro, "big"), 99999)
        self.share = share

    def test_tree_size(self):
        found = {}
        self.assertEqual(core.tree_size(self.share, found, 2), 6300)
        self.assertEqual(found[os.path.join(self.share, "photos")], 5000)
        self.assertEqual(found[os.path.join(self.share, "photos", "2025")], 5000)
        self.assertEqual(found[os.path.join(self.share, "docs")], 300)
        self.assertEqual(found[os.path.join(self.share, "bro-data")], 0)
        self.assertNotIn(os.path.join(self.share, "photos", "2025", "summer"), found)  # deeper than asked
        self.assertEqual(core.tree_size(os.path.join(self.share, "photos")), 5000)

    def wait(self, paths):
        for _ in range(100):
            known, waiting = nas.folder_sizes(paths)
            if not waiting:
                return known
            time.sleep(0.05)
        self.fail("still measuring")

    def test_measured_in_the_background_with_the_folders_below(self):
        real = os.path.realpath(self.share)
        known = self.wait([self.share])
        self.assertEqual(known[self.share], 6300)
        with mock.patch.object(core, "os") as no_walk:  # the folders below came with the same walk
            no_walk.side_effect = AssertionError
            known, waiting = nas.folder_sizes([os.path.join(self.share, "docs")])
        self.assertFalse(waiting)
        self.assertEqual(known[os.path.join(self.share, "docs")], 300)
        self.assertIn(real, nas._sizes)
        self.assertEqual(nas.folder_sizes(["/etc"]), ({"/etc": None}, False))

    def test_endpoint(self):
        self.login()
        self.wait([self.share])
        j = self.c.get("/folder-sizes.json?p=" + self.share + "&p=/etc").get_json()
        self.assertEqual(j, {"sizes": {self.share: 6300, "/etc": None}, "waiting": False})
        page = self.c.get("/settings").get_data(as_text=True)
        self.assertIn('data-sizes="/folder-sizes.json"', page)
        self.assertIn('id="folders-total"', page)
        self.c.post("/logout", data={"csrf": self.csrf("/")})
        self.assertEqual(self.c.get("/folder-sizes.json?p=" + self.share).status_code, 302)
