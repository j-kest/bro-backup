# SPDX-License-Identifier: AGPL-3.0-or-later
"""Each bro can get the folders in Settings, or a choice of his own."""
import os
import shutil
import time
from unittest import mock

import _env  # noqa: F401

from bro import backup, core, web
from test_folders import mk
from test_peers import mk_dest
from test_security import PW, WebBase


class DestFolders(WebBase):
    def setUp(self):
        super().setUp()
        shutil.rmtree(core.NAS_DIR, ignore_errors=True)
        os.makedirs(core.NAS_DIR)
        self.addCleanup(shutil.rmtree, core.NAS_DIR, True)
        self.photos, self.docs, self.films = mk("data", "photos"), mk("data", "docs"), mk("data", "films")
        with core.mutate() as st:
            st["settings"]["sources"] = [self.photos, self.docs, self.films]
        self.d = mk_dest()
        self.url = f"/dest/{self.d['id']}/folders"
        self.notify = mock.patch.object(web, "notify").start()
        core.sources_size.clear()

    def post(self, **data):
        data.setdefault("csrf", self.csrf(self.url))
        return self.c.post(self.url, data=data, follow_redirects=True).get_data(as_text=True)

    def own(self):
        return core.get_dest(self.d["id"]).get("sources")

    def test_follows_settings_until_he_gets_his_own(self):
        self.assertEqual(core.dest_sources(self.d), [self.photos, self.docs, self.films])
        self.assertEqual([i["key"] for i in backup.backup_plan(self.d)], ["data/docs", "data/films", "data/photos"])
        own = dict(self.d, sources=[self.photos])
        self.assertEqual([i["key"] for i in backup.backup_plan(own)], ["data/photos"])
        self.assertNotEqual(backup.sources_key(d=own), backup.sources_key(d=self.d))

    def test_adding_needs_no_password_leaving_out_does(self):
        self.login()
        page = self.c.get(self.url).get_data(as_text=True)
        self.assertIn("The same folders as in", page)
        self.assertIn('data-sizes="/folder-sizes.json"', page)
        extra = mk("data", "music")
        self.post(which="own", src=[self.photos, self.docs, self.films, extra])  # more than before: no password
        self.assertEqual(sorted(self.own()), sorted([self.photos, self.docs, self.films, extra]))
        page = self.post(which="own", src=[self.photos])  # leaves folders out
        self.assertEqual(len(self.own()), 4)
        self.assertIn("password", page.lower())
        self.post(which="own", src=[self.photos], current_pw=PW)
        self.assertEqual(self.own(), [self.photos])
        self.assertIn("Fewer folders go to Bob", self.notify.call_args[0][0])
        self.post(which="same")  # back to all folders in Settings: adds, no password
        self.assertIsNone(self.own())
        self.assertIn('href="/dest/%s/folders">Folders</a>' % self.d["id"], self.c.get("/").get_data(as_text=True))

    def test_own_choice_needs_a_folder_and_stays_inside_the_nas(self):
        self.login()
        self.assertIn("Choose at least one folder", self.post(which="own"))
        self.post(which="own", src=[self.photos, self.docs, self.films, "/etc"])
        self.assertEqual(sorted(self.own()), sorted([self.photos, self.docs, self.films]))
        self.assertIn("3 own", self.c.get("/").get_data(as_text=True))

    def test_space_check_measures_his_folders(self):
        with open(os.path.join(self.photos, "p"), "wb") as f:
            f.write(b"x" * 1000)
        with open(os.path.join(self.films, "f"), "wb") as f:
            f.write(b"x" * 50000)
        self.assertEqual(backup.sources_bytes(d=self.d), 51000)
        self.assertEqual(backup.sources_bytes(d=dict(self.d, sources=[self.photos])), 1000)
        self.assertEqual(len(backup.measured()), 2)  # both kept, each under its own folders

    def test_measurement_from_before_1_5_is_read(self):
        key = backup.sources_key()
        with core.mutate() as st:
            st["sources_measured"] = {"key": key, "bytes": 77, "at": time.time()}
        core.sources_size.clear()
        self.assertEqual(backup.sources_bytes(), 77)
