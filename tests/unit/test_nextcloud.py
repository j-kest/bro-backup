# SPDX-License-Identifier: AGPL-3.0-or-later
"""Nextcloud: find its parts, tell whether every bro gets all of them, from snapshots of one moment."""
import datetime
import os
import shutil
import unittest
from unittest import mock

import _env  # noqa: F401

from bro import web  # noqa: F401  (web first: the modules import each other)
from bro import backup, core, nextcloud, selfcheck
from test_peers import mk_dest
from test_security import WebBase

CONFIG = """<?php
$CONFIG = array (
  'instanceid' => 'oc4b2x9z',
  'datadirectory' => '/var/www/html/data',
  'dbtype' => 'pgsql',
  'dbpassword' => 'not read by the app',
);
"""


def touch(*parts, text=""):
    p = os.path.join(core.NAS_DIR, *parts)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)
    return p


class Tree(unittest.TestCase):
    def setUp(self):
        _env.reset()
        shutil.rmtree(core.NAS_DIR, ignore_errors=True)
        os.makedirs(core.NAS_DIR)
        self.addCleanup(shutil.rmtree, core.NAS_DIR, True)
        base = ("tank", "apps", "nextcloud")
        touch(*base, "html", "occ")
        touch(*base, "html", "config", "config.php", text=CONFIG)
        touch(*base, "data", ".ocdata")
        touch(*base, "data", "appdata_oc4b2x9z", "preview", "1", "64-64.png")
        touch(*base, "data", "anna", "files", "photo.jpg")
        touch(*base, "pgdata", "PG_VERSION", text="17")
        touch(*base, "pgdata", "postgresql.conf")
        touch("tank", "apps", "immich", "postgres", "PG_VERSION", text="16")  # another app's database: a cousin
        touch("tank", "apps", "immich", "postgres", "postgresql.conf")
        self.nc = os.path.realpath(os.path.join(core.NAS_DIR, *base))
        self.html, self.data, self.db = (os.path.join(self.nc, x) for x in ("html", "data", "pgdata"))


class Find(Tree):
    def test_files_only_still_finds_the_rest(self):
        found = nextcloud.find([self.data], core.NAS_DIR)
        self.assertEqual(len(found), 1)
        inst = found[0]
        self.assertEqual((inst["html"], inst["data"], inst["db"]), (self.html, self.data, self.db))  # not Immich's
        self.assertEqual((inst["instance"], inst["dbtype"]), ("oc4b2x9z", "pgsql"))
        self.assertTrue(nextcloud.included(self.data, [self.data]))
        self.assertFalse(nextcloud.included(self.db, [self.data]))
        self.assertTrue(nextcloud.included(self.db, [self.nc]))

    def test_unrelated_folders_find_nothing(self):
        other = os.path.dirname(touch("tank", "media", "film.mkv"))
        self.assertEqual(nextcloud.find([other], core.NAS_DIR), [])


class Rows(Tree):
    def rows(self):
        out = []
        selfcheck.nextcloud_rows(core.load_state(), core.settings(), lambda *a, **k: out.append(a))
        return out

    def test_missing_parts_are_named_per_bro(self):
        with core.mutate() as st:
            st["settings"]["sources"] = [self.nc]
            st["settings"]["use_zfs_snapshots"] = False
        mk_dest()
        d2 = mk_dest(name="Carol")
        core.update_dest(d2["id"], sources=[self.data])
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        _, name, status, text = rows[0][:4]
        self.assertEqual((name, status), ("Nextcloud in tank/apps/nextcloud", "warn"))
        self.assertEqual(text, "Not to Carol: the installation (config and apps), the database")
        self.assertNotIn("Bob", text)
        core.update_dest(d2["id"], sources=None)
        self.assertEqual(self.rows()[0][2], "ok")

    def test_snapshots_of_one_moment(self):
        with core.mutate() as st:
            st["settings"]["sources"] = [self.nc]
        t = core.now()
        snaps = {self.html: t, self.data: t, self.db: t - datetime.timedelta(hours=2)}
        with mock.patch.object(backup, "zfs_root", side_effect=lambda p: p), \
                mock.patch.object(backup, "newest_snapshot", side_effect=lambda r: ((("auto", snaps[r])), None)):
            rows = self.rows()
            self.assertEqual(rows[1][1:3], ("Nextcloud in tank/apps/nextcloud: one moment", "warn"))
            self.assertIn("120 minutes apart", rows[1][3])
            snaps[self.db] = t
            self.assertEqual(self.rows()[1][2], "ok")
        with mock.patch.object(backup, "zfs_root", return_value=None):
            self.assertIn("Read live", self.rows()[1][3])


class Setting(WebBase):
    def test_previews_switch(self):
        self.login()
        self.assertIn('name="exclude_nextcloud_previews" value="1" checked', self.c.get("/settings").get_data(as_text=True))
        data = {"csrf": self.csrf("/settings"), "backup_hour": "2", "alert_hours": "72", "default_quota_gib": "500",
                "retention": "standard", "ransomware_watch": "1", "alert_receivers": "1", "restore_test": "1",
                "report_day": "0", "exclude_defaults": "1"}
        self.assertIn("Settings saved", self.c.post("/settings", data=data, follow_redirects=True).get_data(as_text=True))
        self.assertFalse(core.settings()["exclude_nextcloud_previews"])
        self.assertNotIn("appdata_*/preview", backup.exclude_args())


class TwoPools(unittest.TestCase):
    """The TrueNAS app with its files on a big pool and the rest on a fast one, Nextcloud 31+ and PostgreSQL 18."""
    def setUp(self):
        _env.reset()
        shutil.rmtree(core.NAS_DIR, ignore_errors=True)
        os.makedirs(core.NAS_DIR)
        self.addCleanup(shutil.rmtree, core.NAS_DIR, True)
        touch("fast", "nextcloud", "html", "occ")
        touch("fast", "nextcloud", "html", "config", "config.php", text=CONFIG)
        touch("fast", "nextcloud", "postgres_data", "18", "docker", "PG_VERSION", text="18")
        touch("fast", "nextcloud", "postgres_data", "18", "docker", "postgresql.conf")
        touch("fast", "immich", "pgData", "PG_VERSION", text="16")
        touch("fast", "immich", "pgData", "postgresql.conf")
        touch("big", "nextcloud", "data", ".ncdata", text="# Nextcloud data directory")
        touch("big", "nextcloud", "data", "appdata_oc4b2x9z", "preview", "x")
        touch("big", "nextcloud", "data", "appdata_ocold1234", "x")  # left from an earlier install
        r = lambda *p: os.path.realpath(os.path.join(core.NAS_DIR, *p))  # noqa: E731
        self.html, self.db, self.data = r("fast", "nextcloud", "html"), r("fast", "nextcloud", "postgres_data", "18", "docker"), \
            r("big", "nextcloud", "data")
        self.sources = [self.html, r("fast", "nextcloud", "postgres_data"), self.data, r("fast", "immich", "pgData")]

    def test_all_parts_found(self):
        found = nextcloud.find(self.sources, core.NAS_DIR)
        self.assertEqual(len(found), 1)
        inst = found[0]
        self.assertEqual((inst["html"], inst["data"], inst["db"]), (self.html, self.data, self.db))
        st, s = core.load_state(), dict(core.settings(), sources=self.sources)
        self.assertEqual(nextcloud.status(st, s, core.NAS_DIR)[0]["missing"], {})

    def test_files_on_the_other_pool_not_ticked(self):
        st, s = core.load_state(), dict(core.settings(), sources=self.sources[:2])
        v = nextcloud.status(st, s, core.NAS_DIR)[0]
        self.assertEqual(v["inst"]["db"], self.db)
        self.assertEqual(v["missing"], {"your bros": [
            "the users' files (not found: not in your folders, and not next to the other parts)"]})


class SettingsPage(Tree, WebBase):
    def setUp(self):
        Tree.setUp(self)
        WebBase.setUp(self)

    def test_databases_section_shows_nextcloud(self):
        with core.mutate() as st:
            st["settings"]["sources"] = [self.data]
            st["db_scan"] = {"at": core.iso(core.now()), "sqlite": [], "immich": [], "running": False}
        self.login()
        page = self.c.get("/settings").get_data(as_text=True)
        self.assertIn(">Nextcloud</span> In <code>tank/apps/nextcloud</code>", page)
        self.assertIn("the database <code>tank/apps/nextcloud/pgdata</code>", page)
        self.assertIn("Not to your bros: the installation (config and apps), the database", page)
        with core.mutate() as st:
            st["settings"]["sources"] = [self.nc]
        page = self.c.get("/settings").get_data(as_text=True)
        self.assertIn("All three go to every bro", page)
        with core.mutate() as st:
            st["settings"]["sources"] = [os.path.dirname(touch("tank", "media", "film.mkv"))]
        self.assertIn("No Nextcloud found in your folders.", self.c.get("/settings").get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
