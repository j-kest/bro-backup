# SPDX-License-Identifier: AGPL-3.0-or-later
"""UrBackup storage: found, read from names only, sent offsite, every computer watched."""
import datetime
import os
import re
import shutil
import unittest
from unittest import mock

import _env

from bro import core, safety, urbackup, web
from test_safety import ago

PW = "a-long-test-password"


def stamp(hours_ago, sep="-"):
    t = datetime.datetime.now() - datetime.timedelta(hours=hours_ago)
    return t.strftime(f"%y%m%d{sep}%H%M")


def make_storage(rel="tank/urbackup", clients=None):
    root = os.path.join(core.NAS_DIR, rel)
    os.makedirs(os.path.join(root, "urbackup_tmp_files"), exist_ok=True)
    os.makedirs(os.path.join(root, "urbackup"), exist_ok=True)
    for name, (file_h, image_h) in (clients or {"PC-ANNE": (5, 30), "SERVER01": (200, None)}).items():
        c = os.path.join(root, name)
        os.makedirs(c, exist_ok=True)
        if file_h is not None:
            os.makedirs(os.path.join(c, stamp(file_h)), exist_ok=True)
            os.makedirs(os.path.join(c, stamp(file_h + 24)), exist_ok=True)
            os.symlink(stamp(file_h), os.path.join(c, "current"))
        if image_h is not None:
            for ext in ("vhdz", "vhdz.mbr", "vhdz.hash"):
                open(os.path.join(c, f"Image_C_{stamp(image_h, '_')}.{ext}"), "w").close()
    return root


class UrBackup(unittest.TestCase):
    def setUp(self):
        _env.reset()
        shutil.rmtree(core.NAS_DIR, ignore_errors=True)
        os.makedirs(core.NAS_DIR)
        self.sent = []
        p = mock.patch.object(urbackup, "notify", lambda t, m, priority="high": self.sent.append(t))
        p.start()
        self.addCleanup(mock.patch.stopall)

    def test_found_and_read(self):
        root = make_storage()
        os.makedirs(os.path.join(core.NAS_DIR, "media", "240101-1200"))  # looks like a backup, no UrBackup storage
        self.assertEqual(urbackup.find_storages(), [root])
        clients = {c["name"]: c for c in urbackup.read_storage(root)}
        self.assertEqual(set(clients), {"PC-ANNE", "SERVER01"})
        anne = clients["PC-ANNE"]
        self.assertEqual((anne["file_backups"], anne["image_backups"], anne["volumes"]), (2, 1, ["C"]))
        self.assertLess(abs((core.now() - core.parse(anne["last"])).total_seconds() / 3600 - 5), 0.1)

    def test_odd_names_are_ignored(self):
        root = make_storage(clients={"PC": (5, None)})
        os.makedirs(os.path.join(root, "PC", "991399-2599"))  # not a date
        open(os.path.join(root, "PC", "Image_C_notadate.vhdz"), "w").close()
        self.assertEqual(urbackup.read_storage(root)[0]["file_backups"], 2)

    def test_silent_computer_notified_once(self):
        make_storage()
        with core.mutate() as st:
            st["settings"]["sources"] = [os.path.join(core.NAS_DIR, "tank")]
        urbackup.check()
        urbackup.check()
        self.assertEqual(self.sent, ["SERVER01 has not been backed up for 8 days"])
        st = core.load_state()
        rows = {c["name"]: c["ok"] for c in urbackup.status(st)[0]["clients"]}
        self.assertEqual(rows, {"PC-ANNE": True, "SERVER01": False})

    def test_not_included_is_told(self):
        make_storage(clients={"PC": (5, None)})
        urbackup.check()
        self.assertEqual(self.sent, ["UrBackup storage is not sent offsite"])
        self.assertFalse(urbackup.status()[0]["included"])

    def test_temp_files_never_go_offsite(self):
        self.assertIn("urbackup_tmp_files", core.DEFAULT_EXCLUDES)

    def test_safety_counts_the_computers(self):
        from test_peers import mk_dest
        with core.mutate() as st:
            st["recovery"]["key"] = "k"
            st["settings"].update(ntfy_url="https://ntfy.example/x")
        for name in ("Bob", "Carol"):
            d = mk_dest(name)
            core.update_dest(d["id"], last_ok=ago(0.5), escrow_at=ago(1), restore_test={"ok": True, "at": ago(3)})
        self.assertEqual(safety.compute()["score"], 100)  # without UrBackup: unchanged
        make_storage()
        urbackup.scan()
        r = safety.compute()
        self.assertEqual(r["score"], round(100 * 100 / 120))  # not included and one silent computer: 100 of 120
        self.assertEqual(r["todo"][0]["fix"], "Include the UrBackup folder in Settings")


class Pages(unittest.TestCase):
    def setUp(self):
        _env.reset()
        shutil.rmtree(core.NAS_DIR, ignore_errors=True)
        os.makedirs(core.NAS_DIR)
        with core.mutate() as st:
            st["settings"].update(name="Alice", pw_hash=core.hash_ui_password(PW), sources=[])
        web.auth.clear_fails("127.0.0.1")
        web.app.secret_key = "unit-test"
        self.c = web.app.test_client()
        for p in (mock.patch.object(web.time, "sleep"), mock.patch.object(urbackup, "notify")):
            p.start()
        self.addCleanup(mock.patch.stopall)
        tok = lambda path: re.search(r'name="csrf" value="([^"]+)"', self.c.get(path).get_data(as_text=True)).group(1)
        self.tok = tok
        self.c.post("/login", data={"pw": PW, "csrf": tok("/login")})

    def test_overview_and_include(self):
        root = make_storage()
        urbackup.scan()
        page = self.c.get("/").get_data(as_text=True)
        self.assertIn("PCs and servers (UrBackup)", page)
        self.assertIn("SERVER01", page)
        self.assertIn("is not sent offsite", page)
        self.c.post("/urbackup/include", data={"csrf": self.tok("/"), "path": root})
        self.assertIn(os.path.realpath(root), core.load_state()["settings"]["sources"])
        self.assertEqual(self.c.post("/urbackup/include", data={"csrf": self.tok("/"), "path": "/etc"}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
