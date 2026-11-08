# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pausing backups: nothing new starts, a running restic stops, and the interrupted backup continues later."""
import datetime
import re
import subprocess
import sys
import unittest
from unittest import mock

import _env

from bro import backup, core, scheduler, web

PW = "a-long-test-password"


def iso_in(hours):
    return core.iso(core.now() + datetime.timedelta(hours=hours))


class Pause(unittest.TestCase):
    def setUp(self):
        _env.reset()

    def test_expired_pause_is_none(self):
        self.assertIsNone(core.backups_paused())
        with core.mutate() as st:
            st["pause"] = {"at": iso_in(-2), "until": iso_in(-1)}
        self.assertIsNone(core.backups_paused())
        with core.mutate() as st:
            st["pause"] = {"at": iso_in(0), "until": None}
        self.assertTrue(core.backups_paused())

    def test_scheduler_waits_then_continues(self):
        d = {"id": "x", "last_run": iso_in(-0.1), "last_ok": iso_in(-0.1)}
        with core.mutate() as st:
            st["pause"] = {"at": iso_in(0), "until": None}
        self.assertFalse(scheduler.backup_due(dict(d, pause_stop=iso_in(0)), 2))
        with core.mutate() as st:
            st.pop("pause")
        self.assertFalse(scheduler.backup_due(d, (datetime.datetime.now().hour + 1) % 24))
        self.assertTrue(scheduler.backup_due(dict(d, pause_stop=iso_in(0)), (datetime.datetime.now().hour + 1) % 24))

    def test_running_restic_is_stopped(self):
        real = subprocess.Popen
        slow = [sys.executable, "-c", "import signal, sys, time\n"
                "signal.signal(signal.SIGINT, lambda *a: sys.exit(130))\ntime.sleep(60)"]
        with core.mutate() as st:
            st["pause"] = {"at": iso_in(0), "until": None}
        with mock.patch.object(backup.subprocess, "Popen", lambda args, **kw: real(slow, **kw)), \
                mock.patch.object(backup, "restic_env", lambda *a, **k: None):
            rc, _err, why, _sum = backup._run_restic_item({"id": "x", "password": "p", "repo_password": "r"}, {"key": "tank", "root": "tank", "target": ".",
                                                                         "cwd": "/"}, "Backup", {}, core.settings(),
                                                          "alice", None, None, False)
        self.assertEqual(why, "pause")
        self.assertNotEqual(rc, 0)  # stopped by SIGINT, not finished


class Pages(unittest.TestCase):
    def setUp(self):
        _env.reset()
        with core.mutate() as st:
            st["settings"].update(name="Alice", pw_hash=core.hash_ui_password(PW), sources=[])
            st["destinations"] = [{"id": "d1", "name": "Bob", "pause_stop": iso_in(0)}]
        web.auth.clear_fails("127.0.0.1")
        web.app.secret_key = "unit-test"
        self.c = web.app.test_client()
        mock.patch.object(web.time, "sleep").start()
        self.runs = []
        mock.patch.object(web.backup, "run_backup", lambda dest_id, *a: self.runs.append(dest_id)).start()
        self.addCleanup(mock.patch.stopall)
        self.tok = lambda p: re.search(r'name="csrf" value="([^"]+)"', self.c.get(p).get_data(as_text=True)).group(1)
        self.c.post("/login", data={"pw": PW, "csrf": self.tok("/login")})

    def test_pause_refuse_resume(self):
        page = self.c.post("/pause", data={"csrf": self.tok("/"), "hours": "4"}, follow_redirects=True).get_data(as_text=True)
        self.assertIn("Backups are paused until", page)
        until = core.parse(core.load_state()["pause"]["until"])
        self.assertAlmostEqual((until - core.now()).total_seconds() / 3600, 4, delta=0.01)
        page = self.c.post("/dest/d1/run", data={"csrf": self.tok("/")}, follow_redirects=True).get_data(as_text=True)
        self.assertIn("Resume them first", page)
        self.assertEqual(self.runs, [])
        page = self.c.post("/resume", data={"csrf": self.tok("/")}, follow_redirects=True).get_data(as_text=True)
        self.assertNotIn("pause", core.load_state())
        self.assertIn("interrupted backup continues now", page)
        for _ in range(50):
            if self.runs:
                break
            web.time.sleep.side_effect = None
            import time as t
            t.sleep(0.02)
        self.assertEqual(self.runs, ["d1"])

    def test_until_resumed(self):
        page = self.c.post("/pause", data={"csrf": self.tok("/"), "hours": "0"}, follow_redirects=True).get_data(as_text=True)
        self.assertIn("until you resume them", page)
        self.assertIsNone(core.load_state()["pause"]["until"])


if __name__ == "__main__":
    unittest.main()
