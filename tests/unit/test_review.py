# SPDX-License-Identifier: AGPL-3.0-or-later
"""Findings of the independent review of 1.1.3: one test each."""
import base64
import os
import re
import subprocess
import tempfile
import unittest
from unittest import mock

import _env

from bro import backup, core, lan, pair_api, web
from test_audit import ticket_with
from test_peers import mk_dest, mk_receiver
from test_security import WebBase


class SetupCode(unittest.TestCase):
    def setUp(self):
        _env.reset()
        web.app.secret_key = "unit-test"
        self.c = web.app.test_client()

    def test_without_code_setup_is_open(self):
        self.assertEqual(self.c.get("/setup").status_code, 200)

    def test_with_code_only_the_link_opens_it(self):
        with mock.patch.dict(os.environ, {"BRO_SETUP_CODE": "s3cr3t-code"}):
            self.assertEqual(self.c.get("/setup").status_code, 403)
            self.assertEqual(self.c.get("/folders.json?path=" + core.NAS_DIR).status_code, 403)
            self.assertEqual(self.c.get("/setup?code=wrong").status_code, 403)
            self.assertEqual(self.c.get("/setup?code=s3cr3t-code").status_code, 200)
            self.assertEqual(self.c.get("/setup").status_code, 200)  # remembered for this browser
            self.assertEqual(web.app.test_client().get("/setup").status_code, 403)  # not for another one


class StateFile(unittest.TestCase):
    def setUp(self):
        _env.reset()

    def test_damaged_state_falls_back_to_the_copy(self):
        with core.mutate() as st:
            st["settings"]["name"] = "Alice"
        with core.mutate() as st:
            st["settings"]["name"] = "Alice 2"
        with open(core.STATE_FILE, "w") as f:
            f.write('{"settings": {"na')  # cut off halfway
        self.assertEqual(core.settings()["name"], "Alice")  # the version before
        with open(core.STATE_BAK, "w") as f:
            f.write("garbage")
        with self.assertRaises(RuntimeError):
            core.load_state()  # never a silent new setup over an existing install

    def test_missing_state_uses_the_copy(self):
        with core.mutate() as st:
            st["settings"]["name"] = "Alice"
        with core.mutate() as st:
            st["settings"]["name"] = "Alice 2"
        os.remove(core.STATE_FILE)
        self.assertEqual(core.settings()["name"], "Alice")

    def test_new_install(self):
        self.assertEqual(core.settings()["name"], "")


class Ntfy(unittest.TestCase):
    def test_title_outside_latin1(self):
        sent = []
        with mock.patch.object(core.urllib.request, "urlopen", lambda req, timeout: sent.append(req)):
            core.send_ntfy(dict(core.DEFAULT_SETTINGS, ntfy_url="https://ntfy.example/t"), "Łukasz: backup failed", "x")
        title = sent[0].get_header("Title")
        self.assertTrue(title.startswith("=?UTF-8?B?"))
        self.assertEqual(base64.b64decode(title[10:-2]).decode(), "Łukasz: backup failed")
        self.assertEqual(core.header_text("plain"), "plain")


class FailureAlerts(unittest.TestCase):
    def setUp(self):
        _env.reset()
        self.d = mk_dest()

    def test_once_a_day_and_works_again(self):
        sent = []
        with mock.patch.object(backup, "notify", lambda t, m, priority="high": sent.append(t)):
            for _ in range(5):
                backup.notify_failure(self.d["id"], "Bro not reachable: timeout")
            self.assertEqual(sent, ["BRO Backup to Bob failed"])
            backup.notify_failure(self.d["id"], "Quota at Bob reached")  # another error: told
            self.assertEqual(len(sent), 2)
            core.update_dest(self.d["id"], fail_notified={"text": "Quota at Bob reached",
                                                          "at": core.iso(core.now() - backup.FAIL_REPEAT)})
            backup.notify_failure(self.d["id"], "Quota at Bob reached")  # a day later: again
            self.assertEqual(len(sent), 3)


class Tickets(unittest.TestCase):
    def test_unreadable_ticket_is_refused(self):
        good = ticket_with([lan._entry("192.168.1.50", 7841)])
        raw = base64.b32decode(good[8:].upper() + "=" * (-len(good[8:]) % 8)) + b"\x00"  # one byte too many
        bad = "endpoint" + base64.b32encode(raw).decode().rstrip("=").lower()
        self.assertIsNone(lan.clean_peer_ticket(bad))
        self.assertIsNone(lan.clean_peer_ticket("endpoint!!!"))
        self.assertIsNone(lan.clean_peer_ticket(None))
        self.assertEqual(lan.clean_peer_ticket(good), good)


@unittest.skipUnless(os.path.exists("/usr/local/bin/restic") or os.path.exists("/usr/bin/restic"), "needs restic")
class RestoreRoom(unittest.TestCase):
    def test_refused_when_it_does_not_fit(self):
        _env.reset()
        d = mk_dest()
        repo, src, target = tempfile.mkdtemp(), tempfile.mkdtemp(), tempfile.mkdtemp()
        env = dict(os.environ, RESTIC_REPOSITORY=repo, RESTIC_PASSWORD="pw-test-1", RESTIC_CACHE_DIR=tempfile.mkdtemp())
        subprocess.run([core.RESTIC, "init"], env=env, capture_output=True, check=True)
        with open(os.path.join(src, "a"), "wb") as f:
            f.write(os.urandom(2_000_000))
        subprocess.run([core.RESTIC, "backup", "."], cwd=src, env=env, capture_output=True, check=True)
        with mock.patch.object(backup, "restic_env", return_value=env):
            backup.check_restore_room(d, target, "latest", [])  # plenty of room
            Usage = type("U", (), {"free": 1_000_000})
            with mock.patch.object(backup.shutil, "disk_usage", return_value=Usage()):
                with self.assertRaises(backup.JobError) as e:
                    backup.check_restore_room(d, target, "latest", [])
        self.assertIn("Not restored: this needs 1.9 MiB", str(e.exception))
        self.assertFalse(os.path.exists(target))  # the empty restore folder is not left behind


class SpeedBudget(unittest.TestCase):
    def setUp(self):
        _env.reset()
        pair_api._speed_used.clear()

    def test_one_bro_cannot_test_all_day(self):
        user, pw = mk_receiver("Bob")
        hdr = {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
        c = pair_api.pair_app.test_client()
        with mock.patch.object(pair_api, "SPEED_BUDGET", 3 * 1024 * 1024):
            for _ in range(3):
                self.assertEqual(c.post("/bro/speedtest", headers=hdr, data=b"x" * 1024 * 1024).status_code, 200)
            self.assertEqual(c.post("/bro/speedtest", headers=hdr, data=b"x" * 1024 * 1024).status_code, 429)
            self.assertEqual(c.get("/bro/speedtest?seconds=1", headers=hdr).status_code, 429)


class Csp(WebBase):
    def test_scripts_need_the_nonce(self):
        self.login()
        r = self.c.get("/settings")
        nonce = re.search(r"'nonce-([^']+)'", r.headers["Content-Security-Policy"]).group(1)
        self.assertNotIn("unsafe-inline'; style", r.headers["Content-Security-Policy"].split("script-src")[1][:60])
        page = r.get_data(as_text=True)
        self.assertEqual(page.count("<script"), page.count(f'<script nonce="{nonce}"'))
        self.assertNotIn("onclick=", page + self.c.get("/").get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
