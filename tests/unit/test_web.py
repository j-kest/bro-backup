# SPDX-License-Identifier: AGPL-3.0-or-later
"""The web page through Flask's test client: login, CSRF, headers, and the remove pages."""
import os
import re
import unittest
from unittest import mock

import _env

from bro import core, peers, web
from test_peers import mk_dest, mk_receiver

PW = "a-long-test-password"


class Web(unittest.TestCase):
    def setUp(self):
        _env.reset()
        with core.mutate() as st:
            st["settings"].update(name="Alice", pw_hash=core.hash_ui_password(PW))
        web.auth.clear_fails("127.0.0.1")
        web.app.secret_key = "unit-test"  # set by server.init() in the real app
        self.c = web.app.test_client()
        for p in (mock.patch.object(peers, "notify"), mock.patch.object(peers.threading, "Thread", _env.SyncThread),
                  mock.patch.object(peers.procs, "stop_proc"), mock.patch.object(web.time, "sleep")):
            p.start()
        self.addCleanup(mock.patch.stopall)

    def csrf(self, path):
        return re.search(r'name="csrf" value="([^"]+)"', self.c.get(path).get_data(as_text=True)).group(1)

    def login(self):
        r = self.c.post("/login", data={"pw": PW, "csrf": self.csrf("/login")})
        self.assertEqual(r.status_code, 302)

    def test_needs_login_and_sends_headers(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
        r = self.c.get("/login")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual(self.c.get("/healthz").status_code, 200)

    def test_post_without_csrf_refused(self):
        self.login()
        self.assertEqual(self.c.post("/report-now", data={}).status_code, 400)

    def test_wrong_password(self):
        r = self.c.post("/login", data={"pw": "nope", "csrf": self.csrf("/login")})
        self.assertIn("Wrong password", r.get_data(as_text=True))

    def test_message_survives_the_new_session(self):
        with web.app.test_request_context():
            web.flash("Recovered from the disk", "ok")
            web.start_session()
            self.assertIn(("ok", "Recovered from the disk"), web.session.get("_flashes"))

    def test_update_notice_and_hide(self):
        self.login()
        with core.mutate() as st:
            st["update"] = {"latest": "99.0.0", "url": "https://github.com/j-kest/bro-backup/releases/tag/v99.0.0"}
        page = self.c.get("/").get_data(as_text=True)
        self.assertIn("BRO Backup 99.0.0 is available", page)
        self.c.post("/update/dismiss", data={"csrf": self.csrf("/")})
        self.assertNotIn("is available", self.c.get("/").get_data(as_text=True))

    def test_remove_dest_needs_the_name(self):
        self.login()
        d = mk_dest("Bob")
        tok = self.csrf(f"/dest/{d['id']}/remove")
        with mock.patch.object(peers.procs, "pair_call", return_value={"ok": True}) as call:
            self.c.post(f"/dest/{d['id']}/remove", data={"csrf": tok, "confirm": "Bobby"})
            self.assertTrue(core.get_dest(d["id"]))  # wrong name: nothing happens
            call.assert_not_called()
            self.c.post(f"/dest/{d['id']}/remove", data={"csrf": tok, "confirm": "Bob", "ask_delete": "1"})
            self.assertTrue(core.get_dest(d["id"]))  # right name, no password: nothing happens either
            call.assert_not_called()
            r = self.c.post(f"/dest/{d['id']}/remove", data={"csrf": tok, "confirm": " bob ", "ask_delete": "1",
                                                              "current_pw": PW}, follow_redirects=True)
        self.assertIsNone(core.get_dest(d["id"]))
        self.assertIn("You no longer back up to Bob", r.get_data(as_text=True))
        self.assertEqual(call.call_args[0][3], {"leave": True, "delete": True, "revoked": False})

    def test_stop_receiving_shows_leftover(self):
        self.login()
        user, _ = mk_receiver("Carol")
        page = self.c.get(f"/receiver/{user}/remove").get_data(as_text=True)
        self.assertIn("Stop storing Carol", page)
        r = self.c.post(f"/receiver/{user}/remove", data={"csrf": self.csrf("/"), "confirm": "Carol"},
                        follow_redirects=True)
        body = r.get_data(as_text=True)
        self.assertIn("Backups of bros that stopped", body)
        self.c.post(f"/leftover/{user}/delete", data={"csrf": self.csrf("/")})
        self.assertTrue(os.path.exists(os.path.join(core.RECEIVE_DIR, user)))  # no password: still there
        self.c.post(f"/leftover/{user}/delete", data={"csrf": self.csrf("/"), "current_pw": PW})
        self.assertFalse(os.path.exists(os.path.join(core.RECEIVE_DIR, user)))

    def test_revoked_dest_on_overview(self):
        self.login()
        d = mk_dest("Dave")
        peers.mark_revoked(d["id"])
        body = self.c.get("/").get_data(as_text=True)
        self.assertIn("Stopped by Dave", body)


if __name__ == "__main__":
    unittest.main()
