# SPDX-License-Identifier: AGPL-3.0-or-later
"""One test per finding of the security review of v0.10 (F1 to F9), so none of them comes back."""
import os
import re
import tempfile
import unittest
from unittest import mock

import _env

from bro import core, nas, pair_api, pairing, peers, receiving, scheduler, web
from test_peers import A, B, mk_dest, mk_receiver

PW = "a-long-test-password"
EVIL = "x');alert(document.cookie);//"


class WebBase(unittest.TestCase):
    def setUp(self):
        _env.reset()
        web._live.clear()
        with core.mutate() as st:
            st["settings"].update(name="Alice", pw_hash=core.hash_ui_password(PW))
        web.auth.clear_fails("127.0.0.1")
        web.app.secret_key = "unit-test"
        self.c = web.app.test_client()
        for p in (mock.patch.object(peers, "notify"), mock.patch.object(receiving, "notify"),
                  mock.patch.object(peers.threading, "Thread", _env.SyncThread),
                  mock.patch.object(peers.procs, "stop_proc"), mock.patch.object(web.time, "sleep")):
            p.start()
        self.addCleanup(mock.patch.stopall)

    def csrf(self, path="/"):
        return re.search(r'name="csrf" value="([^"]+)"', self.c.get(path).get_data(as_text=True)).group(1)

    def login(self, client=None):
        c = client or self.c
        tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
        self.assertEqual(c.post("/login", data={"pw": PW, "csrf": tok}).status_code, 302)


class F1NamesNeverInScript(WebBase):
    def test_bro_name_cannot_run_script(self):
        self.login()
        user, _ = mk_receiver("Carol")
        with core.mutate() as st:
            st["receivers"][user]["bro_name"] = EVIL  # as stored by an older version
        peers.revoke_receiver(user)  # now a leftover row with a Delete button
        page = self.c.get("/").get_data(as_text=True)
        self.assertNotIn("return confirm(", page)
        for m in re.finditer(r"data-confirm=\"([^\"]*)\"", page):
            self.assertNotIn("'", m.group(1))  # quotes stay escaped inside the attribute
        self.assertIn("data-confirm=\"Delete the backups of x&#39;);alert(document.cookie);//", page)

    def test_names_cleaned_on_arrival(self):
        self.assertEqual(core.clean_name("Bob\n2026-01-01 WARNING fake"), "Bob 2026-01-01 WARNING fake")
        self.assertEqual(core.clean_name(["x"]), "")
        self.assertEqual(len(core.clean_name("a" * 500)), 40)


class F2SeedLinks(unittest.TestCase):
    def mk_seed(self):
        d = tempfile.mkdtemp()
        for sub in ("data/ab", "index", "keys", "snapshots", "locks"):
            os.makedirs(os.path.join(d, sub))
        for f in ("config", "data/ab/" + "ab" * 32, "keys/" + "cd" * 32):
            with open(os.path.join(d, f), "w") as fh:
                fh.write("x")
        return d

    def test_plain_repo_passes(self):
        nas.check_seed_layout(self.mk_seed())

    def test_link_refused(self):
        d = self.mk_seed()
        os.symlink(core.STATE_FILE, os.path.join(d, "data/ab/" + "ef" * 32))
        with self.assertRaisesRegex(RuntimeError, "link"):
            nas.check_seed_layout(d)

    def test_linked_folder_and_odd_files_refused(self):
        d = self.mk_seed()
        os.symlink("/", os.path.join(d, "data/cd"))
        with self.assertRaises(RuntimeError):
            nas.check_seed_layout(d)
        d = self.mk_seed()
        with open(os.path.join(d, "index", "notes.txt"), "w") as fh:
            fh.write("x")
        with self.assertRaisesRegex(RuntimeError, "Unexpected file"):
            nas.check_seed_layout(d)


class F3NoMatchingOnName(unittest.TestCase):
    def setUp(self):
        _env.reset()
        for p in (mock.patch.object(peers, "notify"), mock.patch.object(peers.procs, "stop_proc")):
            p.start()
        self.addCleanup(mock.patch.stopall)

    def test_other_bro_cannot_revoke_by_name(self):
        mallory, _ = mk_receiver("Mallory")
        alice = mk_dest("Alice")  # one way: no receiver linked
        peers.receive_hello(mallory, {"n": "Alice"})
        peers.receive_goodbye(mallory, {"revoked": True})
        self.assertIsNone(core.get_dest(alice["id"]).get("mode"))


class F4NoOptionInjection(WebBase):
    def test_search_term_never_becomes_an_option(self):
        self.login()
        d = mk_dest("Bob")
        fake = mock.Mock(returncode=0, stdout="[]", stderr="")
        with mock.patch.object(web.backup, "restic", return_value=fake) as r:
            self.c.get(f"/dest/{d['id']}/browse/abcdef12", query_string={"q": "--password-command=sh *"})
        args = r.call_args[0][1:]
        self.assertEqual(args[args.index("--") + 1][0], "*")
        self.assertLess(args.index("--"), len(args) - 1)


class F5QuotaHere(unittest.TestCase):
    def setUp(self):
        _env.reset()
        p = mock.patch.object(receiving, "notify")
        p.start()
        self.addCleanup(mock.patch.stopall)

    def test_block_and_unblock(self):
        user, _ = mk_receiver("Bob", data=b"x" * 2000)
        with core.mutate() as st:
            st["receivers"][user]["quota_gib"] = 1
        with mock.patch.object(receiving, "GIB", 1000):  # 1 "GiB" = 1000 bytes for this test
            scheduler.refresh_receive_stats(only=user)
            self.assertNotIn(user, receiving.read_htpasswd())
            self.assertTrue(core.load_state()["receivers"][user]["quota_blocked"])
            with core.mutate() as st:
                st["receivers"][user]["quota_gib"] = 5
            scheduler.refresh_receive_stats(only=user)
        self.assertIn(user, receiving.read_htpasswd())
        self.assertNotIn("quota_blocked", core.load_state()["receivers"][user])


class F6BadFieldsFromBros(WebBase):
    def test_list_as_name_does_not_lock_removal(self):
        self.login()
        user, _ = mk_receiver("Bob")
        peers.receive_hello(user, {"n": ["x"]})
        self.assertEqual(core.load_state()["receivers"][user]["bro_name"], "Bob")
        r = self.c.post(f"/receiver/{user}/remove", data={"csrf": self.csrf(), "confirm": "Bob"})
        self.assertEqual(r.status_code, 302)
        self.assertNotIn(user, core.load_state()["receivers"])

    def test_pairing_fields_checked(self):
        good = dict(name="Bob", dt=_env.ticket(B), pt=_env.ticket(B), user="alice", pw="p" * 32)
        pairing.check_peer_fields(**good)
        for bad in (dict(dt={"x": 1}), dict(pt="endpoint-x"), dict(user="../config"), dict(user=["a"]),
                    dict(pw="x@evil.example:80/"), dict(pw="short")):
            with self.assertRaises(ValueError, msg=bad):
                pairing.check_peer_fields(**{**good, **bad})


class F7Diagnostics(unittest.TestCase):
    def test_redacted(self):
        st = {"pending_accepts": [{"payload": {"pw": "PWSECRET", "tok": "TOKSECRET", "u": "bob"}}],
              "receivers": {"bob": {"link_key": "LKSECRET"}}, "destinations": [{"link_key": "LK2", "lk": "LK3"}],
              "settings": {"ntfy_url": "https://user:NTFYPASS@ntfy.example/topic"}}
        out = repr(core.redact(st))
        for secret in ("PWSECRET", "TOKSECRET", "LKSECRET", "LK2", "LK3", "NTFYPASS"):
            self.assertNotIn(secret, out)


class F8PairApiLoad(unittest.TestCase):
    def test_one_speed_test_at_a_time(self):
        _env.reset()
        user, pw = mk_receiver("Bob")
        c = pair_api.pair_app.test_client()
        auth = {"Authorization": "Basic " + __import__("base64").b64encode(f"{user}:{pw}".encode()).decode()}
        self.assertTrue(pair_api._speed_slot.acquire(blocking=False))  # a test is running
        try:
            self.assertEqual(c.get("/bro/speedtest?seconds=1", headers=auth).status_code, 429)
        finally:
            pair_api._speed_slot.release()
        r = c.get("/bro/speedtest?seconds=1", headers=auth)
        self.assertEqual(r.status_code, 200)
        r.close()
        self.assertTrue(pair_api._speed_slot.acquire(blocking=False))  # released after the answer
        pair_api._speed_slot.release()


class F9Sessions(WebBase):
    def cookie_data(self):
        raw = self.c.get_cookie("bro_backup_session").value
        return web.app.session_interface.get_signing_serializer(web.app).loads(raw)

    def test_no_secrets_in_cookie(self):
        self.login()
        core.my_tickets.update(data=_env.ticket(A), pair=_env.ticket(A))
        self.c.post("/invite", data={"csrf": self.csrf(), "name": "Bob", "quota": "5"})
        self.assertNotIn("invite_code", self.cookie_data())
        self.assertIn("BRO1.", self.c.get("/").get_data(as_text=True))

    def test_logout_ends_copied_cookie(self):
        self.login()
        raw = self.c.get_cookie("bro_backup_session").value
        other = web.app.test_client()
        other.set_cookie("bro_backup_session", raw)
        self.assertEqual(other.get("/").status_code, 200)
        self.c.post("/logout", data={"csrf": self.csrf()})
        self.assertEqual(other.get("/").status_code, 302)

    def test_password_change_ends_other_logins(self):
        self.login()
        other = web.app.test_client()
        self.login(other)
        tok = self.csrf("/security")
        self.c.post("/security/password", data={"csrf": tok, "current_pw": PW, "new_pw": "another-long-pw",
                                                "new_pw2": "another-long-pw"})
        self.assertEqual(other.get("/").status_code, 302)
        self.assertEqual(self.c.get("/").status_code, 200)


if __name__ == "__main__":
    unittest.main()
