# SPDX-License-Identifier: AGPL-3.0-or-later
"""One test per finding of the independent security audit of v0.10.10 (F1 to F12, S1 to S4)."""
import base64
import http.server
import json
import logging
import os
import re
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from unittest import mock

import _env

from bro import auth, backup, core, lan, nas, pair_api, pairing, peers, procs, receiving, selfcheck, server, urbackup, web
from test_peers import A, B, mk_dest
from test_security import PW, WebBase


# ---------------------------------------------------------------- F3: folder names never become restic options
class F3ResticArguments(unittest.TestCase):
    def setUp(self):
        _env.reset()

    def test_double_dash_before_the_folder(self):
        seen = []

        def fake_popen(args, **kw):
            seen.append(args)
            raise RuntimeError("stop here")
        item = {"key": "x", "root": "/nas/x", "target": "--password-command=touch /tmp/pwned", "cwd": "/"}
        d = mk_dest()
        with mock.patch.object(backup.subprocess, "Popen", fake_popen), mock.patch.object(backup, "restic_env", lambda *a: {}):
            with self.assertRaises(RuntimeError):
                backup._run_restic_item(d, item, 1, {}, core.settings(), "alice", None, None, False)
        args = seen[0]
        self.assertEqual(args[-2:], ["--", item["target"]])

    def test_tags_survive_commas(self):
        for name in ("Foto's, 2024", "100%", "a%2Cb", "plain"):
            self.assertNotIn(",", core.tag_enc(name))
            self.assertEqual(core.tag_dec(core.tag_enc(name)), name)

    def test_urbackup_scan_skips_option_like_names(self):
        base = tempfile.mkdtemp()
        os.makedirs(os.path.join(base, "-evil", "clients"))
        with mock.patch.object(urbackup, "is_storage", lambda p: os.path.basename(p) == "-evil"):
            self.assertEqual(urbackup.find_storages(base), [])


# ---------------------------------------------------------------- F1, F2, F7: answers from a bro are not trusted
class _Handler(http.server.BaseHTTPRequestHandler):
    mode = "ok"

    def do_GET(self):
        if self.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()
            return
        body = b"{\"x\": \"" + b"a" * (procs.PAIR_MAX_ANSWER + 10) + b"\"}" if self.mode == "big" else \
            (b"not json" if self.mode == "junk" else b"{\"ok\": true}")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class F1PairAnswers(unittest.TestCase):
    def setUp(self):
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        port = self.srv.server_address[1]

        @contextmanager
        def tunnel(ticket):
            yield port
        p = mock.patch.object(procs, "pair_tunnel", tunnel)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(lambda: setattr(_Handler, "mode", "ok"))

    def call(self, mode):
        _Handler.mode = mode
        return procs.pair_call("t", "GET", "/bro/status", timeout=5)

    def test_normal_answer(self):
        self.assertEqual(self.call("ok"), {"ok": True})

    def test_redirect_not_followed(self):
        with mock.patch.object(procs.time, "sleep"):
            with self.assertRaises(RuntimeError) as e:
                self.call("redirect")
        self.assertIn("302", str(e.exception))

    def test_too_large_or_not_json(self):
        for mode in ("big", "junk"):
            with self.assertRaises(procs.PairAnswerError):
                self.call(mode)

    def test_status_keeps_known_values_only(self):
        _env.reset()
        d = mk_dest()
        evil = {"usage": "1e999", "snapshots": -5, "quota_gib": [1], "disk": "<b>", "name": {"x": 1},
                "blocked": "yes", "escrow": 1, "v": "<script>"}
        with mock.patch.object(procs, "pair_call", return_value=evil):
            info = backup.bro_status(d)
        self.assertEqual(info, {"usage": 0, "snapshots": 0, "quota_gib": 0, "disk": None, "name": None,
                                "blocked": False, "escrow": False, "v": None})


# ---------------------------------------------------------------- F5, F9: settings that move secrets or weaken retention
class F5Settings(WebBase):
    def save(self, **fields):
        data = {"csrf": self.csrf("/settings"), "backup_hour": "2", "alert_hours": "72", "default_quota_gib": "500",
                "retention": "standard", "ransomware_watch": "1", "alert_receivers": "1", "restore_test": "1", "report_day": "0"}
        data.update(fields)
        return self.c.post("/settings", data=data, follow_redirects=True).get_data(as_text=True)

    def test_sensitive_change_needs_password(self):
        self.login()
        page = self.save(ntfy_url="https://evil.example/topic")
        self.assertIn("needs your current password", page)
        self.assertEqual(core.settings()["ntfy_url"], "")
        self.save(retention="short", current_pw="wrong-password-123")
        self.assertEqual(core.settings()["retention"], "standard")
        self.assertIn("Settings saved", self.save(ntfy_url="https://ntfy.example/t", current_pw=PW))
        self.assertEqual(core.settings()["ntfy_url"], "https://ntfy.example/t")

    def test_other_changes_need_no_password(self):
        self.login()
        self.assertIn("Settings saved", self.save(backup_hour="4"))
        self.assertEqual(core.settings()["backup_hour"], 4)

    def test_secret_does_not_follow_a_new_server(self):
        with core.mutate() as st:
            st["settings"].update(smtp_host="mail.example.be", smtp_user="nas", smtp_password="geheim")
        self.login()
        page = self.save(smtp_host="mail.evil.example", smtp_user="nas", current_pw=PW)
        self.assertIn("Settings saved", page)
        self.assertEqual(core.settings()["smtp_password"], "")


# ---------------------------------------------------------------- F6: the emergency keys
class F6Keys(WebBase):
    def test_only_post_with_password(self):
        self.login()
        self.assertEqual(self.c.get("/keys").status_code, 405)
        with mock.patch.object(selfcheck, "notify") as n:
            r = self.c.post("/keys", data={"csrf": self.csrf("/settings")})
            self.assertEqual(r.status_code, 302)
            n.assert_not_called()
            r = self.c.post("/keys", data={"csrf": self.csrf("/settings"), "current_pw": PW})
            self.assertEqual(r.status_code, 200)
            self.assertIn("attachment", r.headers["Content-Disposition"])
            n.assert_called_once()

    def test_code_needed_and_used_once(self):
        secret = auth.new_totp_secret()
        with core.mutate() as st:
            st["settings"]["totp_secret"] = secret
        code = auth._totp(secret, int(time.time() // auth.TOTP_STEP))
        tok = re.search(r'name="csrf" value="([^"]+)"', self.c.get("/login").get_data(as_text=True)).group(1)
        self.assertEqual(self.c.post("/login", data={"pw": PW, "code": code, "csrf": tok}).status_code, 302)
        with mock.patch.object(selfcheck, "notify"):
            r = self.c.post("/keys", data={"csrf": self.csrf("/settings"), "current_pw": PW, "code": code})
        self.assertEqual(r.status_code, 302)  # the code was used for the login already


# ---------------------------------------------------------------- F10: password checks count as failed logins
class F10Lockout(WebBase):
    def test_wrong_current_password_locks(self):
        self.login()
        for _ in range(12):
            self.c.post("/keys", data={"csrf": self.csrf("/settings"), "current_pw": "wrong-password-123"})
        with mock.patch.object(selfcheck, "notify"):
            r = self.c.post("/keys", data={"csrf": self.csrf("/settings"), "current_pw": PW})
        self.assertEqual(r.status_code, 302)  # locked: even the right password waits


# ---------------------------------------------------------------- F11: polling is not activity
class F11Idle(WebBase):
    def test_live_json_does_not_keep_the_session_alive(self):
        self.login()
        with self.c.session_transaction() as s:
            s["seen"] = 1000
        with mock.patch.object(web.time, "time", return_value=2000):
            self.c.get("/live.json")
        with self.c.session_transaction() as s:
            self.assertEqual(s.get("seen"), 1000)


# ---------------------------------------------------------------- F12: what logs and diagnostics hold
class F12Redaction(unittest.TestCase):
    def test_log_arguments_are_redacted(self):
        rec = logging.LogRecord("x", logging.INFO, __file__, 1, "Code %s for %s", ("BRO1.abcdefghijklmnop", "bob"), None)
        server._redact_record(rec)
        self.assertEqual(rec.getMessage(), "Code BRO1.*** for bob")

    def test_personal_and_ntfy(self):
        out = core.redact({"settings": {"mail_to": "someone@example.com", "ntfy_url": "https://u:pw@ntfy.sh/secret-topic",
                                        "m365_tenant": "contoso.onmicrosoft.com"}})
        self.assertEqual(out["settings"], {"mail_to": "***", "ntfy_url": "https://ntfy.sh/***", "m365_tenant": "***"})


# ---------------------------------------------------------------- F4: an invite has no login until it is accepted
class F4Invites(unittest.TestCase):
    def setUp(self):
        _env.reset()

    def test_no_login_before_accept(self):
        user, pw, tok = receiving.new_receiver("Carol", 5)
        self.assertNotIn(user, receiving.read_htpasswd())

    def test_old_logins_of_waiting_invites_removed(self):
        user, pw, tok = receiving.new_receiver("Carol", 5)
        receiving.set_rest_user(user, pw)  # as an older version did
        receiving.drop_unaccepted_logins()
        self.assertNotIn(user, receiving.read_htpasswd())


# ---------------------------------------------------------------- S1: mounts that are not read-only
class S1Mounts(unittest.TestCase):
    def test_writable_mounts(self):
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write("1 0 0:1 / /nas ro,relatime - zfs p ro\n"
                "2 1 0:2 / /nas/tank ro,relatime - zfs p ro\n"
                "3 2 0:3 / /nas/tank/later rw,relatime - zfs p rw\n"
                "4 2 0:4 / /nas/tank/.zfs/snapshot/s1 rw,relatime - zfs p rw\n"
                "5 0 0:5 / /data rw,relatime - zfs p rw\n"
                "6 2 0:6 / /nas/tank/with\\040space rw - zfs p rw\n")
        f.close()
        with mock.patch.object(nas, "MOUNTINFO", f.name):
            self.assertEqual(nas.writable_mounts("/nas"), ["/nas/tank/later", "/nas/tank/with space"])


# ---------------------------------------------------------------- S2: a bro cannot pick our relay server
def ticket_with(entries):
    raw = bytes.fromhex("00" + A) + lan._varint(len(entries)) + b"".join(entries)
    return "endpoint" + base64.b32encode(raw).decode().rstrip("=").lower()


def relay(url):
    b = url.encode()
    return bytes([0]) + lan._varint(len(b)) + b


class S2Relays(unittest.TestCase):
    def test_unknown_relay_dropped_direct_kept(self):
        good, bad, direct = relay("https://euc1-1.relay.n0.iroh.link./"), relay("http://192.168.0.1:8080/"), lan._entry("192.168.1.50", 7841)
        t = ticket_with([good, bad, direct])
        clean = lan.clean_peer_ticket(t)
        self.assertEqual(clean, ticket_with([good, direct]))
        self.assertTrue(peers.same_identity(t, clean))
        self.assertEqual(lan.clean_peer_ticket(clean), clean)  # nothing to drop: unchanged

    def test_stored_tickets_are_cleaned(self):
        _env.reset()
        t = ticket_with([relay("http://10.0.0.1/"), lan._entry("192.168.1.50", 7842)])
        d = pairing.add_destination("Bob", t, t, "alice", "pw-at-bob-0123456789abcdef")
        self.assertEqual(core.get_dest(d["id"])["pair_ticket"], ticket_with([lan._entry("192.168.1.50", 7842)]))


# ---------------------------------------------------------------- S4: whoever makes the code decides about mutual
class S4Mutual(unittest.TestCase):
    def setUp(self):
        _env.reset()
        core.my_tickets.update(data=_env.ticket(A), pair=_env.ticket(A, ip="0a000002"))
        self.client = pair_api.pair_app.test_client()

    def accept(self, mutual_ok):
        code = pairing.make_invite("Bob", 5, False, mutual_ok=mutual_ok)
        data = pairing.decode_code(code, "BRO1.", ("tok",))
        self.assertEqual(data["m"], mutual_ok)
        with mock.patch.object(pair_api.receiving, "set_rest_user"), \
                mock.patch.object(pair_api.pairing.threading, "Thread", _env.SyncThread), \
                mock.patch.object(pair_api.pairing.backup, "run_backup"):
            r = self.client.post("/bro/accept", json={"tok": data["tok"], "n": "Bob", "mutual": True, "dt": _env.ticket(B),
                                                      "pt": _env.ticket(B, ip="0a000002"), "u": "alice",
                                                      "pw": "pw-at-bob-0123456789abcdef"})
        return r.get_json()

    def test_refused_when_not_allowed(self):
        self.assertFalse(self.accept(False)["mutual"])
        self.assertEqual(core.load_state()["destinations"], [])

    def test_added_when_allowed(self):
        self.assertTrue(self.accept(True)["mutual"])
        self.assertEqual(len(core.load_state()["destinations"]), 1)



# ================================================================ re-check of 0.10.11 (R1 to R8)
def _code_now(secret, offset=0):
    return auth._totp(secret, int(time.time() // auth.TOTP_STEP) + offset)


class R1Reauth(WebBase):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(web, "notify")
        self.notify = p.start()

    def test_new_recovery_code_needs_password(self):
        self.login()
        self.c.post("/recovery-code/new", data={"csrf": self.csrf("/settings")})
        self.assertFalse((core.load_state().get("recovery") or {}).get("key"))
        self.c.post("/recovery-code/new", data={"csrf": self.csrf("/settings"), "current_pw": PW})
        first = core.load_state()["recovery"]["key"]
        self.assertTrue(first)
        self.notify.assert_not_called()  # the first code replaces nothing
        self.c.post("/recovery-code/new", data={"csrf": self.csrf("/settings"), "current_pw": PW})
        self.assertNotEqual(core.load_state()["recovery"]["key"], first)
        self.assertEqual(self.notify.call_args[0][0], "Recovery code replaced")

    def test_code_needed_when_two_step_is_on(self):
        secret = auth.new_totp_secret()
        with core.mutate() as st:
            st["settings"]["totp_secret"] = secret
        tok = re.search(r'name="csrf" value="([^"]+)"', self.c.get("/login").get_data(as_text=True)).group(1)
        self.c.post("/login", data={"pw": PW, "code": _code_now(secret, -1), "csrf": tok})
        self.c.post("/recovery-code/new", data={"csrf": self.csrf("/settings"), "current_pw": PW})
        self.assertFalse((core.load_state().get("recovery") or {}).get("key"))
        self.c.post("/recovery-code/new", data={"csrf": self.csrf("/settings"), "current_pw": PW, "code": _code_now(secret)})
        self.assertTrue(core.load_state()["recovery"]["key"])

    def test_deleting_a_bros_data_needs_password(self):
        from test_peers import mk_receiver
        self.login()
        user, _ = mk_receiver("Carol")
        path = os.path.join(core.RECEIVE_DIR, user)
        self.c.post(f"/receiver/{user}/remove", data={"csrf": self.csrf("/"), "confirm": "Carol", "delete_data": "1"})
        self.assertTrue(os.path.isdir(path))
        self.assertIn(user, core.load_state()["receivers"])
        self.c.post(f"/receiver/{user}/remove", data={"csrf": self.csrf("/"), "confirm": "Carol", "delete_data": "1",
                                                     "current_pw": PW})
        self.assertFalse(os.path.isdir(path))
        self.assertIn("Backups of Carol deleted", self.notify.call_args[0][0])

    def test_replacing_with_a_seed_needs_password(self):
        self.login()
        seed = {"path": "/x", "known": True, "complete": True, "user": "carol", "from": "Carol"}
        with mock.patch.object(web.nas, "scan_seeds", return_value=[seed]), \
                mock.patch.object(web.threading, "Thread") as th:
            self.c.post("/import", data={"csrf": self.csrf("/"), "path": "/x", "replace": "1"})
            th.assert_not_called()
            self.c.post("/import", data={"csrf": self.csrf("/"), "path": "/x", "replace": "1", "current_pw": PW})
            th.assert_called_once()

    def test_two_step_off_uses_up_the_code(self):
        secret = auth.new_totp_secret()
        with core.mutate() as st:
            st["settings"]["totp_secret"] = secret
        code = _code_now(secret)
        tok = re.search(r'name="csrf" value="([^"]+)"', self.c.get("/login").get_data(as_text=True)).group(1)
        self.c.post("/login", data={"pw": PW, "code": code, "csrf": tok})
        self.c.post("/security/two-step/off", data={"csrf": self.csrf("/security"), "current_pw": PW, "code": code})
        self.assertEqual(core.settings()["totp_secret"], secret)  # the login used that code already


class R3PairLogin(unittest.TestCase):
    def setUp(self):
        _env.reset()

    def test_unused_invite_password_opens_nothing(self):
        user, pw, tok = receiving.new_receiver("Carol", 5)
        c = pair_api.pair_app.test_client()
        hdr = {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
        for method, path in (("get", "/bro/status"), ("post", "/bro/goodbye"), ("post", "/bro/hello")):
            self.assertIn(getattr(c, method)(path, headers=hdr, json={"leave": True}).status_code, (401, 403, 410))
        self.assertIn(user, core.load_state()["receivers"])  # the invite is still there for the real bro


class R4Silencing(F5Settings):
    def test_alerts_report_and_restore_test_need_password(self):
        self.login()
        for field in ({"alert_hours": "1000"}, {"report_day": "-1"}, {"alert_receivers": ""}, {"restore_test": ""}):
            self.assertIn("needs your current password", self.save(**field))
        s = core.settings()
        self.assertEqual((s["alert_hours"], s["report_day"], s["alert_receivers"], s["restore_test"]), (72, 0, True, True))
        self.save(alert_hours="1000000", current_pw=PW)
        self.assertEqual(core.settings()["alert_hours"], web.ALERT_HOURS_MAX)

    def test_leaving_things_out_needs_password(self):
        folder = os.path.join(os.environ["NAS_DIR"], "photos")
        os.makedirs(folder, exist_ok=True)
        with core.mutate() as st:
            st["settings"]["sources"] = [os.path.realpath(folder)]
        self.login()
        self.assertIn("needs your current password", self.save())  # the folder is not ticked any more
        self.assertIn("needs your current password", self.save(src=folder, excludes="*.jpg"))
        self.assertIn("needs your current password", self.save(src=folder, exclude_larger_gb="1"))
        self.assertIn("Settings saved", self.save(src=folder, backup_hour="3"))  # the rest: no password
        self.assertIn("Settings saved", self.save(current_pw=PW))
        self.assertEqual(core.settings()["sources"], [])


class R5R7Tickets(unittest.TestCase):
    def test_addresses_a_bro_may_point_us_to(self):
        ok = [lan._entry("192.168.1.50", 7841), lan._entry("10.0.0.1", 40000), lan._entry("2a02::1", 7842)]
        bad = [lan._entry("127.0.0.1", 7841), lan._entry("10.0.0.1", 22), lan._entry("169.254.1.1", 7841),
               lan._entry("224.0.0.1", 7841), lan._entry("::1", 7841), lan._entry("::ffff:127.0.0.1", 7841),
               lan._entry("0.0.0.0", 7841), lan._entry("255.255.255.255", 7841)]
        self.assertEqual(lan.clean_peer_ticket(ticket_with(ok + bad)), ticket_with(ok))

    def test_relays_by_n0_domain(self):
        new_n0 = relay("https://euc9-3.relay.n0.iroh.link/")
        fake = [relay("https://euc1-1.relay.n0.iroh.link.evil.example/"), relay("https://relay.n0.iroh.link.evil/"),
                relay("https://evilrelay.n0.iroh.link/")]
        self.assertEqual(lan.clean_peer_ticket(ticket_with([new_n0] + fake)), ticket_with([new_n0]))


class _SpeedHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    parts = []

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        self.rfile.read(n)
        _SpeedHandler.parts.append(n)
        body = json.dumps({"bytes": n}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class R6SpeedTest(unittest.TestCase):
    def test_upload_in_parts_timed_by_the_sender(self):
        from bro import speed
        _SpeedHandler.parts = []
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SpeedHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        with mock.patch.object(speed, "SPEED_PART", 2 * 1024 * 1024):
            bps = speed.speed_upload(srv.server_address[1], {"user": "a", "password": "b"}, 0.3)
        self.assertGreater(bps, 0)
        self.assertTrue(_SpeedHandler.parts and all(n == 2 * 1024 * 1024 for n in _SpeedHandler.parts))

    def test_receiving_side_counts_a_part(self):
        _env.reset()
        user, pw, _ = receiving.new_receiver("Carol", 5, invite=False)
        c = pair_api.pair_app.test_client()
        hdr = {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
        r = c.post("/bro/speedtest", headers=hdr, data=b"x" * (1024 * 1024))
        self.assertEqual(r.get_json(), {"bytes": 1024 * 1024})


class R8PendingAccept(unittest.TestCase):
    def setUp(self):
        _env.reset()
        core.my_tickets.update(data=_env.ticket(B), pair=_env.ticket(B, ip="0a000002"))

    def test_no_backup_before_the_bro_confirms(self):
        core.my_tickets.update(data=_env.ticket(A), pair=_env.ticket(A, ip="0a000002"))
        with core.mutate() as st:
            st["settings"]["name"] = "Alice"
        code = pairing.make_invite("Bob", 5, False)
        _env.reset()
        core.my_tickets.update(data=_env.ticket(B), pair=_env.ticket(B, ip="0a000002"))
        with mock.patch.object(pairing, "finish_accept", side_effect=RuntimeError("Bro not reachable: timeout")), \
                mock.patch.object(pairing.threading, "Thread") as th:
            d, result = pairing.accept_code(code, False, 5, False)
        th.assert_not_called()
        self.assertTrue(core.get_dest(d["id"])["accepting"])
        with mock.patch.object(pairing, "finish_accept", lambda *a: core.update_dest(d["id"], accepting=False)), \
                mock.patch.object(pairing.threading, "Thread") as th:
            pairing.retry_pending()
        th.assert_called_once()
        self.assertEqual(core.load_state()["pending_accepts"], [])

if __name__ == "__main__":
    unittest.main()
