# SPDX-License-Identifier: AGPL-3.0-or-later
"""Notification mail through Microsoft 365 (Graph API, client credentials)."""
import datetime
import io
import json
import re
import unittest
import urllib.error
import urllib.parse
from unittest import mock

import _env

from bro import core, m365, scheduler, web

PW = "a-long-test-password"
TENANT, CLIENT = "contoso.onmicrosoft.com", "11111111-2222-3333-4444-555555555555"


def m365_settings(**kw):
    s = dict(core.DEFAULT_SETTINGS, name="Alice", mail_method="m365", m365_tenant=TENANT, m365_client_id=CLIENT,
             m365_secret="s3cret~value", m365_sender="nas@contoso.com", mail_to="admin@contoso.com, it@contoso.com")
    s.update(kw)
    return s


class Resp(io.BytesIO):
    def __init__(self, body=b"", status=200):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeMs:
    """Stands in for login.microsoftonline.com and graph.microsoft.com."""

    def __init__(self, login_error=None, send_status=202):
        self.calls, self.login_error, self.send_status = [], login_error, send_status

    def __call__(self, req, timeout=None):
        self.calls.append(req)
        if "login.microsoftonline.com" in req.full_url:
            if self.login_error:
                raise urllib.error.HTTPError(req.full_url, 401, "x", {}, io.BytesIO(json.dumps(self.login_error).encode()))
            return Resp(json.dumps({"access_token": "tok-1", "expires_in": 3599}).encode())
        if self.send_status >= 400:
            body = {"error": {"code": "ErrorAccessDenied", "message": "Access is denied. Check credentials and try again."}}
            raise urllib.error.HTTPError(req.full_url, self.send_status, "x", {}, io.BytesIO(json.dumps(body).encode()))
        return Resp(status=self.send_status)


class Graph(unittest.TestCase):
    def setUp(self):
        _env.reset()
        m365._token.update(key=None, value=None, exp=0)

    def test_sends_with_a_token(self):
        ms = FakeMs()
        m365.send(m365_settings(), "Backup failed", "details", "BRO Backup on Alice", opener=ms)
        login, send = ms.calls
        self.assertEqual(login.full_url, "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token")
        form = urllib.parse.parse_qs(login.data.decode())
        self.assertEqual((form["grant_type"], form["scope"]), (["client_credentials"], ["https://graph.microsoft.com/.default"]))
        self.assertEqual(send.full_url, "https://graph.microsoft.com/v1.0/users/nas@contoso.com/sendMail")
        self.assertEqual(send.get_header("Authorization"), "Bearer tok-1")
        body = json.loads(send.data)
        self.assertEqual([r["emailAddress"]["address"] for r in body["message"]["toRecipients"]],
                         ["admin@contoso.com", "it@contoso.com"])
        self.assertIn("BRO Backup on Alice", body["message"]["body"]["content"])
        self.assertFalse(body["saveToSentItems"])
        m365.send(m365_settings(), "Again", "x", "f", opener=ms)
        self.assertEqual(len(ms.calls), 3)  # the token was reused

    def test_wrong_secret_is_explained(self):
        ms = FakeMs(login_error={"error": "invalid_client",
                                 "error_description": "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"})
        with self.assertRaisesRegex(RuntimeError, r"refused the app login: AADSTS7000215: Invalid client secret provided\.$"):
            m365.send(m365_settings(), "t", "m", "f", opener=ms)

    def test_mailbox_not_allowed_is_explained(self):
        with self.assertRaisesRegex(RuntimeError, r"ErrorAccessDenied.*New-ManagementRoleAssignment.*2 hours"):
            m365.send(m365_settings(), "t", "m", "f", opener=FakeMs(send_status=403))
        self.assertIsNone(m365._token["key"])

    def test_sender_cannot_change_the_url(self):
        ms = FakeMs()
        m365.send(m365_settings(m365_sender="a/../../me@x.be"), "t", "m", "f", opener=ms)
        self.assertEqual(ms.calls[1].full_url, "https://graph.microsoft.com/v1.0/users/a%2F..%2F..%2Fme@x.be/sendMail")

    def test_channel_and_dispatch(self):
        self.assertEqual(core.notification_channels(m365_settings()), ["email"])
        self.assertEqual(core.notification_channels(m365_settings(m365_secret="")), [])
        with mock.patch.object(m365, "send") as send:
            core.send_mail(m365_settings(), "t", "m")
        send.assert_called_once()
        self.assertIn("m365_secret", core.SECRET_KEYS)

    def test_field_checks(self):
        self.assertIsNone(m365.check_fields(TENANT, CLIENT, "nas@contoso.com"))
        self.assertIsNone(m365.check_fields("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", CLIENT, "nas@contoso.com"))
        self.assertIn("tenant", m365.check_fields("contoso", CLIENT, "nas@contoso.com"))
        self.assertIn("client", m365.check_fields(TENANT, "abc", "nas@contoso.com"))
        self.assertIn("mailbox", m365.check_fields(TENANT, CLIENT, "nas"))

    def test_expiry_warned_once_per_step(self):
        sent = []
        exp = (datetime.date.today() + datetime.timedelta(days=20)).isoformat()
        with core.mutate() as st:
            st["settings"].update(mail_method="m365", m365_secret_expires=exp)
        with mock.patch.object(scheduler, "notify", lambda t, m, **k: sent.append(t)):
            scheduler.m365_secret_check()
            scheduler.m365_secret_check()
            with core.mutate() as st:
                st["settings"]["m365_secret_expires"] = (datetime.date.today() + datetime.timedelta(days=5)).isoformat()
            scheduler.m365_secret_check()
        self.assertEqual(len(sent), 2)


class Page(unittest.TestCase):
    def setUp(self):
        _env.reset()
        with core.mutate() as st:
            st["settings"].update(name="Alice", pw_hash=core.hash_ui_password(PW), sources=[])
        web.auth.clear_fails("127.0.0.1")
        web.app.secret_key = "unit-test"
        self.c = web.app.test_client()
        mock.patch.object(web.time, "sleep").start()
        self.addCleanup(mock.patch.stopall)
        self.tok = lambda p: re.search(r'name="csrf" value="([^"]+)"', self.c.get(p).get_data(as_text=True)).group(1)
        self.c.post("/login", data={"pw": PW, "csrf": self.tok("/login")})

    def save(self, **fields):
        data = {"csrf": self.tok("/settings"), "backup_hour": "2", "alert_hours": "72", "default_quota_gib": "500",
                "mail_method": "m365", "m365_tenant": TENANT, "m365_client_id": CLIENT, "m365_sender": "nas@contoso.com",
                "mail_to": "admin@contoso.com", "retention": "standard", "ransomware_watch": "1", "alert_receivers": "1", "restore_test": "1", "report_day": "0", "current_pw": PW}
        data.update(fields)
        return self.c.post("/settings", data=data, follow_redirects=True).get_data(as_text=True)

    def test_save_keep_secret_and_refuse(self):
        self.assertIn("Settings saved", self.save(m365_secret="abc~123", m365_secret_expires="2028-11-06"))
        s = core.settings()
        self.assertEqual((s["mail_method"], s["m365_secret"], s["m365_secret_expires"]), ("m365", "abc~123", "2028-11-06"))
        self.save()  # empty secret field: the saved one stays
        self.assertEqual(core.settings()["m365_secret"], "abc~123")
        page = self.c.get("/settings").get_data(as_text=True)
        self.assertNotIn("abc~123", page)
        self.assertIn("Not saved", self.save(m365_client_id="not-a-guid"))
        self.assertIn("Not saved", self.save(m365_secret_expires="next year"))


if __name__ == "__main__":
    unittest.main()
