# SPDX-License-Identifier: AGPL-3.0-or-later
"""The daily check for a new version, with GitHub mocked."""
import datetime
import io
import json
import unittest
from unittest import mock

import _env

from bro import core, updates


def answer(tag, url=None):
    body = json.dumps({"tag_name": tag, "html_url": url or f"https://github.com/{updates.REPO}/releases/tag/{tag}"})
    return mock.MagicMock(__enter__=lambda s: io.BytesIO(body.encode()), __exit__=lambda *a: False)


class Updates(unittest.TestCase):
    def setUp(self):
        _env.reset()
        core.load_state()
        self.sent = []
        p = mock.patch.object(updates, "notify", lambda title, msg, priority=None: self.sent.append(title))
        p.start()
        self.addCleanup(p.stop)

    def test_versions(self):
        self.assertEqual(updates.parse_version("v0.10.2"), (0, 10, 2))
        self.assertEqual(updates.parse_version("0.10.2"), (0, 10, 2))
        for bad in ("", None, "v1", "0.10.2-rc1", "latest", "v0.10.2\n<script>"):
            self.assertIsNone(updates.parse_version(bad), bad)
        self.assertTrue(updates.newer("0.10.10", "0.10.9"))   # numbers, not text
        self.assertFalse(updates.newer("0.9.9", "0.10.0"))
        self.assertFalse(updates.newer("0.10.1", "0.10.1"))

    def test_newer_version_shown_and_notified_once(self):
        with mock.patch.object(updates, "VERSION", "0.10.1"), \
                mock.patch("urllib.request.urlopen", return_value=answer("v0.10.2")):
            updates.check(force=True)
            updates.check(force=True)
            self.assertEqual(updates.available()["version"], "0.10.2")
        self.assertEqual(self.sent, ["BRO Backup 0.10.2 is available"])

    def test_same_or_older_version_shows_nothing(self):
        for tag in ("v0.10.1", "v0.9.0"):
            with mock.patch.object(updates, "VERSION", "0.10.1"), \
                    mock.patch("urllib.request.urlopen", return_value=answer(tag)):
                updates.check(force=True)
                self.assertIsNone(updates.available())
        self.assertEqual(self.sent, [])

    def test_dismiss_until_next_version(self):
        with mock.patch.object(updates, "VERSION", "0.10.1"):
            with mock.patch("urllib.request.urlopen", return_value=answer("v0.10.2")):
                updates.check(force=True)
            updates.dismiss()
            self.assertIsNone(updates.available())
            with mock.patch("urllib.request.urlopen", return_value=answer("v0.10.3")):
                updates.check(force=True)
            self.assertEqual(updates.available()["version"], "0.10.3")

    def test_turned_off_asks_nothing(self):
        with core.mutate() as st:
            st["settings"]["update_check"] = False
        with mock.patch("urllib.request.urlopen") as op:
            self.assertEqual(updates.check(force=True), {})
            op.assert_not_called()

    def test_once_a_day_and_hourly_retry_after_an_error(self):
        with mock.patch("urllib.request.urlopen", return_value=answer("v0.0.1")) as op:
            updates.check()
            updates.check()
            self.assertEqual(op.call_count, 1)
        with mock.patch("urllib.request.urlopen", side_effect=OSError("no internet")):
            updates.check(force=True)
        self.assertIn("no internet", updates.info()["error"])
        with core.mutate() as st:  # 61 minutes later: try again
            st["update"]["checked_at"] = core.iso(core.now() - datetime.timedelta(minutes=61))
        with mock.patch("urllib.request.urlopen", return_value=answer("v0.0.1")) as op:
            updates.check()
            self.assertEqual(op.call_count, 1)
        self.assertIsNone(updates.info()["error"])

    def test_odd_answers_are_refused(self):
        with mock.patch.object(updates, "VERSION", "0.10.1"):
            with mock.patch("urllib.request.urlopen", return_value=answer("v9.9.9", url="https://evil.example/x")):
                updates.check(force=True)
            self.assertEqual(updates.available()["url"], updates.RELEASES_URL)  # only our own release pages
            with mock.patch("urllib.request.urlopen", return_value=answer("<b>v99</b>")):
                updates.check(force=True)
            self.assertIn("unexpected release tag", updates.info()["error"])

    def test_nothing_about_us_is_sent(self):
        with mock.patch("urllib.request.urlopen", return_value=answer("v0.0.1")) as op:
            updates.check(force=True)
        req = op.call_args[0][0]
        self.assertEqual(req.get_method(), "GET")
        self.assertIsNone(req.data)
        self.assertEqual(req.full_url, updates.API_URL)
        self.assertEqual(req.get_header("User-agent"), f"bro-backup/{core.VERSION}")


if __name__ == "__main__":
    unittest.main()
