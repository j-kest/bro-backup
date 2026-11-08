# SPDX-License-Identifier: AGPL-3.0-or-later
import datetime
import unittest

import _env  # noqa: F401

from bro import backup

T = lambda h: datetime.datetime(2026, 11, 1, h, 30).astimezone()  # noqa: E731


class Limits(unittest.TestCase):
    def test_night_wraps_midnight(self):
        s = {"night_start": 22, "night_end": 7}
        self.assertTrue(backup.is_night(s, T(23)))
        self.assertTrue(backup.is_night(s, T(3)))
        self.assertFalse(backup.is_night(s, T(12)))

    def test_limit_by_time(self):
        s = {"limit_upload_kib": 500, "limit_night_kib": 0, "night_start": 22, "night_end": 7}
        self.assertEqual(backup.limit_kib(s, T(12)), 500)
        self.assertEqual(backup.limit_kib(s, T(2)), 0)  # 0 = unlimited at night
        s["limit_night_kib"] = -1
        self.assertEqual(backup.limit_kib(s, T(2)), 500)  # no separate night limit

    def test_next_change(self):
        s = {"limit_upload_kib": 500, "limit_night_kib": 2000, "night_start": 22, "night_end": 7}
        self.assertEqual(backup.next_limit_change(s, T(12)).hour, 22)
        self.assertEqual(backup.next_limit_change(s, T(23)).hour, 7)
        s["limit_night_kib"] = 500
        self.assertIsNone(backup.next_limit_change(s, T(12)))

    def test_window(self):
        s = {"backup_hour": 1, "backup_end_hour": 6}
        self.assertTrue(backup.in_window(s, T(3)))
        self.assertFalse(backup.in_window(s, T(7)))
        self.assertTrue(backup.in_window({"backup_hour": 1, "backup_end_hour": -1}, T(15)))


class Errors(unittest.TestCase):
    def test_unauthorized_not_fooled_by_port(self):
        # restic's real wording, and the 'repository does not exist' message on tunnel port 54017
        self.assertTrue(backup.UNAUTHORIZED_RE.search("Fatal: unable to open config file: unexpected HTTP response (401): 401 Unauthorized"))
        self.assertFalse(backup.UNAUTHORIZED_RE.search(
            "Fatal: repository does not exist: unable to open config file: <config/> does not exist\n"
            "rest:http://alice-2:***@127.0.0.1:54017/alice-2/"))


class Excludes(unittest.TestCase):
    def test_args(self):
        s = {"exclude_defaults": False, "excludes": ["*.tmp"], "exclude_larger_gb": 1.5}
        self.assertEqual(backup.exclude_args(s), ["--exclude", "*.tmp", "--exclude-larger-than", "1536M"])

    def test_pattern_escapes_wildcards(self):
        self.assertEqual(backup.restic_pattern("/nas/a[1]*?.txt"), r"/nas/a\[1\]\*\?.txt")


if __name__ == "__main__":
    unittest.main()
