# SPDX-License-Identifier: AGPL-3.0-or-later
"""The warning when the disk under the data folder fills up, with the disk size mocked."""
import collections
import datetime
import unittest
from unittest import mock

import _env

from bro import backup, core, space
from test_peers import mk_dest, mk_receiver

GIB = core.GIB
Usage = collections.namedtuple("Usage", "total used free")


def disk(total_gib, free_gib):
    return mock.patch.object(space.shutil, "disk_usage",
                             return_value=Usage(total_gib * GIB, (total_gib - free_gib) * GIB, free_gib * GIB))


class Space(unittest.TestCase):
    def setUp(self):
        _env.reset()
        core.receive_stats.clear()
        self.sent = []
        p = mock.patch.object(space, "notify", lambda title, msg, priority="high": self.sent.append(title))
        p.start()
        self.addCleanup(mock.patch.stopall)

    def test_levels(self):
        for free, level in ((50, "ok"), (11, "ok"), (10, "warn"), (4, "warn"), (3, "err"), (0, "err")):
            with disk(100, free):
                self.assertEqual(space.measure()["level"], level, free)

    def test_notified_once_per_step_then_after_a_few_days(self):
        with disk(100, 8):
            space.check()
            space.check()
        self.assertEqual(self.sent, ["The disk of BRO Backup is filling up"])
        with disk(100, 2):
            space.check()  # worse: again
            space.check()
        self.assertEqual(len(self.sent), 2)
        self.assertIn("almost full", self.sent[1])
        with core.mutate() as st:
            st["space_alert"]["at"] = core.iso(core.now() - datetime.timedelta(days=space.REMIND_DAYS, hours=1))
        with disk(100, 2):
            space.check()  # still almost full a few days later: a reminder
        self.assertEqual(len(self.sent), 3)

    def test_better_is_quiet_and_resets(self):
        with disk(100, 2):
            space.check()
        with disk(100, 8):
            space.check()  # better, still filling: no new message
        self.assertEqual(len(self.sent), 1)
        with disk(100, 60):
            space.check()
        self.assertNotIn("space_alert", core.load_state())
        with disk(100, 8):
            space.check()  # filling up again later: a new message
        self.assertEqual(len(self.sent), 2)

    def test_promised_more_than_free(self):
        user, _ = mk_receiver()  # 5 GiB quota, 1000 bytes in use
        core.receive_stats[user] = {"usage": 1000}
        with disk(100, 4.5):
            m = space.measure()
        self.assertTrue(m["overcommitted"])
        self.assertEqual(m["promised"], 5 * GIB - 1000)
        with disk(1000, 900):
            self.assertFalse(space.check()["overcommitted"])
        with disk(10, 4):  # 60% used, but 4 GiB free for almost 5 GiB promised
            space.check()
            space.check()
        self.assertEqual(self.sent, ["You gave bros more space than is free"])

    def test_blocked_or_unaccepted_bros_promise_nothing(self):
        user, _ = mk_receiver()
        with core.mutate() as st:
            st["receivers"][user]["quota_blocked"] = True
        with disk(100, 1):
            self.assertEqual(space.measure()["promised"], 0)

    def test_sender_sees_the_bros_full_disk(self):
        d = mk_dest()
        sent = []
        with mock.patch.object(backup, "notify", lambda title, msg, priority="high": sent.append(title)):
            for answer in ({"usage": 1, "quota_gib": 5, "disk": "err"}, {"usage": 1, "quota_gib": 5, "disk": "err"}):
                with mock.patch.object(backup, "bro_status", return_value=answer):
                    backup.check_quota(core.get_dest(d["id"]))
            self.assertEqual(sent, ["The NAS of Bob is almost full"])
            with mock.patch.object(backup.procs, "pair_call", return_value={"usage": 1, "quota_gib": 5, "disk": "<b>"}):
                backup.check_quota(core.get_dest(d["id"]))  # through bro_status, which keeps only known values
        self.assertIsNone(core.get_dest(d["id"])["remote_disk"])  # anything odd is ignored


if __name__ == "__main__":
    unittest.main()
