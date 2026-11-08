# SPDX-License-Identifier: AGPL-3.0-or-later
import unittest
import xml.dom.minidom

import _env  # noqa: F401

from bro import charts
from bro.core import human_bytes

E = [{"at": f"2026-10-{d:02d}T02:00:00+00:00", "added": d * 1024 ** 2, "usage": d * 1024 ** 3} for d in range(1, 30)]


class Charts(unittest.TestCase):
    def test_bars_valid_svg(self):
        svg = charts.bars(E, "added", human_bytes, "Sent")
        xml.dom.minidom.parseString(svg)  # well-formed
        self.assertEqual(svg.count("<title>"), len(E))  # a tooltip per bar

    def test_line_marks_only_latest_when_dense(self):
        svg = charts.line(E, "usage", human_bytes, "Used")
        xml.dom.minidom.parseString(svg)
        self.assertEqual(svg.count('r="4"'), 1)

    def test_empty(self):
        self.assertIsNone(charts.bars([], "added", human_bytes, "x"))
        self.assertIsNone(charts.line(E[:1], "usage", human_bytes, "x"))


if __name__ == "__main__":
    unittest.main()
