# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import sqlite3
import tempfile
import threading
import unittest

import _env  # noqa: F401

from bro import dumps


class SqliteDump(unittest.TestCase):
    def test_dump_while_writing(self):
        d = tempfile.mkdtemp()
        src, dst = os.path.join(d, "db.sqlite3"), os.path.join(d, "dump.sqlite3")
        c = sqlite3.connect(src)
        c.execute("pragma journal_mode=wal")
        c.execute("create table t(id integer primary key, v text)")
        c.commit()
        c.close()
        stop = threading.Event()

        def writer():
            w = sqlite3.connect(src)
            while not stop.is_set():
                w.execute("insert into t(v) values (?)", ("x" * 200,))
                w.commit()
            w.close()
        th = threading.Thread(target=writer)
        th.start()
        try:
            method = dumps.dump_sqlite(src, dst)
        finally:
            stop.set()
            th.join()
        self.assertEqual(method, "online backup")
        out = sqlite3.connect(dst)
        self.assertEqual(out.execute("pragma integrity_check").fetchone()[0], "ok")
        self.assertGreaterEqual(out.execute("select count(*) from t").fetchone()[0], 0)
        out.close()

    def test_is_sqlite(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.db")
        with open(p, "wb") as f:
            f.write(b"not a database")
        self.assertFalse(dumps.is_sqlite(p))


if __name__ == "__main__":
    unittest.main()
