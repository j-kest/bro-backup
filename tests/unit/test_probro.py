# SPDX-License-Identifier: AGPL-3.0-or-later
"""Storing for many bros: references, usage per month, CSV export, space requests."""
import csv
import io
import re
import unittest
from unittest import mock

import _env

from bro import core, pair_api, probro, web
from test_peers import mk_dest, mk_receiver

PW = "a-long-test-password"


class ProBro(unittest.TestCase):
    def setUp(self):
        _env.reset()
        self.sent = []
        p = mock.patch.object(probro, "notify", lambda t, m, priority="high": self.sent.append((t, m)))
        p.start()
        self.addCleanup(mock.patch.stopall)

    def test_usage_per_month_keeps_the_peak(self):
        user, _ = mk_receiver("Carol")
        probro.record_usage(user, 100)
        probro.record_usage(user, 300)
        probro.record_usage(user, 200)
        month = core.now().strftime("%Y-%m")
        self.assertEqual(core.load_state()["receivers"][user]["usage_months"], {month: 300})

    def test_only_recent_months_kept(self):
        user, _ = mk_receiver("Carol")
        with core.mutate() as st:
            st["receivers"][user]["usage_months"] = {f"20{y:02d}-01": 1 for y in range(0, 30)}
        probro.record_usage(user, 5)
        self.assertEqual(len(core.load_state()["receivers"][user]["usage_months"]), probro.MONTHS_KEPT)

    def test_csv_export(self):
        user, _ = mk_receiver("=HYPERLINK(evil)")
        probro.set_ref(user, "Klant 0042\nfake line")
        probro.record_usage(user, 5 * core.GIB)
        rows = list(csv.reader(io.StringIO(probro.usage_csv()), delimiter=";"))
        self.assertEqual(rows[0][:4], ["month", "login", "bro", "reference"])
        self.assertEqual(rows[1][2], "'=HYPERLINK(evil)")  # never a formula in Excel
        self.assertEqual(rows[1][3], "Klant 0042 fake line")
        self.assertEqual(rows[1][6], "5.00")

    def test_space_request_and_grant(self):
        user, _ = mk_receiver("Carol")
        self.assertEqual(probro.receive_space_request(user, {"gib": 20, "note": "photos\x1b[31m grow"}), {"ok": True})
        self.assertIn("Carol asks for more space", self.sent[0][0])
        req = core.load_state()["receivers"][user]["space_request"]
        self.assertEqual((req["gib"], req["note"]), (20, "photos [31m grow"))
        name, old, new = probro.answer_request(user, grant=True)
        self.assertEqual((old, new), (5, 25))
        self.assertNotIn("space_request", core.load_state()["receivers"][user])
        with self.assertRaises(LookupError):
            probro.answer_request(user, grant=True)

    def test_decline_keeps_the_quota(self):
        user, _ = mk_receiver("Carol")
        probro.receive_space_request(user, {"gib": 20})
        self.assertEqual(probro.answer_request(user, grant=False)[1:], (5, 5))

    def test_odd_requests_refused(self):
        user, _ = mk_receiver("Carol")
        for p in ({"gib": 0}, {"gib": -5}, {"gib": "lots"}, {"gib": probro.MAX_GIB + 1}, {}):
            self.assertIsNone(probro.receive_space_request(user, p), p)
        self.assertIsNone(probro.receive_space_request("nobody", {"gib": 5}))

    def test_pair_api_needs_the_bros_login(self):
        user, pw = mk_receiver("Carol")
        c = pair_api.pair_app.test_client()
        r = c.post("/bro/space-request", json={"gib": 5})
        self.assertEqual(r.status_code, 401)
        import base64
        auth = {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
        r = c.post("/bro/space-request", json={"gib": 5}, headers=auth)
        self.assertEqual(r.status_code, 200)
        r = c.post("/bro/space-request", json={"gib": "x"}, headers=auth)
        self.assertEqual(r.status_code, 400)

    def test_ask_space_sends_to_the_bro(self):
        d = mk_dest("Bob")
        with mock.patch.object(probro.procs, "pair_call") as call:
            probro.ask_space(d, 50, "more photos")
        args, kw = call.call_args
        self.assertEqual((args[2], args[3]), ("/bro/space-request", {"gib": 50, "note": "more photos"}))
        self.assertEqual(kw["auth"], (d["user"], d["password"]))
        with self.assertRaises(ValueError):
            probro.ask_space(d, 0)


class Pages(unittest.TestCase):
    def setUp(self):
        _env.reset()
        with core.mutate() as st:
            st["settings"].update(name="Alice", pw_hash=core.hash_ui_password(PW), sources=["/nas"])
        web.auth.clear_fails("127.0.0.1")
        web.app.secret_key = "unit-test"
        self.c = web.app.test_client()
        for p in (mock.patch.object(web.time, "sleep"), mock.patch.object(probro, "notify")):
            p.start()
        self.addCleanup(mock.patch.stopall)
        self.tok = lambda: re.search(r'name="csrf" value="([^"]+)"', self.c.get("/").get_data(as_text=True)).group(1)
        self.c.post("/login", data={"pw": PW, "csrf": re.search(r'name="csrf" value="([^"]+)"',
                                                                 self.c.get("/login").get_data(as_text=True)).group(1)})

    def test_overview_safety_search_request(self):
        users = [mk_receiver(f"Bro{i}")[0] for i in range(7)]
        with core.mutate() as st:
            for u in users:
                st["receivers"][u]["accepted"] = True
        probro.receive_space_request(users[0], {"gib": 10, "note": "<script>x</script>"})
        page = self.c.get("/").get_data(as_text=True)
        self.assertIn("How safe is your data?", page)
        self.assertIn('id="rfilter"', page)
        self.assertIn("asks for 10 GiB more", page)
        self.assertNotIn("<script>x</script>", page)
        self.c.post(f"/receiver/{users[0]}/space/grant", data={"csrf": self.tok()})
        self.assertEqual(core.load_state()["receivers"][users[0]]["quota_gib"], 15)
        r = self.c.get("/receivers.csv")
        self.assertEqual(r.mimetype, "text/csv")
        self.assertEqual(self.c.post(f"/receiver/{users[0]}/space/maybe", data={"csrf": self.tok()}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
