# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unpairing, tombstones, leftover data and address changes, without the network (pair_call mocked)."""
import datetime
import os
import unittest
from unittest import mock

import _env

from bro import core, pairing, peers, receiving

A, B = "aa" * 32, "bb" * 32


def mk_receiver(name="Bob", data=b"x" * 1000):
    user, pw, _ = receiving.new_receiver(name, 5, invite=False)
    with core.mutate() as st:
        st["receivers"][user].update(accepted=True, bro_name=name, link_key="lk-1", peer_pt=_env.ticket(B))
    os.makedirs(os.path.join(core.RECEIVE_DIR, user, "data"))
    with open(os.path.join(core.RECEIVE_DIR, user, "data", "pack"), "wb") as f:
        f.write(data)
    return user, pw


def mk_dest(name="Bob", receiver_user=None):
    d = pairing.add_destination(name, _env.ticket(B), _env.ticket(B, ip="0a000002"), "alice", "pw-at-bob-0123456789abcdef",
                                receiver_user=receiver_user)
    core.update_dest(d["id"], link_key="lk-2")
    return core.get_dest(d["id"])


class Base(unittest.TestCase):
    def setUp(self):
        _env.reset()
        p = [mock.patch.object(peers, "notify"), mock.patch.object(peers.threading, "Thread", _env.SyncThread),
             mock.patch.object(peers.procs, "stop_proc")]
        self.notify = p[0].start()
        for x in p[1:]:
            x.start()
        self.addCleanup(mock.patch.stopall)


class Receivers(Base):
    def test_revoke_leaves_tombstone_and_data(self):
        user, pw = mk_receiver()
        peers.revoke_receiver(user)
        st = core.load_state()
        self.assertNotIn(user, st["receivers"])
        self.assertNotIn(user, receiving.read_htpasswd())
        self.assertTrue(peers.tombstone_auth(user, pw))
        self.assertIsNone(peers.tombstone_auth(user, "wrong"))
        left = peers.leftover_data()
        self.assertEqual([(x["user"], x["size"]) for x in left], [(user, 1000)])
        self.assertEqual(peers.delete_data_now(user), 1000)
        self.assertFalse(os.path.exists(os.path.join(core.RECEIVE_DIR, user)))
        self.assertEqual(peers.leftover_data(), [])

    def test_pairing_again_gets_a_new_name(self):
        user, _ = mk_receiver("Bob")
        peers.revoke_receiver(user)  # his data stays behind
        user2, _, _ = receiving.new_receiver("Bob", 5, invite=False)
        self.assertNotEqual(user, user2)
        peers.delete_data_now(user)
        with core.mutate() as st:
            st["revoked"].clear()
        user3, _, _ = receiving.new_receiver("Bob", 5, invite=False)
        self.assertNotIn(user3, (user2,))

    def test_delete_refuses_active_or_odd_names(self):
        user, _ = mk_receiver()
        with self.assertRaises(ValueError):
            peers.delete_data_now(user)  # still backs up here
        for bad in ("../config", "a/b", ".htpasswd", "", "X"):
            with self.assertRaises(ValueError):
                peers.delete_data_now(bad)

    def test_goodbye_with_delete_waits_a_week(self):
        user, _ = mk_receiver()
        peers.receive_goodbye(user, {"leave": True, "delete": True})
        st = core.load_state()
        self.assertNotIn(user, st["receivers"])
        after = core.parse(st["pending_deletes"][user]["after"])
        self.assertAlmostEqual((after - core.now()).days, peers.DELETE_GRACE_DAYS - 1, delta=1)
        peers.run_scheduled_deletes()
        self.assertTrue(os.path.exists(os.path.join(core.RECEIVE_DIR, user)))  # not yet
        with core.mutate() as st:
            st["pending_deletes"][user]["after"] = core.iso(core.now() - datetime.timedelta(minutes=1))
        peers.run_scheduled_deletes()
        self.assertFalse(os.path.exists(os.path.join(core.RECEIVE_DIR, user)))

    def test_goodbye_append_only_never_deletes_by_itself(self):
        user, _ = mk_receiver()
        with core.mutate() as st:
            st["settings"]["append_only"] = True
        peers.receive_goodbye(user, {"leave": True, "delete": True})
        self.assertEqual(core.load_state()["pending_deletes"], {})
        self.assertIn("append-only", self.notify.call_args[0][1])

    def test_keep_cancels_scheduled_delete(self):
        user, _ = mk_receiver()
        peers.receive_goodbye(user, {"leave": True, "delete": True})
        peers.cancel_delete(user)
        self.assertEqual(core.load_state()["pending_deletes"], {})


class Destinations(Base):
    def test_hello_takes_new_address_same_identity_only(self):
        d = mk_dest()
        new_dt = _env.ticket(B, ip="c0a80102")
        with mock.patch.object(peers.procs, "pair_call", return_value={"dt": new_dt, "pt": _env.ticket(A), "lk": "k9-new-link-key-0123456789"}):
            self.assertTrue(peers.hello(d))
        d2 = core.get_dest(d["id"])
        self.assertEqual(d2["data_ticket"], new_dt)
        self.assertEqual(d2["pair_ticket"], d["pair_ticket"])  # other identity: ignored
        self.assertEqual(d2["link_key"], "k9-new-link-key-0123456789")
        self.assertTrue(d2["address_changed"])

    def test_hello_410_marks_revoked(self):
        d = mk_dest()
        with mock.patch.object(peers.procs, "pair_call", side_effect=RuntimeError("Bro refused (410): gone")):
            peers.hello(d)
        d2 = core.get_dest(d["id"])
        self.assertEqual(d2["mode"], "revoked")
        self.assertIn("revoked", core.PAUSED_MODES)
        self.notify.assert_called_once()

    def test_receive_address(self):
        d = mk_dest()
        new = {"u": "alice", "lk": "lk-2", "dt": _env.ticket(B, ip="0a000001"), "pt": _env.ticket(B, ip="0a000002")}
        self.assertTrue(peers.receive_address(new))
        self.assertEqual(core.get_dest(d["id"])["data_ticket"], new["dt"])
        self.assertIsNone(peers.receive_address(dict(new, lk="wrong")))
        self.assertIsNone(peers.receive_address(dict(new, dt=_env.ticket(A))))  # another identity
        core.update_dest(d["id"], address_changed=None)
        self.assertTrue(peers.receive_address(new))  # the same address again: not a change
        self.assertIsNone(core.get_dest(d["id"])["address_changed"])

    def test_remove_mutual_tells_bro_and_revokes_his_login(self):
        user, _ = mk_receiver()
        d = mk_dest(receiver_user=user)
        with mock.patch.object(peers.procs, "pair_call", return_value={"ok": True}) as call:
            peers.remove_destination(d["id"], ask_delete=True, also_receiver=True)
        st = core.load_state()
        self.assertEqual(st["destinations"], [])
        self.assertNotIn(user, st["receivers"])
        args, kw = call.call_args
        self.assertEqual(args[2], "/bro/goodbye")
        self.assertEqual(args[3], {"leave": True, "delete": True, "revoked": True})
        self.assertEqual(kw["auth"], ("alice", "pw-at-bob-0123456789abcdef"))

    def test_goodbye_queued_while_offline(self):
        d = mk_dest()
        with mock.patch.object(peers.procs, "pair_call", side_effect=RuntimeError("Bro not reachable: timeout")):
            peers.remove_destination(d["id"])
        self.assertEqual(len(core.load_state()["pending_goodbyes"]), 1)
        with mock.patch.object(peers.procs, "pair_call", return_value={"ok": True}):
            peers.retry_goodbyes()
        self.assertEqual(core.load_state()["pending_goodbyes"], [])

    def test_stop_receiving_tells_mutual_bro(self):
        user, _ = mk_receiver()
        mk_dest(receiver_user=user)
        with mock.patch.object(peers.procs, "pair_call", return_value={"ok": True}) as call:
            peers.stop_receiving(user)
        self.assertEqual(call.call_args[0][3], {"leave": False, "delete": False, "revoked": True})

    def test_goodbye_revoked_marks_linked_dest(self):
        user, _ = mk_receiver()
        d = mk_dest(receiver_user=user)
        peers.receive_goodbye(user, {"leave": False, "revoked": True})
        self.assertEqual(core.get_dest(d["id"])["mode"], "revoked")
        self.assertIn(user, core.load_state()["receivers"])  # he still backs up here


class KeepInTouch(Base):
    def test_hello_answer_counts_as_push(self):
        user, _ = mk_receiver()
        core.my_tickets.update(data=_env.ticket(A), pair=_env.ticket(A, ip="0a00000a"))
        answer = peers.receive_hello(user, {"n": "Bob", "pt": _env.ticket(B)})
        self.assertEqual(answer["dt"], core.my_tickets["data"])
        with mock.patch.object(peers.procs, "pair_call", return_value={"ok": True}) as call:
            peers.keep_in_touch()
        self.assertNotIn("/bro/address", [c[0][2] for c in call.call_args_list])

    def test_push_after_own_address_change(self):
        user, _ = mk_receiver()
        core.my_tickets.update(data=_env.ticket(A, ip="0a000009"), pair=_env.ticket(A, ip="0a00000a"))
        with mock.patch.object(peers.procs, "pair_call", return_value={"ok": True}) as call:
            peers.keep_in_touch()
            paths = [c[0][2] for c in call.call_args_list]
            self.assertIn("/bro/address", paths)
            call.reset_mock()
            peers.keep_in_touch()  # nothing changed: nothing sent
            self.assertNotIn("/bro/address", [c[0][2] for c in call.call_args_list])
        self.assertEqual(core.load_state()["receivers"][user]["pushed"], [core.my_tickets["data"], core.my_tickets["pair"]])


class Upgraded(Base):
    """Pairs made on v0.9: no link between the two directions, and bros that may not know hello yet."""

    def remote(self, lk="lk-1"):
        """Stands in for the other bro answering /bro/link honestly."""
        def call(ticket, method, path, payload, auth=None, timeout=None):
            pid = peers.ticket_id(ticket)
            if path != "/bro/link" or payload["proof"] != peers._link_proof(lk, "b", payload["nonce"], pid):
                raise RuntimeError("(403)")
            return {"ok": True, "proof": peers._link_proof(lk, "a", payload["nonce"], pid)}
        return call

    def test_try_link_with_proof(self):
        user, _ = mk_receiver()
        d = mk_dest()
        with mock.patch.object(peers.procs, "pair_call", self.remote()):
            self.assertTrue(peers.try_link(user))
        self.assertEqual(core.get_dest(d["id"])["receiver_user"], user)

    def test_try_link_refuses_without_proof(self):
        user, _ = mk_receiver()
        d = mk_dest()
        for answer in ({"ok": True}, {"proof": "00" * 32}):
            with mock.patch.object(peers.procs, "pair_call", return_value=answer):
                self.assertFalse(peers.try_link(user))
        with mock.patch.object(peers.procs, "pair_call", self.remote(lk="another-key")):
            self.assertFalse(peers.try_link(user))
        self.assertIsNone(core.get_dest(d["id"]).get("receiver_user"))

    def test_try_link_only_asks_the_bro_behind_the_claimed_address(self):
        user, _ = mk_receiver()
        with core.mutate() as st:
            st["receivers"][user]["peer_pt"] = _env.ticket("cc" * 32)  # he claims to be someone else
        mk_dest()
        with mock.patch.object(peers.procs, "pair_call") as call:
            self.assertFalse(peers.try_link(user))
            call.assert_not_called()

    def test_receive_link(self):
        caller, _ = mk_receiver()
        d = mk_dest()  # our login at his NAS is "alice", link key lk-2
        core.my_tickets.update(pair=_env.ticket(A))
        me = peers.ticket_id(core.my_tickets["pair"])
        answer = peers.receive_link(caller, {"u": "alice", "nonce": "n1", "proof": peers._link_proof("lk-2", "b", "n1", me)})
        self.assertEqual(answer["proof"], peers._link_proof("lk-2", "a", "n1", me))
        self.assertEqual(core.get_dest(d["id"])["receiver_user"], caller)

    def test_receive_link_refuses_relayed_or_wrong_proofs(self):
        caller, _ = mk_receiver()
        d = mk_dest()
        core.my_tickets.update(pair=_env.ticket(A))
        other = peers.ticket_id(_env.ticket("cc" * 32))
        for p in ({"u": "alice", "nonce": "n1", "proof": peers._link_proof("lk-2", "b", "n1", other)},  # meant for another bro
                  {"u": "alice", "nonce": "n1", "proof": peers._link_proof("lk-1", "b", "n1", peers.ticket_id(_env.ticket(A)))},
                  {"u": "someone", "nonce": "n1", "proof": "x"}, {"u": 1, "nonce": [], "proof": None}, {}):
            self.assertIsNone(peers.receive_link(caller, p))
        self.assertIsNone(core.get_dest(d["id"]).get("receiver_user"))

    def test_hello_to_old_bro_hourly(self):
        mk_dest()
        core.my_tickets.update(data=_env.ticket(A), pair=_env.ticket(A, ip="0a00000a"))
        with mock.patch.object(peers.procs, "pair_call", side_effect=RuntimeError("HTTP (404)")) as call:
            peers.keep_in_touch()
            self.assertEqual([c[0][2] for c in call.call_args_list].count("/bro/hello"), 1)
            peers.keep_in_touch()  # just asked: not again
            self.assertEqual([c[0][2] for c in call.call_args_list].count("/bro/hello"), 1)
            with core.mutate() as st:
                st["destinations"][0]["hello_at"] = core.iso(core.now() - datetime.timedelta(minutes=61))
            peers.keep_in_touch()  # an hour later, not six
            self.assertEqual([c[0][2] for c in call.call_args_list].count("/bro/hello"), 2)

    def test_updated_bro_gets_hello_back_at_once(self):
        user, _ = mk_receiver()
        mk_dest()
        core.my_tickets.update(data=_env.ticket(A), pair=_env.ticket(A, ip="0a00000a"))
        with mock.patch.object(peers, "hello") as h:
            peers.receive_hello(user, {"n": "Bob", "pt": _env.ticket(B)})
            h.assert_called_once()


if __name__ == "__main__":
    unittest.main()
