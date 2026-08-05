"""The forward walk has one job beyond walking: knowing when to stop, and saying honestly
whether it stopped because it ran out of chain or because it ran out of budget.

The walk this replaces did neither. It expanded through a 324-input, 382-output exchange
batch and its frontier grew from 456 pending addresses at hop 5 to 1,034 at hop 6, so it was
enumerating that exchange's customers rather than following a thief. Left to finish it would
have printed a number that was true and meaningless, because past a service every address on
the chain is reachable from every other.

Network-free: publish.esplora is replaced with a hand-built chain, so these run in the same
suite as everything else and test the walker rather than the internet.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import publish
import trace as tracer


def tx(srcs, dests, per_src=1, values=None):
    """A transaction spending from `srcs` to `dests`. Counts are what the predicate reads."""
    vin = [{"prevout": {"scriptpubkey_address": s, "value": 100}}
           for s in srcs for _ in range(per_src)]
    vout = [{"scriptpubkey_address": d, "value": (values or {}).get(d, 100)} for d in dests]
    return {"txid": "tx_" + "_".join(srcs)[:20] + "->" + "_".join(dests)[:20],
            "vin": vin, "vout": vout, "status": {"confirmed": True, "block_height": 1}}


class FakeChain:
    """address -> (list of txs it appears in, balance)."""

    def __init__(self, spends, balances=None):
        self.spends = spends
        self.balances = balances or {}
        self.calls = 0

    def __call__(self, path):
        self.calls += 1
        parts = path.strip("/").split("/")
        addr = parts[1]
        if path.endswith("/txs"):
            return self.spends.get(addr, [])
        bal = self.balances.get(addr, 0)
        return {"chain_stats": {"funded_txo_sum": bal, "spent_txo_sum": 0,
                                "spent_txo_count": 0},
                "mempool_stats": {"funded_txo_sum": 0, "spent_txo_sum": 0}}


class WalkerTest(unittest.TestCase):
    def setUp(self):
        self.real = publish.esplora

    def tearDown(self):
        publish.esplora = self.real

    def run_walk(self, chain, seeds, known=(), **kw):
        publish.esplora = chain
        return tracer.trace_forward(seeds, known=set(known), verbose=False, **kw)

    def test_a_walk_that_runs_out_of_chain_says_it_is_complete(self):
        # a -> b -> c, and c never spends
        chain = FakeChain({"a": [tx(["a"], ["b"])], "b": [tx(["b"], ["c"])], "c": []},
                          balances={"c": 500})
        r = self.run_walk(chain, ["a"])
        self.assertTrue(r["complete"])
        self.assertEqual(r["frontier_left"], 0)
        self.assertEqual([x["addr"] for x in r["resting"]], ["c"])
        self.assertEqual(r["resting"][0]["sats"], 500)

    def test_a_walk_stopped_by_the_address_budget_says_so(self):
        # a fans out wider than the budget allows
        wide = {"a": [tx(["a"], [f"d{i}" for i in range(10)])]}
        for i in range(10):
            wide[f"d{i}"] = [tx([f"d{i}"], [f"e{i}"])]
        r = self.run_walk(FakeChain(wide), ["a"], max_addr=3)
        self.assertFalse(r["complete"], "a budget stop must never report as complete")
        self.assertGreater(r["frontier_left"], 0)
        self.assertEqual(r["walked"], 3)

    def test_a_walk_stopped_by_the_depth_cap_says_so(self):
        chain = FakeChain({"a": [tx(["a"], ["b"])], "b": [tx(["b"], ["c"])],
                           "c": [tx(["c"], ["d"])], "d": []})
        r = self.run_walk(chain, ["a"], max_hops=2)
        self.assertFalse(r["complete"])
        self.assertGreater(r["hit_depth_cap"], 0)

    def test_the_walk_stops_at_a_service_and_does_not_expand_it(self):
        # a pays into a batch merging 60 independent addresses and paying 60 destinations
        srcs = ["a"] + [f"other{i}" for i in range(60)]
        dests = [f"cust{i}" for i in range(60)]
        chain = FakeChain({"a": [tx(srcs, dests)]})
        r = self.run_walk(chain, ["a"])
        self.assertEqual(len(r["reached_service"]), 1)
        self.assertEqual(r["reached_service"][0]["hop"], 1)
        # the customers of that service are NOT followed; this is the frontier explosion
        self.assertNotIn("cust0", [x["addr"] for x in r["resting"]])
        self.assertTrue(r["complete"])
        self.assertLessEqual(r["walked"], 2)

    def test_the_walk_continues_through_the_attackers_own_consolidation(self):
        # 200 vaults the attacker already owns, swept into one address. Every count-based
        # rule calls this a service. It is the thief tidying up, and the walk must go on.
        vaults = [f"vault{i}" for i in range(200)]
        chain = FakeChain({"vault0": [tx(vaults, ["pot"])], "pot": [tx(["pot"], ["next"])],
                           "next": []}, balances={"next": 900})
        r = self.run_walk(chain, ["vault0"], known=vaults)
        self.assertEqual(r["reached_service"], [],
                         "the attacker's own sweep is not a service")
        self.assertEqual([x["addr"] for x in r["resting"]], ["next"])

    def test_the_same_consolidation_by_strangers_does_stop_the_walk(self):
        vaults = [f"vault{i}" for i in range(200)]
        chain = FakeChain({"vault0": [tx(vaults, ["pot"])], "pot": [tx(["pot"], ["next"])]})
        r = self.run_walk(chain, ["vault0"], known=())    # nothing attributed
        self.assertEqual(len(r["reached_service"]), 1)
        self.assertEqual(r["reached_service"][0]["kind"], "merges")

    def test_a_wide_split_stops_the_walk_even_from_a_known_sender(self):
        dests = [f"out{i}" for i in range(80)]
        chain = FakeChain({"a": [tx(["a"], dests)]})
        r = self.run_walk(chain, ["a"], known=["a"])
        self.assertEqual(len(r["reached_service"]), 1)
        self.assertEqual(r["reached_service"][0]["kind"], "splits")

    def test_receiving_is_not_followed_only_spending(self):
        # b receives from a and never spends; the walk must not treat a's tx as b's spend
        chain = FakeChain({"a": [tx(["a"], ["b"])], "b": [tx(["a"], ["b"])]},
                          balances={"b": 250})
        r = self.run_walk(chain, ["a"])
        self.assertEqual([x["addr"] for x in r["resting"]], ["b"])

    def test_a_cycle_does_not_loop_forever(self):
        chain = FakeChain({"a": [tx(["a"], ["b"])], "b": [tx(["b"], ["a"])]})
        r = self.run_walk(chain, ["a"], max_addr=50)
        self.assertTrue(r["complete"])
        self.assertLessEqual(r["walked"], 2)

    def test_describe_states_whether_the_walk_was_complete(self):
        chain = FakeChain({"a": []}, balances={})
        r = self.run_walk(chain, ["a"])
        self.assertIn("ran out of places to go", tracer.describe(r))
        r["complete"] = False
        r["frontier_left"] = 12
        self.assertIn("STOPPED ON A BUDGET", tracer.describe(r))


class PredicateTest(unittest.TestCase):
    """The measured fixtures, so the shapes recorded from the chain stay pinned."""

    def test_every_recorded_fixture_classifies_correctly(self):
        for label, n_src, n_in, n_dst, all_known, expect in tracer.FIXTURES:
            t = tracer._fake(n_src, n_in, n_dst)
            known = {f"src{i}" for i in range(n_src)} if all_known else set()
            self.assertEqual(tracer.service_shaped(t, known)["service"], expect, label)

    def test_distinct_sources_decide_rather_than_input_count(self):
        # the attacker's real 1,212-input consolidation against a real 902-input service
        attacker = tracer.service_shaped(tracer._fake(1, 1212, 1), {"src0"})
        service = tracer.service_shaped(tracer._fake(795, 902, 1), set())
        self.assertFalse(attacker["service"])
        self.assertTrue(service["service"])

    def test_the_threshold_sits_well_above_ordinary_traffic(self):
        # control arm, n=495: p99 was 10 inputs and 18 outputs
        self.assertGreaterEqual(tracer.SERVICE_SOURCES, 5 * 10)
        self.assertGreaterEqual(tracer.SERVICE_DESTS, 2 * 18)

    def test_the_reason_is_always_stated(self):
        v = tracer.service_shaped(tracer._fake(795, 902, 1), set())
        self.assertTrue(v["why"])
        self.assertIn("795", v["why"][0])


if __name__ == "__main__":
    unittest.main()
