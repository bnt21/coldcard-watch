"""The automatic gate decides what this site publishes without a human, so what it
REFUSES matters more than what it accepts.

Origin, 2026-08-05. A 112-victim cluster had to be reported by hand because the gate
discarded it, and the reasons were all fixable without weakening anything:

  unspent  False   the collector forwarded its whole take one hop down, so it read as
  enough   False   spent and empty, and the dust floor dropped it
  tight    False   sweeps spread over 109 blocks, past the 30-block window
  fee      False   81% of sweeps at ONE below-market constant, under the 90% bar

The methodology page publishes two independent convergence tests and says an address is
listed when its sweep shows ONE of them. The gate only implemented the fee test and
treated it as the whole standard. Destination convergence, which is what waves 1, 2 and 5
are listed on, had no code at all.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import autopilot
import cluster
import publish


def fp(**kw):
    """A fingerprint that clears every shape requirement; override to break one."""
    base = {"block_span": [1000, 1010], "balance": 3_600_000_000, "fee_uniform": True,
            "no_change_ratio": 1.0, "fresh": True, "unspent": True, "victims": 40,
            "hold_addr": None}
    base.update(kw)
    return base


class AcceptsTest(unittest.TestCase):
    def test_the_fee_route_still_works(self):
        ok, route = autopilot.accepts(fp(victims=6))
        self.assertTrue(ok)
        self.assertEqual(route, "fee")

    def test_the_cluster_that_had_to_be_reported_by_hand_is_now_caught(self):
        # its real numbers: 112 victims, no fee uniformity, 109-block span
        ok, route = autopilot.accepts(
            fp(victims=112, fee_uniform=False, block_span=[960624, 960733]))
        self.assertTrue(ok, "this is the miss the whole change exists for")
        self.assertEqual(route, "destination")

    def test_destination_convergence_needs_far_more_victims_than_the_fee_route(self):
        # one below the bar, with nothing else carrying it
        ok, _ = autopilot.accepts(
            fp(victims=autopilot.DEST_CONVERGENCE_MIN - 1, fee_uniform=False,
               block_span=[1, 500]))
        self.assertFalse(ok)
        ok, route = autopilot.accepts(
            fp(victims=autopilot.DEST_CONVERGENCE_MIN, fee_uniform=False,
               block_span=[1, 500]))
        self.assertTrue(ok)
        self.assertEqual(route, "destination")

    # --- what must still be refused, whichever route is claimed ---

    def test_a_service_is_refused_on_both_routes(self):
        for extra in ({}, {"fee_uniform": False, "victims": 500}):
            self.assertFalse(autopilot.accepts(fp(fresh=False, **extra))[0],
                             "unrelated history means a business, not a collector")

    def test_a_collector_that_spent_the_money_is_refused(self):
        self.assertFalse(autopilot.accepts(fp(unspent=False))[0])

    def test_dust_is_refused_however_many_victims(self):
        self.assertFalse(autopilot.accepts(fp(balance=1_000, victims=900))[0],
                         "a dust address must never be called attacker-controlled")

    def test_change_producing_transactions_are_refused(self):
        # a sweep empties the address; leftover change is an ordinary payment
        self.assertFalse(autopilot.accepts(fp(no_change_ratio=0.5, victims=900))[0])

    def test_a_wide_window_alone_does_not_pass_on_the_fee_route(self):
        ok, _ = autopilot.accepts(fp(victims=6, block_span=[1, 5000]))
        self.assertFalse(ok, "the fee route still requires a tight window")

    def test_a_lone_owner_consolidating_their_own_wallets_is_refused(self):
        # the realistic false positive: one person sweeping a handful of their own
        # addresses to safety, at whatever fee their wallet picked
        ok, _ = autopilot.accepts(fp(victims=4, fee_uniform=False, block_span=[1, 900]))
        self.assertFalse(ok)


class ForwardedToTest(unittest.TestCase):
    """Reading the balance one hop down is only safe if the hop is unambiguous."""

    def setUp(self):
        self.real = publish.esplora

    def tearDown(self):
        publish.esplora = self.real

    @staticmethod
    def tx(srcs, dests):
        return {"txid": "t", "vin": [{"prevout": {"scriptpubkey_address": s}} for s in srcs],
                "vout": [{"scriptpubkey_address": d} for d in dests]}

    def test_one_spend_into_one_output_is_the_forward(self):
        txs = [self.tx(["coll"], ["vault"]), self.tx(["victim"], ["coll"])]
        self.assertEqual(cluster.forwarded_to("coll", txs), "vault")

    def test_a_spend_with_change_is_not_a_forward(self):
        txs = [self.tx(["coll"], ["somewhere", "coll"])]
        self.assertIsNone(cluster.forwarded_to("coll", txs),
                          "change means it kept some; this is a peel, not a park")

    def test_several_spends_are_not_a_forward(self):
        txs = [self.tx(["coll"], ["a"]), self.tx(["coll"], ["b"])]
        self.assertIsNone(cluster.forwarded_to("coll", txs))

    def test_a_split_is_not_a_forward(self):
        txs = [self.tx(["coll"], ["a", "b", "c"])]
        self.assertIsNone(cluster.forwarded_to("coll", txs))

    def test_an_address_that_never_spent_has_no_forward(self):
        self.assertIsNone(cluster.forwarded_to("coll", [self.tx(["victim"], ["coll"])]))

    def test_the_fingerprint_judges_the_money_where_it_actually_sits(self):
        chain = {
            "/address/coll/txs/chain": [
                {"txid": "fwd", "status": {"block_height": 10, "block_time": 1},
                 "weight": 400, "fee": 100,
                 "vin": [{"prevout": {"scriptpubkey_address": "coll"}}],
                 "vout": [{"scriptpubkey_address": "vault"}]},
                {"txid": "s1", "status": {"block_height": 9, "block_time": 1},
                 "weight": 400, "fee": 100,
                 "vin": [{"prevout": {"scriptpubkey_address": "v1", "value": 5}}],
                 "vout": [{"scriptpubkey_address": "coll"}]},
            ],
            "/address/coll/txs": None,      # filled below
            "/address/coll": {"chain_stats": {"funded_txo_sum": 5, "spent_txo_sum": 5,
                                              "funded_txo_count": 1}},
            "/address/vault": {"chain_stats": {"funded_txo_sum": 5, "spent_txo_sum": 0,
                                               "funded_txo_count": 1}},
        }
        chain["/address/coll/txs"] = chain["/address/coll/txs/chain"]
        publish.esplora = lambda p: chain.get(p, [])
        v = cluster.cluster_fingerprint("coll")
        self.assertEqual(v["hold_addr"], "vault")
        self.assertTrue(v["unspent"], "the money is parked, not spent")
        self.assertEqual(v["balance"], 5)


class DeployGuardTest(unittest.TestCase):
    """A publish ships the whole public/ directory, not the files it touched.

    This tree is carried between machines by syncthing, so a cron can be about to deploy
    a directory holding another session's half-written script. One script that does not
    parse takes the entire page down, because the first error stops every line after it.
    """

    def test_the_live_page_parses(self):
        ok, why = cluster.js_parses(
            open(os.path.join(ROOT, "public", "index.html"), encoding="utf-8").read())
        self.assertTrue(ok, why)

    def test_an_unparseable_script_is_refused(self):
        ok, why = cluster.js_parses("<script>function broken( {</script>", "fixture")
        self.assertFalse(ok)
        self.assertIn("does not parse", why)

    def test_a_good_script_beside_a_broken_one_does_not_excuse_it(self):
        ok, _ = cluster.js_parses("<script>var a=1;</script><script>if(</script>")
        self.assertFalse(ok)

    def test_external_scripts_are_not_checked_as_inline_source(self):
        ok, why = cluster.js_parses('<script src="/data.js"></script>')
        self.assertTrue(ok, why)

    def test_an_empty_script_tag_is_fine(self):
        self.assertTrue(cluster.js_parses("<script></script>")[0])

    def test_add_cluster_actually_calls_the_guard(self):
        # the helper being correct is not the same as it being wired in. Mutating the
        # refusal out of add_cluster left every js_parses test green.
        import inspect
        src = inspect.getsource(cluster.add_cluster)
        self.assertIn("js_parses(", src)
        self.assertIn("refusing to publish", src)

    def test_add_cluster_refuses_when_the_page_does_not_parse(self):
        real_parses, real_conflict, real_check = (
            cluster.js_parses, publish.conflict_guard, publish.self_check)
        real_victims = cluster.collector_victims
        try:
            publish.conflict_guard = lambda: []
            publish.self_check = lambda verbose=True: []
            cluster.collector_victims = lambda c: ({}, 0, 10**9, {})
            cluster.js_parses = lambda html, label="index.html": (False, "boom")
            r = cluster.add_cluster("coll", "src", "note", dry=True)
            # it stops before any edit; whichever refusal it reaches, it must not publish
            self.assertEqual(r["added"], 0)
        finally:
            (cluster.js_parses, publish.conflict_guard, publish.self_check,
             cluster.collector_victims) = (real_parses, real_conflict, real_check,
                                           real_victims)


if __name__ == "__main__":
    unittest.main()
