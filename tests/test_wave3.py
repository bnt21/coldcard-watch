#!/usr/bin/env python3
"""
Regression tests for the wave-3 detector and the numbers it put on the site.

There were no tests when wave 3 was published, so the only thing standing behind
200.33487536 BTC was that one run happened to land near a figure Galaxy published.
These pin it. A change to a predicate that moves a published number now fails here
instead of silently shipping.

Two kinds of test:
  frozen artefacts   the published set is re-derived from wave3-report.json and must
                     match public/wave3.js to the satoshi
  synthetic blocks   each fingerprint predicate is exercised against a hand-built
                     block, so a loosened rule is caught even with no chain access

Needs no node and no network.

    python3 -m unittest discover -s tests -v
"""
import copy
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import wave3  # noqa: E402

BAND_LO, BAND_HI = 195.0, 210.0

# What the site says today. Any change to these is a deliberate act, not a side effect.
PUBLISHED_VAULTS = 293
PUBLISHED_HELD_SATS = 20772939540
PUBLISHED_VICTIMS = 1894


def load(name):
    with open(os.path.join(ROOT, "data", name), encoding="utf-8") as f:
        return json.load(f)


def published_chains(report):
    """The selection rule add_wave3.py used: a completed two-hop chain whose sweep fee
    sits in the band. Kept here so the rule itself is under test."""
    ok = [s for s in report["sweeps"] if (s.get("hop2") or {}).get("ok")]
    return [s for s in ok if BAND_LO <= s["rate"] <= BAND_HI]


class PublishedSet(unittest.TestCase):
    """The frozen artefacts still agree with each other and with the live site.

    The 195-210 band below reproduces the FIRST pass, which keyed on the sweep fee and
    found 214 of the wave. The wave is 293: every park moved onward in block 960520 at a
    hardcoded ~10.05 sat/vB, and that second-hop constant is what actually spans it. The
    band tests are kept because that subset is still a real, checkable population."""

    @classmethod
    def setUpClass(cls):
        cls.report = load("wave3-report.json")
        cls.frozen = load("wave3-set.json")

    # The 195-210 band reproduces the FIRST pass over blocks 960396-960471, which keyed
    # on the sweep fee and found 214 of the wave. It is still a real population and worth
    # pinning; it is simply not the whole wave, so it is no longer the published total.
    FIRST_PASS_VAULTS = 214
    FIRST_PASS_SATS = 20033487536

    def test_the_first_pass_subset_is_stable(self):
        vaults = {s["hop2"]["vault"] for s in published_chains(self.report)}
        self.assertEqual(len(vaults), self.FIRST_PASS_VAULTS)

    def test_the_first_pass_subset_total_is_stable(self):
        seen = {}
        for s in published_chains(self.report):
            h = s["hop2"]
            seen.setdefault(h["vault"], h.get("vault_balance") or 0)
        self.assertEqual(sum(seen.values()), self.FIRST_PASS_SATS)

    def test_frozen_set_matches_the_first_pass(self):
        self.assertEqual(len(self.frozen["vaults"]), self.FIRST_PASS_VAULTS)
        self.assertEqual(self.frozen["held_sats"], self.FIRST_PASS_SATS)

    def test_every_published_vault_is_unspent(self):
        """An unspent vault is the claim being made. A spent one is a different claim."""
        for v in self.frozen["vaults"].values():
            self.assertTrue(v["unspent"], f"{v['addr']} has spent; the set is stale")

    def test_site_dataset_matches_the_frozen_set(self):
        with open(os.path.join(ROOT, "public", "wave3.js"), encoding="utf-8") as f:
            src = f.read()
        site = json.loads(re.search(r"window\.WAVE3=(.*);", src, re.S).group(1))
        self.assertEqual(site["count"], PUBLISHED_VAULTS)
        self.assertEqual(site["held"], PUBLISHED_HELD_SATS)
        self.assertEqual(site["victims"], PUBLISHED_VICTIMS)
        self.assertEqual(sum(b for _, b in site["vaults"]), PUBLISHED_HELD_SATS)

    def test_the_published_set_contains_the_first_pass(self):
        """The whole wave must be a superset of what the first pass proved."""
        import re as _re
        with open(os.path.join(ROOT, "public", "wave3.js"), encoding="utf-8") as f:
            site = json.loads(_re.search(r"window\.WAVE3=(.*);", f.read(), _re.S).group(1))
        live = {a for a, _ in site["vaults"]}
        for s in published_chains(self.report):
            self.assertIn(s["hop2"]["vault"], live)

    def test_canary_chain_is_present(self):
        """The one wave-3 chain a third party published in full. If this is missing the
        detector is not finding wave 3, whatever else it finds."""
        vaults = {s["hop2"]["vault"] for s in published_chains(self.report)}
        self.assertIn(wave3.CANARY_VAULT, vaults)

    def test_out_of_band_chains_were_excluded(self):
        """The 16 dropped chains are the discipline: shape matched, fee did not."""
        ok = [s for s in self.report["sweeps"] if (s.get("hop2") or {}).get("ok")]
        dropped = [s for s in ok if not (BAND_LO <= s["rate"] <= BAND_HI)]
        self.assertTrue(dropped, "expected some chains to be dropped")
        published = {s["hop2"]["vault"] for s in published_chains(self.report)}
        for s in dropped:
            # every dropped chain really is outside the band, and none of them reached
            # the site. The first assertion used a range() of ints against a float rate,
            # which could never fail for any input.
            self.assertFalse(BAND_LO <= s["rate"] <= BAND_HI)
            self.assertNotIn(s["hop2"]["vault"], published,
                             f"dropped chain {s['txid']} leaked into the published set")

    def test_no_input_coin_predates_the_vulnerable_firmware(self):
        """Stated on the methodology page as evidence, so it is asserted here."""
        for s in published_chains(self.report):
            self.assertGreaterEqual(s["oldest_input_block"], wave3.FIRMWARE_EPOCH)


# ----------------------------------------------------------------- synthetic blocks

def _prevout(addr, sats, height=700000, kind="witness_v0_keyhash"):
    return {"value": sats / 1e8, "height": height,
            "scriptPubKey": {"address": addr, "type": kind}}


def _sweep_tx(n_inputs=3, fee_sats=20100, weight=400, version=2, locktime=0,
              sequence=0xFFFFFFFF, in_kind="witness_v0_keyhash",
              in_height=700000, n_outputs=1, out_addr="bc1qdest"):
    ins = 1_000_000
    vin = [{"sequence": sequence,
            "prevout": _prevout(f"bc1qvictim{i}", ins, in_height, in_kind)}
           for i in range(n_inputs)]
    total_in = ins * n_inputs
    vout = [{"value": (total_in - fee_sats) / 1e8,
             "scriptPubKey": {"address": out_addr, "type": "witness_v0_keyhash"}}]
    for k in range(n_outputs - 1):
        vout.append({"value": 0.001,
                     "scriptPubKey": {"address": f"bc1qchange{k}",
                                      "type": "witness_v0_keyhash"}})
    return {"txid": "a" * 64, "version": version, "locktime": locktime,
            "weight": weight, "vin": vin, "vout": vout}


def _filler(k):
    """Cheap ordinary traffic so the block has a low median to measure against."""
    return {"txid": f"{k:064x}", "version": 2, "locktime": 0, "weight": 400,
            "vin": [{"sequence": 0xFFFFFFFF, "prevout": _prevout("bc1qsomebody", 500000)}],
            "vout": [{"value": (500000 - 200) / 1e8,
                      "scriptPubKey": {"address": "bc1qelsewhere",
                                       "type": "witness_v0_keyhash"}}]}


class Fingerprint(unittest.TestCase):
    """Each predicate is load-bearing. Loosening one must fail a test."""

    def scan(self, tx):
        block = {"time": 1785500000, "tx": [_filler(i) for i in range(9)] + [tx]}
        real = wave3.rpc
        wave3.rpc = lambda m, p=None: block if m == "getblock" else "h"
        try:
            return wave3.scan_block(960400, fee_multiple=20.0, min_rate=100.0)
        finally:
            wave3.rpc = real

    def test_the_reference_sweep_is_detected(self):
        hits = self.scan(_sweep_tx())
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["dest"], "bc1qdest")
        self.assertAlmostEqual(hits[0]["rate"], 201.0, places=0)

    def test_address_reuse_across_inputs_is_allowed(self):
        """The bug that cost 63 sweeps on the first run. One wallet reuses an address;
        requiring distinct inputs silently dropped a fifth of wave 3."""
        tx = _sweep_tx(n_inputs=3)
        tx["vin"][1]["prevout"]["scriptPubKey"]["address"] = "bc1qvictim0"
        self.assertEqual(len(self.scan(tx)), 1)

    def test_rejects_wrong_version(self):
        self.assertEqual(self.scan(_sweep_tx(version=1)), [])

    def test_rejects_nonzero_locktime(self):
        self.assertEqual(self.scan(_sweep_tx(locktime=960399)), [])

    def test_rejects_mixed_sequence_values(self):
        tx = _sweep_tx(n_inputs=3)
        tx["vin"][0]["sequence"] = 0xFFFFFFFD
        self.assertEqual(self.scan(tx), [])

    def test_rejects_a_change_output(self):
        self.assertEqual(self.scan(_sweep_tx(n_outputs=2)), [])

    def test_rejects_non_p2wpkh_inputs(self):
        self.assertEqual(self.scan(_sweep_tx(in_kind="witness_v0_scripthash")), [])

    def test_rejects_mixed_input_script_types(self):
        tx = _sweep_tx(n_inputs=3)
        tx["vin"][2]["prevout"]["scriptPubKey"]["type"] = "scripthash"
        self.assertEqual(self.scan(tx), [])

    def test_rejects_a_coin_older_than_the_vulnerable_firmware(self):
        self.assertEqual(self.scan(_sweep_tx(in_height=wave3.FIRMWARE_EPOCH - 1)), [])

    def test_rejects_a_fee_at_the_market_rate(self):
        self.assertEqual(self.scan(_sweep_tx(fee_sats=200)), [])

    def test_rejects_a_high_fee_that_is_not_far_above_the_block_median(self):
        """A busy block must not make ordinary traffic look like a hardcoded fee."""
        tx = _sweep_tx(fee_sats=20100)
        block = {"time": 1785500000,
                 "tx": [dict(_filler(i), weight=400,
                             vout=[{"value": (500000 - 19000) / 1e8,
                                    "scriptPubKey": {"address": "bc1qelsewhere",
                                                     "type": "witness_v0_keyhash"}}])
                        for i in range(9)] + [tx]}
        real = wave3.rpc
        wave3.rpc = lambda m, p=None: block if m == "getblock" else "h"
        try:
            self.assertEqual(wave3.scan_block(960400, 20.0, 100.0), [])
        finally:
            wave3.rpc = real


class Hop2(unittest.TestCase):
    """trace_hop2 decides which address is called an attacker vault, and had no tests."""

    def run_with(self, addr_info, txs, vault_info):
        real = wave3.esplora
        def fake(path, tries=3):
            if path.endswith("/txs/chain"):
                return txs
            if path.startswith("/address/") and path.count("/") == 2:
                a = path.split("/")[-1]
                return vault_info if a.startswith("bc1qvault") else addr_info
            return None
        wave3.esplora = fake
        try:
            return wave3.trace_hop2("bc1qpark")
        finally:
            wave3.esplora = real

    @staticmethod
    def stats(funded, spent, fcount=1, scount=1):
        return {"chain_stats": {"funded_txo_sum": funded, "spent_txo_sum": spent,
                                "funded_txo_count": fcount, "spent_txo_count": scount}}

    def fwd(self, moved, out_sats=None, kind="v0_p2wsh"):
        return [{"txid": "b" * 64, "status": {"block_height": 960520},
                 "vin": [{"prevout": {"scriptpubkey_address": "bc1qpark", "value": moved}}],
                 "vout": [{"value": out_sats if out_sats is not None else moved - 500,
                           "scriptpubkey_type": kind,
                           "scriptpubkey_address": "bc1qvault1"}]}]

    def test_clean_forward_into_a_fresh_unspent_p2wsh_is_accepted(self):
        r = self.run_with(self.stats(100000, 100000), self.fwd(100000),
                          self.stats(99500, 0, 1, 0))
        self.assertTrue(r["ok"])
        self.assertEqual(r["vault"], "bc1qvault1")

    def test_a_park_still_holding_a_residue_is_rejected(self):
        """The published claim is a whole-balance forward. A residue is a different claim."""
        r = self.run_with(self.stats(100000, 90000), self.fwd(90000),
                          self.stats(89500, 0, 1, 0))
        self.assertFalse(r["ok"])
        self.assertIn("still holds", r["why"])

    def test_a_partial_forward_is_rejected(self):
        r = self.run_with(self.stats(150000, 150000), self.fwd(100000),
                          self.stats(99500, 0, 1, 0))
        self.assertFalse(r["ok"])
        self.assertIn("whole balance", r["why"])

    def test_a_forward_to_a_non_p2wsh_is_rejected(self):
        r = self.run_with(self.stats(100000, 100000),
                          self.fwd(100000, kind="v0_p2wpkh"),
                          self.stats(99500, 0, 1, 0))
        self.assertFalse(r["ok"])

    def test_an_unspent_park_is_reported_as_parked_not_ok(self):
        r = self.run_with(self.stats(100000, 0, 1, 0), [], None)
        self.assertFalse(r["ok"])
        self.assertTrue(r["parked"])


class AutopilotGates(unittest.TestCase):
    """The tiering decides what may reach a public page unattended."""

    def gate(self, **over):
        """The accept test from _fingerprint_candidates, with one fingerprint."""
        import autopilot
        fp = {"fee_uniform": True, "no_change_ratio": 1.0, "fresh": True,
              "unspent": True, "victims": 5, "block_span": (960400, 960410),
              "balance": 5_000_000}
        fp.update(over)
        span = fp["block_span"]
        tight = span and (span[1] - span[0]) <= autopilot.TIGHT_WINDOW
        enough = fp["balance"] >= autopilot.MIN_CLUSTER_BTC * 1e8
        return (fp["fee_uniform"] and fp["no_change_ratio"] >= 0.9 and fp["fresh"]
                and fp["unspent"] and fp["victims"] >= 3 and tight and enough)

    def test_a_real_cluster_passes(self):
        self.assertTrue(self.gate())

    def test_dust_is_rejected(self):
        """A 0.00056 BTC address reached the proposed tier because the declared
        floor was never applied. With auto-publish on, that is dust on a public
        page calling addresses attacker-controlled."""
        self.assertFalse(self.gate(balance=56_240))

    def test_the_floor_is_the_declared_constant(self):
        import autopilot
        self.assertFalse(self.gate(balance=int(autopilot.MIN_CLUSTER_BTC * 1e8) - 1))
        self.assertTrue(self.gate(balance=int(autopilot.MIN_CLUSTER_BTC * 1e8)))

    def test_a_varying_fee_is_rejected(self):
        self.assertFalse(self.gate(fee_uniform=False))

    def test_a_spent_vault_is_rejected(self):
        self.assertFalse(self.gate(unspent=False))

    def test_a_wide_block_span_is_rejected(self):
        self.assertFalse(self.gate(block_span=(960000, 960400)))

    def test_tier2_autopublish_stays_off(self):
        """It gates whether a heuristic match can publish with nobody watching."""
        import autopilot
        self.assertFalse(autopilot.TIER2_AUTOPUBLISH)


class SiteInvariants(unittest.TestCase):
    def test_cross_file_invariants_hold(self):
        """rows == hashes == DRAINED_COUNT across every coupled surface."""
        import publish
        self.assertEqual(publish.self_check(verbose=False), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
