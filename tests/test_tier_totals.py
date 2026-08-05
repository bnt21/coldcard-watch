"""The site carries figures it did not verify, and the arithmetic around them is the only
thing keeping that honest. These pin the two rules, at the point where potential.js is
written rather than after it is published, so a broken rule fails here instead of on the
live headline.

  A tier stores the source's TOTAL, and the remainder is derived. The first version froze
  the remainder at 229.4226 BTC against a verified 1,366.5774; the verified figure moved to
  1,366.5874 the same week, so the frozen number was already counting 0.01 BTC twice.

  A report inside a tier is listed, never added. An independent post reported the same
  fourth wave Galaxy already count, and summing both put 1,984.94 BTC on the site — a total
  no source claims.
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import potential

ATTESTED = 159_600_000_000          # Galaxy, 1,596 BTC, victim-corroborated
SUSPECTED = 205_500_000_000         # Galaxy, 2,055 BTC, medium-high
VERIFIED = 136_658_736_354          # this site's own, 1,366.58736354 BTC


def write(tmp, data):
    """save() into a throwaway public dir, and read back what the browser would get."""
    real = potential.POT_JS
    potential.POT_JS = os.path.join(tmp, "potential.js")
    try:
        potential.save(data, deploy=False)
        s = open(potential.POT_JS).read()
    finally:
        potential.POT_JS = real
    assert s.startswith("window.POTENTIAL="), s[:40]
    return json.loads(s[s.index("{"):s.rindex("}") + 1])


class SummingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_a_report_inside_a_tier_is_not_summed(self):
        d = write(self.tmp, {"tiers": [], "entries": [
            {"id": "w4", "sats": 44_873_000_000, "status": "potential",
             "subsumed_by": "suspected"}]})
        self.assertEqual(d["total_sats"], 0,
                         "the fourth wave is already inside the suspected total")

    def test_a_report_outside_every_tier_still_counts(self):
        d = write(self.tmp, {"tiers": [], "entries": [
            {"id": "loose", "sats": 500_000_000, "status": "potential"}]})
        self.assertEqual(d["total_sats"], 500_000_000)

    def test_only_the_subsumed_one_is_dropped_when_both_are_present(self):
        d = write(self.tmp, {"tiers": [], "entries": [
            {"id": "w4", "sats": 44_873_000_000, "status": "potential",
             "subsumed_by": "suspected"},
            {"id": "loose", "sats": 500_000_000, "status": "potential"}]})
        self.assertEqual(d["total_sats"], 500_000_000)

    def test_a_graduated_entry_stops_counting(self):
        d = write(self.tmp, {"tiers": [], "entries": [
            {"id": "g", "sats": 900, "status": "confirmed"}]})
        self.assertEqual(d["total_sats"], 0)


class DerivedRemainderTest(unittest.TestCase):
    def test_the_remainder_is_the_source_total_minus_our_own(self):
        t = {"key": "attested", "total_sats": ATTESTED}
        self.assertEqual(potential.tier_delta(t, VERIFIED), ATTESTED - VERIFIED)

    def test_verifying_more_shrinks_the_remainder_by_exactly_that_much(self):
        t = {"key": "attested", "total_sats": ATTESTED}
        before = potential.tier_delta(t, VERIFIED)
        after = potential.tier_delta(t, VERIFIED + 10_000_000_000)
        self.assertEqual(before - after, 10_000_000_000)

    def test_a_tier_we_have_overtaken_adds_nothing(self):
        t = {"key": "attested", "total_sats": ATTESTED}
        self.assertEqual(potential.tier_delta(t, ATTESTED + 1), 0)

    def test_the_verified_basis_matches_what_the_site_publishes(self):
        # drained value, not the balance still held, so the remainder does not grow when
        # the attacker finally spends
        self.assertEqual(potential.verified_sats(), VERIFIED)


class OrderingTest(unittest.TestCase):
    """A suspected total below the attested one is a transcription error: suspected
    contains everything attested does, plus a wave nobody has confirmed.

    Every test here points POT_JS at a throwaway file first. These exercise the refusals,
    so a refusal that stops working writes the published dataset instead of the fixture —
    which is exactly what happened while mutation-testing the confidence check: the guard
    correctly went red AND the run left a live tier with a null confidence on it."""

    def setUp(self):
        self.real_js = potential.POT_JS
        potential.POT_JS = os.path.join(tempfile.mkdtemp(), "potential.js")

    def tearDown(self):
        potential.POT_JS = self.real_js

    class Args:
        def __init__(self, **kw):
            self.tier = kw.get("tier")
            self.sats = kw.get("sats")
            self.source = "@glxyresearch"
            self.url = "https://x.com/glxyresearch/status/1"
            self.confidence = "medium-high"
            self.addresses = 7300
            self.note = ""
            self.reported_ts = 1785797499
            self.no_deploy = True

    def test_suspected_below_attested_is_refused(self):
        real = potential.load
        potential.load = lambda: {"schema": 2, "entries": [], "total_sats": 0, "tiers": [
            {"key": "attested", "total_sats": ATTESTED}]}
        try:
            with self.assertRaises(SystemExit):
                potential.cmd_tier(self.Args(tier="suspected", sats=ATTESTED - 1))
        finally:
            potential.load = real

    def test_attested_above_suspected_is_refused(self):
        real = potential.load
        potential.load = lambda: {"schema": 2, "entries": [], "total_sats": 0, "tiers": [
            {"key": "suspected", "total_sats": SUSPECTED}]}
        try:
            with self.assertRaises(SystemExit):
                potential.cmd_tier(self.Args(tier="attested", sats=SUSPECTED + 1))
        finally:
            potential.load = real

    def test_a_tier_without_the_sources_own_confidence_is_refused(self):
        a = self.Args(tier="attested", sats=ATTESTED)
        a.confidence = None
        with self.assertRaises(SystemExit):
            potential.cmd_tier(a)

    def test_a_tier_without_a_source_is_refused(self):
        a = self.Args(tier="attested", sats=ATTESTED)
        a.source = None
        with self.assertRaises(SystemExit):
            potential.cmd_tier(a)


class PublishedStateTest(unittest.TestCase):
    """What is actually on the site right now."""

    def setUp(self):
        s = open(os.path.join(ROOT, "public", "potential.js")).read()
        self.d = json.loads(s[s.index("{"):s.rindex("}") + 1])

    def test_both_galaxy_totals_are_carried(self):
        by = {t["key"]: t for t in self.d["tiers"]}
        self.assertEqual(by["attested"]["total_sats"], ATTESTED)
        self.assertEqual(by["suspected"]["total_sats"], SUSPECTED)

    def test_every_tier_names_its_source_and_its_confidence(self):
        for t in self.d["tiers"]:
            self.assertTrue(t.get("source"), t)
            self.assertTrue(t.get("confidence"), t)
            self.assertTrue(t.get("source_url"), t)

    def test_nothing_is_being_added_on_top_of_the_tiers(self):
        self.assertEqual(self.d["total_sats"], 0)

    def test_the_frozen_remainder_entry_is_gone(self):
        ids = [e["id"] for e in self.d["entries"]]
        self.assertNotIn("galaxy-remainder-960945", ids,
                         "superseded by the attested tier, which derives the remainder")


if __name__ == "__main__":
    unittest.main()
