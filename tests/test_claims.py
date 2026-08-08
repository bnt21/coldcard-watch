"""The falsifiable check the notification rule demands: paste the ACTUAL text of the posts
the monitor should have caught, and confirm the detector fires. These two tweets went past
the pipeline on 2026-08-03 while the site sat 14.4% low.

Every string below is verbatim from the X API, not paraphrased, because a detector tested
against text someone retyped is a detector tested against its own author's imagination —
which is exactly how the regex it replaces came to miss this."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import claims

# verbatim, via GET /2/tweets — the posts the old WAVE_RE did not match
GALAXY_HEADLINE = (
    "\U0001f6a8LOSSES FROM COLDCARD HACK EXCEED $100M \n\n"
    "High confidence 1,596 BTC has been stolen from ~7300 addresses across 3 confirmed "
    "waves + more 14 smaller incidents. \n\n"
    "If we add suspected (but unconfirmed), the total balloons to $130m (2k BTC).\n\n"
    "More in the thread below \U0001f447 https://t.co/RAl3ib67qa"
)
GALAXY_REPLY = (
    "While we have also identified a potential Wave 4, we have yet to receive specific "
    "victim confirmation of inclusion in this wave. Including it would bring the total to "
    "2055 BTC ($130m). \n\n"
    "We believe with medium-high confidence that Wave 4 is substantially comprised of an "
    "attacker, https://t.co/d4xSCu11UB https://t.co/VzZKv51iMM"
)

# what the site published at the time, and what it carried beyond it: nothing. Every
# assertion below about the 2026-08-03 miss passes CARRIED=0 explicitly, because the
# site now carries Galaxy's own totals and the same posts must no longer fire.
PUB_BTC, PUB_ADDR, CARRIED = 1366.5774, 4580, 0


class TheMissedPostsTest(unittest.TestCase):
    def test_headline_tweet_is_caught(self):
        v = claims.assess(GALAXY_HEADLINE, PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        self.assertTrue(v["behind"], "the post that was missed must fire")
        # both of their totals are reported; neither is silently dropped, because which one
        # is "confirmed" lives in prose this module deliberately does not try to read
        self.assertEqual(v["claims_btc"], [2000.0, 1596.0])
        self.assertEqual(v["claim_btc"], 2000.0, "the trigger uses the largest")

    def test_the_confirmed_figure_is_not_discarded(self):
        # 1,596 is the number that makes the site 229 BTC low; losing it would understate
        v = claims.assess(GALAXY_HEADLINE, PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        self.assertIn(1596.0, v["claims_btc"])
        self.assertAlmostEqual(1596.0 - v["published_btc"], 229.4226, places=3)

    def test_headline_address_count_is_caught(self):
        v = claims.assess(GALAXY_HEADLINE, PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        self.assertEqual(v["claim_addresses"], 7300, "the ~7300 form must parse")
        self.assertEqual(v["gap_addresses"], 2720)

    def test_reply_tweet_is_caught(self):
        # this one was never even fetched; it must at least be detectable once it is
        v = claims.assess(GALAXY_REPLY, PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        self.assertTrue(v["behind"])
        self.assertEqual(v["claim_btc"], 2055.0)

    def test_the_largest_figure_wins_not_the_first(self):
        # the headline carries 1,596 then "2k BTC"; 2k is larger and must be the claim
        self.assertEqual(claims.biggest_claim(GALAXY_HEADLINE), 2000.0)

    def test_gap_is_a_range_when_several_totals_are_stated(self):
        # quoting only the largest gap overstates it: their confirmed 1,596 puts the site
        # 229 low, their suspected-inclusive 2k puts it 633 low. Both belong in the message.
        v = claims.assess(GALAXY_HEADLINE, PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        s = claims.describe(v, source="glxyresearch")
        self.assertIn("gap: 229 to 633 BTC", s, s)

    def test_gap_is_a_single_number_when_one_total_is_stated(self):
        v = claims.assess("2055 BTC stolen in total", PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        s = claims.describe(v, source="glxyresearch")
        self.assertIn("gap: 688.42 BTC", s, s)

    def test_describe_states_every_figure_and_ours(self):
        v = claims.assess(GALAXY_HEADLINE, PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        s = claims.describe(v, source="glxyresearch", url="https://x.com/x/status/1")
        for must in ("2,000 and 1,596 BTC", "1,366.5774", "7,300", "4,580", "not verified"):
            self.assertIn(must, s, s)


class ParsingTest(unittest.TestCase):
    def test_thousand_and_million_suffixes(self):
        self.assertEqual(claims.figures("2k BTC")["btc"], [2000.0])
        self.assertEqual(claims.figures("1.5m BTC")["btc"], [1_500_000.0])

    def test_comma_and_decimal_forms(self):
        self.assertEqual(claims.figures("1,596 BTC")["btc"], [1596.0])
        self.assertEqual(claims.figures("207.72939540 BTC")["btc"], [207.7293954])

    def test_usd_is_not_read_as_btc(self):
        # "$100M" must never become a 100-million-BTC claim
        self.assertEqual(claims.figures("LOSSES EXCEED $100M")["btc"], [])

    def test_absurd_figures_are_rejected(self):
        self.assertEqual(claims.figures("99,000,000 BTC stolen")["btc"], [])

    def test_one_victims_loss_is_not_a_total_claim(self):
        # the pipeline sees these constantly; they must not read as a claim about the total
        self.assertIsNone(claims.biggest_claim("they took my 0.42 BTC"))
        self.assertIsNone(claims.biggest_claim("lost 12 BTC from my coldcard"))

    def test_victims_and_wallets_count_as_address_words(self):
        self.assertEqual(claims.figures("~7300 wallets")["addresses"], [7300])
        self.assertEqual(claims.figures("3,000 victims")["addresses"], [3000])


class NotBehindTest(unittest.TestCase):
    def test_a_claim_matching_our_number_does_not_fire(self):
        v = claims.assess("the tracker shows 1,366.5774 BTC", PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        self.assertFalse(v["behind"], "quoting our own figure must not alert")

    def test_rounding_of_our_own_figure_does_not_fire(self):
        v = claims.assess("about 1,367 BTC drained", PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        self.assertFalse(v["behind"], "a rounded restatement is not a larger claim")

    def test_a_smaller_claim_does_not_fire(self):
        v = claims.assess("only 900 BTC was taken", PUB_BTC, PUB_ADDR)
        self.assertFalse(v["behind"])

    def test_text_with_no_figure_does_not_fire(self):
        v = claims.assess("coldcard users should migrate now", PUB_BTC, PUB_ADDR)
        self.assertFalse(v["behind"])
        self.assertIsNone(v["claim_btc"])

    def test_missing_published_total_never_fires(self):
        # no published number to compare against => report nothing rather than guess
        v = claims.assess(GALAXY_HEADLINE, None, None, public_dir="/nonexistent")
        self.assertFalse(v["behind"])


class PublishedTotalsTest(unittest.TestCase):
    def test_reads_the_live_page_not_a_cache(self):
        btc, addr = claims.published_totals()
        self.assertIsNotNone(btc, "totalBtc must be readable from index.html")
        self.assertIsNotNone(addr, "DRAINED_COUNT must be readable from index.html")
        self.assertGreater(btc, 1000)
        self.assertGreater(addr, 1000)

    def test_a_missing_page_returns_none_rather_than_raising(self):
        self.assertEqual(claims.published_totals("/nonexistent"), (None, None))



class NoAskPhrasingTest(unittest.TestCase):
    """This detector's output is one of the few things allowed to reach Telegram, so it has
    to report rather than ask. The repo's notify-type guard reads call sites, and this
    message is built in claims.describe() where that guard cannot see it — so check it here.
    """
    ASKS = ["review before", "awaiting your go", "to add: run", "investigate it",
            "your call", "approve ", "verify before", "needs a look", "reply approve"]

    def test_describe_reports_and_does_not_ask(self):
        v = claims.assess(GALAXY_HEADLINE, PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        low = claims.describe(v, source="glxyresearch").lower()
        for ask in self.ASKS:
            self.assertNotIn(ask, low, f"the message must not ask ({ask!r})")

    def test_describe_says_the_claim_is_unverified(self):
        # it reports someone else's arithmetic; the message must not imply we proved it
        v = claims.assess(GALAXY_HEADLINE, PUB_BTC, PUB_ADDR, carried_btc=CARRIED)
        self.assertIn("not verified", claims.describe(v, source="glxyresearch"))

if __name__ == "__main__":
    unittest.main()


class CarriedFigureTest(unittest.TestCase):
    """Once the site carries a source's own total, that total is no longer news.

    The detector's whole value is that it fires when the site is understating. Left
    comparing against the verified figure alone, it would report the site as behind the
    very numbers printed on its own toggle, on every run, until the channel was ignorable —
    which is the failure the notification rule exists to prevent."""

    # what the site carries today: Galaxy's attested 1,596 and their suspected 2,055
    CARRIED_NOW = 2055.0

    def test_the_post_that_started_this_no_longer_fires(self):
        v = claims.assess(GALAXY_HEADLINE, PUB_BTC, PUB_ADDR, carried_btc=self.CARRIED_NOW)
        self.assertFalse(v["behind"], "the site is already showing both of these figures")

    def test_the_reply_no_longer_fires_either(self):
        v = claims.assess(GALAXY_REPLY, PUB_BTC, PUB_ADDR, carried_btc=self.CARRIED_NOW)
        self.assertFalse(v["behind"], "2,055 is the figure the toggle publishes")

    def test_a_genuinely_larger_figure_still_fires(self):
        v = claims.assess("now 2,400 BTC across 9,000 addresses", PUB_BTC, PUB_ADDR,
                          carried_btc=self.CARRIED_NOW)
        self.assertTrue(v["behind"], "a total above every standard shown is still news")

    def test_a_figure_just_above_the_carried_one_is_rounding_not_news(self):
        v = claims.assess("about 2,060 BTC", PUB_BTC, PUB_ADDR, carried_btc=self.CARRIED_NOW)
        self.assertFalse(v["behind"])

    def test_a_lower_figure_from_the_source_is_flagged_as_a_possible_revision(self):
        # the site carries this number on their authority, so if they lower it the site
        # overstates, and no amount of reading the chain would ever show that.
        # Measured against the LOWEST tier carried, not the highest: against the ceiling,
        # every figure sitting between the tiers looked like a cut, which is how a
        # confirmed RISE to 1,719 was classified as a revision down on 2026-08-07.
        v = claims.assess("revised down to 1,400 BTC", PUB_BTC, PUB_ADDR,
                          carried_btc=self.CARRIED_NOW)
        self.assertTrue(v["revised_down"])
        self.assertFalse(v["behind"])
        self.assertEqual(v["gap_carried"], round(1400.0 - min(claims.carried_tiers()), 4))

    def test_a_restatement_of_the_carried_figure_is_not_a_revision(self):
        v = claims.assess("still 2,055 BTC", PUB_BTC, PUB_ADDR, carried_btc=self.CARRIED_NOW)
        self.assertFalse(v["revised_down"])
        self.assertFalse(v["behind"])

    def test_the_carried_figure_is_read_from_the_published_file(self):
        # not from a constant that can drift away from what the toggle actually shows
        self.assertAlmostEqual(claims.carried_total(), 2055.0, places=4)

    def test_the_message_says_what_the_site_already_shows(self):
        v = claims.assess("now 2,400 BTC", PUB_BTC, PUB_ADDR, carried_btc=self.CARRIED_NOW)
        s = claims.describe(v, source="glxyresearch")
        self.assertIn("already carries 2,055 BTC", s, s)


# verbatim, via GET /2/tweets — the post that went silent on 2026-08-07
GALAXY_1719 = (
    "$111 MILLION CONFIRMED STOLEN SO FAR IN COLDCARD EXPLOIT\n\n"
    "Thanks to victim reports, we can confirm with high confidence that 1719 BTC has been "
    "stolen from Coldcard victims so far\n\nWe have many more coins we are vetting for "
    "confirmation - we think total losses likely exceed $130m https://t.co/pLfiMQZFyX"
)


class TierStaleTest(unittest.TestCase):
    """A figure landing BETWEEN the tiers the site carries.

    2026-08-07: Galaxy confirmed 1,719 BTC while the site carried attested 1,596 and
    suspected 2,055. Both accounts were watched and both tweets were ingested. Nothing
    fired, because the bar was a single scalar — the MAXIMUM tier — so a claim under the
    ceiling could not read as news, and the same claim then tripped revised_down for being
    below 2,055. A confirmed figure rising by 123 BTC was classified as a possible cut and
    written to a log.
    """

    TIERS = [1596.0, 2055.0]

    def v(self, text):
        return claims.assess(text, PUB_BTC, PUB_ADDR, carried_btc=max(self.TIERS))

    def test_the_missed_post_is_now_caught(self):
        v = self.v(GALAXY_1719)
        self.assertTrue(v["tier_stale"], "this is the post the change exists for")
        self.assertEqual(v["claim_btc"], 1719.0)
        self.assertEqual(v["stale_tier_btc"], 1596.0)
        self.assertEqual(v["gap_tier"], 123.0)

    def test_a_rise_is_never_reported_as_a_cut(self):
        self.assertFalse(self.v(GALAXY_1719)["revised_down"],
                         "1,719 is above the lowest tier; calling it a revision down is "
                         "the bug that hid it")

    def test_it_is_not_reported_as_behind_because_it_is_under_the_ceiling(self):
        self.assertFalse(self.v(GALAXY_1719)["behind"])

    def test_a_figure_above_every_tier_is_still_behind_not_stale(self):
        v = self.v("now 2,400 BTC confirmed")
        self.assertTrue(v["behind"])
        self.assertFalse(v["tier_stale"])

    def test_restating_a_carried_tier_fires_nothing(self):
        for txt in ("still 1,596 BTC", "still 2,055 BTC"):
            v = self.v(txt)
            self.assertFalse(v["tier_stale"], txt)
            self.assertFalse(v["behind"], txt)
            self.assertFalse(v["revised_down"], txt)

    def test_a_figure_below_every_tier_is_still_a_possible_revision_down(self):
        v = self.v("revised to 1,400 BTC")
        self.assertTrue(v["revised_down"])
        self.assertFalse(v["tier_stale"])

    def test_one_tier_alone_cannot_be_stale(self):
        # nothing to sit between; the behind/revised split still applies
        v = claims.assess(GALAXY_1719, PUB_BTC, PUB_ADDR, carried_btc=1596.0)
        self.assertFalse(v["tier_stale"])

    def test_the_message_names_the_stale_figure_and_the_gap(self):
        s = claims.describe(self.v(GALAXY_1719), source="glxyresearch")
        for must in ("STALE", "1,719", "1,596", "123"):
            self.assertIn(must, s, s)
        self.assertNotIn("BEHIND THE PRIMARY SOURCE", s)

    def test_the_tiers_are_read_from_the_published_file(self):
        self.assertEqual(claims.carried_tiers(), [1596.0, 2055.0])

    def test_x_watch_actually_routes_the_stale_case_to_the_channel(self):
        # claims.py being right is not the same as the pipeline acting on it. Mutating the
        # branch out of x_watch left every test above green.
        import inspect
        import x_watch
        src = inspect.getsource(x_watch.detect_site_behind)
        self.assertIn('tier_stale', src)
        self.assertIn("notify_change", src)

    def test_the_quoting_post_alone_carries_no_total_claim(self):
        # @intangiblecoins quoted Galaxy with per-victim statistics. Those are not a claim
        # about the total and must not fire anything; the total lives in the quoted post,
        # which is read because its author is on the watchlist.
        quote = ("as of now:\n\nmedian dormancy 3.5 years\n88% of coins stolen were 1+ year old\n\n"
                 "by address:\nmedian loss 0.014 BTC\nmean loss 0.212 BTC\n\n"
                 "victim reports received: 250+\n\nby victim (as reported):\n"
                 "median loss 1.022 BTC\nmean loss 4.04 BTC\n"
                 "loss range across all reports: 624 sats to 58.97 BTC")
        v = self.v(quote)
        self.assertFalse(v["behind"])
        self.assertFalse(v["tier_stale"])
