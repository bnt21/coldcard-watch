#!/usr/bin/env python3
"""
claims.py — read a figure out of someone's post and compare it to the figure we publish.

Why this exists, 2026-08-03. Galaxy Research is the primary source for this incident; the
methodology page cites them and every mainstream article is single-sourced to them. They
posted "1,596 BTC has been stolen from ~7300 addresses" while the site published
1,366.5774 BTC / 4,580 — 14.4% low — and the pipeline saw nothing, because the detector
watching for this was a regex enumerating phrasings someone had imagined in advance
("new wave", "wave 4", "another wave"). Galaxy wrote "3 confirmed waves + more 14 smaller
incidents", which matches none of them. It had also been gated on the post carrying an
address list, which a headline summary never does.

So this module does not look for words. It extracts every quantity from the text and asks
one structural question: does anyone credible claim a number materially larger than the one
we publish? That is true whatever wording is used, and it is the thing worth knowing,
because it means the site is understating the theft.

Deliberately has no network and no X specifics, so the comparison is unit-tested against
real post text rather than mocked API responses.
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(HERE, "public")

# 21e6 is the only hard ceiling that exists; anything above it is not a bitcoin figure.
MAX_BTC = 21_000_000
# Below this a "BTC" number is one victim's loss or a fee, not a claim about the total.
MIN_TOTAL_BTC = 50
# How far above our published figure a claim must sit before it means anything. Rounding
# ("1,367 BTC") and a genuinely stale-by-minutes number should not fire.
MATERIAL_FRACTION = 0.02

# A quantity, then its unit. Handles 1,596 / 1596.42 / 2k / ~7300, and the unit forms these
# posts actually use. Written to over-collect: a wrong unit guess is filtered by the
# plausibility bounds below, whereas a missed number is invisible.
_NUM = r"(?:~|about\s+|approx\.?\s+|over\s+|nearly\s+)?([0-9][0-9,]*(?:\.[0-9]+)?)\s*([kKmM])?"
BTC_RE = re.compile(_NUM + r"\s*(?:BTC|bitcoins?|₿)\b", re.I)
ADDR_COUNT_RE = re.compile(_NUM + r"\s*(?:addresses|addrs|wallets|victims)\b", re.I)


def _scale(raw, suffix):
    v = float(raw.replace(",", ""))
    if suffix and suffix.lower() == "k":
        v *= 1_000
    elif suffix and suffix.lower() == "m":
        v *= 1_000_000
    return v


def figures(text):
    """Every BTC amount and address/victim count in the text, largest first.

    Returns {"btc": [...], "addresses": [...]}, each sorted largest first. A post normally
    carries several BTC figures (a confirmed total and a suspected one); this reports all of
    them and leaves the choice to assess()."""
    out = {"btc": [], "addresses": []}
    for raw, suf in BTC_RE.findall(text or ""):
        v = _scale(raw, suf)
        if 0 < v <= MAX_BTC:
            out["btc"].append(v)
    for raw, suf in ADDR_COUNT_RE.findall(text or ""):
        v = _scale(raw, suf)
        if 0 < v <= 10_000_000:
            out["addresses"].append(int(v))
    out["btc"].sort(reverse=True)
    out["addresses"].sort(reverse=True)
    return out


def published_totals(public_dir=None):
    """What the live site currently says, read from the page itself rather than from any
    cached state, so a comparison can never be made against a number the site has moved on
    from. Returns (btc, addresses); either may be None if the page shape changed."""
    pub = public_dir or PUBLIC
    btc = addresses = None
    try:
        with open(os.path.join(pub, "index.html"), encoding="utf-8") as fh:
            html = fh.read()
    except OSError:
        return None, None
    m = re.search(r'id="totalBtc"[^>]*>([0-9][0-9,]*\.?[0-9]*)<', html)
    if m:
        btc = float(m.group(1).replace(",", ""))
    m = re.search(r"var\s+DRAINED_COUNT\s*=\s*([0-9]+)", html)
    if m:
        addresses = int(m.group(1))
    return btc, addresses


def carried_total(public_dir=None):
    """The largest figure the site CARRIES, in BTC, across every standard — its own
    verified total plus any attested or suspected tier standing above it. None when the
    site carries nothing beyond its own work.

    This is the number a claim has to beat to be news. Comparing against the verified
    total alone was right while the site published only what it had proven; now that it
    carries Galaxy's 1,596 and 2,055, that comparison would report the site as behind the
    very figures it is already showing, hourly, forever."""
    pub = public_dir or PUBLIC
    p = os.path.join(pub, "potential.js")
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as fh:
            s = fh.read()
        d = json.loads(s[s.index("{"):s.rindex("}") + 1])
    except (OSError, ValueError):
        return None
    tiers = [t.get("total_sats") or 0 for t in d.get("tiers") or []]
    return max(tiers) / 1e8 if tiers else None


def biggest_claim(text):
    """The largest BTC figure in the text that is big enough to be a claim about the total
    rather than one victim's loss. None when the post carries no such figure."""
    vals = [v for v in figures(text)["btc"] if v >= MIN_TOTAL_BTC]
    return max(vals) if vals else None


def assess(text, pub_btc=None, pub_addresses=None, public_dir=None, carried_btc=None):
    """Does this post claim a loss the site is not already showing at some standard?

    Returns a verdict dict. `behind` is the field a caller branches on; `revised_down` is
    its opposite and matters just as much, because the site carries a figure it cannot
    check — if the source lowers it, the site overstates until it follows, and nothing
    on-chain would ever reveal that.

    carried_btc is the largest figure the site already shows. Pass 0 to compare against the
    verified total alone, which is what the comparison meant before any attested figure was
    carried."""
    if pub_btc is None or pub_addresses is None:
        p_btc, p_addr = published_totals(public_dir)
        pub_btc = pub_btc if pub_btc is not None else p_btc
        pub_addresses = pub_addresses if pub_addresses is not None else p_addr
    if carried_btc is None:
        carried_btc = carried_total(public_dir)

    f = figures(text)
    # A report normally carries several totals — Galaxy's carried a confirmed 1,596 and a
    # 2k "including suspected". Which is which is stated in prose ("high confidence",
    # "unconfirmed"), and reading that reliably is the wording-guessing this module exists
    # to avoid. So the trigger uses the LARGEST (it can never under-fire) and the
    # notification lists every figure found, so nobody mistakes a suspected number for a
    # confirmed one.
    all_claims = sorted([v for v in f["btc"] if v >= MIN_TOTAL_BTC], reverse=True)
    claim = all_claims[0] if all_claims else None
    addr_claim = max(f["addresses"]) if f["addresses"] else None

    v = {"claim_btc": claim, "claims_btc": all_claims, "claim_addresses": addr_claim,
         "published_btc": pub_btc, "published_addresses": pub_addresses,
         "carried_btc": carried_btc or 0,
         "gap_btc": None, "gap_addresses": None, "gap_fraction": None,
         "behind": False, "revised_down": False}
    if claim is None or not pub_btc:
        return v
    v["gap_btc"] = round(claim - pub_btc, 4)
    v["gap_fraction"] = (claim - pub_btc) / claim if claim else 0
    if addr_claim is not None and pub_addresses:
        v["gap_addresses"] = addr_claim - pub_addresses
    # the bar is the largest figure the site already shows at any standard, so a post
    # restating a number already on the toggle is not news and does not fire
    bar = max(pub_btc, carried_btc or 0)
    v["behind"] = claim > bar * (1 + MATERIAL_FRACTION)
    # a source lowering the figure the site carries on their authority is the other way
    # this goes wrong, and it is invisible from the chain
    if carried_btc and claim < carried_btc * (1 - MATERIAL_FRACTION):
        v["revised_down"] = True
        v["gap_carried"] = round(claim - carried_btc, 4)
    return v


def describe(v, source=None, url=None):
    """The notification body. States both numbers and the gap, and says what it does not
    know, because the claim is someone else's arithmetic and has not been verified here."""
    who = f"@{source}" if source else "a watched source"
    figs = v.get("claims_btc") or ([v["claim_btc"]] if v.get("claim_btc") else [])
    shown = ", ".join(f"{x:,.0f}" for x in figs[:-1])
    shown = f"{shown} and {figs[-1]:,.0f}" if len(figs) > 1 else f"{figs[0]:,.0f}"
    pub = v["published_btc"]
    carried = v.get("carried_btc") or 0
    lines = [f"SITE IS BEHIND THE PRIMARY SOURCE — {who} reports {shown} BTC; "
             f"the site publishes {pub:,.4f}.", ""]
    if carried:
        # the message has to say what the site already shows, or the gap it quotes reads as
        # larger than it is: the toggle is already carrying an attested figure above the
        # verified one
        lines += [f"  the site already carries {carried:,.0f} BTC on the toggle, so this "
                  f"claim is above every standard it shows", ""]
    # When they state several totals, quoting only the largest gap overstates it: Galaxy's
    # confirmed figure put the site 229 BTC low while their suspected-inclusive figure put it
    # 688 low. Which is which is stated in prose this module does not read, so report the
    # RANGE and let their own post settle it.
    over = [x for x in figs if x > pub]
    if len(over) > 1:
        lines.append(f"  gap: {min(over) - pub:,.0f} to {max(over) - pub:,.0f} BTC, "
                     f"depending on which of their totals is the confirmed one")
    else:
        lines.append(f"  gap: {v['gap_btc']:,.2f} BTC "
                     f"({v['gap_fraction']*100:.1f}% of their figure)")
    if v.get("gap_addresses") is not None:
        lines.append(f"  addresses: they say {v['claim_addresses']:,}, "
                     f"the site lists {v['published_addresses']:,} "
                     f"({v['gap_addresses']:+,})")
    if url:
        lines += ["", f"  {url}"]
    lines += ["", "Their figure is not verified here and nothing was published. The site's "
                  "own number stays as it is until our detectors prove the difference "
                  "on-chain."]
    return "\n".join(lines)


if __name__ == "__main__":
    import json
    import sys
    txt = sys.stdin.read() if not sys.argv[1:] else " ".join(sys.argv[1:])
    print(json.dumps(assess(txt), indent=1))
