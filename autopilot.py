#!/usr/bin/env python3
"""
autopilot.py — keep coldcard-watch.vercel.app accurate on its own.

Finds new attacker clusters and adds them to the site with no human in the loop,
but only where the proof is strong enough that a human would add nothing. The whole
worth of this site is that every address on it is true, so the autonomy is tiered by
how the cluster is proven, and the weakest tier is never published automatically.

  Tier 1  co-spend proven   Two addresses that sign the same transaction share an
                            owner. Walking outward from the known attacker addresses
                            through shared inputs finds more of their addresses with
                            certainty. Deterministic. AUTO-PUBLISHED.
  Tier 2  fingerprint + a credible source names it.  A collector that matches the
                            drain fingerprint (uniform hardcoded fee, no-change,
                            fresh vault) AND is independently reported by a research
                            account on the watchlist. This is the bar waves 1-3 and 5
                            were added on. AUTO-PUBLISHED.
  Tier 3  fingerprint only, unproven, unreported.  Batched sweeps at a normal fee are
                            shape-identical to an owner moving to safety. HELD for a
                            person; a Telegram message, never a site edit.

The publish DECISION is code, not a model. claude -p is used only to read a tweet and
decide whether a source attributes a specific address — evidence gathering, never the
final say. Every auto-publish appends to an audit log and sends a Telegram receipt, and
--rollback undoes the last one.

usage:
  autopilot.py                 one cycle (cron)
  autopilot.py --dry-run       find + classify, never write
  autopilot.py --cospend-only  tier 1 only
  autopilot.py --rollback ID   undo an audit-log entry
  autopilot.py --log           print the audit log
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

import publish
import cluster

AUDIT = os.path.expanduser("~/.coldcard-autopilot-log.jsonl")
LOCK = os.path.expanduser("~/.coldcard-autopilot.lock")

# research accounts whose attribution counts as corroboration (tier 2)
WATCHLIST = ["glxyresearch", "AnchorWatch", "kelbieb", "blockxyz", "arkham",
             "mononautical", "lopp"]

MAX_KNOWN = 250          # runaway guard on co-spend expansion
COSPEND_PER_RUN = 40     # addresses expanded per cycle; checkpointed, resumes next run
MIN_CLUSTER_BTC = 0.02   # ignore dust collectors
TIGHT_WINDOW = 30        # a real cluster's sweeps land within this many blocks

# Tier 1 (co-spend, deterministic) always auto-publishes. Tier 2 (fingerprint +
# credible-source corroboration) is strong but rests on a heuristic + an LLM read, and
# a false positive there is the one thing that damages this site, so it starts in
# notify-mode: it Telegrams the candidate with a one-command add. Flip to True once it
# has shown itself correct on real cases; it is a one-line change.
TIER2_AUTOPUBLISH = False


# ------------------------------------------------------------- audit + lock

def audit(entry):
    entry["ts"] = int(time.time())
    with open(AUDIT, "a") as f:
        f.write(json.dumps(entry) + "\n")


def read_audit():
    if not os.path.exists(AUDIT):
        return []
    return [json.loads(l) for l in open(AUDIT) if l.strip()]


# ------------------------------------------------------------- tier 1: co-spend

def is_service_shaped(cstats):
    """A wallet whose history dwarfs this incident is a service, not an attacker
    address; never expand through it (its co-inputs are other people's money)."""
    return cstats.get("funded_txo_count", 0) > 400 or cstats.get("tx_count", 0) > 400


def cospend_expand(st):
    """Grow the known-attacker set by common-input ownership. Co-spend only reveals
    addresses that have SPENT (they were inputs), so it is a DISCOVERY tool, not a
    publisher: it feeds the anchor set (which strengthens the fingerprint tier and the
    X pipeline) and flags collector-shaped finds for a human. Checkpointed via `st` so
    steady-state cycles do almost nothing. Returns (newly_found, collector_candidates)."""
    known = set(publish.ANCHORS) | set(st.get("cospend_known", []))
    expanded = set(st.get("cospend_expanded", []))
    frontier = [a for a in known if a not in expanded]
    collector_stats = {}          # addr -> cheap chain_stats (looks like a collector)
    processed = 0

    def checkpoint():
        st["cospend_known"] = sorted(known)
        st["cospend_expanded"] = sorted(expanded)
        publish.save_state(st)

    # Bounded per run and checkpointed every few addresses, so a slow or interrupted
    # cycle still makes durable progress and the next run resumes where it left off.
    while frontier and len(known) < MAX_KNOWN and processed < COSPEND_PER_RUN:
        a = frontier.pop()
        expanded.add(a)
        processed += 1
        try:
            c = publish.esplora(f"/address/{a}")["chain_stats"]
        except Exception:
            expanded.discard(a)             # let it retry next run
            continue
        if not is_service_shaped(c):
            if 3 <= c["funded_txo_count"] <= 400 and c["funded_txo_sum"] > 0:
                collector_stats[a] = c      # cheap collector test from stats in hand
            if c["spent_txo_sum"] > 0:
                try:
                    txs = publish.esplora(f"/address/{a}/txs")
                except Exception:
                    txs = []
                for t in txs:
                    ins = [(i.get("prevout") or {}).get("scriptpubkey_address")
                           for i in t.get("vin", [])]
                    if a not in ins:
                        continue
                    for other in ins:
                        if other and other not in known:
                            known.add(other)
                            frontier.append(other)
        if processed % 15 == 0:
            checkpoint()
        time.sleep(0.3)

    checkpoint()
    newly = known - set(publish.ANCHORS)
    return newly, {a: c for a, c in collector_stats.items()
                   if a not in publish.ANCHORS}


# ------------------------------------------------------------- tier 2: corroboration

def corroborated(coll):
    """Has a watchlist research account reported this collector? Returns (bool, source).
    The X search is deterministic; claude -p only judges attribution from the text."""
    env = publish.load_env()
    if not env.get("X_BEARER_TOKEN"):
        return False, None
    frm = " OR ".join(f"from:{u}" for u in WATCHLIST)
    # a short prefix is enough to match a truncated address in a chart caption
    query = f"({frm}) (coldcard OR coinkite OR {coll[:12]})"
    import urllib.parse
    import urllib.request
    url = ("https://api.x.com/2/tweets/search/recent?max_results=25&"
           "tweet.fields=text,author_id,created_at&expansions=author_id&"
           "user.fields=username&query=" + urllib.parse.quote(query, safe=':"()'))
    try:
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + env["X_BEARER_TOKEN"]})
        d = json.load(urllib.request.urlopen(req, timeout=30))
    except Exception:
        return False, None
    users = {u["id"]: u["username"] for u in d.get("includes", {}).get("users", [])}
    hits = d.get("data", [])
    if not hits:
        return False, None
    # direct: the full or a distinctive prefix of the collector appears in a hit
    for t in hits:
        if coll[:16] in t.get("text", ""):
            return True, users.get(t.get("author_id"), "watchlist")
    # otherwise let the model judge whether these posts attribute the drain, and to
    # whom — evidence only; it cannot authorize a publish, it only gates tier 2.
    verdict = _llm_attributes(coll, hits, users)
    return verdict, (users.get(hits[0].get("author_id"), "watchlist") if verdict else None)


def _llm_attributes(coll, hits, users):
    items = [{"user": users.get(t.get("author_id"), "?"), "text": t.get("text", "")[:500]}
             for t in hits]
    prompt = (
        "These tweets are from Bitcoin research accounts about the July 2026 Coldcard "
        f"wallet drain. A collector address {coll} matches the drain fingerprint on-chain. "
        "Do any of these posts attribute this drain incident to a thief (as opposed to "
        "discussing something unrelated)? Answer strictly with JSON: "
        '{"attributes_drain": true|false}. Only true if a post clearly frames the '
        "Coldcard sweeps as theft by the same operator.\n\n" + json.dumps(items))
    try:
        r = subprocess.run(["claude", "-p", "--model", "claude-sonnet-5"],
                           input=prompt, capture_output=True, text=True, timeout=120)
        m = re.search(r'\{.*\}', r.stdout, re.S)
        return bool(json.loads(m.group(0)).get("attributes_drain")) if m else False
    except Exception:
        return False


# ------------------------------------------------------------- orchestrator

def run(dry=False, cospend_only=False):
    st = publish.load_state()
    published = []

    # tier 1 — co-spend DISCOVERY: grow the known-attacker set, flag collectors for review.
    # Co-spend only surfaces addresses that already spent, so nothing here auto-publishes;
    # it makes the fingerprint tier and the X pipeline smarter, and surfaces victims.
    newly, collector_stats = cospend_expand(st)
    fresh_anchors = [a for a in newly if a not in st.get("cospend_reported", [])]
    if fresh_anchors and not dry:
        publish.record_anchors(newly)
    for coll in collector_stats:
        rk = f"cospend_flagged:{coll}"
        if st.get(rk):
            continue
        if not dry:
            st[rk] = int(time.time())
        _flag_cospend_collector(coll, collector_stats[coll], dry)
    st["cospend_reported"] = sorted(set(st.get("cospend_reported", [])) | set(newly))

    if not cospend_only:
        # tier 2/3: fingerprint candidates from the block scanner's recent output
        for coll, fp in _fingerprint_candidates():
            if _already(coll):
                continue
            ok, src = corroborated(coll)
            if ok and TIER2_AUTOPUBLISH:
                note = (f"Matches the drain fingerprint and independently reported by "
                        f"{src}. Verified on-chain.")
                published.append(_publish(coll, f"corroborated:{src}", note,
                                          "tier2-corroborated", fp, st, dry))
            elif ok:
                _propose(coll, fp, src, st, dry)      # strong candidate, awaiting flip
            else:
                _hold(coll, fp, st, dry)

    publish.save_state(st)
    done = [p for p in published if p and p.get("added")]
    print(f"autopilot: {len(done)} cluster(s) added, "
          f"total now {done[-1]['new_total'] if done else 'unchanged'}")
    return 0


def _already(coll):
    drains, _, _ = publish.parse_site()
    have = {r[0] for r in drains["rows"]}
    # a collector is "already on the site" if it is a tracked wallet
    idx = cluster._read(os.path.join(publish.PUBLIC, "index.html"))
    return coll in idx


ROLLBACK_DIR = os.path.expanduser("~/.coldcard-rollback")
_COUPLED = ["drains.js", "drained.js", "data.js", "index.html", "list.html",
            "methodology.html"]


def _snapshot(tag):
    """Copy every coupled file to a timestamped dir so an auto-publish is reversible."""
    import shutil
    d = os.path.join(ROLLBACK_DIR, tag)
    os.makedirs(d, exist_ok=True)
    for f in _COUPLED:
        src = os.path.join(publish.PUBLIC, f)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(d, f))
    for m in publish.MONITORS:
        if os.path.exists(m):
            shutil.copy2(m, os.path.join(d, os.path.basename(m)))
    return d


def _publish(coll, source, note, tier, fp, st, dry):
    if dry:
        r = cluster.add_cluster(coll, source, note, dry=True, st=st)
        print(f"  [{tier}] WOULD add {coll}: {r}")
        return r
    tag = f"{coll[:12]}-{int(time.time())}"
    snap = _snapshot(tag)                 # pre-publish state, for --rollback
    try:
        r = cluster.add_cluster(coll, source, note, dry=False, st=st)
        if r.get("added"):
            audit({"action": "add", "tier": tier, "collector": coll, "source": source,
                   "victims": r["added"], "sats": r["balance"],
                   "count_after": r["new_count"], "snapshot": snap})
            print(f"  [{tier}] ADDED {coll}: {r['added']} victims, {r['new_total']} BTC")
        return r
    except Exception as e:
        print(f"  [{tier}] add FAILED for {coll}: {e}", file=sys.stderr)
        publish.send_telegram(f"Autopilot tried to add {coll} ({tier}) but failed:\n{e}\n"
                              "Nothing was published; it will retry.", publish.load_env())
        return {"added": 0, "error": str(e)}


def _hold(coll, fp, st, dry):
    key = f"held:{coll}"
    if st.get(key):
        return
    if not dry:
        st[key] = int(time.time())
    publish.send_telegram(
        "HELD — a possible cluster matches the fingerprint but is neither co-spend "
        f"proven nor reported by a research account.\n\n{coll}\n  "
        f"{fp['victims']} victims, {fp['balance']/1e8:.8f} BTC, fees {fp['fee_rates']}\n\n"
        "A batched sweep at a normal fee can also be an owner moving to safety, so this "
        "is not auto-published.\n"
        f"To add: run  publish.py --add <a victim address>  or approve on review.\n"
        f"  https://mempool.space/address/{coll}", publish.load_env(), dry)


def _propose(coll, fp, src, st, dry):
    """Tier-2 while it is still supervised: a strong, corroborated candidate that WOULD
    auto-publish once TIER2_AUTOPUBLISH is on. One command adds it now."""
    key = f"proposed:{coll}"
    if st.get(key):
        return
    if not dry:
        st[key] = int(time.time())
    publish.send_telegram(
        f"READY TO ADD (tier 2, awaiting your go) — matches the drain fingerprint and "
        f"{src} reports the incident.\n\n{coll}\n  {fp['victims']} victims, "
        f"{fp['balance']/1e8:.8f} BTC held unspent, fees {fp['fee_rates']}, blocks "
        f"{fp['block_span']}\n\nThis is exactly what autopilot will add on its own once "
        f"tier 2 is switched to auto. To add it now:\n"
        f"  cd ~/CLAUDE/personal/coldcard-watch && python3 -c \"import autopilot,cluster,"
        f"publish; print(cluster.add_cluster('{coll}','manual','Fingerprint + {src}, "
        f"verified on-chain.'))\"\n" + publish.SITE, publish.load_env(), dry)


def _flag_cospend_collector(coll, cstats, dry):
    """Co-spend proved this address is the attacker's and it collected sweeps. Its funds
    have already moved (co-spend only finds spent addresses), so tracking a vault is a
    judgement call — flag it, don't auto-publish. Its victims are provably drained."""
    bal = cstats["funded_txo_sum"] - cstats["spent_txo_sum"]
    publish.send_telegram(
        "CO-SPEND found an attacker collector (provably co-owned with a known attacker "
        f"address).\n\n{coll}\n  {cstats['funded_txo_count']} deposits, "
        f"{cstats['funded_txo_sum']/1e8:.8f} BTC in, now holds {bal/1e8:.8f} BTC.\n\n"
        "Its funds have peeled onward, so where they sit now needs a look before the "
        "site tracks a vault. The addresses that fed it are provably drained and can be "
        f"added.\n  https://mempool.space/address/{coll}", publish.load_env(), dry)


HERE = os.path.dirname(os.path.abspath(__file__))
SCAN_STATE = os.path.expanduser("~/.coldcard-autopilot-scan.json")
UA = {"User-Agent": "coldcard-autopilot/1.0"}
FIRST_DRAIN_BLOCK = 960183
MIN_SWEEPS = 5             # a collector needs this many sweeps in the window to flag


def _rawblock(h):
    """Whole block in one call (blockchain.info), esplora fallback for the hash."""
    import urllib.request
    bh = publish._get(f"https://blockstream.info/api/block-height/{h}",
                      timeout=30).decode().strip()
    return json.loads(publish._get(f"https://blockchain.info/rawblock/{bh}", timeout=90))


def scan_recent_for_candidates(max_blocks=20):
    """Scan blocks since the last autopilot scan for fingerprint collectors: a
    destination receiving several no-change sweeps (single OR batched) at one hardcoded
    fee. Returns candidate collector addresses. Self-contained so it does not couple to
    the other scanners. Bounded per run; state persists the last height."""
    st = {"last": FIRST_DRAIN_BLOCK - 1}
    if os.path.exists(SCAN_STATE):
        try:
            st = json.load(open(SCAN_STATE))
        except Exception:
            pass
    try:
        tip = int(publish._get("https://blockstream.info/api/blocks/tip/height",
                               timeout=30).decode().strip())
    except Exception:
        return []
    start = st["last"] + 1
    end = min(tip, start + max_blocks - 1)
    if start > tip:
        return []

    groups = {}    # dest -> {sweeps, sats, rates{}}
    reached = start - 1
    for h in range(start, end + 1):
        try:
            blk = _rawblock(h)
        except Exception:
            break                          # stop; retry this block next run
        for t in blk.get("tx", []):
            outs = t.get("out", [])
            ins = t.get("inputs", [])
            if len(outs) != 1:             # no-change only
                continue
            dst = outs[0].get("addr")
            srcs = [(i.get("prev_out") or {}).get("addr") for i in ins]
            if not dst or not all(s and s.startswith("bc1q") for s in srcs) or not srcs:
                continue
            w = t.get("weight") or 0
            rate = round((t.get("fee") or 0) / (w / 4.0), 1) if w else None
            g = groups.setdefault(dst, {"sweeps": 0, "sats": 0, "rates": {}})
            g["sweeps"] += 1
            g["sats"] += sum((i.get("prev_out") or {}).get("value", 0) for i in ins)
            if rate is not None:
                g["rates"][rate] = g["rates"].get(rate, 0) + 1
        reached = h
        time.sleep(0.3)

    st["last"] = reached
    if reached >= start:
        json.dump(st, open(SCAN_STATE, "w"))

    cands = []
    for dst, g in groups.items():
        if dst in publish.ANCHORS or g["sweeps"] < MIN_SWEEPS or not g["rates"]:
            continue
        # dominance with adjacent rates merged (a tool stamping 10.0/10.1 is one fee)
        top = sorted(g["rates"].items(), key=lambda kv: -kv[1])
        dom = top[0][1]
        if len(top) > 1 and abs(top[0][0] - top[1][0]) <= 0.2:
            dom += top[1][1]
        if dom / g["sweeps"] >= 0.85:
            cands.append(dst)
    return cands


def _fingerprint_candidates():
    """Scan recent blocks, then confirm each candidate against the full fingerprint."""
    out = []
    for coll in scan_recent_for_candidates():
        try:
            fp = cluster.cluster_fingerprint(coll)
        except Exception:
            continue
        span = fp["block_span"]
        tight = span and (span[1] - span[0]) <= TIGHT_WINDOW
        if (fp["fee_uniform"] and fp["no_change_ratio"] >= 0.9 and fp["fresh"]
                and fp["unspent"] and fp["victims"] >= 3 and tight):
            out.append((coll, fp))
        time.sleep(0.2)
    return out


def rollback(entry_id):
    """Undo an auto-publish by restoring the pre-publish snapshot and redeploying.
    Deterministic: the snapshot IS the exact prior state of every coupled file."""
    import shutil
    entries = [e for e in read_audit() if e.get("action") == "add"
               and (str(e.get("ts")) == entry_id or e.get("collector") == entry_id
                    or (e.get("snapshot") or "").endswith(entry_id))]
    if not entries:
        print(f"no auto-publish audit entry matches '{entry_id}'")
        return 1
    e = entries[-1]
    snap = e.get("snapshot")
    if not snap or not os.path.isdir(snap):
        print(f"snapshot missing for {e['collector']} ({snap}); cannot auto-rollback")
        return 1
    for f in os.listdir(snap):
        dst = (os.path.join(publish.PUBLIC, f) if f in _COUPLED
               else next((m for m in publish.MONITORS
                          if os.path.basename(m) == f), None))
        if dst:
            shutil.copy2(os.path.join(snap, f), dst)
    probs = publish.self_check(verbose=True)
    if probs:
        print(f"restored files fail self-check: {probs}")
        return 1
    url = publish.deploy()
    drains, _, n = publish.parse_site()
    if not publish.verify_deployed(n):
        print(f"redeployed ({url}) but live count != {n}")
        return 1
    audit({"action": "rollback", "collector": e["collector"], "restored_to_count": n})
    publish.send_telegram(
        f"ROLLED BACK the auto-publish of {e['collector']} ({e.get('victims')} victims). "
        f"Site restored to {n:,} addresses.\n" + publish.SITE, publish.load_env())
    print(f"rolled back {e['collector']}: site restored to {n:,} addresses")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--cospend-only", action="store_true")
    ap.add_argument("--rollback", metavar="ID")
    ap.add_argument("--log", action="store_true")
    a = ap.parse_args()
    if a.log:
        for e in read_audit():
            print(json.dumps(e))
        return 0
    if a.rollback:
        return rollback(a.rollback)
    return run(dry=a.dry_run, cospend_only=a.cospend_only)


if __name__ == "__main__":
    sys.exit(main())
