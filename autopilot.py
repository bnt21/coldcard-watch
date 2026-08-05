#!/usr/bin/env python3
"""
autopilot.py — keep coldcardwatch.com accurate on its own.

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
# Victims needed for DESTINATION convergence to stand on its own, without the fee test.
# The site already publishes clusters on this basis (waves 1, 2 and 5 are listed on it),
# and the argument is that a hundred strangers cannot share one fresh destination. 20 is
# four times MIN_SWEEPS and well past any plausible single owner consolidating their own
# wallets: the largest legitimate case is somebody sweeping their own UTXOs, which is one
# address, not twenty. Every published cluster clears it by a wide margin.
DEST_CONVERGENCE_MIN = 20

# Tier 1 (co-spend, deterministic) always auto-publishes. Tier 2 (fingerprint +
# credible-source corroboration) rests on a heuristic plus an LLM read of whether a
# watchlist account named the address, and a false positive there is the one thing that
# damages this site, so it ran in notify-mode until it had shown itself correct on real
# cases.
#
# Turned on 2026-08-05 by the site owner. The evidence by then: 27 candidates had
# reached this tier and none was ever shown to be wrong, the criterion is decided by code
# rather than judgement, every add sends a notify_change receipt, and each one is
# reversible per cluster by --rollback from a pre-publish snapshot of every coupled file.
#
# The standing risk this accepts, stated so it is not rediscovered: an add ends in
# publish.deploy(), which ships the WHOLE public/ directory, not just the files the add
# touched. Anything sitting unfinished in public/ on the machine that runs the cron goes
# live with it.
TIER2_AUTOPUBLISH = True

# Every network call here already had a timeout, and the run still wedged for four
# hours. Per-call timeouts bound a call; they do not bound a program that makes an
# unbounded number of calls. _get retries four times at up to 90s, _rawblock makes two
# of those per block, and the fingerprint walk pages through an address's whole
# history, so the worst case multiplied out to most of a day.
#
# So the run carries its own wall clock and stops at it. The cron's `timeout 900` is
# still there as a backstop, but a SIGKILL is a bad way to end: this way the run exits
# on its own terms with its checkpoint written and a line in the log saying why.
RUN_BUDGET = 600
_started = time.time()


def over_budget():
    return (time.time() - _started) > RUN_BUDGET


def budget_note(where):
    print(f"autopilot: stopped early in {where} at the {RUN_BUDGET}s budget "
          f"({time.time() - _started:.0f}s elapsed); progress is checkpointed")


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


def cospend_expand(st, dry=False):
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
        if not dry:                       # --dry-run is documented as never writing
            publish.save_state(st)

    # Bounded per run and checkpointed every few addresses, so a slow or interrupted
    # cycle still makes durable progress and the next run resumes where it left off.
    while frontier and len(known) < MAX_KNOWN and processed < COSPEND_PER_RUN:
        if over_budget():
            budget_note('co-spend expansion')
            break
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
        # A context manager, because json.load(urlopen(...)) never closes the response.
        # Each corroboration check leaked a socket; they accumulated in CLOSE-WAIT until
        # a run sat parked in poll() for four hours holding the shared pipeline lock,
        # which silently stopped x_watch and wave3_refresh with it.
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
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
    newly, collector_stats = cospend_expand(st, dry=dry)
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
    if not dry:
        st["cospend_reported"] = sorted(set(st.get("cospend_reported", [])) | set(newly))

    if not cospend_only:
        # tier 2/3: fingerprint candidates from the block scanner's recent output
        fp_cands, w3_cands = _fingerprint_candidates()
        for w3 in w3_cands:
            _hold_wave3(w3, st, dry)
        for coll, fp in fp_cands:
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

    if not dry:
        publish.save_state(st)
    done = [p for p in published if p and p.get("added")]
    print(f"autopilot: {len(done)} cluster(s) added, "
          f"total now {done[-1]['new_total'] if done else 'unchanged'} "
          f"[{time.time() - _started:.0f}s]")
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
    # A two-hop cluster's money sits one forward down, and the add rejects a collector
    # holding nothing. The fingerprint already located it; pass it through rather than
    # letting the add rediscover a zero balance and refuse.
    hold = (fp or {}).get("hold_addr")
    if dry:
        r = cluster.add_cluster(coll, source, note, dry=True, st=st, hold_addr=hold)
        print(f"  [{tier}] WOULD add {coll}: {r}")
        return r
    tag = f"{coll[:12]}-{int(time.time())}"
    snap = _snapshot(tag)                 # pre-publish state, for --rollback
    try:
        r = cluster.add_cluster(coll, source, note, dry=False, st=st, hold_addr=hold)
        if r.get("added"):
            audit({"action": "add", "tier": tier, "collector": coll, "source": source,
                   "victims": r["added"], "sats": r["balance"],
                   "count_after": r["new_count"], "snapshot": snap})
            print(f"  [{tier}] ADDED {coll}: {r['added']} victims, {r['new_total']} BTC")
        return r
    except Exception as e:
        print(f"  [{tier}] add FAILED for {coll}: {e}", file=sys.stderr)
        publish.note_internal(f"Autopilot tried to add {coll} ({tier}) but failed:\n{e}\n"
                              "Nothing was published; it will retry.", publish.load_env())
        return {"added": 0, "error": str(e)}


def _hold(coll, fp, st, dry):
    key = f"held:{coll}"
    if st.get(key):
        return
    if not dry:
        st[key] = int(time.time())
    publish.note_internal(
        "HELD — a possible cluster matches the fingerprint but is neither co-spend "
        f"proven nor reported by a research account.\n\n{coll}\n  "
        f"{fp['victims']} victims, {fp['balance']/1e8:.8f} BTC, fees {fp['fee_rates']}\n\n"
        "A batched sweep at a normal fee can also be an owner moving to safety, so this "
        "is not auto-published.\n"
        f"To add: run  publish.py --add <a victim address>  or approve on review.\n"
        f"  https://mempool.space/address/{coll}", publish.load_env(), dry)


def _hold_wave3(w3, st, dry):
    """Tier 3, no-collector shape. Many sweeps at ONE hardcoded fee going to many
    DIFFERENT fresh addresses is what wave 3 looked like, and it is invisible to every
    collector-shaped test above. Reported, never published: the same shape is what
    Coinkite's advisory told owners to produce, and without the second hop and the
    firmware-epoch check (which need a node) this is the weakest signal here."""
    key = f"held_w3:{w3['rate']}:{w3['blocks'][0]}"
    if st.get(key):
        return
    if not dry:
        st[key] = int(time.time())
    dests = w3["dests"]
    publish.note_internal(
        "HELD — possible NO-COLLECTOR wave (the wave-3 shape).\n\n"
        f"{len(dests)} separate fresh destinations, all fed at {w3['rate']} sat/vB\n"
        f"blocks {w3['blocks'][0]}-{w3['blocks'][-1]}, {w3['sats']/1e8:.8f} BTC\n\n"
        + "\n".join(f"  {d}" for d in dests[:5])
        + (f"\n  ...and {len(dests)-5} more" if len(dests) > 5 else "")
        + "\n\nNothing shared between them, so no collector test can see this. Confirm "
          "with:  python3 wave3.py --from " + str(w3["blocks"][0])
        + " --to " + str(w3["blocks"][-1]) + "\n"
          "That adds the two-hop P2WSH check and the firmware-epoch floor, which need "
          "a node and are not applied here.", publish.load_env(), dry)


def _propose(coll, fp, src, st, dry):
    """Tier-2 while it is still supervised: a strong, corroborated candidate that WOULD
    auto-publish once TIER2_AUTOPUBLISH is on. One command adds it now."""
    key = f"proposed:{coll}"
    if st.get(key):
        return
    if not dry:
        st[key] = int(time.time())
    publish.note_internal(
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
    publish.note_internal(
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
WAVE3_MIN_DESTS = 5        # distinct fresh destinations at ONE fee rate = a no-collector wave
WAVE3_FEE_MULTIPLE = 20.0  # and the rate must sit far above what that block charged
WAVE3_MIN_RATE = 100.0     # absolute floor, so a quiet block cannot make 6 sat/vB look extreme


# Plain-text Esplora reads go through publish.esplora_text, which carries the same
# primary/fallback order as esplora(). A concurrent session added it to publish.py
# while this file grew its own copy; one helper, in the module that owns the hosts.
def _chain_tip():
    return int(publish.esplora_text("/blocks/tip/height"))


def _block_hash(h):
    """Height to hash, across both Esplora hosts.

    blockstream.info rate-limits this endpoint long before it limits /address: a probe
    from the box got 429 here while /address answered in 0.2s. _rawblock used to
    hardcode that one host, so a single 429 broke the scan loop, the checkpoint never
    advanced, and the forward scan sat 432 blocks behind while every run still reported
    success. mempool.space is slow from here (measured 20s), so it gets a wide timeout
    and is only ever reached as a fallback.
    """
    return publish.esplora_text(f"/block-height/{h}")


def _rawblock(h):
    """Whole block in one call (blockchain.info), with a two-host lookup for the hash."""
    bh = _block_hash(h)
    return json.loads(publish._get(f"https://blockchain.info/rawblock/{bh}", timeout=90))


def scan_recent_for_candidates(max_blocks=12):
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
        tip = _chain_tip()
    except Exception:
        return [], []                  # both detectors, or run() cannot unpack
    start = st["last"] + 1
    end = min(tip, start + max_blocks - 1)
    if start > tip:
        return [], []                  # caught up to the tip: the steady state

    groups = {}    # dest -> {sweeps, sats, rates{}}          collector convergence
    byrate = {}    # rate -> {dests:set, sats, blocks:set}    fee convergence (wave 3)
    reached = start - 1
    for h in range(start, end + 1):
        if over_budget():
            budget_note('the block scan')
            break
        try:
            blk = _rawblock(h)
        except Exception:
            break                          # stop; retry this block next run
        # the block's own median rate, so "far above market" means something here
        rates = []
        for t in blk.get("tx", []):
            w = t.get("weight") or 0
            if w > 0 and t.get("fee") is not None:
                rates.append(t["fee"] / (w / 4.0))
        rates.sort()
        median = rates[len(rates) // 2] if rates else 1.0

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

            # --- wave-3 shape: no shared destination, so convergence is on the fee ---
            # Same signer fingerprint wave3.py uses, minus the firmware-epoch floor,
            # which needs each input's funding height and public block data omits it.
            if rate is None or rate < max(median * WAVE3_FEE_MULTIPLE, WAVE3_MIN_RATE):
                continue
            if t.get("ver") != 2 or t.get("lock_time") != 0:
                continue
            if len({i.get("sequence") for i in ins}) != 1:
                continue
            if not all(s and len(s) == 42 for s in srcs):     # homogeneous P2WPKH
                continue
            b = byrate.setdefault(rate, {"dests": set(), "sats": 0, "blocks": set()})
            b["dests"].add(dst)
            b["sats"] += sum((i.get("prev_out") or {}).get("value", 0) for i in ins)
            b["blocks"].add(h)
        reached = h
        # Checkpoint every block, not once at the end. A 20-block pass can take longer
        # than the cron's 900s timeout, and a run killed mid-pass used to write nothing,
        # so the next run restarted at the same block and was killed at the same place.
        # The scan stood still for days while every cycle looked like a clean no-op.
        # Durable per block means a killed run still leaves progress behind.
        st["last"] = reached
        try:
            with open(SCAN_STATE + ".tmp", "w") as f:
                json.dump(st, f)
            os.replace(SCAN_STATE + ".tmp", SCAN_STATE)
        except Exception:
            pass                       # a failed checkpoint must not abort the scan
        time.sleep(0.3)

    st["last"] = reached
    if reached >= start:
        json.dump(st, open(SCAN_STATE, "w"))
    # Say what was covered. A scan that examined no blocks and a scan that found
    # nothing used to print the same summary and exit zero, which is how this sat 432
    # blocks behind for days while every cycle looked clean. An absence has to be
    # visible or it is indistinguishable from a quiet day.
    if reached < start:
        print(f"autopilot: scanned NO blocks (wanted {start}..{end}, tip {tip}); "
              f"the first fetch failed, so nothing advanced")
    else:
        print(f"autopilot: scanned {start}..{reached} ({reached - start + 1} blocks), "
              f"{tip - reached} behind the tip")

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

    # A wave-3 cluster is many sweeps at ONE fee rate going to many DIFFERENT fresh
    # addresses. That is the opposite shape from a collector, and it is the blind spot
    # that let wave 3 sit unnoticed for two days.
    w3 = []
    for rate, b in byrate.items():
        if len(b["dests"]) >= WAVE3_MIN_DESTS:
            w3.append({"rate": rate, "dests": sorted(b["dests"]),
                       "sats": b["sats"], "blocks": sorted(b["blocks"])})
    w3.sort(key=lambda x: -len(x["dests"]))
    return cands, w3


def _fingerprint_candidates():
    """Scan recent blocks, then confirm each candidate against the full fingerprint."""
    out = []
    collectors, w3 = scan_recent_for_candidates()
    for coll in collectors:
        if over_budget():
            budget_note('fingerprint confirmation')
            break
        try:
            fp = cluster.cluster_fingerprint(coll)
        except Exception:
            continue
        ok, route = accepts(fp)
        if ok:
            fp["converged_by"] = route
            out.append((coll, fp))
        time.sleep(0.2)
    return out, w3


def accepts(fp):
    """Does this fingerprint clear the automatic bar? Returns (bool, route).

    A pure function of the fingerprint so it can be driven directly by tests, which the
    inline version could not be: deleting a clause broke no test.
    """
    span = fp["block_span"]
    tight = bool(span) and (span[1] - span[0]) <= TIGHT_WINDOW
    # MIN_CLUSTER_BTC was declared and never applied, so a 0.00056 BTC address
    # reached the proposed tier. With TIER2_AUTOPUBLISH on, that would have put
    # dust on a public page that calls addresses attacker-controlled. A real
    # cluster of this theft holds real money; the floor is what says so.
    # fp["balance"] and fp["unspent"] now read through a single no-change forward, so
    # a collector that parked its take one hop down is judged where the money is.
    enough = fp["balance"] >= MIN_CLUSTER_BTC * 1e8

    # The methodology page publishes TWO independent convergence tests and says an
    # address is listed when its sweep shows one of them. This gate only ever
    # implemented the fee one, so a cluster that converges on a DESTINATION but pays
    # two hardcoded rates was discarded — which is what happened to the 112-victim
    # cluster a victim's colleague had to report by hand on 2026-08-05: 81% of its
    # sweeps at one below-market constant, under the 90% bar, and spread over 109
    # blocks, over the 30-block window.
    #
    #   fee         one hardcoded rate dominates, inside a tight window
    #   destination many independent addresses swept into ONE fresh address
    #
    # Destination convergence needs a far higher victim count than the fee route,
    # because that count IS the evidence: an owner moving their own coins to safety
    # cannot produce dozens of unrelated addresses converging on one fresh destination.
    by_fee = fp["fee_uniform"] and tight
    by_destination = fp["victims"] >= DEST_CONVERGENCE_MIN
    converges = by_fee or by_destination

    # These hold for both routes and are what keep a service or a peel chain out:
    # every funding transaction a no-change sweep, no unrelated history, and the money
    # still sitting where it landed.
    shape = (fp["no_change_ratio"] >= 0.9 and fp["fresh"] and fp["unspent"]
             and fp["victims"] >= 3 and enough)
    if not (shape and converges):
        return False, None
    return True, ("fee" if by_fee else "destination")


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
    publish.notify_change(
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
