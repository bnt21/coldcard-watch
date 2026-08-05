#!/usr/bin/env python3
"""
trace.py — follow the attacker's money forward, and stop where following it stops meaning
anything.

Why this exists, 2026-08-05. A forward walk from the thirteen known attacker addresses that
have spent was left to run without a stopping rule. Four hops out it entered transactions
with three hundred inputs and four hundred outputs, and from there the frontier grew faster
than it was consumed: 456 addresses pending at hop 5, 1,034 at hop 6. That walk was no
longer following the thief. It was enumerating an exchange's customer withdrawals, and with
enough hops through a service every address on the chain is reachable from every other, so
the answer it was heading toward would have been true and worthless.

A human analyst does not do that. They follow the money until it reaches a service, write
down that it reached a service, and stop, because the next hop belongs to the service's
customers rather than to the suspect. That is what this does.

WHAT IT DOES NOT DO. It does not name the service. Naming one needs off-chain address
tagging this project does not have, and guessing would be the same error as publishing an
address on a pattern match. It reports the shape and where the shape was hit.

  trace.py --from-known                 walk from every known attacker address that spent
  trace.py --addr <address> [--addr b]  walk from specific addresses
  trace.py --selftest                   no network; the predicate against measured fixtures
"""
import argparse
import json
import os
import sys
import time
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import publish
import potential

# ---------------------------------------------------------------- measured thresholds
#
# CONTROL ARM, measured 2026-08-05 over 495 non-coinbase transactions sampled from five
# blocks spread across ~9,000 blocks (961179, 960884, 959684, 957184, 952184):
#
#     inputs   median 1   p90 3   p99 10   p99.9 149   max 149
#     outputs  median 2   p90 3   p99 18   p99.9 151   max 151
#
# So 50 sits five times above the p99 for inputs and roughly three times above it for
# outputs, and catches 0.2% to 0.4% of ordinary traffic. Without the control arm a number
# like this is an invention; with it, it is a stated distance from what the chain does.
SERVICE_SOURCES = 50       # distinct input ADDRESSES merged in one transaction
SERVICE_DESTS = 50         # distinct output addresses paid in one transaction

# COUNT DISTINCT ADDRESSES, NOT INPUTS. This is the whole correctness of the predicate, and
# an input count gets it exactly backwards on the real data:
#
#     the attacker's own consolidations   491 / 204 / 1,212 inputs   but 1 or 2 addresses
#     a service's deposit sweep             902 inputs               but 795 addresses
#
# A wallet spending many of its own UTXOs is one source. A service aggregating customer
# deposits is hundreds. Thresholding on inputs would have declared the thief's own wallet a
# service and halted the walk on the first hop that mattered.


def _addrs_in(tx):
    return {(i.get("prevout") or {}).get("scriptpubkey_address") for i in tx.get("vin", [])} - {None}


def _addrs_out(tx):
    return {o.get("scriptpubkey_address") for o in tx.get("vout", [])} - {None}


def service_shaped(tx, known=frozenset()):
    """Does this transaction destroy the ability to follow a specific coin through it?

    Two independent ways it can, reported separately because they mean different things:

      merges   many independent addresses funded it, so no output can be tied to any one
               input. This is a service aggregating deposits.
      splits   it pays many distinct destinations, so following every one is the frontier
               explosion rather than a trail. This is a service paying out.

    `known` is the set of addresses already attributed to the attacker. When every input
    address is in it, the sources are NOT independent — it is one party spending its own
    coins — and the merge test does not apply, whatever the input count. The split test
    still does: an attacker fanning into four hundred outputs ends a followable trail just
    as surely, and that is a finding worth reporting rather than a reason to expand.
    """
    srcs, dests = _addrs_in(tx), _addrs_out(tx)
    all_known = bool(srcs) and srcs <= set(known)
    merges = len(srcs) >= SERVICE_SOURCES and not all_known
    splits = len(dests) >= SERVICE_DESTS
    why = []
    if merges:
        why.append(f"{len(srcs)} independent addresses merged in one transaction")
    if splits:
        why.append(f"{len(dests)} distinct destinations paid in one transaction")
    if all_known and len(srcs) >= SERVICE_SOURCES:
        why.append(f"{len(srcs)} input addresses, all already attributed to the attacker, "
                   f"so this is one party spending its own coins")
    kind = None
    if merges and splits:
        kind = "aggregating"
    elif merges:
        kind = "merges"
    elif splits:
        kind = "splits"
    return {"service": bool(merges or splits), "kind": kind,
            "sources": len(srcs), "dests": len(dests),
            "inputs": len(tx.get("vin", [])), "outputs": len(tx.get("vout", [])),
            "all_inputs_known": all_known, "why": why}


def spent_known(known=None, verbose=True):
    """Known attacker addresses that have actually spent. Everything still sitting is
    already tracked on the site; only the ones that moved have anywhere to be followed.

    Prints progress, because this is three hundred sequential calls and a run that says
    nothing for ten minutes is indistinguishable from one that has wedged. The first
    version printed one line and then went quiet, and it read as a hang."""
    known = sorted(known if known is not None else potential.known_attacker_set())
    out, errs = [], 0
    if verbose:
        print(f"  checking {len(known)} known addresses for any spend", flush=True)
    for i, a in enumerate(known, 1):
        try:
            cs = publish.esplora(f"/address/{a}")["chain_stats"]
            if cs.get("spent_txo_count", 0) > 0:
                out.append(a)
        except Exception:
            errs += 1
        if verbose and i % 25 == 0:
            print(f"    {i}/{len(known)} checked, {len(out)} have spent"
                  + (f", {errs} unreadable" if errs else ""), flush=True)
        if i % 60 == 0:
            time.sleep(0.3)
    if verbose:
        print(f"  {len(out)} of {len(known)} have spent"
              + (f" ({errs} unreadable)" if errs else ""), flush=True)
    return out


def trace_forward(seeds, known=None, max_hops=12, max_addr=400, verbose=True):
    """Walk forward from `seeds`, terminating each branch at the first service-shaped
    transaction rather than expanding through it.

    Returns a report. `complete` is the field that matters and the one an earlier version of
    this codebase left out elsewhere: it says whether the walk ran out of places to go or
    ran out of budget. A capped walk that reports the same shape as an exhausted one invites
    a conclusion the data does not support.
    """
    known = set(known if known is not None else potential.known_attacker_set())
    seen = set(seeds)
    q = deque((a, 0) for a in seeds)
    reached, resting, walked, capped_depth = [], [], 0, 0

    while q:
        if walked >= max_addr:
            break
        a, d = q.popleft()
        if d >= max_hops:
            capped_depth += 1
            continue
        try:
            info = publish.esplora(f"/address/{a}")
            txs = publish.esplora(f"/address/{a}/txs")
        except Exception:
            continue
        walked += 1
        cs, ms = info.get("chain_stats", {}), info.get("mempool_stats", {})
        bal = (cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)
               + ms.get("funded_txo_sum", 0) - ms.get("spent_txo_sum", 0))
        moved = False
        for t in txs:
            if a not in _addrs_in(t):
                continue                      # only follow value leaving this address
            moved = True
            v = service_shaped(t, known)
            if v["service"]:
                # the trail ends here on purpose: the next hop belongs to the service's
                # customers, not to whoever sent this
                reached.append({"from": a, "hop": d + 1, "txid": t["txid"],
                                "kind": v["kind"], "sources": v["sources"],
                                "dests": v["dests"], "why": v["why"],
                                "value": sum(i.get("prevout", {}).get("value", 0)
                                             for i in t.get("vin", [])
                                             if (i.get("prevout") or {}).get("scriptpubkey_address") == a)})
                continue
            for o in t.get("vout", []):
                dst = o.get("scriptpubkey_address")
                if not dst or dst in seen:
                    continue
                seen.add(dst)
                q.append((dst, d + 1))
        if not moved and bal > 0:
            resting.append({"addr": a, "sats": bal, "hop": d})
        if verbose and walked % 25 == 0:
            print(f"  ...{walked} walked, frontier {len(q)}, reached-a-service {len(reached)}",
                  flush=True)
            time.sleep(0.3)

    complete = not q and walked < max_addr and capped_depth == 0
    return {"complete": complete, "walked": walked, "touched": len(seen),
            "frontier_left": len(q), "hit_depth_cap": capped_depth,
            "max_hops": max_hops, "max_addr": max_addr,
            "reached_service": reached, "resting": resting}


def describe(r):
    lines = []
    status = ("the walk ran out of places to go" if r["complete"]
              else f"the walk STOPPED ON A BUDGET, not on the data "
                   f"(frontier {r['frontier_left']} left, {r['hit_depth_cap']} branches at the "
                   f"{r['max_hops']}-hop cap, {r['walked']}/{r['max_addr']} addresses walked)")
    lines.append(f"{status}; {r['touched']} addresses touched")
    tot = sum(x["value"] for x in r["reached_service"])
    lines.append(f"branches ending at a service: {len(r['reached_service'])}, "
                 f"{tot/1e8:,.4f} BTC sent in")
    for x in sorted(r["reached_service"], key=lambda x: -x["value"])[:12]:
        lines.append(f"  hop {x['hop']}  {x['value']/1e8:>12,.4f} BTC  {x['from'][:20]}… "
                     f"-> {x['txid'][:16]}…  [{x['kind']}: {x['sources']} sources, "
                     f"{x['dests']} destinations]")
    rest = sum(x["sats"] for x in r["resting"])
    lines.append(f"still resting, never spent: {len(r['resting'])} addresses, {rest/1e8:,.4f} BTC")
    for x in sorted(r["resting"], key=lambda x: -x["sats"])[:12]:
        lines.append(f"  hop {x['hop']}  {x['sats']/1e8:>12,.4f} BTC  {x['addr']}")
    lines.append("")
    lines.append("A branch that reached a service is not a dead end because the money "
                 "vanished. It is a dead end because the next hop belongs to that service's "
                 "customers. Naming the service needs off-chain data this project does not "
                 "have, and is not guessed here.")
    return "\n".join(lines)


# ------------------------------------------------------------------------- selftest
#
# Fixtures are the MEASURED shapes of real transactions, recorded 2026-08-05, so the
# predicate is tested against the chain rather than against its author's expectations. Both
# service cases are from the transaction chain @mariusoffchain reported as a thief mixing
# coins; all three attacker cases are the known cluster's own consolidations.
FIXTURES = [
    # (label, distinct input addrs, total inputs, distinct output addrs, inputs all known, expect service)
    ("service deposit sweep (d72e2d8e)",      795,  902,    1, False, True),
    ("service payout batch (f3ee6e61)",       324,  324,  382, False, True),
    ("attacker consolidation (ba119968)",       1, 1212,    1, True,  False),
    ("attacker consolidation (14edd9ee)",       1,  491,    1, True,  False),
    ("attacker consolidation (4b50d61a)",       2,  204,    1, True,  False),
    # THE CASE THE ATTACKER-OWNED EXCEPTION EXISTS FOR, and the one this incident makes
    # likely: wave 3 left the thief holding 293 separate vaults. If they ever sweep those
    # together, the shape is hundreds of distinct sources merging in one transaction, which
    # is a service by every count-based rule. It is not a service. It is the thief tidying
    # up, every input already attributed, and the walk must continue through it.
    ("attacker sweeping 200 of its own vaults", 200,  200,    1, True,  False),
    ("a Coldcard theft sweep",                  1,    1,    1, True,  False),
    ("an ordinary payment (control median)",    1,    1,    2, False, False),
    # the largest transaction in the 495-transaction control sample. It matches, and that
    # is the right answer rather than a false positive: services appear in ordinary blocks
    # too, and this one has the shape of one. 0.2% of ordinary traffic looks like this.
    ("the largest tx in the control sample",   149,  149,  151, False, True),
]


def _fake(n_src, n_in, n_dst):
    """A transaction with the given shape. Addresses are synthetic; only counts matter."""
    vin = [{"prevout": {"scriptpubkey_address": f"src{i % n_src}"}} for i in range(n_in)]
    vout = [{"scriptpubkey_address": f"dst{i}"} for i in range(n_dst)]
    return {"vin": vin, "vout": vout}


def selftest():
    bad = 0
    for label, n_src, n_in, n_dst, all_known, expect in FIXTURES:
        tx = _fake(n_src, n_in, n_dst)
        known = {f"src{i}" for i in range(n_src)} if all_known else set()
        v = service_shaped(tx, known)
        ok = v["service"] == expect
        bad += 0 if ok else 1
        print(f"  {'ok  ' if ok else 'FAIL'}  {label:<38} "
              f"{n_in:>5} in / {n_src:>4} sources / {n_dst:>4} dests -> "
              f"service={v['service']} ({v['kind']})")
    # the discriminator itself: the same input count decides differently on source count
    a = service_shaped(_fake(1, 1212, 1), {"src0"})
    b = service_shaped(_fake(795, 902, 1), set())
    if a["service"] or not b["service"]:
        print("  FAIL  distinct sources must decide, not input count"); bad += 1
    else:
        print("  ok    1,212 inputs from one address is not a service; "
              "902 from 795 addresses is")
    # a service the attacker happens to own inputs in must still stop a SPLIT
    c = service_shaped(_fake(1, 1, 400), {"src0"})
    if not c["service"] or c["kind"] != "splits":
        print("  FAIL  a 400-way split must end the trail even when the sender is known"); bad += 1
    else:
        print("  ok    a 400-way split ends the trail even when the sender is known")
    print("\nservice-shape predicate holds" if not bad else f"\n{bad} failure(s)")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-known", action="store_true",
                    help="walk from every known attacker address that has spent")
    ap.add_argument("--addr", action="append", default=[])
    ap.add_argument("--max-hops", type=int, default=12)
    ap.add_argument("--max-addr", type=int, default=400)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    seeds = list(a.addr)
    if a.from_known:
        print("finding known attacker addresses that have spent...", flush=True)
        seeds += spent_known()
        print(f"  {len(seeds)} of them", flush=True)
    if not seeds:
        ap.print_help()
        return 2
    r = trace_forward(seeds, max_hops=a.max_hops, max_addr=a.max_addr)
    print(json.dumps(r, indent=1) if a.json else "\n" + describe(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
