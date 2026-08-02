#!/usr/bin/env python3
"""
wave3-diag.py — why does wave3.py land 40% short of Galaxy's Wave 3?

Takes every transaction in the window that is a single-output spend paying a fee rate
in the Wave 3 band, and tallies which of wave3.py's strict predicates rejected it. The
answer tells us whether the shortfall is a real limit or one filter that is too tight.

usage: wave3-diag.py [--from 960396] [--to 960471] [--lo 150] [--hi 260]
"""
import argparse
import collections
import json
import os
import sys

import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("w3", os.path.join(HERE, "wave3.py"))
w3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w3)

DIAG = os.path.join(HERE, "wave3-diag.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="start", type=int, default=960396)
    ap.add_argument("--to", dest="end", type=int, default=960471)
    ap.add_argument("--lo", type=float, default=150.0)
    ap.add_argument("--hi", type=float, default=260.0)
    a = ap.parse_args()

    why = collections.Counter()
    examples = collections.defaultdict(list)
    passed = []

    for h in range(a.start, a.end + 1):
        try:
            blk = w3.rpc("getblock", [w3.rpc("getblockhash", [h]), 3])
        except Exception as e:
            print(f"  block {h} failed: {e}", file=sys.stderr)
            continue
        for t in blk.get("tx", []):
            vin, vout = t.get("vin", []), t.get("vout", [])
            if not vin or "coinbase" in vin[0]:
                continue
            if len(vout) != 1:
                continue
            w = t.get("weight") or 0
            if w <= 0:
                continue
            prevs = [(v.get("prevout") or {}) for v in vin]
            if any(not p for p in prevs):
                continue
            ins = sum(w3.sats(p.get("value", 0)) for p in prevs)
            outs = w3.sats(vout[0].get("value", 0))
            rate = (ins - outs) / (w / 4.0)
            if not (a.lo <= rate <= a.hi):
                continue            # only the Wave 3 fee band is in question

            fails = []
            if t.get("version") != 2:
                fails.append("version != 2")
            if t.get("locktime") != 0:
                fails.append("locktime != 0")
            if len({v.get("sequence") for v in vin}) != 1:
                fails.append("mixed nSequence")
            types = {w3.spk(p).get("type") for p in prevs}
            if types != {"witness_v0_keyhash"}:
                fails.append("input types " + "+".join(sorted(x or "?" for x in types)))
            addrs = [w3.spk(p).get("address") for p in prevs]
            if not all(addrs):
                fails.append("input without address")
            elif len(set(addrs)) != len(addrs):
                fails.append("REUSED input address")
            hs = [p.get("height") for p in prevs]
            if any(x is None for x in hs):
                fails.append("input height missing")
            elif min(hs) < w3.FIRMWARE_EPOCH:
                fails.append(f"input coin predates firmware ({min(hs)})")

            if not fails:
                passed.append({"h": h, "txid": t.get("txid"), "rate": round(rate, 2),
                               "ins": len(vin), "sats": ins,
                               "dest_type": w3.spk(vout[0]).get("type")})
                continue
            for f in fails:
                why[f] += 1
                if len(examples[f]) < 3:
                    examples[f].append({"h": h, "txid": t.get("txid"),
                                        "rate": round(rate, 2), "ins": len(vin),
                                        "sats": ins})
        if (h - a.start) % 10 == 0:
            print(f"  ...{h}  passing: {len(passed)}  rejected: {sum(why.values())}")

    print(f"\nin the {a.lo}-{a.hi} sat/vB band, single-output spends:")
    print(f"  pass every predicate : {len(passed)}  ({sum(p['sats'] for p in passed)/1e8:.8f} BTC)")
    print(f"  rejected at least once: {sum(why.values())} predicate failures\n")
    for k, v in why.most_common():
        print(f"  {v:5}  {k}")
        for e in examples[k][:2]:
            print(f"           e.g. block {e['h']} {e['ins']} in, {e['sats']/1e8:.8f} BTC, "
                  f"{e['rate']} sat/vB  {e['txid'][:24]}...")

    json.dump({"passed": passed, "why": dict(why), "examples": dict(examples)},
              open(DIAG, "w"), indent=1)
    print(f"\nwritten: {DIAG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
