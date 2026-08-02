#!/usr/bin/env python3
"""
wave3-publish-set.py — freeze exactly what Wave 3 puts on the site.

wave3.py finds candidates. This picks the subset that clears the publish bar and
writes it once, so the site edit reads a fixed file rather than re-deciding anything.

The bar, and why it is narrower than what the detector found:
  - the chain must be complete (sweep -> fresh park -> fresh P2WSH vault, vault unspent)
  - the sweep fee rate must sit in 195-210 sat/vB

That second clause drops 16 vaults holding 2.92 BTC whose rates scatter (108, 120, 138,
320, 4746, 5630). Scatter is what people and unrelated activity look like. 215 sweeps
landing on one constant while the network charged under 3 sat/vB is a machine, and it is
the evidence that replaces the per-address list Galaxy never published. Losing 1.4% of
the value is worth not naming somebody's own post-advisory rescue as a thief's vault.

Per-victim amounts come from the node (getrawtransaction verbosity 2), because the
detector's report keeps only the sweep total.

writes: wave3-set.json
usage: wave3-publish-set.py [--lo 195] [--hi 210]
"""
import argparse
import importlib.util
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
spec = importlib.util.spec_from_file_location("w3", os.path.join(HERE, "wave3.py"))
w3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w3)

REPORT = os.path.join(DATA, "wave3-report.json")
OUT = os.path.join(DATA, "wave3-set.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lo", type=float, default=195.0)
    ap.add_argument("--hi", type=float, default=210.0)
    a = ap.parse_args()

    rep = json.load(open(REPORT))
    ok = [s for s in rep["sweeps"] if (s.get("hop2") or {}).get("ok")]
    inb = [s for s in ok if a.lo <= s["rate"] <= a.hi]
    dropped = [s for s in ok if not (a.lo <= s["rate"] <= a.hi)]
    print(f"completed chains {len(ok)}; in {a.lo}-{a.hi} sat/vB: {len(inb)}; "
          f"dropped {len(dropped)}")

    victims, seen_tx = {}, set()
    for i, s in enumerate(inb):
        if s["txid"] in seen_tx:
            continue
        seen_tx.add(s["txid"])
        t = w3.rpc("getrawtransaction", [s["txid"], 2])
        for v in t.get("vin", []):
            p = v.get("prevout") or {}
            addr = (p.get("scriptPubKey") or {}).get("address")
            if not addr:
                continue
            val = w3.sats(p.get("value", 0))
            e = victims.setdefault(addr, {"sats": 0, "height": s["height"],
                                          "time": s["time"], "txid": s["txid"]})
            e["sats"] += val
        if (i + 1) % 50 == 0:
            print(f"  ...{i+1}/{len(inb)} sweeps read")

    vaults = {}
    for s in inb:
        h = s["hop2"]
        vaults.setdefault(h["vault"], {
            "addr": h["vault"], "balance": h.get("vault_balance") or 0,
            "txid": h.get("vault_txid"), "height": h.get("vault_height"),
            "park": s["dest"], "unspent": bool(h.get("vault_unspent")),
        })

    blocks = {}
    for s in inb:
        blocks[s["height"]] = s["time"]

    held = sum(v["balance"] for v in vaults.values())
    vin = sum(v["sats"] for v in victims.values())
    still_unspent = all(v["unspent"] for v in vaults.values())

    print(f"\nvictims {len(victims)}  ({vin/1e8:.8f} BTC of inputs)")
    print(f"vaults  {len(vaults)}  holding {held/1e8:.8f} BTC  "
          f"(all unspent: {still_unspent})")
    print(f"blocks  {len(blocks)}")

    json.dump({
        "generated": int(time.time()),
        "band": [a.lo, a.hi],
        "window": rep["sweeps"][0]["height"] if rep["sweeps"] else None,
        "victims": victims, "vaults": vaults, "blocks": blocks,
        "held_sats": held, "victim_input_sats": vin,
        "dropped_vaults": len({s["hop2"]["vault"] for s in dropped}),
        "dropped_sats": sum({s["hop2"]["vault"]: (s["hop2"].get("vault_balance") or 0)
                             for s in dropped}.values()),
    }, open(OUT, "w"), indent=1)
    print(f"\nwritten: {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
