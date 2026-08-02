#!/usr/bin/env python3
"""
verify_candidate.py — can an autopilot candidate be promoted to proof?

Autopilot holds two weaker tiers: a fingerprint match that a credible source also
reported, and a fingerprint match with nothing behind it. Neither may publish on its
own. The only thing that promotes one is common-input ownership: a transaction where
the candidate signs alongside an address already known to be the attacker's.

This asks that question for a specific address and answers it three ways: does it
co-spend with a known address, does it pay one, is it paid by one. All three empty
means the candidate stays exactly where it is.

Run against the two candidates open on 2026-08-02, both came back empty, and the
0.00056 BTC one exposed a real bug: MIN_CLUSTER_BTC was declared and never applied,
so dust could reach the proposed tier. Fixed in autopilot.py, pinned by a test.

usage: verify_candidate.py [addr ...]      defaults to the open candidates
"""
import json, urllib.request, time, re, os
import sys
UA = {"User-Agent": "coldcard-verify/1.0"}
def get(p, tries=3):
    hosts = ["https://blockstream.info/api", "https://mempool.space/api"]
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(hosts[i % 2] + p, headers=UA), timeout=40) as r:
                return json.load(r)
        except Exception:
            if i == tries - 1: raise
            time.sleep(3)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import publish
st = publish.load_state()
KNOWN = set(st.get("cospend_known", [])) | set(st.get("cospend_expanded", []))
idx = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "public", "index.html")).read()
KNOWN |= set(re.findall(r"bc1q[0-9a-z]{38}", idx))
print("known-attacker set size:", len(KNOWN))

DEFAULTS = [("HELD", "bc1qmhr9kr0r3jh3ft0jh2a0hs2eqpcnhrrdyj04xv"),
            ("PROPOSED", "bc1qamgg7r3v5tykq5twhtzpdzrfkplz573wl2k7yn")]
args = [a for a in sys.argv[1:] if a.startswith("bc1")]
targets = [("ARG", a) for a in args] if args else DEFAULTS
for tag, a in targets:
    print("\n==============", tag, a)
    stx = get("/address/" + a)["chain_stats"]
    bal = (stx["funded_txo_sum"] - stx["spent_txo_sum"]) / 1e8
    print("  received %.8f BTC in %d deposits; balance %.8f; spent_txo_count %d"
          % (stx["funded_txo_sum"] / 1e8, stx["funded_txo_count"], bal, stx["spent_txo_count"]))
    txs = get("/address/" + a + "/txs")
    cospend, sentto, recvfrom = [], [], []
    for t in txs:
        vin = [(v.get("prevout") or {}).get("scriptpubkey_address") for v in t.get("vin", [])]
        vin = [x for x in vin if x]
        vout = [o.get("scriptpubkey_address") for o in t.get("vout", [])]
        vout = [x for x in vout if x]
        if a in vin:
            hit = (set(vin) - {a}) & KNOWN
            if hit: cospend.append((t["txid"], sorted(hit)))
            sk = set(vout) & KNOWN
            if sk: sentto.append((t["txid"], sorted(sk)))
        elif a in vout:
            rk = set(vin) & KNOWN
            if rk: recvfrom.append((t["txid"], sorted(rk)))
    print("  co-spend with known: %d %s" % (len(cospend), cospend[:2]))
    print("  sent to known:       %d %s" % (len(sentto), sentto[:2]))
    print("  received from known: %d %s" % (len(recvfrom), recvfrom[:2]))
    time.sleep(1)
