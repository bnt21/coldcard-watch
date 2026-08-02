#!/usr/bin/env python3
"""
co-spend.py — deterministic linking pass over the batched-sweep candidates.

The batched detector produces shape matches. Shape cannot separate a thief from an
owner rescuing after Coinkite's advisory. Common-input-ownership can: if a candidate
destination ever spends in the same transaction as a known attacker address, one
signer controls both. That is the only test in here treated as proof.

Weaker signals are recorded but labeled as such:
  - a candidate destination spending INTO a known attacker address (sent-to-known)
  - a candidate destination funded by a known attacker address (received-from-known)
  - two candidate destinations co-spending with each other (candidate cluster —
    one entity ran multiple batched sweeps, but that entity could still be a
    rescue service, not the thief)
  - second-hop convergence: several candidate destinations spending to the same
    place (custodial deposit addresses will do this innocently)

Reads scan-batched-report.json. Writes co-spend-state.json (checkpoint, one entry
per address, resumable) and co-spend-report.json. Nothing publishes.
"""
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_IN = os.path.join(HERE, "scan-batched-report.json")
STATE = os.path.join(HERE, "co-spend-state.json")
REPORT = os.path.join(HERE, "co-spend-report.json")
UA = {"User-Agent": "coldcard-co-spend/1.0"}

# Confirmed attacker addresses only. No candidates, no inferences.
KNOWN = {
    # tracked vaults / collectors (site + scan.py verified clusters)
    "bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0", "bc1qc779m8gec84k3t0ffvu0pps94zheht7lr7ueyn",
    "bc1qh0l7q0mca3ln7wsl9luwns0jc9jhgrtft025l4", "bc1qdaarag7729c2n4l2wnyt3hkhfpcs66n98z7uuh",
    "bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9r", "bc1qx76cae2706qd5q576feh7xq8rfcsjpf2htfhe3",
    "bc1q8jy96fe5lf8vfugydnte3cguk92gpev7kwtp3q", "bc1qsjrf5ze5tmulz7y2x4pc7qaex2a35sanp3rqlx",
    "bc1qtfrwa4j6rmj9rsgspv6a0yjumkg39js2numu75", "bc1qjd6tcd5ey96fdujpkr7zgn2zjzp29h208xlvxg",
    "bc1qhh4jkkj07vxpdt0zlvxctjlfhqmurhxa24x3h2", "bc1qelcnp9m9qh5r2su986d8kdkmdc9grlsujc8uuv",
    # sixth cluster, proven by co-spend in tx bc9255a5... (2026-08-01)
    "bc1qzrl67rtyaqdvtl78rlklxmraqjk7d9f6cf23jm", "bc1q0mh6rs0mjvv5ncdyqwhqma7hgup3aycucsc279",
    "bc1qgt5s8rsjyvennup3dz3rk92pczlzqtvy8f5t09", "bc1qn79gwljlqwwrgpqqdulvmlnssazm9gasjg090r",
    # confirmed batched theft (@OasisHodl, block 960469, tx 89e5574c...)
    "bc1qndu56ewzgf3yjlzumljgt8cpngnqrwv753l973",
    "bc1qxueed4eqvhu77qjfg32nxu5w0gejsrsljyq399k89ck82x4wlxrsy4m72x",
}


HOSTS = ["https://blockstream.info/api", "https://mempool.space/api"]


def get(path, tries=4):
    for i in range(tries):
        host = HOSTS[i % len(HOSTS)]
        try:
            with urllib.request.urlopen(urllib.request.Request(host + path, headers=UA), timeout=45) as r:
                return json.load(r)
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(5 * (i + 1))


def addr_txs(a):
    """All confirmed transactions touching address a, paginated."""
    txs, last = [], None
    while True:
        path = f"/address/{a}/txs/chain"
        if last:
            path += f"/{last}"
        page = get(path)
        txs.extend(page)
        if len(page) < 25 or len(txs) >= 200:
            break
        last = page[-1]["txid"]
        time.sleep(1.0)
    return txs


def analyze(dest, sweep_txids):
    """One candidate destination -> classified history."""
    out = {"txs": 0, "cospend_known": [], "sent_to_known": [], "recv_from_known": [],
           "co_inputs": [], "spend_dests": [], "other_fund_srcs": []}
    txs = addr_txs(dest)
    out["txs"] = len(txs)
    for t in txs:
        txid = t["txid"]
        vin_addrs = [(v.get("prevout") or {}).get("scriptpubkey_address") for v in t.get("vin", [])]
        vin_addrs = [a for a in vin_addrs if a]
        vout_addrs = [o.get("scriptpubkey_address") for o in t.get("vout", [])]
        vout_addrs = [a for a in vout_addrs if a]
        if dest in vin_addrs:                       # candidate SPENDS here
            co = sorted(set(vin_addrs) - {dest})
            hit = sorted(set(co) & KNOWN)
            if hit:
                out["cospend_known"].append({"txid": txid, "known": hit})
            out["co_inputs"].extend(co)
            sk = sorted(set(vout_addrs) & KNOWN)
            if sk:
                out["sent_to_known"].append({"txid": txid, "known": sk})
            out["spend_dests"].extend(sorted(set(vout_addrs)))
        elif dest in vout_addrs and txid not in sweep_txids:  # funded outside the sweep
            rk = sorted(set(vin_addrs) & KNOWN)
            if rk:
                out["recv_from_known"].append({"txid": txid, "known": rk})
            out["other_fund_srcs"].extend(sorted(set(vin_addrs)))
    out["co_inputs"] = sorted(set(out["co_inputs"]))
    out["spend_dests"] = sorted(set(out["spend_dests"]))
    out["other_fund_srcs"] = sorted(set(out["other_fund_srcs"]))
    return out


def main():
    rep = json.load(open(REPORT_IN))
    by_dest = {}
    for c in rep:
        by_dest.setdefault(c["dest"], []).append(c)
    dests = list(by_dest)
    cand_set = set(dests)
    print(f"{len(dests)} candidate destinations to analyze ({len(rep)} sweeps)")

    state = json.load(open(STATE)) if os.path.exists(STATE) else {}
    for i, d in enumerate(dests):
        if d in state:
            continue
        try:
            state[d] = analyze(d, {c["txid"] for c in by_dest[d]})
        except Exception as e:
            print(f"  {d} FAILED: {e}", file=sys.stderr)
            time.sleep(3)
            continue
        with open(STATE, "w") as f:
            json.dump(state, f)
        if i % 20 == 0:
            print(f"  ...{i}/{len(dests)}", flush=True)
        time.sleep(1.0)

    # ---- synthesis ----
    proofs, sent, recv = [], [], []
    cand_links = []          # candidate co-spending with another candidate
    hop2 = {}                # second-hop address -> which candidates spend to it
    for d, r in state.items():
        if r["cospend_known"]:
            proofs.append({"dest": d, "evidence": r["cospend_known"]})
        if r["sent_to_known"]:
            sent.append({"dest": d, "evidence": r["sent_to_known"]})
        if r["recv_from_known"]:
            recv.append({"dest": d, "evidence": r["recv_from_known"]})
        linked = sorted(set(r["co_inputs"]) & cand_set)
        if linked:
            cand_links.append({"dest": d, "co_spends_with": linked})
        for s in r["spend_dests"]:
            if s not in cand_set:
                hop2.setdefault(s, []).append(d)
    converge = {s: ds for s, ds in hop2.items() if len(ds) >= 2}

    final = {"analyzed": len(state), "known_set": sorted(KNOWN),
             "proof_cospend_with_known": proofs, "sent_to_known": sent,
             "received_from_known": recv, "candidate_cospend_links": cand_links,
             "second_hop_convergence": {s: sorted(ds) for s, ds in
                                        sorted(converge.items(), key=lambda kv: -len(kv[1]))}}
    with open(REPORT, "w") as f:
        json.dump(final, f, indent=1)

    print("=" * 70)
    print(f"analyzed {len(state)} destinations")
    print(f"PROOF co-spend with known attacker: {len(proofs)}")
    for p in proofs:
        print(f"  {p['dest']}  via {p['evidence'][0]['txid'][:16]}... known={p['evidence'][0]['known']}")
    print(f"sent to known attacker address:     {len(sent)}")
    for p in sent:
        print(f"  {p['dest']}  -> {p['evidence'][0]['known']}")
    print(f"received from known attacker:       {len(recv)}")
    for p in recv:
        print(f"  {p['dest']}  <- {p['evidence'][0]['known']}")
    print(f"candidate<->candidate co-spend links: {len(cand_links)}")
    print(f"second-hop convergence points (>=2 candidates): {len(converge)}")
    for s, ds in sorted(converge.items(), key=lambda kv: -len(kv[1]))[:15]:
        print(f"  {s}  <- {len(ds)} candidates")
    print(f"\nfull report: {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
