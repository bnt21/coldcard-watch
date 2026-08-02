#!/usr/bin/env python3
"""
wave3.py — the no-collector detector.

Every earlier detector on this project keys on a funnel. scan.py wants many sweeps
landing in one collector; co_spend.py wants two addresses signing the same transaction.
Wave 3 removed the funnel: each victim wallet got its own fresh holding address and its
own fresh P2WSH vault, ~293 one-to-one chains with nothing shared for a detector to
cluster on. Both existing detectors are structurally blind to it, which is why the site
sat 207 BTC behind Galaxy Research.

What survives when the attacker deletes the shared address is the *signer*. A wallet is
identified by the fields its software fills in, not by where the coins go, so this keys
on invariance rather than on any funnel or on fee magnitude alone:

  hop 1, the sweep      every input P2WPKH and a distinct address, exactly one output
                        (no change), nVersion 2, nLockTime 0, one nSequence value across
                        all inputs, one homogeneous input script type, and a fee rate far
                        above the block's own median
  firmware epoch        no input UTXO created before block 674,951 (17 Mar 2021), the
                        block the vulnerable firmware shipped in. Galaxy: not one coin
                        in waves 1-3 predates it. A real invariant, cheap to test.
  hop 2, the park       that fresh destination later spends its whole balance, one output,
                        no change, into a fresh P2WSH address that then sits unspent

The field list is Clay Garrett's (Block), who found the original pattern: "version 2,
locktime 0, final sequence on every input, one output and inputs from one source address,
a P2WPKH destination, one homogeneous supported input type". Wave 3 keeps the fields and
changes two things — it batches ~6.37 victims per sweep instead of one, and it parks in
P2WSH instead of P2WPKH — so the source-address and destination-type clauses are widened
here and the rest held exactly.

WHAT THIS DOES NOT DO: publish. A batched full-drain into a fresh address at an urgent
fee is also precisely what Coinkite's own advisory told every affected owner to do, so
the shape cannot separate a theft from a rescue. Output goes to a review file for a
person to read, and the run reports how far it lands from Galaxy's published totals as
its own accuracy check. Nothing here edits the site.

usage: wave3.py [--from 960396] [--to 960471] [--fee-multiple 20] [--min-rate 100]
                [--rescan] [--no-hop2]
"""
import argparse
import base64
import json
import os
import socket
import ssl
import statistics
import sys
import time
import urllib.request

import nodeconf

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
STATE = os.path.join(HERE, "wave3-state.json")
# The report path carries the window. A fixed path meant scanning a different range
# overwrote the published window's report in place, which is how a forward probe
# silently destroyed the evidence behind 214 published vaults.
REPORT = os.path.join(DATA, "wave3-report.json")
REVIEW = os.path.join(DATA, "wave3-review.json")


def _paths_for(start, end):
    if (start, end) == GALAXY["blocks"]:
        return REPORT, REVIEW          # the canonical window keeps the canonical name
    tag = f"{start}-{end}"
    return (os.path.join(DATA, f"wave3-report-{tag}.json"),
            os.path.join(DATA, f"wave3-review-{tag}.json"))

# Node location comes from local config or the environment, never from this file.
# With none set, nodeconf reports no node and the caller uses public block APIs.
UA = {"User-Agent": "coldcard-wave3/1.0"}

# The block the vulnerable Coldcard firmware shipped in, 17 Mar 2021. Galaxy Research:
# "Not one of the coins we have identified in Waves 1-3 taken was created before that block."
FIRMWARE_EPOCH = 674951

# Bump this whenever scan_block's accept/reject logic changes, so the block cache
# cannot serve hits produced by a different rule set.
PREDICATES = "v2:ver2+lock0+seq-uniform+1out+p2wpkh-homogeneous+epoch"

# Galaxy Research's published Wave 3 figures, used only to score this run against theirs.
GALAXY = {"blocks": (960396, 960471), "victims": 1912, "sweeps": 300, "parks": 293,
          "vaults": 293, "drained_btc": 208.24, "held_btc": 207.73, "fee_rate": 200.0}

# The one Wave 3 chain any third party has published in full. The detector has to find
# this pair or it is not working. (Kelbie/coldcard-rng-postmortem chain walk, 2026-08-01.)
CANARY_PARK = "bc1q7kwz5k8w0m5qljkc0z8996wt02u0vgdxem6jsu"
CANARY_VAULT = "bc1qqu0sp6d4wxnp33ghgrtexrczzzl85f3vnlueep2hlsw69t38xazqltw5ac"

# Already on the site or already attributed; not a new finding.
KNOWN_DEST = {
    "bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0", "bc1qc779m8gec84k3t0ffvu0pps94zheht7lr7ueyn",
    "bc1qh0l7q0mca3ln7wsl9luwns0jc9jhgrtft025l4", "bc1qdaarag7729c2n4l2wnyt3hkhfpcs66n98z7uuh",
    "bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9r", "bc1qx76cae2706qd5q576feh7xq8rfcsjpf2htfhe3",
    "bc1q8jy96fe5lf8vfugydnte3cguk92gpev7kwtp3q", "bc1qsjrf5ze5tmulz7y2x4pc7qaex2a35sanp3rqlx",
    "bc1qtfrwa4j6rmj9rsgspv6a0yjumkg39js2numu75", "bc1qjd6tcd5ey96fdujpkr7zgn2zjzp29h208xlvxg",
    "bc1qmd5m5ktv7m5ffujxv4248fxv36myvdx79n8jp6", "bc1qhh4jkkj07vxpdt0zlvxctjlfhqmurhxa24x3h2",
}


def pw():
    return nodeconf.rpc_password()


def rpc(method, params=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = json.dumps({"jsonrpc": "1.0", "id": "w3", "method": method, "params": params or []})
    s = socket.create_connection((nodeconf.node()["addr"], 443), timeout=180)
    ss = ctx.wrap_socket(s, server_hostname=nodeconf.node().get("host") or nodeconf.node()["addr"])
    auth = base64.b64encode(f"bitcoin:{pw()}".encode()).decode()
    host = nodeconf.node().get("host") or nodeconf.node()["addr"]
    ss.sendall((f"POST / HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {auth}\r\n"
                f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n{body}").encode())
    buf = b""
    while True:
        c = ss.recv(1 << 20)
        if not c:
            break
        buf += c
    ss.close()
    t = buf.partition(b"\r\n\r\n")[2].decode(errors="replace")
    i = t.find('{"result"')
    if i < 0:
        i = t.find("{")
    return json.loads(t[i:t.rfind("}") + 1])["result"]


def esplora(path, tries=3):
    for host in ("https://blockstream.info/api", "https://mempool.space/api"):
        for _ in range(tries):
            try:
                with urllib.request.urlopen(urllib.request.Request(host + path, headers=UA),
                                            timeout=45) as r:
                    return json.load(r)
            except Exception:
                time.sleep(1.0)
    return None


def sats(v):
    return int(round(float(v) * 1e8))


def spk(o):
    return o.get("scriptPubKey") or {}


# ---------------------------------------------------------------- hop 1: the sweep

def scan_block(height, fee_multiple, min_rate):
    """Every transaction in `height` that carries the signer fingerprint. Deterministic:
    reads block data and decides on fields, never on a model's judgement."""
    blk = rpc("getblock", [rpc("getblockhash", [height]), 3])
    txs = blk.get("tx", [])

    rates = []
    for t in txs:
        vin, vout = t.get("vin", []), t.get("vout", [])
        if not vin or "coinbase" in vin[0]:
            continue
        w = t.get("weight") or 0
        if w <= 0:
            continue
        ins = sum(sats((v.get("prevout") or {}).get("value", 0)) for v in vin)
        outs = sum(sats(o.get("value", 0)) for o in vout)
        rates.append((ins - outs) / (w / 4.0))
    rates.sort()
    median = rates[len(rates) // 2] if rates else 1.0
    floor = max(median * fee_multiple, min_rate)

    hits = []
    for t in txs:
        vin, vout = t.get("vin", []), t.get("vout", [])
        if not vin or "coinbase" in vin[0]:
            continue

        # --- the signer fingerprint (Garrett/Block), held exactly ---
        if t.get("version") != 2:
            continue
        if t.get("locktime") != 0:
            continue
        seqs = {v.get("sequence") for v in vin}
        if len(seqs) != 1:                     # one nSequence value across every input
            continue
        if len(vout) != 1:                     # one output, no change: a full drain
            continue

        prevs = [(v.get("prevout") or {}) for v in vin]
        if any(not p for p in prevs):
            continue
        types = {spk(p).get("type") for p in prevs}
        if types != {"witness_v0_keyhash"}:    # homogeneous P2WPKH, BIP-84 default path
            continue
        addrs = [spk(p).get("address") for p in prevs]
        if not all(addrs):
            continue
        # NOT required: that every input sit at a distinct address. scan_batched.py demands
        # that, to tell a multi-victim batch from an owner consolidating their own UTXOs, and
        # inheriting it here cost 63 sweeps in the fee band on the first run — Wave 3 batches
        # one WALLET per sweep, and a wallet reuses an address routinely. Recorded, not judged.

        # --- firmware epoch: no coin predates the vulnerable build ---
        heights = [p.get("height") for p in prevs]
        if any(h is None for h in heights):
            continue
        if min(heights) < FIRMWARE_EPOCH:
            continue

        w = t.get("weight") or 0
        if w <= 0:
            continue
        ins = sum(sats(p.get("value", 0)) for p in prevs)
        outs = sats(vout[0].get("value", 0))
        rate = (ins - outs) / (w / 4.0)
        if rate < floor:                       # an owner does not overpay like this
            continue

        dst = spk(vout[0]).get("address")
        if not dst:
            continue

        hits.append({
            "height": height, "txid": t.get("txid"), "time": blk.get("time"),
            "dest": dst, "dest_type": spk(vout[0]).get("type"),
            "victims": sorted(set(addrs)), "inputs": len(addrs), "sats": ins, "out_sats": outs,
            "rate": round(rate, 2), "block_median": round(median, 3),
            "overpay": round(rate / median, 1) if median else None,
            "sequence": list(seqs)[0], "oldest_input_block": min(heights),
        })
    return hits


# ---------------------------------------------------------------- hop 2: park -> vault

def trace_hop2(dest):
    """Did this fresh holding address forward its whole balance, no change, into a fresh
    P2WSH that now sits unspent? Returns the vault leg or a reason it is not one."""
    info = esplora(f"/address/{dest}")
    if not info:
        return {"ok": False, "why": "lookup failed"}
    c = info["chain_stats"]
    out = {
        "deposits": c["funded_txo_count"],
        "balance": c["funded_txo_sum"] - c["spent_txo_sum"],
        "spent_count": c["spent_txo_count"],
        "fresh": c["funded_txo_count"] <= 8,   # a holding address, not a service
    }
    if c["spent_txo_count"] == 0:
        out.update({"ok": False, "why": "unspent, still parked", "parked": True})
        return out

    # The claim being published is that the park forwarded its WHOLE balance with no
    # change. That has to be tested, not assumed: a park still holding a residue, or one
    # whose vault also holds unrelated coins, is a different claim entirely.
    if out["balance"] != 0:
        out.update({"ok": False, "why": f"still holds {out['balance']} sats; not a clean forward"})
        return out

    txs = esplora(f"/address/{dest}/txs/chain") or []
    for t in txs:
        spends = [i for i in t.get("vin", [])
                  if (i.get("prevout") or {}).get("scriptpubkey_address") == dest]
        if not spends:
            continue
        vout = t.get("vout", [])
        if len(vout) != 1:                     # a change output means this is not the park leg
            continue
        # and it must move everything the address ever received, in this one transaction
        moved = sum((i.get("prevout") or {}).get("value", 0) for i in spends)
        if moved != c["funded_txo_sum"]:
            out.update({"ok": False,
                        "why": "forward does not carry the whole balance"})
            return out
        o = vault = vout[0]
        if o.get("scriptpubkey_type") != "v0_p2wsh":
            out.update({"ok": False, "why": f"forwards to {o.get('scriptpubkey_type')}, not P2WSH"})
            return out
        va = o.get("scriptpubkey_address")
        vi = esplora(f"/address/{va}")
        vc = (vi or {}).get("chain_stats", {})
        out.update({
            "ok": True, "vault": va, "vault_txid": t.get("txid"),
            "vault_height": (t.get("status") or {}).get("block_height"),
            "vault_sats": sats(vault.get("value", 0)) if isinstance(vault.get("value"), float)
                          else vault.get("value", 0),
            "vault_unspent": vc.get("spent_txo_count", 1) == 0,
            "vault_deposits": vc.get("funded_txo_count"),
            "vault_balance": vc.get("funded_txo_sum", 0) - vc.get("spent_txo_sum", 0),
        })
        return out
    out.update({"ok": False, "why": "spent, but not as a single no-change forward"})
    return out


# ---------------------------------------------------------------- run

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="start", type=int, default=GALAXY["blocks"][0])
    ap.add_argument("--to", dest="end", type=int, default=GALAXY["blocks"][1])
    ap.add_argument("--fee-multiple", type=float, default=20.0,
                    help="fee rate must exceed this many times the block's own median")
    ap.add_argument("--min-rate", type=float, default=100.0,
                    help="absolute sat/vB floor, so a quiet block cannot make 6 sat/vB look extreme")
    ap.add_argument("--rescan", action="store_true", help="ignore the block cache")
    ap.add_argument("--no-hop2", action="store_true", help="stop after the sweep pass")
    a = ap.parse_args()

    global REPORT, REVIEW
    REPORT, REVIEW = _paths_for(a.start, a.end)
    print(f"wave3: blocks {a.start}..{a.end}  "
          f"(fee >= {a.fee_multiple}x block median and >= {a.min_rate} sat/vB, "
          f"inputs newer than block {FIRMWARE_EPOCH})")

    cache = {}
    if os.path.exists(STATE) and not a.rescan:
        cache = json.loads(open(STATE).read())
    # The key covers every input to a hit, not just the fee args. Editing a predicate
    # without this would silently reuse hits the old rules produced.
    key = f"v3|{a.fee_multiple}|{a.min_rate}|{FIRMWARE_EPOCH}|{PREDICATES}"
    cache.setdefault(key, {})

    sweeps = []
    for h in range(a.start, a.end + 1):
        k = str(h)
        if k in cache[key]:
            found = cache[key][k]
        else:
            try:
                found = scan_block(h, a.fee_multiple, a.min_rate)
            except Exception as e:
                print(f"  block {h} failed: {type(e).__name__} {e}", file=sys.stderr)
                continue
            cache[key][k] = found
            with open(STATE, "w") as f:
                json.dump(cache, f)
        sweeps.extend(found)
        if (h - a.start) % 10 == 0:
            print(f"  ...{h}  sweeps so far: {len(sweeps)}")

    victims = {v for s in sweeps for v in s["victims"]}
    drained = sum(s["sats"] for s in sweeps)
    print(f"\nhop 1 — {len(sweeps)} sweeps, {len(victims)} distinct victim addresses, "
          f"{drained/1e8:.8f} BTC")

    if sweeps:
        rr = sorted(s["rate"] for s in sweeps)
        print(f"  fee rate: min {rr[0]}  median {statistics.median(rr)}  max {rr[-1]}")
        band = [s for s in sweeps if 195 <= s["rate"] <= 210]
        print(f"  in the 195-210 sat/vB band: {len(band)} of {len(sweeps)} sweeps "
              f"({sum(s['sats'] for s in band)/1e8:.8f} BTC)")
        print(f"  victims per sweep: mean {len(victims)/len(sweeps):.2f} "
              f"(Galaxy reports 6.37)")

    if a.no_hop2:
        json.dump(sweeps, open(REPORT, "w"), indent=1)
        print(f"\nsweeps written to {REPORT}")
        return 0

    print(f"\nhop 2 — tracing {len(set(s['dest'] for s in sweeps))} destinations")
    legs, seen = {}, set()
    for i, s in enumerate(sweeps):
        d = s["dest"]
        if d in KNOWN_DEST:
            s["hop2"] = {"ok": False, "why": "already attributed"}
            continue
        if d not in legs:
            legs[d] = trace_hop2(d)
            time.sleep(0.2)
            if len(legs) % 25 == 0:
                print(f"  ...{len(legs)} traced")
        s["hop2"] = legs[d]
        seen.add(d)

    chains = [s for s in sweeps if s.get("hop2", {}).get("ok")]
    parked = [s for s in sweeps if s.get("hop2", {}).get("parked")]
    vaults = {s["hop2"]["vault"]: s["hop2"] for s in chains}
    held = sum(v.get("vault_balance") or 0 for v in vaults.values())
    cv = sum(s["sats"] for s in chains)

    print(f"\nhop 2 — {len(chains)} sweeps completed a park->P2WSH chain into "
          f"{len(vaults)} distinct vaults")
    print(f"  still parked, not yet forwarded: {len(parked)}")
    print(f"  BTC through completed chains: {cv/1e8:.8f}")
    print(f"  BTC resting in those vaults:   {held/1e8:.8f}")

    # --- accuracy check against the only published figures ---
    cvic = {v for s in chains for v in s["victims"]}
    print("\naccuracy check vs Galaxy Research (their Wave 3, same block range)")
    for label, got, want in (("victim addresses", len(cvic), GALAXY["victims"]),
                             ("sweeps", len(chains), GALAXY["sweeps"]),
                             ("P2WSH vaults", len(vaults), GALAXY["vaults"]),
                             ("BTC held in vaults", round(held / 1e8, 4), GALAXY["held_btc"])):
        d = (got - want) / want * 100 if want else 0
        print(f"  {label:22} this run {got:>12}   Galaxy {want:>10}   {d:+.1f}%")

    canary = CANARY_VAULT in vaults
    print(f"\n  canary chain {CANARY_PARK[:14]}... -> {CANARY_VAULT[:16]}...: "
          f"{'FOUND' if canary else 'MISSING — detector is not working'}")

    json.dump({"sweeps": sweeps, "vaults": vaults}, open(REPORT, "w"), indent=1)
    review = {
        "generated": int(time.time()),
        "detector": "wave3.py (no-collector, two-hop, signer-fingerprint)",
        "window": [a.start, a.end],
        "criteria": {"fee_multiple": a.fee_multiple, "min_rate": a.min_rate,
                     "firmware_epoch": FIRMWARE_EPOCH,
                     "fields": "version=2, locktime=0, uniform nSequence, 1 output, "
                               "homogeneous P2WPKH inputs (address reuse allowed)"},
        "status": "CANDIDATES — NOT PUBLISHED. A batched full-drain into a fresh address "
                  "at an urgent fee is also what Coinkite's advisory told owners to do. "
                  "Shape alone cannot separate a theft from a rescue.",
        "canary_found": canary,
        "totals": {"sweeps": len(chains), "victims": len(cvic), "vaults": len(vaults),
                   "held_sats": held, "drained_sats": cv},
        "vaults": vaults,
    }
    json.dump(review, open(REVIEW, "w"), indent=1)
    print(f"\nreport: {REPORT}\nreview queue (nothing published): {REVIEW}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
