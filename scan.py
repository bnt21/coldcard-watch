#!/usr/bin/env python3
"""
scan.py — find Coldcard drain clusters by scanning blocks, instead of waiting to be told.

The site's original method walked outward from an attacker address someone else had
already named. That cannot discover a cluster nobody reported, which is exactly how
waves 4 and 5 were missed. This does the opposite: it reads every block since the
first known drain and looks for the pattern.

The pattern, per block:
  - one input, one output, no change output (the address is emptied exactly)
  - the input is a single-sig native segwit key (bc1q, 42 chars)
  - several such sweeps land in the SAME block paying into the SAME address
  - every one of them pays an identical fee rate (a hardcoded rate, not a market one)

That alone is not enough. Exchanges produce similar-looking bursts, so each candidate
destination is then checked for freshness: an attacker collector is a new address whose
entire history is this incident, while a service has a deep unrelated history. The
false positive that motivated this check had 1,490,277 prior deposits.

Nothing here publishes anything. It writes a report for a human to read.

usage:
  scan.py                      scan from the first known drain to the chain tip
  scan.py --from 960400        start at a specific height
  scan.py --to 960520          stop at a specific height
  scan.py --min-sweeps 3       how many same-block sweeps make a candidate
"""
import argparse
import json
import os
import sys
import time
import urllib.request

import nodeconf

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
STATE = os.path.join(HERE, "scan-state.json")
REPORT = os.path.join(DATA, "scan-report.json")

FIRST_DRAIN_BLOCK = 960183
UA = {"User-Agent": "coldcard-scan/1.0"}

# clusters already on the site, so the report only surfaces what is new
KNOWN = {
    "bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0",  # wave 1-3 collector
    "bc1qc779m8gec84k3t0ffvu0pps94zheht7lr7ueyn",
    "bc1qh0l7q0mca3ln7wsl9luwns0jc9jhgrtft025l4",
    "bc1qdaarag7729c2n4l2wnyt3hkhfpcs66n98z7uuh",
    "bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9r",
    "bc1qx76cae2706qd5q576feh7xq8rfcsjpf2htfhe3",
    "bc1q8jy96fe5lf8vfugydnte3cguk92gpev7kwtp3q",
    "bc1qsjrf5ze5tmulz7y2x4pc7qaex2a35sanp3rqlx",  # wave 4
    "bc1qtfrwa4j6rmj9rsgspv6a0yjumkg39js2numu75",
    "bc1qjd6tcd5ey96fdujpkr7zgn2zjzp29h208xlvxg",  # wave 5
    "bc1qhh4jkkj07vxpdt0zlvxctjlfhqmurhxa24x3h2",
}


def get(url, timeout=90, tries=4):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
                return r.read()
        except Exception as e:
            if i == tries - 1:
                raise
            print(f"    retry {i+1}: {e}", file=sys.stderr)
            time.sleep(3 + i * 3)


def is_p2wpkh(addr):
    return bool(addr) and addr.startswith("bc1q") and len(addr) == 42



# ---- Bitcoin Core over the StartOS LAN interface ------------------------------
# Reading blocks from a local node instead of a public API: no rate limit, no
# third party, and about five times faster. Falls back to blockchain.info if the
# node cannot be reached, so the scan still runs away from home.
# Node location comes from local config or the environment, never from this file.
# With none set, nodeconf reports no node and the caller uses public block APIs.


def _pw():
    return nodeconf.rpc_password()


def rpc(method, params=None):
    import ssl, socket, base64
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    body = json.dumps({"jsonrpc": "1.0", "id": "s", "method": method, "params": params or []})
    s = socket.create_connection((nodeconf.node()["addr"], 443), timeout=120)
    ss = ctx.wrap_socket(s, server_hostname=nodeconf.node().get("host") or nodeconf.node()["addr"])
    auth = base64.b64encode(f"bitcoin:{_pw()}".encode()).decode()
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


_node_ok = None


def node_available():
    """Cached probe. False when no node is configured, which sends the scan down the
    public-API path instead of raising."""
    global _node_ok
    if _node_ok is None:
        if not nodeconf.have_node():
            _node_ok = False
        else:
            try:
                rpc("getblockcount")
                _node_ok = True
            except Exception:
                _node_ok = False
    return _node_ok


def sats(v):
    return int(round(float(v) * 1e8))


def scan_block_node(height):
    """Same detection as scan_block, reading from the node."""
    blk = rpc("getblock", [rpc("getblockhash", [height]), 3])
    groups = {}
    for t in blk.get("tx", []):
        vin, vout = t.get("vin", []), t.get("vout", [])
        if len(vin) != 1 or len(vout) != 1 or "coinbase" in vin[0]:
            continue
        prev = vin[0].get("prevout") or {}
        src = (prev.get("scriptPubKey") or {}).get("address")
        dst = (vout[0].get("scriptPubKey") or {}).get("address")
        if not is_p2wpkh(src) or not dst:
            continue
        w = t.get("weight") or 0
        if w <= 0:
            continue
        fee = sats(prev.get("value", 0)) - sats(vout[0].get("value", 0))
        rate = round(fee / (w / 4.0), 1)
        g = groups.setdefault(dst, {"sweeps": 0, "sats": 0, "rates": {}, "sources": [],
                                    "rbf": 0, "height": height})
        g["sweeps"] += 1
        g["sats"] += sats(prev.get("value", 0))
        g["rates"][rate] = g["rates"].get(rate, 0) + 1
        g["sources"].append(src)
        if vin[0].get("sequence", 0xFFFFFFFF) < 0xFFFFFFFE:
            g["rbf"] += 1
    return groups


def scan_block(height):
    """Return {destination: {sweeps, btc, rates, sources}} for this block."""
    h = get(f"https://blockstream.info/api/block-height/{height}").decode().strip()
    blk = json.loads(get(f"https://blockchain.info/rawblock/{h}"))
    groups = {}
    for t in blk.get("tx", []):
        ins, outs = t.get("inputs", []), t.get("out", [])
        if len(ins) != 1 or len(outs) != 1:
            continue                       # must be one-in, one-out with no change
        prev = ins[0].get("prev_out") or {}
        src, dst = prev.get("addr"), outs[0].get("addr")
        if not is_p2wpkh(src) or not dst:
            continue
        weight = t.get("weight") or 0
        fee = t.get("fee") or 0
        if weight <= 0:
            continue
        rate = round(fee / (weight / 4.0), 1)
        g = groups.setdefault(dst, {"sweeps": 0, "sats": 0, "rates": {}, "sources": [],
                                    "rbf": 0, "height": height})
        g["sweeps"] += 1
        g["sats"] += prev.get("value", 0)
        g["rates"][rate] = g["rates"].get(rate, 0) + 1
        g["sources"].append(src)
        if ins[0].get("sequence", 0xFFFFFFFF) < 0xFFFFFFFE:
            g["rbf"] += 1
    return groups


def address_stats(addr):
    d = json.loads(get(f"https://blockstream.info/api/address/{addr}", timeout=45))
    c = d["chain_stats"]
    return {
        "deposits": c["funded_txo_count"],
        "received": c["funded_txo_sum"],
        "spent_outputs": c["spent_txo_count"],
        "balance": c["funded_txo_sum"] - c["spent_txo_sum"],
        "tx_count": c["tx_count"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="start", type=int, default=FIRST_DRAIN_BLOCK)
    ap.add_argument("--to", dest="end", type=int, default=0)
    ap.add_argument("--min-sweeps", type=int, default=3)
    a = ap.parse_args()

    tip = int(get("https://blockstream.info/api/blocks/tip/height").decode().strip())
    end = a.end or tip
    print(f"scanning blocks {a.start} to {end} ({end - a.start + 1} blocks), tip {tip}")

    done = {}
    if os.path.exists(STATE):
        try:
            done = json.loads(open(STATE).read())
        except Exception:
            done = {}

    hits = {}
    for h in range(a.start, end + 1):
        key = str(h)
        if key in done:
            found = done[key]
        else:
            try:
                groups = scan_block_node(h) if node_available() else scan_block(h)
            except Exception as e:
                print(f"  block {h}: FAILED ({e})", file=sys.stderr)
                continue
            found = {}
            for dst, g in groups.items():
                if g["sweeps"] < a.min_sweeps:
                    continue
                # a hardcoded fee rate means one value dominates the batch
                top_rate, top_n = max(g["rates"].items(), key=lambda kv: kv[1])
                if top_n / g["sweeps"] < 0.9:
                    continue
                found[dst] = {"sweeps": g["sweeps"], "sats": g["sats"], "rate": top_rate,
                              "rbf": g["rbf"], "height": h}
            done[key] = found
            with open(STATE, "w") as f:
                json.dump(done, f)
            time.sleep(0 if node_available() else 0.8)
        for dst, g in found.items():
            if dst in hits:
                hits[dst]["sweeps"] += g["sweeps"]; hits[dst]["sats"] += g["sats"]
                hits[dst]["blocks"].append(g["height"])
            else:
                hits[dst] = dict(g, blocks=[g["height"]])
        if (h - a.start) % 20 == 0:
            print(f"  ...{h}  candidates so far: {len(hits)}")

    print(f"\nraw candidates: {len(hits)}")
    new = {d: g for d, g in hits.items() if d not in KNOWN}
    print(f"already known: {len(hits) - len(new)}   new to check: {len(new)}\n")

    results = []
    for dst, g in sorted(new.items(), key=lambda kv: -kv[1]["sats"]):
        try:
            st = address_stats(dst)
        except Exception as e:
            print(f"  {dst}: stats failed ({e})")
            continue
        time.sleep(0.3)
        # a fresh collector's whole history is this incident; a service has far more
        unrelated = st["deposits"] - g["sweeps"]
        fresh = unrelated <= max(5, g["sweeps"] * 0.25)
        results.append({
            "address": dst, "sweeps": g["sweeps"], "btc": g["sats"] / 1e8,
            "fee_rate": g["rate"], "rbf_inputs": g["rbf"], "blocks": sorted(set(g["blocks"])),
            "deposits_total": st["deposits"], "unrelated_deposits": unrelated,
            "balance_btc": st["balance"] / 1e8, "looks_fresh": fresh,
        })

    likely = [r for r in results if r["looks_fresh"]]
    services = [r for r in results if not r["looks_fresh"]]

    with open(REPORT, "w") as f:
        json.dump({"scanned": [a.start, end], "likely": likely, "rejected": services}, f, indent=1)

    print("=" * 78)
    print(f"LIKELY CLUSTERS ({len(likely)}) — review each before adding anything to the site")
    print("=" * 78)
    for r in likely:
        print(f"\n  {r['address']}")
        print(f"    {r['sweeps']} sweeps, {r['btc']:.8f} BTC, {r['fee_rate']} sat/vB, "
              f"rbf={r['rbf_inputs']}/{r['sweeps']}")
        print(f"    blocks {r['blocks']}")
        print(f"    deposits {r['deposits_total']} total, {r['unrelated_deposits']} unrelated  "
              f"| balance {r['balance_btc']:.8f} BTC")
        print(f"    https://mempool.space/address/{r['address']}")
    print(f"\nrejected as services/high-history: {len(services)}")
    for r in services[:8]:
        print(f"  {r['address'][:24]}...  {r['sweeps']} sweeps but {r['deposits_total']:,} total deposits")
    print(f"\nfull report: {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
