#!/usr/bin/env python3
"""
scan-batched.py — the second detector: thefts that sweep many victims in ONE transaction.

scan.py hunts the shape every known cluster used: one victim per transaction, many of
them in a block. A theft reported by a victim on 1 August used a different shape, so
scan.py could not see it: fifteen victim addresses signed into a single transaction
with one output and no change.

An owner consolidating their own coins produces the same shape, which is why this
cannot key on the shape alone. The discriminator is the fee. The batch that prompted
this paid 201.1 sat/vB into a block whose median was a fraction of that. Nobody
overpays by two orders of magnitude to move their own money; a script that hardcodes
a fee does exactly that.

So a candidate needs all of: many inputs, every input a distinct single-sig segwit
address, exactly one output, and a fee rate far above what the block was charging.
Destinations are then freshness-checked like the other detector.

Nothing publishes. It writes a report for a person to read.

usage: scan-batched.py [--from H] [--to H] [--min-inputs 5] [--fee-multiple 5]
"""
import argparse
import json
import os
import ssl
import socket
import base64
import sys
import time
import urllib.request

import nodeconf

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "scan-batched-state.json")
REPORT = os.path.join(HERE, "scan-batched-report.json")

# Node location comes from local config or the environment, never from this file.
# With none set, nodeconf reports no node and the caller uses public block APIs.
FIRST_DRAIN_BLOCK = 960183
UA = {"User-Agent": "coldcard-scan-batched/1.0"}

KNOWN_DEST = {
    "bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0", "bc1qc779m8gec84k3t0ffvu0pps94zheht7lr7ueyn",
    "bc1qh0l7q0mca3ln7wsl9luwns0jc9jhgrtft025l4", "bc1qdaarag7729c2n4l2wnyt3hkhfpcs66n98z7uuh",
    "bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9r", "bc1qx76cae2706qd5q576feh7xq8rfcsjpf2htfhe3",
    "bc1q8jy96fe5lf8vfugydnte3cguk92gpev7kwtp3q", "bc1qsjrf5ze5tmulz7y2x4pc7qaex2a35sanp3rqlx",
    "bc1qtfrwa4j6rmj9rsgspv6a0yjumkg39js2numu75", "bc1qjd6tcd5ey96fdujpkr7zgn2zjzp29h208xlvxg",
    "bc1qhh4jkkj07vxpdt0zlvxctjlfhqmurhxa24x3h2",
}


def pw():
    return nodeconf.rpc_password()


def rpc(method, params=None):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    body = json.dumps({"jsonrpc": "1.0", "id": "b", "method": method, "params": params or []})
    s = socket.create_connection((nodeconf.node()["addr"], 443), timeout=120)
    ss = ctx.wrap_socket(s, server_hostname=nodeconf.node().get("host") or nodeconf.node()["addr"])
    auth = base64.b64encode(f"bitcoin:{pw()}".encode()).decode()
    ss.sendall((f"POST / HTTP/1.1\r\nHost: {nodeconf.node().get("host") or nodeconf.node()["addr"]}\r\nAuthorization: Basic {auth}\r\n"
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


def sats(v):
    return int(round(float(v) * 1e8))


def is_p2wpkh(a):
    return bool(a) and a.startswith("bc1q") and len(a) == 42


def esplora(path, timeout=45):
    with urllib.request.urlopen(urllib.request.Request(
            "https://blockstream.info/api" + path, headers=UA), timeout=timeout) as r:
        return json.load(r)


def scan(height, min_inputs, fee_multiple):
    blk = rpc("getblock", [rpc("getblockhash", [height]), 3])
    rates, cands = [], []
    txs = blk.get("tx", [])
    for t in txs:
        vin, vout = t.get("vin", []), t.get("vout", [])
        if not vin or "coinbase" in vin[0]:
            continue
        w = t.get("weight") or 0
        if w <= 0:
            continue
        ins = sum(sats((v.get("prevout") or {}).get("value", 0)) for v in vin)
        outs = sum(sats(o.get("value", 0)) for o in vout)
        rate = (ins - outs) / (w / 4.0)
        rates.append(rate)
    rates.sort()
    median = rates[len(rates) // 2] if rates else 1.0
    floor = max(median * fee_multiple, 20.0)

    for t in txs:
        vin, vout = t.get("vin", []), t.get("vout", [])
        if not vin or "coinbase" in vin[0]:
            continue
        if len(vin) < min_inputs or len(vout) != 1:
            continue                      # many in, one out, no change
        addrs = [((v.get("prevout") or {}).get("scriptPubKey") or {}).get("address") for v in vin]
        if not all(is_p2wpkh(a) for a in addrs):
            continue
        if len(set(addrs)) != len(addrs):
            continue                      # every input a DIFFERENT victim, not one wallet's UTXOs
        w = t.get("weight") or 0
        ins = sum(sats((v.get("prevout") or {}).get("value", 0)) for v in vin)
        outs = sats(vout[0].get("value", 0))
        rate = (ins - outs) / (w / 4.0)
        if rate < floor:
            continue                      # an owner does not overpay like this
        dst = (vout[0].get("scriptPubKey") or {}).get("address")
        if not dst:
            continue
        cands.append({"height": height, "txid": t.get("txid"), "dest": dst,
                      "victims": addrs, "sats": ins, "rate": round(rate, 1),
                      "block_median": round(median, 2)})
    return cands


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="start", type=int, default=FIRST_DRAIN_BLOCK)
    ap.add_argument("--to", dest="end", type=int, default=0)
    ap.add_argument("--min-inputs", type=int, default=5)
    ap.add_argument("--fee-multiple", type=float, default=5.0)
    a = ap.parse_args()

    tip = rpc("getblockcount")
    end = a.end or tip
    print(f"scanning {a.start}..{end} for batched sweeps "
          f"(>={a.min_inputs} distinct inputs, fee >= {a.fee_multiple}x block median)")

    done = json.loads(open(STATE).read()) if os.path.exists(STATE) else {}
    hits = []
    for h in range(a.start, end + 1):
        k = str(h)
        if k in done:
            found = done[k]
        else:
            try:
                found = scan(h, a.min_inputs, a.fee_multiple)
            except Exception as e:
                print(f"  block {h} failed: {e}", file=sys.stderr)
                continue
            done[k] = found
            with open(STATE, "w") as f:
                json.dump(done, f)
        hits.extend(found)
        if (h - a.start) % 25 == 0:
            print(f"  ...{h}  batched candidates so far: {len(hits)}")

    print(f"\nbatched candidates: {len(hits)}")
    out = []
    for c in hits:
        if c["dest"] in KNOWN_DEST:
            continue
        try:
            st = esplora(f"/address/{c['dest']}")["chain_stats"]
        except Exception:
            continue
        time.sleep(0.25)
        c["dest_deposits"] = st["funded_txo_count"]
        c["dest_balance"] = st["funded_txo_sum"] - st["spent_txo_sum"]
        c["dest_dormant"] = st["spent_txo_count"] == 0
        c["dest_fresh"] = st["funded_txo_count"] <= 5
        out.append(c)

    out.sort(key=lambda x: -x["sats"])
    with open(REPORT, "w") as f:
        json.dump(out, f, indent=1)

    print("=" * 78)
    for c in out:
        flag = "LIKELY" if (c["dest_fresh"] or c["dest_dormant"]) else "check"
        print(f"\n  [{flag}] {c['dest']}")
        print(f"    {len(c['victims'])} victims in ONE tx, {c['sats']/1e8:.8f} BTC")
        print(f"    fee {c['rate']} sat/vB vs block median {c['block_median']}  (block {c['height']})")
        print(f"    dest: {c['dest_deposits']} deposits, {c['dest_balance']/1e8:.8f} BTC, "
              f"{'DORMANT' if c['dest_dormant'] else 'has spent'}")
        print(f"    https://mempool.space/tx/{c['txid']}")
    print(f"\nfull report: {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
