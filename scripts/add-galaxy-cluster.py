#!/usr/bin/env python3
"""
One-time cluster addition: the wave-2 collector bc1qmd5m5ktv7m5ffujxv4248fxv36myvdx79n8jp6,
reported by Galaxy Research (2026-08-01) and verified here on-chain — 352 victims, 30.18
BTC, held unspent, swept at a hardcoded ~10 sat/vB across blocks 960352-960356.

Adds every coupled surface atomically (rollback on any failure), reusing publish.py's
deploy + deployed-byte verification. Not part of the recurring X pipeline; this is the
manual cluster path the site used for waves 4 and 5.

usage: add-galaxy-cluster.py [--dry-run]
"""
import hashlib
import json
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import publish

COLL = "bc1qmd5m5ktv7m5ffujxv4248fxv36myvdx79n8jp6"
COLL_BALANCE = 3018476329          # sats held, verified unspent
VICTIMS_FILE = "/tmp/coll_full.json"
BLOCK_TIMES = {960352: 1785476910, 960353: 1785476882, 960354: 1785476898,
               960355: 1785476958, 960356: 1785477487}
WAVE_INDEX = 2                     # same chart band as the other wave-2 sweeps
T0 = 1785373820


def read(p):
    return open(p, encoding="utf-8").read()


def main():
    dry = "--dry-run" in sys.argv

    conflicts = publish.conflict_guard()
    if conflicts:
        raise SystemExit(f"syncthing conflict copies present, refusing: {conflicts}")
    if publish.self_check(verbose=False):
        raise SystemExit("site invariants broken before edit; aborting")

    data = json.load(open(VICTIMS_FILE))
    victims = data["victims"]        # addr -> {sats,height,time,txid,batched}
    if data["coll"] != COLL:
        raise SystemExit("victim file collector mismatch")

    drains, hashes, old_n = publish.parse_site()
    rows, blocks = drains["rows"], drains["blocks"]
    have = {r[0] for r in rows}
    new_v = {a: v for a, v in victims.items() if a not in have}
    print(f"victims: {len(victims)} total, {len(new_v)} new to add")

    # extend the blocks array with the five wave-2 blocks these sweeps landed in
    h2i = {b["h"]: i for i, b in enumerate(blocks)}
    for h, t in sorted(BLOCK_TIMES.items()):
        if h not in h2i:
            blocks.append({"h": h, "t": t})
            h2i[h] = len(blocks) - 1

    # rows + hashes + chart events
    sweep_src = read(os.path.join(publish.PUBLIC, "data.js"))
    sweep = json.loads(re.search(r'window\.SWEEP\s*=\s*(.*)', sweep_src, re.S)
                       .group(1).rstrip().rstrip(";"))
    added_sats = 0
    for a, v in new_v.items():
        h = v["height"]
        rows.append([a, v["sats"], h2i[h]])
        hashes.append(hashlib.sha256(a.encode()).hexdigest()[:16])
        off = BLOCK_TIMES[h] - T0
        sweep["events"].append([off, v["sats"], WAVE_INDEX])
        added_sats += v["sats"]
    new_n = len(rows)
    print(f"count {old_n} -> {new_n}; added {added_sats/1e8:.8f} BTC of victim inputs; "
          f"collector holds {COLL_BALANCE/1e8:.8f}")

    old_total = 112866326171
    new_total = old_total + COLL_BALANCE
    old_total_disp, new_total_disp = "1,128.6633", f"{new_total/1e8:,.4f}"
    old_meta, new_meta = "1,128.66 BTC", f"{new_total/1e8:,.2f} BTC"
    of, nf = f"{old_n:,}", f"{new_n:,}"

    edits = {}
    # datasets
    edits[os.path.join(publish.PUBLIC, "drains.js")] = \
        "window.DRAINS=" + json.dumps({"blocks": blocks, "rows": rows},
                                      separators=(",", ":")) + ";\n"
    edits[os.path.join(publish.PUBLIC, "drained.js")] = \
        "window.DRAINED=" + json.dumps(hashes, separators=(",", ":")) + ";\n"
    edits[os.path.join(publish.PUBLIC, "data.js")] = \
        "window.SWEEP=" + json.dumps(sweep, separators=(",", ":")) + ";\n"

    # index.html: 7th wallet, count, total, meta
    idx = read(os.path.join(publish.PUBLIC, "index.html"))
    wallet_line = ('    {addr:"bc1qhh4jkkj07vxpdt0zlvxctjlfhqmurhxa24x3h2", '
                   'attributed:19153809,    baselineSpent:0,   origin:"seed"}')
    if wallet_line not in idx:
        raise SystemExit("could not find the last WALLETS entry to append after")
    new_wallet = (wallet_line + ',\n'
                  '    {addr:"%s", attributed:%d,  baselineSpent:0,   origin:"seed"}'
                  % (COLL, COLL_BALANCE))
    idx = idx.replace(wallet_line, new_wallet, 1)
    idx = idx.replace(f"var DRAINED_COUNT = {old_n};", f"var DRAINED_COUNT = {new_n};")
    idx = idx.replace(f'<span id="totalBtc">{old_total_disp}</span>',
                      f'<span id="totalBtc">{new_total_disp}</span>')
    idx = idx.replace(old_meta, new_meta)
    idx = publish.swap_count(idx, old_n, new_n)
    edits[os.path.join(publish.PUBLIC, "index.html")] = idx

    # list.html: count strings only
    edits[os.path.join(publish.PUBLIC, "list.html")] = \
        publish.swap_count(read(os.path.join(publish.PUBLIC, "list.html")), old_n, new_n)

    # methodology: the Galaxy row via the marker
    meth = read(os.path.join(publish.PUBLIC, "methodology.html"))
    row = ('<!-- xrow --><tr><td>31 Jul<br>04:54&ndash;08:36</td>'
           '<td>352 addresses<br>30.18 BTC</td><td>10.0 sat/vB</td>'
           '<td>A second wave-2 collector, reported by Galaxy Research on 1 Aug and '
           'verified here on-chain: 352 addresses swept into one address that has not '
           'moved, at a fee unrelated to the network rate. Distinct from the 50.2 sat/vB '
           'batch above.</td></tr><!-- /xrow -->')
    meth = re.sub(r'<!-- xrow -->.*?<!-- /xrow -->', row, meth, flags=re.S)
    edits[os.path.join(publish.PUBLIC, "methodology.html")] = meth

    # monitor: WATCHED + DRAINED_COUNT
    for m in publish.MONITORS:
        if not os.path.exists(m):
            continue
        s = read(m)
        anchor = '    "bc1qhh4jkkj07vxpdt0zlvxctjlfhqmurhxa24x3h2": 19153809,'
        if anchor not in s:
            raise SystemExit(f"could not find WATCHED anchor in {m}")
        s = s.replace(anchor, anchor + f'\n    "{COLL}": {COLL_BALANCE},')
        s = re.sub(r'DRAINED_COUNT = \d+', f"DRAINED_COUNT = {new_n}", s)
        edits[m] = s

    if dry:
        print(f"dry run. total {old_total_disp} -> {new_total_disp} BTC, "
              f"count {of} -> {nf}, wallets 6 -> 7")
        print("files that would change:", [os.path.basename(p) for p in edits])
        return 0

    baks = {}
    try:
        for path, content in edits.items():
            baks[path] = path + ".galbak"
            shutil.copy2(path, baks[path])
            tmp = path + ".tmp"
            open(tmp, "w", encoding="utf-8").write(content)
            os.replace(tmp, path)
        probs = publish.self_check(verbose=True)
        if probs:
            raise RuntimeError(f"invariants broken after edit: {probs}")
        # confirm the new total renders
        idx2 = read(os.path.join(publish.PUBLIC, "index.html"))
        assert new_total_disp in idx2 and COLL in idx2, "total/wallet not written"
    except Exception:
        for path, bak in baks.items():
            shutil.copy2(bak, path)
        raise
    finally:
        for bak in baks.values():
            if os.path.exists(bak):
                os.remove(bak)

    print("edits applied + self-check clean. Deploying...")
    url = publish.deploy()
    if not publish.verify_deployed(new_n):
        raise SystemExit(f"deployed ({url}) but live count != {new_n}; investigate")
    print(f"deployed and verified live: count {new_n}, total {new_total_disp} BTC")

    # record + telegram
    st = publish.load_state()
    st.setdefault("clusters", []).append(
        {"collector": COLL, "victims": len(new_v), "sats": COLL_BALANCE,
         "source": "Galaxy Research", "added_count": new_n})
    publish.save_state(st)
    publish.send_telegram(
        "ADDED a wave-2 cluster reported by Galaxy Research and verified on-chain.\n\n"
        f"{COLL}\n  {len(new_v)} victims, {COLL_BALANCE/1e8:.8f} BTC, held unspent\n\n"
        f"site total now {new_total_disp} BTC across 7 tracked addresses, {nf} drained "
        f"addresses.\n" + publish.SITE)
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
