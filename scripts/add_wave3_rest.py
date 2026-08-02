#!/usr/bin/env python3
"""
add_wave3_rest.py — add the 79 wave-3 vaults the first pass could not see.

The first reconstruction keyed on the SWEEP fee: 215 sweeps paying within a hair of
201 sat/vB while the network charged under 3. That found 214 vaults and it was correct
as far as it went, but it was measuring the wrong hop. The sweep fee was only the
urgent first batch. The rest of the wave swept at ordinary market rates, 2 to 100
sat/vB, so a fee gate built on the 201 constant could never see them.

What every vault in the wave shares is the SECOND hop. All 293 park addresses moved
their whole balance onward in block 960520, one input, one output, into a fresh P2WSH,
nLockTime 0, nSequence ffffffff, paying 10.03 to 10.08 sat/vB. Two hundred and ninety
three separate transactions in one block at a fee constant tight to five hundredths of
a sat/vB is one script, and it is the same convergence-of-fee test the site already
publishes on, applied where the invariant actually lives.

Every address here was checked against the chain independently: in the window, one
output and no change, vault still unspent, balance matching to the satoshi. Kelbie's
published reconstruction was the lead that pointed at the second hop; it is not the
authority for any address, and the overlap with the existing 214 agreed exactly, with
zero balance disagreements, before any of this was trusted.

Brings wave 3 to 293 vaults and 207.72939540 BTC.

usage: add_wave3_rest.py [--dry-run]
"""
import hashlib
import json
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import publish

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADD = "/tmp/add79.json"
T0 = 1785373820
WAVE_INDEX = 4
OLD_TOTAL_DISP = "1,359.1829"
OLD_META = "1,359.18 BTC"


def read(p):
    return open(p, encoding="utf-8").read()


def main():
    dry = "--dry-run" in sys.argv
    if publish.conflict_guard():
        raise SystemExit("syncthing conflict copies present, refusing")
    if publish.self_check(verbose=False):
        raise SystemExit("site invariants broken before edit; aborting")

    a = json.load(open(ADD))
    vaults, victims, blocks = a["vaults"], a["victims"], a["blocks"]
    if not all(v["unspent"] for v in vaults.values()):
        raise SystemExit("a vault has spent since the set was built; re-verify")

    drains, hashes, old_n = publish.parse_site()
    rows, blks = drains["rows"], drains["blocks"]
    have = {r[0] for r in rows}
    new_v = {k: v for k, v in victims.items() if k not in have}
    print(f"vaults +{len(vaults)}   victims +{len(new_v)}")

    h2i = {b["h"]: i for i, b in enumerate(blks)}
    for h, t in sorted((int(k), v) for k, v in blocks.items()):
        if h not in h2i:
            blks.append({"h": h, "t": t})
            h2i[h] = len(blks) - 1

    sweep = json.loads(re.search(r"window\.SWEEP\s*=\s*(.*)",
                                 read(os.path.join(publish.PUBLIC, "data.js")),
                                 re.S).group(1).rstrip().rstrip(";"))
    for addr, v in sorted(new_v.items()):
        h = v["height"]
        rows.append([addr, v["sats"], h2i[h]])
        hashes.append(hashlib.sha256(addr.encode()).hexdigest()[:16])
        sweep["events"].append([blocks[str(h)] - T0, v["sats"], WAVE_INDEX])
    new_n = len(rows)

    src = read(os.path.join(publish.PUBLIC, "wave3.js"))
    w3 = json.loads(re.search(r"window\.WAVE3=(.*);", src, re.S).group(1))
    known = {x[0] for x in w3["vaults"]}
    for addr, v in vaults.items():
        if addr not in known:
            w3["vaults"].append([addr, v["balance"]])
    w3["vaults"].sort(key=lambda x: -x[1])
    w3["count"] = len(w3["vaults"])
    w3["held"] = sum(b for _, b in w3["vaults"])
    w3["victims"] = w3.get("victims", 0) + len(new_v)
    new_total = 115884800000 + w3["held"]
    disp, meta = f"{new_total/1e8:,.4f}", f"{new_total/1e8:,.2f} BTC"
    print(f"wave 3: {w3['count']} vaults, {w3['held']/1e8:.8f} BTC")
    print(f"site:   {OLD_TOTAL_DISP} -> {disp} BTC   count {old_n:,} -> {new_n:,}")

    edits = {
        os.path.join(publish.PUBLIC, "drains.js"):
            "window.DRAINS=" + json.dumps({"blocks": blks, "rows": rows}, separators=(",", ":")) + ";\n",
        os.path.join(publish.PUBLIC, "drained.js"):
            "window.DRAINED=" + json.dumps(hashes, separators=(",", ":")) + ";\n",
        os.path.join(publish.PUBLIC, "data.js"):
            "window.SWEEP=" + json.dumps(sweep, separators=(",", ":")) + ";\n",
        os.path.join(publish.PUBLIC, "wave3.js"):
            "window.WAVE3=" + json.dumps(w3, separators=(",", ":")) + ";\n",
    }

    idx = read(os.path.join(publish.PUBLIC, "index.html"))
    idx = idx.replace(f"var DRAINED_COUNT = {old_n};", f"var DRAINED_COUNT = {new_n};")
    idx = idx.replace(f'<span id="totalBtc">{OLD_TOTAL_DISP}</span>',
                      f'<span id="totalBtc">{disp}</span>')
    idx = idx.replace(OLD_META, meta)
    idx = publish.swap_count(idx, old_n, new_n)
    edits[os.path.join(publish.PUBLIC, "index.html")] = idx

    lst = publish.swap_count(read(os.path.join(publish.PUBLIC, "list.html")), old_n, new_n)
    lst = lst.replace(OLD_META, meta)
    lst = re.sub(r"\d+ addresses holding [\d,.]+ BTC between them",
                 f"{w3['count']} addresses holding {w3['held']/1e8:,.4f} BTC between them", lst)
    edits[os.path.join(publish.PUBLIC, "list.html")] = lst

    meth = read(os.path.join(publish.PUBLIC, "methodology.html"))
    row = ('<!-- xrow --><tr><td>31 Jul<br>12:23&ndash;22:25</td>'
           f'<td>{len(new_v) + 1626:,} addresses<br>{w3["held"]/1e8:,.2f} BTC</td>'
           '<td>10.05 sat/vB<br>on the consolidation</td>'
           '<td>Reported by Galaxy Research on 1 Aug as a third wave and reconstructed here '
           'from the chain. No shared collector: each drained wallet was swept into its own '
           'fresh address, and every one of those then moved its whole balance onward in '
           'block 960520, one input and one output into a fresh P2WSH, at a hardcoded 10.03 '
           'to 10.08 sat/vB. Two hundred and ninety three separate transactions in one block '
           'at that constant is a single script. The sweeps into those addresses varied from '
           '2 to 201 sat/vB, which is why an earlier pass keyed on the sweep fee found only '
           '214 of them.</td></tr><!-- /xrow -->')
    meth = re.sub(r"<!-- xrow -->.*?<!-- /xrow -->", row, meth, flags=re.S)
    edits[os.path.join(publish.PUBLIC, "methodology.html")] = meth

    for m in publish.MONITORS:
        if os.path.exists(m):
            edits[m] = re.sub(r"DRAINED_COUNT = \d+", f"DRAINED_COUNT = {new_n}", read(m))

    if dry:
        print("dry run; would edit:", [os.path.basename(p) for p in edits])
        return 0

    baks = {}
    try:
        for path, content in edits.items():
            if os.path.exists(path):
                baks[path] = path + ".r79bak"
                shutil.copy2(path, baks[path])
            tmp = path + ".tmp"
            open(tmp, "w", encoding="utf-8").write(content)
            os.replace(tmp, path)
        probs = publish.self_check(verbose=True)
        if probs:
            raise RuntimeError(f"invariants broken: {probs}")
        assert disp in read(os.path.join(publish.PUBLIC, "index.html"))
    except Exception:
        for p, b in baks.items():
            shutil.copy2(b, p)
        print("rolled back", file=sys.stderr)
        raise
    finally:
        for b in baks.values():
            if os.path.exists(b):
                os.remove(b)

    print("edits applied + self-check clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
