#!/usr/bin/env python3
"""
add_wave3.py — put Wave 3 on the site.

Reads the frozen set from wave3_publish_set.py (215 sweeps in the 195-210 sat/vB band,
1,626 victim addresses, 214 fresh P2WSH vaults holding 200.33487536 BTC, all unspent)
and writes every coupled surface atomically, rolling back all of it on any failure.

Why the 214 vaults do NOT join WALLETS. That array is the live-tracked set: it drives the
websocket subscription, a single blockchain.info batch URL, and the follow-the-money
trace, and it is capped at MAX_TRACKED = 40. 214 more addresses would blow the cap, build
a 9KB request URL, and turn the money section into a 214-row wall. So Wave 3 lands in its
own window.WAVE3 dataset: counted in the headline, listed in full on the list page, and
refreshed by wave3_refresh.py rather than streamed to the browser. The page says so.

The timer is deliberately untouched. "Since coins last moved" anchors on lastMoveTs, which
is set only when an address in WALLETS spends. Every Wave 3 movement is older than the
wave-5 vault spend the timer already points at (park->vault ran to block 960522 on 1 Aug
06:41 UTC; the wave-5 spend is block 960610 on 1 Aug 19:17 UTC), and the page only ever
advances that anchor to a strictly later timestamp. Wave 3 vaults are all unspent, so they
have no spend to contribute either way.

SWEEP_END does move, from the wave-4 consolidation to the last Wave 3 sweep (block 960471,
31 Jul 22:25 UTC), because that is now genuinely where the drain window ends and the chart
splits its two time scales there. It is only a fallback for the timer, never the anchor
while a real movement is known.

usage: add_wave3.py [--dry-run]
"""
import hashlib
import json
import os
import re
import shutil
import sys

import subprocess
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import publish

HERE = os.path.dirname(os.path.abspath(__file__))


def js_check(name, html):
    """node --check every inline script block. The rule on this project is that a
    frontend change is verified by syntax check and reading, never by a browser."""
    blocks = re.findall(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', html, re.S)
    for k, b in enumerate(blocks):
        if not b.strip():
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(b)
            p = f.name
        try:
            r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
            if r.returncode != 0:
                raise SystemExit(f"{name}: inline script #{k+1} is invalid JS\n{r.stderr}")
        finally:
            os.unlink(p)
    return len(blocks)
SET = os.path.join(HERE, "wave3-set.json")

WAVE_INDEX = 4                      # chart metadata only; the curve does not colour by it
T0 = 1785373820
NEW_SWEEP_END = 1785536717          # block 960471, last Wave 3 sweep
NEW_SWEEP_END_HEIGHT = 960471
OLD_SWEEP_END = 1785489777
OLD_SWEEP_END_HEIGHT = 960377

OLD_TOTAL = 115884800000            # sats, the seven live-tracked addresses
OLD_TOTAL_DISP = "1,158.8480"
OLD_META = "1,158.85 BTC"


def read(p):
    return open(p, encoding="utf-8").read()


def main():
    dry = "--dry-run" in sys.argv

    if publish.conflict_guard():
        raise SystemExit(f"syncthing conflict copies present, refusing")
    if publish.self_check(verbose=False):
        raise SystemExit("site invariants broken before edit; aborting")

    s = json.load(open(SET))
    victims, vaults, wblocks = s["victims"], s["vaults"], s["blocks"]
    held = s["held_sats"]
    if not all(v["unspent"] for v in vaults.values()):
        raise SystemExit("a vault has spent since the set was frozen; re-run the detector")

    drains, hashes, old_n = publish.parse_site()
    rows, blocks = drains["rows"], drains["blocks"]
    have = {r[0] for r in rows}
    new_v = {a: v for a, v in victims.items() if a not in have}
    print(f"victims: {len(victims)} in set, {len(new_v)} new")
    print(f"vaults : {len(vaults)} holding {held/1e8:.8f} BTC")

    # blocks
    h2i = {b["h"]: i for i, b in enumerate(blocks)}
    for h, t in sorted((int(k), v) for k, v in wblocks.items()):
        if h not in h2i:
            blocks.append({"h": h, "t": t})
            h2i[h] = len(blocks) - 1

    # rows + hashes + chart events
    sweep_src = read(os.path.join(publish.PUBLIC, "data.js"))
    sweep = json.loads(re.search(r'window\.SWEEP\s*=\s*(.*)', sweep_src, re.S)
                       .group(1).rstrip().rstrip(";"))
    added = 0
    for a, v in sorted(new_v.items()):
        h = v["height"]
        rows.append([a, v["sats"], h2i[h]])
        hashes.append(hashlib.sha256(a.encode()).hexdigest()[:16])
        sweep["events"].append([wblocks[str(h)] - T0, v["sats"], WAVE_INDEX])
        added += v["sats"]
    new_n = len(rows)
    new_total = OLD_TOTAL + held
    new_total_disp = f"{new_total/1e8:,.4f}"
    new_meta = f"{new_total/1e8:,.2f} BTC"
    of, nf = f"{old_n:,}", f"{new_n:,}"
    print(f"count {of} -> {nf}; victim inputs added {added/1e8:.8f} BTC")
    print(f"total {OLD_TOTAL_DISP} -> {new_total_disp} BTC")

    edits = {}
    edits[os.path.join(publish.PUBLIC, "drains.js")] = \
        "window.DRAINS=" + json.dumps({"blocks": blocks, "rows": rows},
                                      separators=(",", ":")) + ";\n"
    edits[os.path.join(publish.PUBLIC, "drained.js")] = \
        "window.DRAINED=" + json.dumps(hashes, separators=(",", ":")) + ";\n"
    edits[os.path.join(publish.PUBLIC, "data.js")] = \
        "window.SWEEP=" + json.dumps(sweep, separators=(",", ":")) + ";\n"

    # the Wave 3 dataset, snapshot-refreshed rather than streamed
    vlist = sorted(vaults.values(), key=lambda v: -v["balance"])
    edits[os.path.join(publish.PUBLIC, "wave3.js")] = "window.WAVE3=" + json.dumps({
        "held": held, "count": len(vlist), "victims": len(victims),
        "verified": s["generated"], "band": s["band"],
        "vaults": [[v["addr"], v["balance"]] for v in vlist],
    }, separators=(",", ":")) + ";\n"

    # ---- index.html
    idx = read(os.path.join(publish.PUBLIC, "index.html"))

    tag = '<script src="/drained.js"></script>'
    if tag not in idx:
        raise SystemExit("could not find the drained.js script tag")
    idx = idx.replace(tag, tag + '\n<script src="/wave3.js"></script>', 1)

    anchor = "  var MAX_TRACKED   = 40;"
    if anchor not in idx:
        raise SystemExit("could not find MAX_TRACKED to anchor the WAVE3 binding")
    idx = idx.replace(anchor,
        "  // Wave 3 gave every victim wallet its own vault, so there are 214 of them and they\n"
        "  // cannot be live-polled from a browser the way the seven collectors are. They are\n"
        "  // counted here from a snapshot the scanner refreshes, and listed in full on /list.html.\n"
        "  var WAVE3 = window.WAVE3 || {held:0, count:0, vaults:[], verified:0};\n"
        + anchor, 1)

    old_held = ("  function heldTotal(){\n"
                "    var t = 0;\n"
                "    WALLETS.forEach(function(w){ t += effective(w); });\n"
                "    return t;\n"
                "  }")
    if old_held not in idx:
        raise SystemExit("could not find heldTotal to extend")
    idx = idx.replace(old_held,
        "  function heldTotal(){\n"
        "    var t = 0;\n"
        "    WALLETS.forEach(function(w){ t += effective(w); });\n"
        "    return t + (WAVE3.held || 0);\n"
        "  }", 1)

    old_count = ('    var n = WALLETS.length;\n'
                 '    el("addrCount").textContent = n === 6\n'
                 '      ? "The six addresses the drains paid into. Nothing has left them."\n'
                 '      : n + " addresses tracked. The trail below updates as coins move.";')
    if old_count not in idx:
        raise SystemExit("could not find the addrCount block")
    idx = idx.replace(old_count,
        '    if (WAVE3.count && !el("w3row")){\n'
        '      var r = document.createElement("div");\n'
        '      r.className = "row"; r.id = "w3row";\n'
        '      r.innerHTML = \'<span class="a">\' + WAVE3.count + \' separate vaults, one per drained wallet\'\n'
        '        + \' <a href="/list.html#wave3">see all of them</a></span>\'\n'
        '        + \'<span class="b"><span class="bal">\' + fmt(btc(WAVE3.held),4)\n'
        '        + \'</span><span class="unit">BTC</span></span>\'\n'
        '        + \'<span class="s"><span class="dot"></span><span class="st">holding</span></span>\';\n'
        '      rowsHost.appendChild(r);\n'
        '    }\n'
        '    var n = WALLETS.length + (WAVE3.count || 0);\n'
        '    el("addrCount").textContent = n + " addresses hold the proceeds. The seven below stream live; "\n'
        '      + "the Wave 3 vaults are checked by the scanner and listed on the address list.";', 1)

    idx = idx.replace(f"var DRAINED_COUNT = {old_n};", f"var DRAINED_COUNT = {new_n};")
    idx = idx.replace(f'<span id="totalBtc">{OLD_TOTAL_DISP}</span>',
                      f'<span id="totalBtc">{new_total_disp}</span>')
    idx = idx.replace(OLD_META, new_meta)
    idx = idx.replace(f"var SWEEP_END   = {OLD_SWEEP_END};",
                      f"var SWEEP_END   = {NEW_SWEEP_END};")
    idx = idx.replace(f"var SWEEP_END_HEIGHT = {OLD_SWEEP_END_HEIGHT};",
                      f"var SWEEP_END_HEIGHT = {NEW_SWEEP_END_HEIGHT};")
    idx = publish.swap_count(idx, old_n, new_n)
    edits[os.path.join(publish.PUBLIC, "index.html")] = idx

    # ---- list.html: counts, plus the vault list
    lst = publish.swap_count(read(os.path.join(publish.PUBLIC, "list.html")), old_n, new_n)
    lst = lst.replace(OLD_META, new_meta)
    marker = "</main>"
    if marker not in lst:
        raise SystemExit("could not find </main> in list.html")
    sec = (
        '<section id="wave3" style="max-width:1080px;margin:0 auto;padding:48px 24px">\n'
        '  <h2 style="font-size:1rem;font-weight:500;color:#c9cfd6;margin:0 0 8px">'
        'Wave 3 vaults</h2>\n'
        '  <p style="color:#c9cfd6;margin:0 0 16px;font-size:.92rem">'
        f'{len(vlist)} addresses holding {held/1e8:,.4f} BTC between them, one for each drained '
        'wallet rather than a shared collector. Every one is unspent. Balances here are a '
        'snapshot the scanner refreshes, not a live stream.</p>\n'
        '  <div id="w3list" style="display:grid;gap:1px;background:#1e2128;border:1px solid '
        '#1e2128;border-radius:10px;overflow:hidden;font-size:.82rem"></div>\n'
        '</section>\n'
        '<script src="/wave3.js"></script>\n'
        '<script>(function(){var h=document.getElementById("w3list");'
        'if(!h||!window.WAVE3)return;var f=document.createDocumentFragment();'
        'WAVE3.vaults.forEach(function(v){var d=document.createElement("div");'
        'd.style.cssText="background:#14161a;padding:10px 16px;display:flex;gap:16px;'
        'justify-content:space-between;align-items:center";'
        'd.innerHTML=\'<a href="https://mempool.space/address/\'+v[0]+\'" target="_blank" '
        'rel="noopener" style="color:#a4acb6;word-break:break-all">\'+v[0]+\'</a>\'+'
        '\'<span style="color:#f2f4f7;white-space:nowrap;font-variant-numeric:tabular-nums">\'+'
        '(v[1]/1e8).toFixed(8)+\' BTC</span>\';f.appendChild(d);});h.appendChild(f);})();</script>\n'
    )
    lst = lst.replace(marker, marker + "\n" + sec, 1)
    edits[os.path.join(publish.PUBLIC, "list.html")] = lst

    # ---- methodology.html
    meth = read(os.path.join(publish.PUBLIC, "methodology.html"))

    old_li = ("    <li>Every input is a single-signature native segwit key. No multisig appears "
              "anywhere in the set.</li>")
    if old_li not in meth:
        raise SystemExit("could not find the multisig line in methodology.html")
    meth = meth.replace(old_li,
        "    <li>Every input is a single-signature native segwit key, the default path of the "
        "affected wallet.</li>", 1)

    # Another session rewrote this paragraph into the "convergence" argument at 20:38 on
    # 1 Aug. That argument is right for the collector waves and is kept word for word; it
    # just cannot cover Wave 3, which has no shared destination by construction. So the
    # claim is scoped to the waves it holds for and a second paragraph carries Wave 3.
    conv = "An address is listed here only when its sweep is part of that convergence."
    if conv not in meth:
        raise SystemExit("could not find the convergence sentence; methodology.html changed "
                         "again, re-read it before editing")
    meth = meth.replace(conv,
        "In the first, second and fifth clusters, an address is listed here only when its sweep "
        "is part of that convergence.\n"
        "  </p>\n"
        "  <p>\n"
        "    Wave 3 removed that convergence on purpose, and it is why this site missed it for two "
        "days. Each drained wallet was swept into its own fresh address and then forwarded into its "
        "own fresh P2WSH vault, 214 of them, sharing nothing for a detector to key on. What survives "
        "is the fee. Its 215 sweeps all paid within a hair of 201 sat/vB while the network was "
        "charging under 3, and a rate that constant across transactions that share no address is a "
        "number hardcoded in a script rather than 215 separate people picking the same urgent fee. "
        "Sixteen further chains matched the shape but paid scattered rates, and they were left off "
        "this site rather than published on shape alone. So an address enters this set through one "
        "of two convergences, of destination or of fee, and never through shape alone.", 1)

    old_cannot = ("    The detector looks for one specific shape. A thief who signs many recovered keys "
                  "into a single\n    transaction, uses an address type other than single-signature "
                  "native segwit, varies the fee from one\n    sweep to the next, or spreads a theft "
                  "thinly enough that no single block holds a group would not match\n    it.")
    if old_cannot in meth:
        meth = meth.replace(old_cannot,
            "    The detector now looks for two shapes rather than one, but both are still shapes. A "
            "thief who\n    uses an address type other than single-signature native segwit, varies the "
            "fee from one sweep to\n    the next, or spreads a theft thinly enough that no block holds "
            "a group would still not match it.\n    Wave 3 is the worked example: removing the shared "
            "collector made every detector on this site blind\n    to it until the fee constant was "
            "used instead.", 1)
    else:
        print("  note: 'what this cannot see' paragraph not matched, left as-is")

    row = ('<!-- xrow --><tr><td>31 Jul<br>12:23&ndash;22:25</td>'
           '<td>1,626 addresses<br>200.33 BTC</td><td>201.0 sat/vB</td>'
           '<td>Reported by Galaxy Research on 1 Aug as a third wave and reconstructed here '
           'independently from the chain. No shared collector: each drained wallet was swept '
           'into its own fresh address and forwarded into its own fresh P2WSH vault, 214 of them, '
           'all unspent. Galaxy published no addresses for this wave, so every address here comes '
           'from this reconstruction; their reported total of 207.73 BTC is 2.2% above what is '
           'shown, and the difference is small chains this site has not confirmed.</td></tr>'
           '<!-- /xrow -->')
    if "<!-- /xrow -->" not in meth:
        raise SystemExit("could not find the xrow marker in methodology.html")
    meth = meth.replace("<!-- /xrow -->", "<!-- /xrow -->" + row, 1)
    edits[os.path.join(publish.PUBLIC, "methodology.html")] = meth

    # ---- monitors
    for m in publish.MONITORS:
        if os.path.exists(m):
            edits[m] = re.sub(r'DRAINED_COUNT = \d+', f"DRAINED_COUNT = {new_n}", read(m))

    n_idx = js_check("index.html", edits[os.path.join(publish.PUBLIC, "index.html")])
    n_lst = js_check("list.html", edits[os.path.join(publish.PUBLIC, "list.html")])
    print(f"js syntax OK (index.html {n_idx} inline blocks, list.html {n_lst})")
    for f in ("data.js", "drained.js", "drains.js", "wave3.js"):
        p = os.path.join(publish.PUBLIC, f)
        json.loads(re.search(r'window\.\w+\s*=\s*(.*)', edits[p], re.S)
                   .group(1).rstrip().rstrip(";"))
    print("dataset files parse as JSON")

    if dry:
        print("\ndry run. files that would change:")
        for p in edits:
            print("   ", os.path.basename(p))
        return 0

    baks = {}
    try:
        for path, content in edits.items():
            if os.path.exists(path):
                baks[path] = path + ".w3bak"
                shutil.copy2(path, baks[path])
            tmp = path + ".tmp"
            open(tmp, "w", encoding="utf-8").write(content)
            os.replace(tmp, path)
        probs = publish.self_check(verbose=True)
        if probs:
            raise RuntimeError(f"invariants broken after edit: {probs}")
        idx2 = read(os.path.join(publish.PUBLIC, "index.html"))
        assert new_total_disp in idx2, "new total not written"
        assert "wave3.js" in idx2, "wave3.js not wired"
        assert f"var SWEEP_END   = {NEW_SWEEP_END};" in idx2, "SWEEP_END not moved"
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
    print(f"deployed and verified: count {new_n}, total {new_total_disp} BTC")

    st = publish.load_state()
    st.setdefault("clusters", []).append(
        {"wave": 3, "vaults": len(vlist), "victims": len(new_v), "sats": held,
         "source": "Galaxy Research + reconstructed here", "added_count": new_n})
    publish.save_state(st)
    publish.send_telegram(
        "ADDED Wave 3, reconstructed here from the chain.\n\n"
        f"{len(vlist)} P2WSH vaults, {held/1e8:.8f} BTC, all unspent\n"
        f"{len(new_v)} newly listed drained addresses\n\n"
        f"site total now {new_total_disp} BTC, {nf} drained addresses.\n" + publish.SITE)
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
