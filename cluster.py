#!/usr/bin/env python3
"""
cluster.py — resolve an attacker collector to its victims, verify it against the
drain fingerprint, and add the whole cluster to the site in one atomic pass.

This is the generalized form of the one-off add_galaxy_cluster.py. autopilot.py
calls add_cluster() once a candidate has cleared a proof tier. Everything here is
deterministic; no model judgement is involved in what gets written.

Public functions:
  collector_victims(coll)   -> (victims: {addr:{sats,height,time}}, total_sats, balance)
  cluster_fingerprint(coll) -> verdict dict (unspent, fee uniformity, window, fresh)
  add_cluster(coll, source, note, dry=False, st=None) -> result dict
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

import publish

T0 = 1785373820                    # chart origin, first drain block time
FRESH_MAX_UNRELATED = 8            # a collector's history is the incident; a service has more

# Both walks below page through an address's whole history 25 transactions at a
# time. A real collector in this incident has a few hundred; a service has
# hundreds of thousands, and nothing stopped the walk from following it forever.
# One unbounded walk is what let a run sit for four hours holding the pipeline
# lock. 200 pages is 5,000 transactions, far past any genuine cluster here.
MAX_PAGES = 200


def _read(p):
    return open(p, encoding="utf-8").read()


def collector_victims(coll):
    """Every address that swept into `coll`, with amount, block height and time.
    Deterministic: reads the confirmed chain history."""
    victims, seen = {}, set()
    last = None
    pages = 0
    while pages < MAX_PAGES:
        pages += 1
        path = f"/address/{coll}/txs/chain" + (f"/{last}" if last else "")
        page = publish.esplora(path)
        if not page:
            break
        for t in page:
            if not any(o.get("scriptpubkey_address") == coll for o in t.get("vout", [])):
                continue
            st = t.get("status", {})
            for i in t.get("vin", []):
                p = i.get("prevout") or {}
                a = p.get("scriptpubkey_address")
                if a and a != coll:
                    v = victims.setdefault(a, {"sats": 0, "height": st.get("block_height"),
                                               "time": st.get("block_time")})
                    v["sats"] += p.get("value", 0)
        if len(page) < 25:
            break
        last = page[-1]["txid"]
        time.sleep(0.3)
    info = publish.esplora(f"/address/{coll}")
    c = info["chain_stats"]
    balance = c["funded_txo_sum"] - c["spent_txo_sum"]
    total = sum(v["sats"] for v in victims.values())
    return victims, total, balance, c


def js_parses(html, label="index.html"):
    """Does every inline script in this page parse? Returns (ok, message).

    A publish ends in deploy(), which ships the WHOLE public/ directory rather than the
    files the add touched. Whatever is sitting in there goes live, and this repo's working
    tree is carried between machines by syncthing, so another session's half-written script
    can be in the directory a cron is about to deploy. One unparseable script takes the
    whole page down: the first error stops every line after it, so the headline, the chart
    and the address checker all die at once.

    Cheap insurance against that, and it never blocks on its own tooling — if node is not
    installed the check reports ok and says why, rather than stopping a publish over a
    missing dev dependency."""
    try:
        subprocess.run(["node", "--version"], capture_output=True, timeout=10, check=True)
    except Exception:
        return True, "node unavailable; inline scripts not checked"
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S | re.I)
    for i, src in enumerate(blocks):
        if not src.strip():
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
            fh.write(src)
            tmp = fh.name
        try:
            r = subprocess.run(["node", "--check", tmp], capture_output=True,
                               text=True, timeout=30)
        finally:
            os.unlink(tmp)
        if r.returncode != 0:
            first = (r.stderr or "").strip().splitlines()
            return False, (f"{label} inline script #{i + 1} does not parse: "
                           + (first[1] if len(first) > 1 else (first[0] if first else "?")))
    return True, f"{len(blocks)} inline script(s) parse"


def forwarded_to(coll, txs=None):
    """The single fresh address a collector emptied itself into, or None.

    The two-hop shape: sweeps pool into `coll`, then `coll` sends the whole balance onward
    in one transaction with no change. Wave 3 was built this way and so was the cluster
    reported on 2026-08-05, and the detector treats a collector that did this as worthless
    twice over — it reads as spent, and its balance reads as zero, so the dust floor drops
    it. The money is one hop down, still sitting there.

    Deliberately narrow. Exactly one spending transaction, exactly one output, and no
    change back to the collector. Anything else (several spends, a peel with change, a
    split) is not this shape and returns None rather than a guess."""
    if txs is None:
        txs = publish.esplora(f"/address/{coll}/txs")
    spends = [t for t in txs
              if any((i.get("prevout") or {}).get("scriptpubkey_address") == coll
                     for i in t.get("vin", []))]
    if len(spends) != 1:
        return None
    outs = spends[0].get("vout", [])
    if len(outs) != 1:
        return None
    dst = outs[0].get("scriptpubkey_address")
    return dst if dst and dst != coll else None


def cluster_fingerprint(coll):
    """Deterministic read of whether `coll` looks like an attacker collector:
    many no-change single-output sweeps at one hardcoded fee, in a tight window,
    fresh (not a service). Returns the evidence, never a publish decision."""
    v = {"collector": coll, "victims": 0, "total_sats": 0, "balance": 0,
         "unspent": None, "fee_rates": {}, "fee_uniform": False,
         "no_change_ratio": 0.0, "block_span": None, "fresh": None,
         "forwards_to_anchor": None, "hold_addr": None, "evidence": []}
    txs = []
    last = None
    pages = 0
    while pages < MAX_PAGES:
        pages += 1
        page = publish.esplora(f"/address/{coll}/txs/chain" + (f"/{last}" if last else ""))
        if not page:
            break
        txs.extend(page)
        if len(page) < 25:
            break
        last = page[-1]["txid"]
        time.sleep(0.3)

    funding = [t for t in txs
               if any(o.get("scriptpubkey_address") == coll for o in t.get("vout", []))]
    if not funding:
        v["evidence"].append("no funding transactions found")
        return v

    no_change = 0
    rates = {}
    heights, victims = [], set()
    for t in funding:
        outs, ins = t.get("vout", []), t.get("vin", [])
        if len(outs) == 1:
            no_change += 1
        w = t.get("weight") or 0
        if w:
            r = round(t.get("fee", 0) / (w / 4.0), 1)
            rates[r] = rates.get(r, 0) + 1
        h = (t.get("status") or {}).get("block_height")
        if h:
            heights.append(h)
        for i in ins:
            a = (i.get("prevout") or {}).get("scriptpubkey_address")
            if a and a != coll:
                victims.add(a)

    info = publish.esplora(f"/address/{coll}")
    c = info["chain_stats"]
    v["balance"] = c["funded_txo_sum"] - c["spent_txo_sum"]
    v["unspent"] = c["spent_txo_sum"] == 0
    v["victims"] = len(victims)
    # A collector that emptied itself in one no-change forward has not spent the money, it
    # has parked it one hop down. Judge "still holding" where the coins actually are, and
    # report the address so the caller can track that one instead.
    if not v["unspent"] and v["balance"] == 0:
        fwd = forwarded_to(coll, txs)
        if fwd:
            fi = publish.esplora(f"/address/{fwd}")["chain_stats"]
            v["hold_addr"] = fwd
            v["balance"] = fi["funded_txo_sum"] - fi["spent_txo_sum"]
            v["unspent"] = fi["spent_txo_sum"] == 0
            v["evidence"].append(
                f"forwarded its whole balance once into {fwd[:16]}…, which holds "
                f"{v['balance']/1e8:.8f} BTC and is "
                + ("unspent" if v["unspent"] else "already spent"))
    v["total_sats"] = sum((i.get("prevout") or {}).get("value", 0)
                          for t in funding for i in t.get("vin", []))
    v["fee_rates"] = dict(sorted(rates.items()))
    v["no_change_ratio"] = round(no_change / len(funding), 3)
    if heights:
        v["block_span"] = [min(heights), max(heights)]
    # fee uniformity: one rate (or an adjacent pair like 10.0/10.1) dominates the batch
    if rates:
        top = sorted(rates.items(), key=lambda kv: -kv[1])
        dom = top[0][1]
        if len(top) > 1 and abs(top[0][0] - top[1][0]) <= 0.2:
            dom += top[1][1]
        v["fee_uniform"] = dom / len(funding) >= 0.9
    # freshness: a collector's whole history is this incident
    unrelated = c["funded_txo_count"] - len(funding)
    v["fresh"] = unrelated <= max(FRESH_MAX_UNRELATED, len(funding) * 0.25)
    if v["fee_uniform"]:
        v["evidence"].append(f"one hardcoded fee rate dominates {len(funding)} sweeps: "
                             f"{v['fee_rates']}")
    if v["no_change_ratio"] >= 0.9:
        v["evidence"].append(f"{v['no_change_ratio']*100:.0f}% single-output, no-change sweeps")
    if v["unspent"]:
        v["evidence"].append(f"holds {v['balance']/1e8:.8f} BTC, never spent (fresh vault)")
    if not v["fresh"]:
        v["evidence"].append(f"NOT fresh: {c['funded_txo_count']} deposits total "
                             f"(possible service, needs a human)")
    return v


def _wave_for(sweep, blocktime):
    """Pick the chart colour-band for a new sweep: join an existing wave whose time
    range contains this block, else allocate a fresh band."""
    bands = {}
    for off, _sats, w in sweep["events"]:
        lo, hi = bands.get(w, (1e18, 0))
        bands[w] = (min(lo, off), max(hi, off))
    off = blocktime - T0
    for w, (lo, hi) in bands.items():
        if lo - 3600 <= off <= hi + 3600:
            return w
    return (max(bands) + 1) if bands else 0


def holds_downstream_of(hold_addr, coll):
    """Is `hold_addr` funded by a transaction that spends from `coll`?

    The guard on hold_addr below. Without it, a typo or a bad call would attach an
    unrelated address's balance to this cluster's victims and put someone else's coins in
    the headline. One hop only, because that is the shape this exists for: a collector that
    pooled the sweeps and then forwarded the lot onward."""
    try:
        txs = publish.esplora(f"/address/{hold_addr}/txs")
    except Exception:
        return False
    for t in txs:
        if not any(o.get("scriptpubkey_address") == hold_addr for o in t.get("vout", [])):
            continue
        srcs = {(i.get("prevout") or {}).get("scriptpubkey_address") for i in t.get("vin", [])}
        if coll in srcs:
            return True
    return False


def add_cluster(coll, source, note, dry=False, st=None, min_victims=3, hold_addr=None):
    """Atomically add collector `coll` and its victims to every coupled surface,
    deploy, verify the live bytes, log, and Telegram-notify. `source`/`note` become
    the methodology-row attribution. Rolls back every file on any failure.

    `hold_addr` is for the two-hop shape wave 3 already established and the balance check
    below would otherwise reject: the sweeps pool into `coll`, and `coll` immediately
    forwards everything into a fresh address that then sits. The victims belong to `coll`,
    the money is at `hold_addr`, and tracking either one alone is wrong. When it is given,
    victims still come from `coll` and only the tracked balance moves. It must be one hop
    downstream of `coll` or this refuses.
    """
    if publish.conflict_guard():
        raise RuntimeError("syncthing conflict copies present; refusing to edit")
    if publish.self_check(verbose=False):
        raise RuntimeError("site invariants broken before edit")

    victims, total, balance, cstats = collector_victims(coll)
    track = coll
    if hold_addr and hold_addr != coll:
        if not holds_downstream_of(hold_addr, coll):
            return {"added": 0, "reason": f"{hold_addr} is not funded by a spend from "
                    f"{coll}; refusing to attach its balance to this cluster"}
        hi = publish.esplora(f"/address/{hold_addr}")["chain_stats"]
        balance = hi["funded_txo_sum"] - hi["spent_txo_sum"]
        track = hold_addr
    if balance < 2_000_000:      # < 0.02 BTC held: an emptied/peeled address, never track it
        return {"added": 0, "reason": f"collector holds only {balance/1e8:.8f} BTC; "
                "funds moved on, tracking address would be wrong"}
    drains, hashes, old_n = publish.parse_site()
    rows, blocks = drains["rows"], drains["blocks"]
    have = {r[0] for r in rows}
    new_v = {a: d for a, d in victims.items() if a not in have}
    if len(new_v) < min_victims:
        return {"added": 0, "reason": f"only {len(new_v)} new victims (< {min_victims})"}

    sweep_src = _read(os.path.join(publish.PUBLIC, "data.js"))
    sweep = json.loads(re.search(r'window\.SWEEP\s*=\s*(.*)', sweep_src, re.S)
                       .group(1).rstrip().rstrip(";"))

    # fetch block times we do not already have
    need_h = {d["height"] for d in new_v.values() if d.get("height")}
    h2t = {b["h"]: b["t"] for b in blocks}
    for h in sorted(need_h):
        if h not in h2t:
            bh = publish.esplora_text(f"/block-height/{h}")
            h2t[h] = publish.esplora(f"/block/{bh}")["timestamp"]

    h2i = {b["h"]: i for i, b in enumerate(blocks)}
    for h in sorted(need_h):
        if h not in h2i:
            blocks.append({"h": h, "t": h2t[h]})
            h2i[h] = len(blocks) - 1

    for a, d in new_v.items():
        h = d["height"]
        rows.append([a, d["sats"], h2i[h]])
        hashes.append(hashlib.sha256(a.encode()).hexdigest()[:16])
        sweep["events"].append([h2t[h] - T0, d["sats"], _wave_for(sweep, h2t[h])])

    new_n = len(rows)
    # Recompute the displayed total the SAME way the page's heldTotal() does:
    # sum of every seed/traced wallet's attributed value PLUS the wave-3 pool held
    # in wave3.js. Summing only attributed:N drops the wave-3 contribution
    # (~200 BTC) and regresses the headline, so wave3.held is added back here.
    idx = _read(os.path.join(publish.PUBLIC, "index.html"))
    wallet_sats = [int(x) for x in re.findall(r'attributed:(\d+)', idx)]
    wave3_held = 0
    w3path = os.path.join(publish.PUBLIC, "wave3.js")
    if os.path.exists(w3path):
        m3 = re.search(r'"held"\s*:\s*(\d+)', _read(w3path))
        if m3:
            wave3_held = int(m3.group(1))
    new_total = sum(wallet_sats) + wave3_held + balance
    old_total_disp = re.search(r'id="totalBtc">([\d,.]+)<', idx).group(1)
    new_total_disp = f"{new_total/1e8:,.4f}"
    of, nf = f"{old_n:,}", f"{new_n:,}"

    edits = {}
    edits[os.path.join(publish.PUBLIC, "drains.js")] = \
        "window.DRAINS=" + json.dumps({"blocks": blocks, "rows": rows},
                                      separators=(",", ":")) + ";\n"
    edits[os.path.join(publish.PUBLIC, "drained.js")] = \
        "window.DRAINED=" + json.dumps(hashes, separators=(",", ":")) + ";\n"
    edits[os.path.join(publish.PUBLIC, "data.js")] = \
        "window.SWEEP=" + json.dumps(sweep, separators=(",", ":")) + ";\n"

    # 7th+ wallet appended after the last WALLETS entry
    last_wallet = re.findall(r'\{addr:"bc1[^"]+", attributed:\d+[^\}]*\}', idx)[-1]
    new_wallet = (last_wallet + ',\n    {addr:"%s", attributed:%d,  baselineSpent:0,   '
                  'origin:"seed"}' % (track, balance))
    idx = idx.replace(last_wallet, new_wallet, 1)
    idx = idx.replace(f"var DRAINED_COUNT = {old_n};", f"var DRAINED_COUNT = {new_n};")
    idx = idx.replace(f'id="totalBtc">{old_total_disp}</span>',
                      f'id="totalBtc">{new_total_disp}</span>')
    # meta headline BTC figure (2 decimals)
    idx = re.sub(r'(A live chart of the )[\d,]+\.\d+( BTC)',
                 lambda m: m.group(1) + f"{new_total/1e8:,.2f}" + m.group(2), idx)
    idx = publish.swap_count(idx, old_n, new_n)
    # A cluster whose collector already forwarded its coins moved money, and that movement
    # can be more recent than the clock the page displays. It is invisible to the routine
    # refresh, which walks downstream from the tracked addresses only, so the collector is
    # seeded explicitly here. Without this the page claimed the coins had sat untouched
    # since a timestamp ten hours before the cluster it had just published last moved.
    idx, moved_ts = publish.apply_last_move(idx, extra_seeds=[coll, track])
    edits[os.path.join(publish.PUBLIC, "index.html")] = idx

    edits[os.path.join(publish.PUBLIC, "list.html")] = \
        publish.swap_count(_read(os.path.join(publish.PUBLIC, "list.html")), old_n, new_n)

    meth = _read(os.path.join(publish.PUBLIC, "methodology.html"))
    if "<!-- xrow -->" in meth:
        span = f"blocks {h2i and min(need_h)}&ndash;{max(need_h)}" if need_h else ""
        row = ('<!-- xrow --><tr><td>Added<br>%s</td><td>%d addresses<br>%.2f BTC</td>'
               '<td>%s</td><td>%s</td></tr><!-- /xrow -->'
               % (time.strftime("%d %b", time.gmtime()), len(new_v), balance / 1e8,
                  _fee_label(coll), note))
        meth = re.sub(r'<!-- xrow -->.*?<!-- /xrow -->', row, meth, flags=re.S)
        edits[os.path.join(publish.PUBLIC, "methodology.html")] = meth

    for m in publish.MONITORS:
        if not os.path.exists(m):
            continue
        s = _read(m)
        anchor = '    "bc1qhh4jkkj07vxpdt0zlvxctjlfhqmurhxa24x3h2": 19153809,'
        if anchor in s and f'"{track}"' not in s:
            s = s.replace(anchor, anchor + f'\n    "{track}": {balance},')
        # No expected-count is written here any more. The monitor derives it from the
        # served page, because this file reaches the box that runs it by syncthing and a
        # publish always beat the sync, reporting a healthy site as broken.
        edits[m] = s

    # Refuse to ship a page whose scripts do not parse. deploy() sends the whole public/
    # directory, so this catches a half-written edit sitting in the tree beside the add.
    ok, why = js_parses(edits[os.path.join(publish.PUBLIC, "index.html")])
    if not ok:
        return {"added": 0, "reason": f"refusing to publish: {why}"}

    if dry:
        return {"added": 0, "dry": len(new_v), "collector": coll, "js": why,
                "new_count": new_n, "new_total": new_total_disp, "balance": balance}

    baks = {}
    deployed = False
    try:
        for path, content in edits.items():
            baks[path] = path + ".clbak"
            shutil.copy2(path, baks[path])
            tmp = path + ".tmp"
            open(tmp, "w", encoding="utf-8").write(content)
            os.replace(tmp, path)
        probs = publish.self_check(verbose=False)
        if probs:
            raise RuntimeError(f"invariants broken after edit: {probs}")
        idx2 = _read(os.path.join(publish.PUBLIC, "index.html"))
        assert new_total_disp in idx2 and track in idx2
        # Deploy inside the protected region. If deploy() raises (invalid token,
        # network error), nothing reached production and the except clause restores
        # every local file from its backup, so local can never sit diverged ahead of
        # live with no way back — the exact failure that stranded a manual add.
        url = publish.deploy()
        deployed = True
        if not publish.verify_deployed(new_n):
            raise RuntimeError(f"deployed ({url}) but live count != {new_n}")
    except Exception:
        # Roll the local files back only when NOTHING reached production. Once
        # deploy() has succeeded, live carries the new content and restoring local
        # would re-introduce the divergence, so a post-deploy verify miss (usually
        # CDN lag) is raised without touching the files.
        if not deployed:
            for path, bak in baks.items():
                if os.path.exists(bak):
                    shutil.copy2(bak, path)
        raise
    finally:
        for bak in baks.values():
            if os.path.exists(bak):
                os.remove(bak)

    own = st is None
    if own:
        st = publish.load_state()
    st.setdefault("clusters", []).append(
        {"collector": coll, "victims": len(new_v), "sats": balance,
         "source": source, "count_after": new_n, "ts": int(time.time())})
    if own:
        publish.save_state(st)

    publish.notify_change(
        f"SITE SELF-UPDATED ({source}).\n\n{coll}\n  {len(new_v)} victims, "
        f"{balance/1e8:.8f} BTC, verified on-chain\n\n{note}\n\ntotal now "
        f"{new_total_disp} BTC, {nf} drained addresses.\n" + publish.SITE)
    return {"added": len(new_v), "collector": coll, "new_count": new_n,
            "new_total": new_total_disp, "balance": balance, "url": url}


def _fee_label(coll):
    fp = cluster_fingerprint(coll)
    rates = list(fp["fee_rates"].keys())
    if not rates:
        return "varies"
    lo, hi = min(rates), max(rates)
    return f"{lo} sat/vB" if lo == hi else f"{lo}–{hi} sat/vB"
