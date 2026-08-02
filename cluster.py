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
import time

import publish

T0 = 1785373820                    # chart origin, first drain block time
FRESH_MAX_UNRELATED = 8            # a collector's history is the incident; a service has more


def _read(p):
    return open(p, encoding="utf-8").read()


def collector_victims(coll):
    """Every address that swept into `coll`, with amount, block height and time.
    Deterministic: reads the confirmed chain history."""
    victims, seen = {}, set()
    last = None
    while True:
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


def cluster_fingerprint(coll):
    """Deterministic read of whether `coll` looks like an attacker collector:
    many no-change single-output sweeps at one hardcoded fee, in a tight window,
    fresh (not a service). Returns the evidence, never a publish decision."""
    v = {"collector": coll, "victims": 0, "total_sats": 0, "balance": 0,
         "unspent": None, "fee_rates": {}, "fee_uniform": False,
         "no_change_ratio": 0.0, "block_span": None, "fresh": None,
         "forwards_to_anchor": None, "evidence": []}
    txs = []
    last = None
    while True:
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


def add_cluster(coll, source, note, dry=False, st=None, min_victims=3):
    """Atomically add collector `coll` and its victims to every coupled surface,
    deploy, verify the live bytes, log, and Telegram-notify. `source`/`note` become
    the methodology-row attribution. Rolls back every file on any failure."""
    if publish.conflict_guard():
        raise RuntimeError("syncthing conflict copies present; refusing to edit")
    if publish.self_check(verbose=False):
        raise RuntimeError("site invariants broken before edit")

    victims, total, balance, cstats = collector_victims(coll)
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
            bh = publish._get(f"https://blockstream.info/api/block-height/{h}",
                              timeout=30).decode().strip()
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
    old_total = 112866326171
    # recompute the displayed total from the CURRENT wallet set + this collector
    idx = _read(os.path.join(publish.PUBLIC, "index.html"))
    wallet_sats = [int(x) for x in re.findall(r'attributed:(\d+)', idx)]
    new_total = sum(wallet_sats) + balance
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
                  'origin:"seed"}' % (coll, balance))
    idx = idx.replace(last_wallet, new_wallet, 1)
    idx = idx.replace(f"var DRAINED_COUNT = {old_n};", f"var DRAINED_COUNT = {new_n};")
    idx = idx.replace(f'id="totalBtc">{old_total_disp}</span>',
                      f'id="totalBtc">{new_total_disp}</span>')
    # meta headline BTC figure (2 decimals)
    idx = re.sub(r'(A live chart of the )[\d,]+\.\d+( BTC)',
                 lambda m: m.group(1) + f"{new_total/1e8:,.2f}" + m.group(2), idx)
    idx = publish.swap_count(idx, old_n, new_n)
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
        if anchor in s and f'"{coll}"' not in s:
            s = s.replace(anchor, anchor + f'\n    "{coll}": {balance},')
        s = re.sub(r'DRAINED_COUNT = \d+', f"DRAINED_COUNT = {new_n}", s)
        edits[m] = s

    if dry:
        return {"added": 0, "dry": len(new_v), "collector": coll,
                "new_count": new_n, "new_total": new_total_disp, "balance": balance}

    baks = {}
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
        assert new_total_disp in idx2 and coll in idx2
    except Exception:
        for path, bak in baks.items():
            shutil.copy2(bak, path)
        raise
    finally:
        for bak in baks.values():
            if os.path.exists(bak):
                os.remove(bak)

    url = publish.deploy()
    if not publish.verify_deployed(new_n):
        raise RuntimeError(f"deployed ({url}) but live count != {new_n}")

    own = st is None
    if own:
        st = publish.load_state()
    st.setdefault("clusters", []).append(
        {"collector": coll, "victims": len(new_v), "sats": balance,
         "source": source, "count_after": new_n, "ts": int(time.time())})
    if own:
        publish.save_state(st)

    publish.send_telegram(
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
