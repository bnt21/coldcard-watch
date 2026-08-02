#!/usr/bin/env python3
"""
wave3-refresh.py — keep the Wave 3 snapshot true.

The seven collector addresses stream to the browser over a websocket. The 214 Wave 3
vaults cannot: that many addresses would blow past MAX_TRACKED, build a 9KB batch URL,
and hammer a free API every 60 seconds. So the site ships their balances as a snapshot,
and /list.html says so in as many words. This is the thing that refreshes it, which is
what makes that sentence honest.

It re-reads all 214 balances, rewrites wave3.js, and shouts if any vault has spent. A
first spend matters twice over: it moves the money, and it reveals the vault's script,
which is the one thing that could tie these 214 to each other or to the earlier waves.

Deploys only when a balance actually changed, so it is safe to run on a schedule.

usage: wave3-refresh.py [--dry-run] [--no-deploy]
"""
import json
import os
import re
import shutil
import sys
import time
import urllib.request

import publish

HERE = os.path.dirname(os.path.abspath(__file__))
W3 = os.path.join(publish.PUBLIC, "wave3.js")
CHUNK = 50
UA = {"User-Agent": "coldcard-wave3-refresh/1.0"}


def _atomic(path, content):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def load():
    s = open(W3, encoding="utf-8").read()
    return json.loads(re.search(r'window\.WAVE3\s*=\s*(.*)', s, re.S)
                      .group(1).rstrip().rstrip(";"))


def balances(addrs):
    """blockchain.info in batches, esplora per-address as the fallback."""
    out = {}
    for i in range(0, len(addrs), CHUNK):
        part = addrs[i:i + CHUNK]
        try:
            url = "https://blockchain.info/balance?active=" + "|".join(part)
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                        timeout=45) as r:
                d = json.load(r)
            for a in part:
                e = d.get(a)
                if e is not None:
                    # "has spent" means money LEFT, not "has more than one tx". A vault
                    # that merely receives a second deposit has not moved, and calling
                    # that a first movement is a false alarm on the one alert that
                    # matters. total_received - final_balance is what actually left.
                    out[a] = {"balance": e["final_balance"],
                              "spent": e.get("total_received", 0) > e["final_balance"]}
        except Exception as ex:
            print(f"  batch {i//CHUNK} fell back to esplora ({type(ex).__name__})")
            for a in part:
                info = publish.esplora(f"/address/{a}")
                if not info:
                    continue
                c = info["chain_stats"]
                out[a] = {"balance": c["funded_txo_sum"] - c["spent_txo_sum"],
                          "spent": c["spent_txo_count"] > 0}
                time.sleep(0.15)
        time.sleep(0.4)
    return out


def main():
    dry = "--dry-run" in sys.argv
    d = load()
    addrs = [v[0] for v in d["vaults"]]
    print(f"refreshing {len(addrs)} Wave 3 vaults (snapshot from "
          f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(d['verified']))})")

    cur = balances(addrs)
    missing = [a for a in addrs if a not in cur]
    if missing:
        print(f"  {len(missing)} addresses could not be read; keeping their old values")

    moved, changed, total = [], 0, 0
    new_vaults = []
    for a, old in d["vaults"]:
        e = cur.get(a)
        bal = e["balance"] if e else old
        if e and e.get("spent"):
            moved.append(a)
        if bal != old:
            changed += 1
        total += bal
        new_vaults.append([a, bal])

    print(f"  held {d['held']/1e8:.8f} -> {total/1e8:.8f} BTC "
          f"({changed} balances changed, {len(moved)} vaults have spent)")

    if moved:
        msg = ("WAVE 3 VAULT SPENT — first movement.\n\n"
               + "\n".join(f"  {a}" for a in moved[:10])
               + (f"\n  ...and {len(moved)-10} more" if len(moved) > 10 else "")
               + "\n\nA spend reveals the P2WSH script. A cosigner key reused across two "
                 "vaults would link them.\n" + publish.SITE)
        print("\n" + msg)
        if not dry:
            publish.send_telegram(msg)

    if changed == 0:
        print("nothing changed; not deploying")
        return 0
    if dry:
        print("dry run; wave3.js not written")
        return 0

    # Every other write path in this repo guards with these four before touching the
    # site, and this one runs unattended on a schedule, so it gets the same treatment.
    if publish.conflict_guard():
        print("syncthing conflict copies present; refusing to write", file=sys.stderr)
        return 1
    if publish.self_check(verbose=False):
        print("site invariants already broken; refusing to write", file=sys.stderr)
        return 1

    idx_path = os.path.join(publish.PUBLIC, "index.html")
    baks = {}
    try:
        for p in (W3, idx_path):
            if os.path.exists(p):
                baks[p] = p + ".w3rbak"
                shutil.copy2(p, baks[p])

        d["vaults"] = new_vaults
        d["held"] = total
        d["verified"] = int(time.time())
        _atomic(W3, "window.WAVE3=" + json.dumps(d, separators=(",", ":")) + ";\n")
        print(f"wrote {W3}")

        # the headline is the seven live addresses plus this figure, so it has to move
        # with it or the page contradicts its own dataset
        with open(idx_path, encoding="utf-8") as f:
            idx = f.read()
        m = re.search(r'<span id="totalBtc">([0-9,.]+)</span>', idx)
        if m:
            live = sum(_wallet_attributed(idx))
            new_disp = f"{(live + total)/1e8:,.4f}"
            if new_disp != m.group(1):
                _atomic(idx_path,
                        idx.replace(f'<span id="totalBtc">{m.group(1)}</span>',
                                    f'<span id="totalBtc">{new_disp}</span>', 1))
                print(f"  headline {m.group(1)} -> {new_disp}")

        probs = publish.self_check(verbose=False)
        if probs:
            raise RuntimeError(f"invariants broken after write: {probs}")
    except Exception:
        for p, b in baks.items():
            shutil.copy2(b, p)
        print("rolled back", file=sys.stderr)
        raise
    finally:
        for b in baks.values():
            if os.path.exists(b):
                os.remove(b)

    if "--no-deploy" in sys.argv:
        print("skipping deploy")
        return 0
    publish.deploy()
    print("deployed")
    return 0


def _wallet_attributed(idx):
    for m in re.finditer(r'attributed:(\d+)', idx):
        yield int(m.group(1))


if __name__ == "__main__":
    sys.exit(main())
