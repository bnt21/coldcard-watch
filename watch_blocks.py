#!/usr/bin/env python3
"""
watch_blocks.py — keep scanning new blocks for Coldcard drain clusters, forever.

scan.py establishes a baseline over history. This keeps that going: every run it
reads whatever blocks have appeared since the last run, applies the same pattern
test, and sends a Telegram message when a candidate survives the freshness check.

The point is that a new cluster is found here rather than arriving by tweet.

Pattern, per block: several one-input, one-output, no-change sweeps from single-sig
native segwit addresses landing in the same block, paying into the same address, at
one identical hardcoded fee rate. Candidates are then checked for freshness, because
exchanges produce similar bursts and must not be reported as thieves.

Nothing publishes. It notifies; a human decides.

state: watch-state.json   (last height scanned + every candidate ever reported)
usage: watch_blocks.py [--catch-up N] [--dry-run]
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "watch-state.json")
ENV_PATH = "/etc/cc-connect/env"

MIN_SWEEPS = 3
UA = {"User-Agent": "coldcard-watch-blocks/1.0"}

KNOWN = {
    "bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0", "bc1qc779m8gec84k3t0ffvu0pps94zheht7lr7ueyn",
    "bc1qh0l7q0mca3ln7wsl9luwns0jc9jhgrtft025l4", "bc1qdaarag7729c2n4l2wnyt3hkhfpcs66n98z7uuh",
    "bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9r", "bc1qx76cae2706qd5q576feh7xq8rfcsjpf2htfhe3",
    "bc1q8jy96fe5lf8vfugydnte3cguk92gpev7kwtp3q", "bc1qsjrf5ze5tmulz7y2x4pc7qaex2a35sanp3rqlx",
    "bc1qtfrwa4j6rmj9rsgspv6a0yjumkg39js2numu75", "bc1qjd6tcd5ey96fdujpkr7zgn2zjzp29h208xlvxg",
    "bc1qhh4jkkj07vxpdt0zlvxctjlfhqmurhxa24x3h2",
}


def get(url, timeout=90, tries=4):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
                return r.read()
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(3 + i * 3)


def load():
    if os.path.exists(STATE):
        try:
            return json.loads(open(STATE).read())
        except Exception:
            pass
    return {"last_height": 0, "reported": []}


def save(st):
    with open(STATE, "w") as f:
        json.dump(st, f, indent=1)


def send(text, dry=False):
    if dry:
        print("--- would send ---\n" + text)
        return
    env = {}
    try:
        for line in open(ENV_PATH):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except Exception as e:
        print(f"cannot read {ENV_PATH}: {e}", file=sys.stderr)
        return
    tok, chat = env.get("TELEGRAM_BOT_TOKEN"), env.get("CC_ADMIN_ID")
    if not tok or not chat:
        print("missing telegram credentials", file=sys.stderr)
        return
    data = urllib.parse.urlencode({"chat_id": chat, "text": text,
                                   "disable_web_page_preview": "true"}).encode()
    urllib.request.urlopen(urllib.request.Request(
        f"https://api.telegram.org/bot{tok}/sendMessage", data=data, headers=UA), timeout=30).read()
    print("notified")


def is_p2wpkh(a):
    return bool(a) and a.startswith("bc1q") and len(a) == 42


def scan_block(height):
    h = get(f"https://blockstream.info/api/block-height/{height}").decode().strip()
    blk = json.loads(get(f"https://blockchain.info/rawblock/{h}"))
    groups = {}
    for t in blk.get("tx", []):
        ins, outs = t.get("inputs", []), t.get("out", [])
        if len(ins) != 1 or len(outs) != 1:
            continue
        prev = ins[0].get("prev_out") or {}
        src, dst = prev.get("addr"), outs[0].get("addr")
        w = t.get("weight") or 0
        if not is_p2wpkh(src) or not dst or w <= 0:
            continue
        rate = round((t.get("fee") or 0) / (w / 4.0), 1)
        g = groups.setdefault(dst, {"sweeps": 0, "sats": 0, "rates": {}})
        g["sweeps"] += 1
        g["sats"] += prev.get("value", 0)
        g["rates"][rate] = g["rates"].get(rate, 0) + 1
    out = {}
    for dst, g in groups.items():
        if g["sweeps"] < MIN_SWEEPS or dst in KNOWN:
            continue
        rate, n = max(g["rates"].items(), key=lambda kv: kv[1])
        if n / g["sweeps"] < 0.9:          # one hardcoded rate must dominate the batch
            continue
        out[dst] = {"sweeps": g["sweeps"], "sats": g["sats"], "rate": rate, "height": height}
    return out


def fresh(addr, sweeps):
    """An attacker collector's whole history is this incident. A service has far more."""
    d = json.loads(get(f"https://blockstream.info/api/address/{addr}", timeout=45))
    c = d["chain_stats"]
    unrelated = c["funded_txo_count"] - sweeps
    return unrelated <= max(5, sweeps * 0.25), c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--catch-up", type=int, default=40, help="max blocks per run")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    st = load()
    tip = int(get("https://blockstream.info/api/blocks/tip/height").decode().strip())
    start = st["last_height"] + 1 if st["last_height"] else tip
    end = min(tip, start + a.catch_up - 1)
    if start > tip:
        print(f"nothing new (tip {tip})")
        return 0
    print(f"scanning {start}..{end} (tip {tip})")

    found = {}
    for h in range(start, end + 1):
        try:
            for dst, g in scan_block(h).items():
                if dst in found:
                    found[dst]["sweeps"] += g["sweeps"]; found[dst]["sats"] += g["sats"]
                else:
                    found[dst] = g
        except Exception as e:
            print(f"  block {h} failed: {e}", file=sys.stderr)
            end = h - 1                     # stop here so the block is retried next run
            break
        time.sleep(0.8)

    reported = set(st.get("reported", []))
    news = []
    for dst, g in sorted(found.items(), key=lambda kv: -kv[1]["sats"]):
        if dst in reported:
            continue
        try:
            ok, c = fresh(dst, g["sweeps"])
        except Exception:
            continue
        time.sleep(0.3)
        if not ok:
            continue                        # a service, not a collector
        news.append((dst, g, c))
        reported.add(dst)

    if news:
        lines = ["POSSIBLE NEW COLDCARD CLUSTER", ""]
        for dst, g, c in news:
            lines += [
                dst,
                f"  {g['sweeps']} sweeps, {g['sats']/1e8:.8f} BTC, {g['rate']} sat/vB",
                f"  block {g['height']}, {c['funded_txo_count']} deposits total",
                f"  https://mempool.space/address/{dst}", ""]
        lines.append("Verify before adding anything to the site.")
        send("\n".join(lines), a.dry_run)

    if not a.dry_run:
        st["last_height"] = end
        st["reported"] = sorted(reported)
        save(st)
    print(f"done through {end} | candidates this run: {len(found)} | new reported: {len(news)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
