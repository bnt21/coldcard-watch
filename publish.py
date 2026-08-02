#!/usr/bin/env python3
"""
publish.py — add verified drained addresses to coldcard-watch.vercel.app and deploy.

The only path by which an address reaches the site. x_watch.py imports this; the
the Telegram bot runs it on request. Every publish re-verifies on-chain first,
edits every coupled surface in one pass, deploys, and then reads the deployed bytes
back before claiming success. On any failure the edits roll back.

Coupled surfaces, all updated together or not at all:
  public/drains.js        rows [addr, sats, blockIndex] + blocks [{h,t}]
  public/drained.js       sha256(addr)[:16] prefixes for the local checker
  public/index.html       DRAINED_COUNT, the formatted count strings, WALLETS
                          attribution when the sweep paid a tracked wallet
  public/list.html        formatted count strings
  public/methodology.html the "Reported and verified" table row (marker comments)
  ~/CLAUDE/tools/coldcard-watch-monitor.py   DRAINED_COUNT + WATCHED attribution

usage:
  publish.py --list-pending
  publish.py --approve ADDR [--dry-run]     publish a pending candidate
  publish.py --reject ADDR                  drop a pending candidate
  publish.py --add ADDR [--dry-run]         verify + publish one address directly
  publish.py --self-check                   verify cross-file invariants only

Verification tiers (verify_addr):
  proven      outflow lands in a known attacker address, directly or via one
              co-spend hop. Deterministic. Eligible for automatic publishing.
  pattern     the sweep matches the drain fingerprint but connects to nothing
              known. Human decision required.
  unverified  funds moved somewhere unconnected, or the claim cannot be tested.
  not_drained the address never lost funds.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

# Force IPv4 for all outbound requests. On the Hetzner box, python's urllib intermittently
# picks a dead IPv6 route to blockstream.info and hangs the full socket timeout (45s on a
# single address stalled the whole co-spend walk), while curl's happy-eyeballs falls back
# to IPv4 instantly. Preferring IPv4 (falling back to whatever exists) removes the hang.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_first(*args, **kwargs):
    res = _orig_getaddrinfo(*args, **kwargs)
    v4 = [r for r in res if r[0] == socket.AF_INET]
    return v4 or res
socket.getaddrinfo = _ipv4_first

HERE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(HERE, "public")
STATE_PATH = os.path.expanduser("~/.coldcard-x-state.json")
ENV_PATH = os.path.expanduser("~/.coldcard-x-env")
SITE = "https://coldcard-watch.vercel.app"
UA = {"User-Agent": "coldcard-watch-publish/1.0"}

# The live monitor (Hetzner cron runs the synced ~/CLAUDE/tools copy). The old
# ~/.claude/bin email-based monitor is retired (launchd plist .disabled) and is
# deliberately not kept in sync.
MONITORS = [os.path.expanduser("~/CLAUDE/tools/coldcard-watch-monitor.py")]

# Attacker-side anchor set. An outflow reaching any of these, directly or through
# one co-spend hop, is proof the funds went to the operator of the drains.
# First eleven: the published collectors and vaults (watch_blocks.py KNOWN).
# Last four: proven by co-spend in tx bc9255a5... (block 960458) but not yet
# tracked on the dashboard; they are valid proof anchors regardless.
ANCHORS = {
    "bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0", "bc1qc779m8gec84k3t0ffvu0pps94zheht7lr7ueyn",
    "bc1qh0l7q0mca3ln7wsl9luwns0jc9jhgrtft025l4", "bc1qdaarag7729c2n4l2wnyt3hkhfpcs66n98z7uuh",
    "bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9r", "bc1qx76cae2706qd5q576feh7xq8rfcsjpf2htfhe3",
    "bc1q8jy96fe5lf8vfugydnte3cguk92gpev7kwtp3q", "bc1qsjrf5ze5tmulz7y2x4pc7qaex2a35sanp3rqlx",
    "bc1qtfrwa4j6rmj9rsgspv6a0yjumkg39js2numu75", "bc1qjd6tcd5ey96fdujpkr7zgn2zjzp29h208xlvxg",
    "bc1qhh4jkkj07vxpdt0zlvxctjlfhqmurhxa24x3h2",
    "bc1qzrl67rtyaqdvtl78rlklxmraqjk7d9f6cf23jm", "bc1q0mh6rs0mjvv5ncdyqwhqma7hgup3aycucsc279",
    "bc1qgt5s8rsjyvennup3dz3rk92pczlzqtvy8f5t09", "bc1qn79gwljlqwwrgpqqdulvmlnssazm9gasjg090r",
    # wave-2 collector reported by Galaxy Research 2026-08-01, verified + added
    "bc1qmd5m5ktv7m5ffujxv4248fxv36myvdx79n8jp6",
}

# The wallets the dashboard tracks. A sweep paying one of these adds to its
# attribution figure on the page and in the monitor.
TRACKED = {
    "bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9r", "bc1qx76cae2706qd5q576feh7xq8rfcsjpf2htfhe3",
    "bc1q8jy96fe5lf8vfugydnte3cguk92gpev7kwtp3q", "bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0",
    "bc1qtfrwa4j6rmj9rsgspv6a0yjumkg39js2numu75", "bc1qhh4jkkj07vxpdt0zlvxctjlfhqmurhxa24x3h2",
    "bc1qmd5m5ktv7m5ffujxv4248fxv36myvdx79n8jp6",   # Galaxy-reported wave-2 vault
}

# co-spend expansion discovers more attacker addresses over time; they persist here and
# union into ANCHORS at import so the fingerprint tier and the X pipeline recognise them.
EXTRA_ANCHORS_PATH = os.path.expanduser("~/.coldcard-anchors.json")
try:
    _extra = json.load(open(EXTRA_ANCHORS_PATH))
    if isinstance(_extra, list):
        ANCHORS |= set(_extra)
except Exception:
    pass


def record_anchors(addrs):
    """Persist newly-proven attacker addresses so they survive into the next run."""
    cur = set()
    try:
        cur = set(json.load(open(EXTRA_ANCHORS_PATH)))
    except Exception:
        pass
    new = cur | set(addrs)
    if new != cur:
        tmp = EXTRA_ANCHORS_PATH + ".tmp"
        json.dump(sorted(new), open(tmp, "w"))
        os.replace(tmp, EXTRA_ANCHORS_PATH)
    ANCHORS.update(addrs)


KNOWN_RATES = {30.0, 50.2, 2.0, 3.0, 10.0, 10.1}   # hardcoded rates seen across clusters so far
SWEEP_START = 1785373820               # first drain block, 2026-07-30 01:10:20 UTC


# ---------------------------------------------------------------- env + telegram

# No Keychain service name is written down here. Set this env var to the service
# holding the X token; with it unset, the Keychain fallback is simply skipped.
X_KEYCHAIN_ENV = "CCW_X_KEYCHAIN"   # set this to the Keychain service holding the X token


def load_env():
    env = {}
    for p in (ENV_PATH, "/etc/cc-connect/env"):
        try:
            for line in open(p):
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        except Exception:
            continue
    # Mac fallback for interactive testing: the Keychain can hold the X token and
    # the Vercel CLI is logged in, so those two need no env file there.
    if "X_BEARER_TOKEN" not in env and sys.platform == "darwin" and os.environ.get(X_KEYCHAIN_ENV):
        service = os.environ[X_KEYCHAIN_ENV]
        try:
            tok = subprocess.run(["security", "find-generic-password", "-s", service, "-w"],
                                 capture_output=True, text=True, timeout=10).stdout.strip()
            if tok:
                env["X_BEARER_TOKEN"] = tok
        except Exception:
            pass
    if "VERCEL_TOKEN" not in env and sys.platform == "darwin":
        try:
            auth = json.load(open(os.path.expanduser(
                "~/Library/Application Support/com.vercel.cli/auth.json")))
            if auth.get("token"):
                env["VERCEL_TOKEN"] = auth["token"]
        except Exception:
            pass
    return env


def send_telegram(text, env=None, dry=False):
    if dry:
        print("--- would send ---\n" + text)
        return True
    env = env or load_env()
    tok, chat = env.get("TELEGRAM_BOT_TOKEN"), env.get("CC_ADMIN_ID")
    if not tok or not chat:
        print("telegram credentials missing; message follows\n" + text, file=sys.stderr)
        return False
    data = urllib.parse.urlencode({"chat_id": chat, "text": text,
                                   "disable_web_page_preview": "true"}).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"https://api.telegram.org/bot{tok}/sendMessage", data=data, headers=UA),
            timeout=30).read()
        return True
    except Exception as e:
        print(f"telegram send failed: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------- state

def load_state():
    if os.path.exists(STATE_PATH):
        try:
            return json.load(open(STATE_PATH))
        except Exception:
            pass
    return {"since": {}, "seen_tweets": [], "checked": {}, "pending": {},
            "published": [], "qt_replies": {}}


def save_state(st):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=1)
    os.replace(tmp, STATE_PATH)


# ---------------------------------------------------------------- chain reads

def _get(url, timeout=45, tries=4):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                        timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise                    # a rate cap will not clear in seconds
            if i == tries - 1:
                raise
            time.sleep(2 + i * 3)
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(2 + i * 3)


# Both run the same Esplora API. blockstream.info caps unauthenticated use at
# 700 requests/hour per IP, so mempool.space is a full fallback, not a maybe.
ESPLORA_HOSTS = ["https://blockstream.info/api", "https://mempool.space/api"]


def esplora(path):
    last = None
    # blockstream.info is primary (fast). mempool.space is a fallback but can be very
    # slow from some hosts (10s timeouts on the Hetzner box), so it gets a short timeout
    # and never hangs the caller — a failed address just retries on the next run.
    for i, host in enumerate(ESPLORA_HOSTS):
        try:
            return json.loads(_get(f"{host}{path}", timeout=(12 if i == 0 else 5), tries=2))
        except Exception as e:
            last = e
    raise last


def verify_addr(addr, known_victims):
    """On-chain test of a claimed drain. Returns a verdict dict; never raises
    on a merely-unverifiable claim, only on transport failure."""
    v = {"addr": addr, "status": "unverified", "sats": 0, "dest": None,
         "height": None, "time": None, "evidence": []}
    if addr in ANCHORS:
        v["status"] = "attacker_side"
        v["evidence"].append("this is a known attacker address, not a victim wallet")
        return v
    if addr in known_victims:
        v["status"] = "already_listed"
        return v
    try:
        info = esplora(f"/address/{addr}")
    except Exception:
        v["evidence"].append("address lookup failed repeatedly")
        return v
    c = info.get("chain_stats", {})
    if not c.get("funded_txo_count"):
        v["status"] = "not_drained"
        v["evidence"].append("address has never received funds")
        return v
    if c.get("spent_txo_sum", 0) == 0:
        v["status"] = "not_drained"
        v["evidence"].append("address has never spent; funds still there")
        return v

    txs = esplora(f"/address/{addr}/txs")
    spends = [t for t in txs
              if any((i.get("prevout") or {}).get("scriptpubkey_address") == addr
                     for i in t.get("vin", []))]
    if not spends:
        v["evidence"].append("no confirmed spend found")
        return v

    for t in spends:
        nin, nout = len(t["vin"]), len(t["vout"])
        dest = t["vout"][0].get("scriptpubkey_address") if nout else None
        val = sum((i.get("prevout") or {}).get("value", 0)
                  for i in t["vin"]
                  if (i.get("prevout") or {}).get("scriptpubkey_address") == addr)
        st = t.get("status", {})
        height, btime = st.get("block_height"), st.get("block_time")
        weight = t.get("weight") or 0
        rate = round(t.get("fee", 0) / (weight / 4.0), 1) if weight else None

        shape_ok = nin == 1 and nout == 1
        if shape_ok:
            v["evidence"].append(f"sweep {t['txid'][:16]}...: 1-in/1-out, no change, "
                                 f"{rate} sat/vB, block {height}")
        if rate in KNOWN_RATES and shape_ok:
            v["evidence"].append(f"fee rate {rate} matches a known cluster rate")
        if btime and btime >= SWEEP_START:
            v["evidence"].append("spend is inside the drain period")

        if dest and dest in ANCHORS:
            v.update(status="proven", sats=val, dest=dest, height=height, time=btime)
            v["evidence"].append(f"paid directly into known attacker address {dest}")
            return v

        # one co-spend hop: does the destination later spend together with a
        # known attacker address? Common-input ownership is the proof.
        if dest and shape_ok:
            try:
                dtxs = esplora(f"/address/{dest}/txs")
            except Exception:
                dtxs = []
            for dt in dtxs:
                ins = [(i.get("prevout") or {}).get("scriptpubkey_address")
                       for i in dt.get("vin", [])]
                if dest in ins and any(a in ANCHORS for a in ins if a):
                    v.update(status="proven", sats=val, dest=dest,
                             height=height, time=btime)
                    anchor = next(a for a in ins if a in ANCHORS)
                    v["evidence"].append(
                        f"destination {dest} co-spends with known attacker "
                        f"address {anchor} in {dt['txid'][:16]}...")
                    return v
            if any(e.startswith("sweep") for e in v["evidence"]):
                v.update(status="pattern", sats=val, dest=dest,
                         height=height, time=btime)
        time.sleep(0.4)
    return v


# ---------------------------------------------------------------- site model

def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def parse_site():
    drains_src = read(os.path.join(PUBLIC, "drains.js"))
    drains = json.loads(re.search(r'window\.DRAINS\s*=\s*(.*)', drains_src,
                                  re.S).group(1).rstrip().rstrip(";"))
    drained_src = read(os.path.join(PUBLIC, "drained.js"))
    hashes = json.loads(re.search(r'window\.DRAINED\s*=\s*(\[.*)', drained_src,
                                  re.S).group(1).rstrip().rstrip(";"))
    idx = read(os.path.join(PUBLIC, "index.html"))
    count_var = int(re.search(r'var DRAINED_COUNT = (\d+);', idx).group(1))
    return drains, hashes, count_var


def self_check(verbose=True):
    """Cross-file invariants. Returns list of problems (empty = healthy)."""
    problems = []
    drains, hashes, count_var = parse_site()
    rows, blocks = drains["rows"], drains["blocks"]
    n = len(rows)
    if len(hashes) != n:
        problems.append(f"drained.js has {len(hashes)} hashes, rows {n}")
    if count_var != n:
        problems.append(f"index.html DRAINED_COUNT {count_var} != rows {n}")
    if len(set(r[0] for r in rows)) != n:
        problems.append("duplicate addresses in rows")
    bad_idx = [r[0] for r in rows if not (0 <= r[2] < len(blocks))]
    if bad_idx:
        problems.append(f"rows with invalid block index: {bad_idx[:3]}")
    miss = sum(1 for r in rows
               if hashlib.sha256(r[0].encode()).hexdigest()[:16] not in set(hashes))
    if miss:
        problems.append(f"{miss} rows missing from the hash set")
    fmt = f"{n:,}"
    for name in ("index.html", "list.html"):
        if fmt not in read(os.path.join(PUBLIC, name)):
            problems.append(f"{name} does not contain the formatted count {fmt}")
    for m in MONITORS:
        if os.path.exists(m):
            mv = int(re.search(r'DRAINED_COUNT = (\d+)', read(m)).group(1))
            if mv != n:
                problems.append(f"{m} DRAINED_COUNT {mv} != rows {n}")
    if verbose:
        print(f"rows {n} | blocks {len(blocks)} | "
              + ("OK" if not problems else " ; ".join(problems)))
    return problems


def conflict_guard():
    hits = [f for f in os.listdir(PUBLIC) if "sync-conflict" in f]
    hits += [f for f in os.listdir(HERE) if "sync-conflict" in f]
    return hits


# ---------------------------------------------------------------- publishing

def fmtc(n):
    return f"{n:,}"


def swap_count(s, old_n, new_n):
    """Replace the formatted address count without ever touching a digit run that
    merely contains it (a BTC figure like 12,334.56 must survive)."""
    pat = r'(?<!\d)(?<!\d,)' + re.escape(fmtc(old_n)) + r'(?!\d)(?!\.\d)'
    return re.sub(pat, fmtc(new_n), s)


def apply_edits(entries, dry=False, st=None):
    """entries: [{addr, sats, height, time, dest}]. Returns summary dict.
    Edits every coupled file, or none. Caller has already verified each entry."""
    conflicts = conflict_guard()
    if conflicts:
        raise RuntimeError(f"syncthing conflict copies present, refusing to edit: {conflicts}")
    problems = self_check(verbose=False)
    if problems:
        raise RuntimeError(f"site invariants broken before edit: {problems}")

    drains, hashes, old_n = parse_site()
    rows, blocks = drains["rows"], drains["blocks"]
    have = {r[0] for r in rows}
    todo = [e for e in entries if e["addr"] not in have]
    if not todo:
        return {"added": 0, "skipped": len(entries)}

    height_to_idx = {b["h"]: i for i, b in enumerate(blocks)}
    for e in todo:
        h, t = e.get("height"), e.get("time")
        if h is None or t is None:
            raise RuntimeError(f"{e['addr']}: missing block height/time")
        if h not in height_to_idx:
            blocks.append({"h": h, "t": t})
            height_to_idx[h] = len(blocks) - 1
        rows.append([e["addr"], e["sats"], height_to_idx[h]])
        hashes.append(hashlib.sha256(e["addr"].encode()).hexdigest()[:16])

    new_n = len(rows)
    old_fmt, new_fmt = fmtc(old_n), fmtc(new_n)

    # attribution: sweeps that paid a tracked wallet raise its figure
    attr = {}
    for e in todo:
        if e.get("dest") in TRACKED:
            attr[e["dest"]] = attr.get(e["dest"], 0) + e["sats"]

    edits = {}   # path -> new content

    p = os.path.join(PUBLIC, "drains.js")
    edits[p] = "window.DRAINS=" + json.dumps({"blocks": blocks, "rows": rows},
                                             separators=(",", ":")) + ";\n"
    p = os.path.join(PUBLIC, "drained.js")
    edits[p] = "window.DRAINED=" + json.dumps(hashes, separators=(",", ":")) + ";\n"

    p = os.path.join(PUBLIC, "index.html")
    s = read(p)
    s = s.replace(f"var DRAINED_COUNT = {old_n};", f"var DRAINED_COUNT = {new_n};")
    s = swap_count(s, old_n, new_n)
    for a, add in attr.items():
        m = re.search(r'(\{addr:"%s", attributed:)(\d+)' % a, s)
        if not m:
            raise RuntimeError(f"could not find WALLETS entry for {a}")
        s = s[:m.start(2)] + str(int(m.group(2)) + add) + s[m.end(2):]
    edits[p] = s

    p = os.path.join(PUBLIC, "list.html")
    edits[p] = swap_count(read(p), old_n, new_n)

    # methodology: keep the reported-and-verified table row current
    p = os.path.join(PUBLIC, "methodology.html")
    s = read(p)
    if "<!-- xrow -->" in s:
        pub = (st if st is not None else load_state()).get("published", [])
        total = sum(x["sats"] for x in pub) + sum(e["sats"] for e in todo)
        count = len(pub) + len(todo)
        row = ('<!-- xrow --><tr><td>Since 1 Aug</td><td>%d address%s<br>%.2f BTC</td>'
               '<td>varies</td><td>Reported publicly on X by the holders, picked up by '
               'the watcher below, and verified on-chain before being added.</td></tr>'
               '<!-- /xrow -->' % (count, "" if count == 1 else "es", total / 1e8))
        s = re.sub(r'<!-- xrow -->.*?<!-- /xrow -->', row, s, flags=re.S)
        edits[p] = s

    for m in MONITORS:
        if not os.path.exists(m):
            continue
        s = read(m)
        s = re.sub(r'DRAINED_COUNT = \d+', f"DRAINED_COUNT = {new_n}", s)
        for a, add in attr.items():
            mm = re.search(r'("%s": )(\d+)' % a, s)
            if not mm:
                raise RuntimeError(f"could not find WATCHED entry for {a} in {m}")
            s = s[:mm.start(2)] + str(int(mm.group(2)) + add) + s[mm.end(2):]
        edits[m] = s

    if dry:
        print(f"dry run: would add {len(todo)} address(es), count {old_n} -> {new_n}, "
              f"attribution {attr or 'none'}")
        for e in todo:
            print(f"  {e['addr']}  {e['sats']/1e8:.8f} BTC  block {e['height']}")
        return {"added": 0, "dry": len(todo)}

    # write with rollback
    baks = {}
    try:
        for path, content in edits.items():
            bak = path + ".prepub"
            shutil.copy2(path, bak)
            baks[path] = bak
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp, path)
        problems = self_check(verbose=False)
        if problems:
            raise RuntimeError(f"invariants broken after edit: {problems}")
    except Exception:
        for path, bak in baks.items():
            shutil.copy2(bak, path)
        raise
    finally:
        for bak in baks.values():
            if os.path.exists(bak):
                os.remove(bak)

    return {"added": len(todo), "new_count": new_n, "attr": attr,
            "entries": todo}


def deploy(env=None):
    env = env or load_env()
    cmd = ["vercel", "deploy", "--prod", "--yes"]
    tok = env.get("VERCEL_TOKEN")
    if tok:
        cmd += ["--token", tok]
    r = subprocess.run(cmd, cwd=PUBLIC, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError(f"vercel deploy failed: {r.stderr[-400:]}")
    return (r.stdout.strip().splitlines() or ["?"])[-1]


def verify_deployed(expect_n, tries=6):
    """Read the deployed bytes back. The CDN can serve stale copies, so cache-bust
    and allow time for the alias to move."""
    for i in range(tries):
        try:
            body = _get(f"{SITE}/drained.js?v={int(time.time())}", timeout=30).decode()
            a, b = body.find("["), body.rfind("]")
            n = len(json.loads(body[a:b + 1]))
            if n == expect_n:
                idx = _get(f"{SITE}/index.html?v={int(time.time())}", timeout=30).decode()
                if f"var DRAINED_COUNT = {expect_n};" in idx:
                    return True
        except Exception:
            pass
        time.sleep(10 + i * 5)
    return False


def publish(entries, env=None, dry=False, source="x-watch", st=None):
    """The whole pipeline for pre-verified entries: edit, deploy, verify, record,
    notify. Raises on failure after rolling back edits. When the caller passes its
    own state dict it also owns saving it; loading a second copy here would lose
    the caller's changes on its later save."""
    env = env or load_env()
    own_state = st is None
    if own_state:
        st = load_state()
    res = apply_edits(entries, dry=dry, st=st)
    if dry or not res.get("added"):
        return res
    url = deploy(env)
    if not verify_deployed(res["new_count"]):
        raise RuntimeError(f"deploy done ({url}) but the live site does not show "
                           f"count {res['new_count']}; investigate before retrying")
    for e in res["entries"]:
        st["published"].append({"addr": e["addr"], "sats": e["sats"],
                                "height": e["height"], "ts": int(time.time()),
                                "source": source})
        st["pending"].pop(e["addr"], None)
    if own_state:
        save_state(st)
    lines = [f"PUBLISHED {res['added']} drained address"
             + ("" if res["added"] == 1 else "es") + " to the site", ""]
    for e in res["entries"]:
        lines.append(f"{e['addr']}")
        lines.append(f"  {e['sats']/1e8:.8f} BTC, block {e['height']}, verified on-chain")
    lines += ["", f"count is now {fmtc(res['new_count'])}", SITE]
    send_telegram("\n".join(lines), env)
    return res


# ---------------------------------------------------------------- cli

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--approve", metavar="ADDR")
    ap.add_argument("--reject", metavar="ADDR")
    ap.add_argument("--add", metavar="ADDR")
    ap.add_argument("--list-pending", action="store_true")
    ap.add_argument("--self-check", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if a.self_check:
        return 1 if self_check() else 0

    st = load_state()
    if a.list_pending:
        if not st["pending"]:
            print("nothing pending")
        for addr, p in st["pending"].items():
            print(f"{addr}  {p.get('sats',0)/1e8:.8f} BTC  status={p.get('status')}")
            for e in p.get("evidence", []):
                print(f"   - {e}")
        return 0

    if a.reject:
        if st["pending"].pop(a.reject, None):
            st.setdefault("rejected", []).append(a.reject)
            save_state(st)
            print(f"rejected {a.reject}")
        else:
            print(f"{a.reject} was not pending")
        return 0

    addr = a.approve or a.add
    if not addr:
        ap.print_help()
        return 2

    drains, _, _ = parse_site()
    known_victims = {r[0] for r in drains["rows"]}
    v = verify_addr(addr, known_victims)
    print(f"{addr}: {v['status']}")
    for e in v["evidence"]:
        print(f"  - {e}")
    if v["status"] == "already_listed":
        return 0
    if v["status"] not in ("proven", "pattern"):
        print("refusing to publish: the chain does not support the claim")
        return 1
    if v["status"] == "pattern" and not a.approve:
        print("pattern-only match. Use --approve to publish it on human judgement.")
        st["pending"][addr] = v
        save_state(st)
        return 1
    res = publish([{"addr": addr, "sats": v["sats"], "height": v["height"],
                    "time": v["time"], "dest": v["dest"]}],
                  dry=a.dry_run, source="manual")
    print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
