#!/usr/bin/env python3
"""
gh_watch.py — watch the public repo, verify disputes, and never touch anything.

The repo is the control plane for jobs that run on a schedule holding live credentials,
and the directory it lives in replicates to the box. So a merge is a path from a
stranger's pull request to code running with those credentials, and nothing here is
allowed anywhere near it. This process only reads.

  it never   merges, comments, labels, pushes, pulls, or deploys
  it never   runs contributor code
  it never   passes contributor text to a model

That last one is the point. Everything a contributor writes (a title, a body, a diff, a
filename) is text an attacker chose. If a model read it and then decided something, the
text would be steering the decision. Instead every decision below is a regex or an
arithmetic comparison against the chain, and the contributor's words are only ever
relayed to a human, quoted and truncated. There is no instruction path.

Authentication: none. The repo is public, so this uses anonymous API reads, which means
no GitHub credential exists on the box for anyone to steal.

The useful part is the dispute check. Someone says an address is theirs; this pulls the
address out, looks up what the site actually claims about it, re-reads the chain, and puts
the verdict in the message. Judgment stays with the person; the arithmetic is already done
by the time they read it.

state: ~/.coldcard-gh-watch.json
usage: gh_watch.py [--dry-run] [--since-all]
"""
import json
import os
import re
import sys
import time
import urllib.request

import publish

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
STATE = os.path.expanduser("~/.coldcard-gh-watch.json")
REPO = "bnt21/coldcard-watch"
API = "https://api.github.com"
UA = {"User-Agent": "coldcard-gh-watch/1.0", "Accept": "application/vnd.github+json"}

ADDR_RE = re.compile(r'\b(bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')

# A change to any of these reaches something that runs unattended with credentials, or
# changes what the site claims. Not a verdict, just the thing to look at first.
SENSITIVE = ("publish.py", "autopilot.py", "x_watch.py", "wave3_refresh.py",
             "cluster.py", "watch_blocks.py", ".github/workflows/", "data/",
             "public/", "check_clean.py", "nodeconf.py")


def get(path, tries=3):
    for _ in range(tries):
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(API + path, headers=UA), timeout=30) as r:
                return json.load(r)
        except Exception:
            time.sleep(2)
    return None


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {"seen": []}


def save_state(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


def quote(s, n=400):
    """Contributor text, flattened and truncated. Relayed to a human, never acted on."""
    s = re.sub(r'\s+', ' ', (s or "").strip())
    return (s[:n] + "…") if len(s) > n else (s or "(empty)")


# ------------------------------------------------------------------ the site's claims

def published():
    """What the site currently asserts, read from the files it serves."""
    out = {"vaults": {}, "victims": set(), "tracked": set()}
    try:
        src = open(os.path.join(publish.PUBLIC, "wave3.js"), encoding="utf-8").read()
        w3 = json.loads(re.search(r"window\.WAVE3=(.*);", src, re.S).group(1))
        out["vaults"] = {a: b for a, b in w3["vaults"]}
    except Exception:
        pass
    try:
        drains, _, _ = publish.parse_site()
        out["victims"] = {r[0] for r in drains["rows"]}
    except Exception:
        pass
    out["tracked"] = set(publish.TRACKED)
    return out


def sweep_detail(addr):
    """If this is a Wave 3 vault, what the frozen set says produced it."""
    try:
        s = json.load(open(os.path.join(DATA, "wave3-set.json")))
    except Exception:
        return None
    v = s.get("vaults", {}).get(addr)
    if not v:
        return None
    return {"park": v.get("park"), "vault_txid": v.get("txid"),
            "height": v.get("height"), "balance": v.get("balance")}


def verify(addr):
    """Deterministic. What does the site claim about this address, and does the chain
    still agree? No judgement, no model, only lookups and arithmetic."""
    p = published()
    r = {"addr": addr, "listed_as": None, "lines": []}

    if addr in p["vaults"]:
        r["listed_as"] = "Wave 3 attacker vault"
        d = sweep_detail(addr) or {}
        r["lines"].append(f"site says it holds {p['vaults'][addr]/1e8:.8f} BTC")
        if d.get("park"):
            r["lines"].append(f"fed by park {d['park']} in block {d.get('height')}")
    elif addr in p["tracked"]:
        r["listed_as"] = "tracked attacker address (waves 1, 2 or 5)"
    elif addr in p["victims"]:
        r["listed_as"] = "drained victim address"
    else:
        r["listed_as"] = "NOT on the site"
        r["lines"].append("nothing to remove; the claim may be about a different address")
        return r

    info = publish.esplora(f"/address/{addr}")
    if not info:
        r["lines"].append("chain lookup failed; re-check by hand")
        return r
    c = info["chain_stats"]
    bal = c["funded_txo_sum"] - c["spent_txo_sum"]
    r["lines"].append(f"chain now: {bal/1e8:.8f} BTC, {c['funded_txo_count']} in, "
                      f"{c['spent_txo_count']} out")
    if addr in p["vaults"]:
        if c["spent_txo_count"] > 0:
            r["lines"].append("SPENT since publication, so the site is already stale here")
        if abs(bal - p["vaults"][addr]) > 0:
            r["lines"].append("balance differs from what the site shows")
    return r


# ------------------------------------------------------------------ polling

def touched(num):
    files = get(f"/repos/{REPO}/pulls/{num}/files") or []
    paths = [f.get("filename", "") for f in files]
    hot = sorted({s for s in SENSITIVE for p in paths if p.startswith(s) or p == s})
    return paths, hot


def describe(item):
    is_pr = "pull_request" in item
    num, title = item["number"], item.get("title", "")
    who = (item.get("user") or {}).get("login", "?")
    labels = [l["name"] for l in item.get("labels", [])]
    body = item.get("body") or ""

    head = [f"{'PR' if is_pr else 'ISSUE'} #{num} by {who}",
            f"  {quote(title, 120)}",
            f"  {item.get('html_url')}"]
    if labels:
        head.append(f"  labels: {', '.join(labels)}")

    out = head + ["", "  they wrote:", f"  \"{quote(body)}\""]

    if is_pr:
        paths, hot = touched(num)
        out += ["", f"  changes {len(paths)} file(s)"]
        if hot:
            out.append("  TOUCHES SENSITIVE PATHS: " + ", ".join(hot))
            out.append("  do not merge without reading the diff yourself")
        else:
            out.append("  nothing under the sensitive paths")
        out.append("  CI: check the run before anything else")

    addrs = [a for a in dict.fromkeys(ADDR_RE.findall(body))][:5]
    if addrs:
        out.append("")
        out.append("  addresses named, checked against the chain:")
        for a in addrs:
            v = verify(a)
            out.append(f"    {a}")
            out.append(f"      listed as: {v['listed_as']}")
            for line in v["lines"]:
                out.append(f"      {line}")

    if "dispute" in labels or (not is_pr and addrs):
        out += ["", "  this is the queue you said comes first"]
    out.append("")
    out.append("  nothing was merged, commented on, or deployed.")
    return "\n".join(out)


def main():
    dry = "--dry-run" in sys.argv
    st = load_state()
    seen = set(st.get("seen", []))

    items = get(f"/repos/{REPO}/issues?state=open&sort=created&direction=desc&per_page=30")
    if items is None:
        print("github unreachable", file=sys.stderr)
        return 1

    fresh = [i for i in items if i["number"] not in seen]
    if "--since-all" in sys.argv:
        fresh = items
    print(f"{len(items)} open, {len(fresh)} new")

    for item in reversed(fresh):
        msg = "coldcard-watch repo\n\n" + describe(item)
        print("\n" + msg)
        if not dry:
            publish.notify_owner(msg, publish.load_env())
        seen.add(item["number"])

    if not dry:
        st["seen"] = sorted(seen)
        st["last_run"] = int(time.time())
        save_state(st)
    return 0


if __name__ == "__main__":
    sys.exit(main())
