#!/usr/bin/env python3
"""
x-watch.py — watch X for people reporting their own addresses drained, verify each
claim on-chain, and feed the publishing pipeline.

Runs from cron on the Hetzner box every 30 minutes, so it keeps watching with the
Mac off. The block scanner (watch-blocks.py) finds clusters from the chain side;
this finds them from the human side: a victim saying "this address was mine."

Per run:
  1. Search X since the last run: replies to the tracked threads, new quote tweets
     and replies to them, tweets linking the site, and a broad theft-keyword sweep.
  2. Pull every bitcoin address out of the new tweets.
  3. Classify each tweet with a local Claude call: is the author reporting their
     own loss, and which address do they claim as theirs?
  4. Verify every candidate on-chain (publish.verify_addr). The chain decides,
     not the tweet.
  5. Route by proof:
       proven      -> published automatically (publish.publish), Telegram receipt
       pattern     -> pending + Telegram, a human decides (publish.py --approve)
       collector   -> Telegram as a possible new cluster, never auto-published
       everything else -> recorded in state, no noise
  6. Re-check pending candidates every few hours; a later consolidation can turn
     a pattern match into proof.

usage: x-watch.py [--dry-run] [--backfill] [--once-query "..."]
state: ~/.coldcard-x-state.json (shared with publish.py)
env:   ~/.coldcard-x-env (X_BEARER_TOKEN, TELEGRAM_BOT_TOKEN, CC_ADMIN_ID, VERCEL_TOKEN)
"""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

import publish

ROOT_TWEET = "2083331338522820667"          # the launch thread
SEED_CONVERSATIONS = [ROOT_TWEET, "2083545024231567362"]   # + @americanhodl8 thread
API = "https://api.x.com/2"
UA = {"User-Agent": "coldcard-x-watch/1.0"}

KEYWORD_QUERY = ('(coldcard OR "cold card" OR coinkite) '
                 '(drained OR drain OR stolen OR stole OR hacked OR swept OR sweep '
                 'OR theft OR victim OR "lost my" OR "my btc" OR "my bitcoin" '
                 'OR "my funds" OR "my coins") -is:retweet')
URL_QUERY = 'url:"coldcard-watch.vercel.app" -is:retweet'

ADDR_RE = re.compile(r'\b(bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b',
                     re.IGNORECASE)
TFIELDS = "tweet.fields=author_id,conversation_id,created_at,public_metrics,note_tweet"
RECHECK_SECS = 6 * 3600
MAX_CLASSIFY = 20        # tweets per claude call
MAX_QT_CONVOS = 12       # bounded per normal run


class XError(Exception):
    pass


def xget(env, path, params, tries=3):
    url = f"{API}{path}?" + urllib.parse.urlencode(params, safe=':"()')
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {env['X_BEARER_TOKEN']}", **UA})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = int(e.headers.get("x-rate-limit-reset", 0)) - int(time.time())
                wait = min(max(wait, 15), 900)
                print(f"  rate limited on {path}, sleeping {wait}s", flush=True)
                time.sleep(wait)
                continue
            if e.code in (500, 502, 503) and i < tries - 1:
                time.sleep(5)
                continue
            raise XError(f"{path}: HTTP {e.code} {e.read().decode()[:200]}")
        except Exception as e:
            if i == tries - 1:
                raise XError(f"{path}: {e}")
            time.sleep(5)
    raise XError(f"{path}: retries exhausted")


def tweet_text(t):
    nt = t.get("note_tweet") or {}
    return nt.get("text") or t.get("text", "")


def search(env, query, since_id=None, start_time=None, archive=False, max_pages=3):
    """Yield tweets. Recent search for the cron loop, full archive for backfill."""
    path = "/tweets/search/all" if archive else "/tweets/search/recent"
    params = {"query": query, "max_results": 100}
    params["tweet.fields"] = TFIELDS.split("=", 1)[1]
    if since_id:
        params["since_id"] = since_id
    elif start_time:
        params["start_time"] = start_time
    pages = 0
    while pages < max_pages:
        d = xget(env, path, params)
        for t in d.get("data", []):
            yield t
        nxt = (d.get("meta") or {}).get("next_token")
        if not nxt:
            break
        params["next_token"] = nxt
        pages += 1
        time.sleep(1.2)


def quote_tweets(env, tweet_id, max_pages=3):
    params = {"max_results": 100}
    params["tweet.fields"] = TFIELDS.split("=", 1)[1]
    pages = 0
    while pages < max_pages:
        d = xget(env, f"/tweets/{tweet_id}/quote_tweets", params)
        for t in d.get("data", []):
            yield t
        nxt = (d.get("meta") or {}).get("next_token")
        if not nxt:
            break
        params["pagination_token"] = nxt
        pages += 1
        time.sleep(1.2)


def extract_addrs(text):
    out = []
    for m in ADDR_RE.findall(text):
        a = m.lower() if m.lower().startswith("bc1") else m
        if a not in out:
            out.append(a)
    return out


# ---------------------------------------------------------------- classification

def classify(tweets):
    """One local Claude call for a batch. Returns {tweet_id: verdict}. On any
    failure returns {}, and every address stays a candidate — the on-chain gate
    is what protects the site, not this step."""
    if not tweets:
        return {}
    items = [{"id": t["id"], "text": tweet_text(t)[:800]} for t in tweets]
    prompt = (
        "These tweets are from a discussion of the July 2026 Coldcard wallet drain "
        "incident. Each may mention bitcoin addresses. For each tweet decide:\n"
        "- victim_report: true if the AUTHOR claims funds THEY OWN were stolen or "
        "drained, false if they are discussing someone else's loss, quoting an "
        "attacker address, sharing news, or unclear.\n"
        "- victim_addrs: addresses the author presents as their own drained address.\n"
        "- attacker_addrs: addresses the author presents as the thief's.\n"
        "- summary: one short factual line.\n\n"
        "Reply with ONLY a JSON array, one object per tweet: "
        '[{"id": "...", "victim_report": true, "victim_addrs": [], '
        '"attacker_addrs": [], "summary": "..."}]\n\n'
        + json.dumps(items))
    try:
        r = subprocess.run(["claude", "-p", "--model", "claude-sonnet-5"],
                           input=prompt, capture_output=True, text=True, timeout=180)
        out = r.stdout.strip()
        m = re.search(r'\[.*\]', out, re.S)
        parsed = json.loads(m.group(0)) if m else []
        return {str(x.get("id")): x for x in parsed if isinstance(x, dict)}
    except Exception as e:
        print(f"  classification failed ({e}); continuing without it", flush=True)
        return {}


# ---------------------------------------------------------------- collector guard

def collector_shaped(addr):
    """True when the address looks like an attacker collector rather than a victim:
    three or more single-input single-output deposits landing in one block. A tweet
    often quotes the THIEF's address; publishing that as a victim would be the worst
    possible error, so anything collector-shaped goes to a human."""
    try:
        txs = publish.esplora(f"/address/{addr}/txs")
    except Exception:
        return False
    per_block = {}
    for t in txs:
        outs = t.get("vout", [])
        ins = t.get("vin", [])
        if len(ins) == 1 and len(outs) == 1 \
                and outs[0].get("scriptpubkey_address") == addr:
            h = (t.get("status") or {}).get("block_height")
            if h:
                per_block[h] = per_block.get(h, 0) + 1
    return any(v >= 3 for v in per_block.values())


# ---------------------------------------------------------------- main loop

def gather(env, st, backfill=False):
    """Collect new tweets from every watch surface. Returns list of tweets."""
    seen = set(st["seen_tweets"])
    found = {}

    def take(key, gen):
        newest = int(st["since"].get(key) or 0)
        try:
            for t in gen:
                newest = max(newest, int(t["id"]))
                if t["id"] not in seen:
                    found[t["id"]] = t
        except XError as e:
            print(f"  {key}: {e}", flush=True)
            return
        if newest:
            st["since"][key] = str(newest)

    start = "2026-07-29T00:00:00Z" if backfill else None
    arch = backfill

    for conv in SEED_CONVERSATIONS:
        key = f"conv:{conv}"
        take(key, search(env, f"conversation_id:{conv}",
                         since_id=None if backfill else st["since"].get(key),
                         start_time=start, archive=arch,
                         max_pages=10 if backfill else 3))
        time.sleep(1.2)

    key = "url"
    take(key, search(env, URL_QUERY,
                     since_id=None if backfill else st["since"].get(key),
                     start_time=start, archive=arch,
                     max_pages=10 if backfill else 3))
    time.sleep(1.2)

    key = "kw"
    take(key, search(env, KEYWORD_QUERY,
                     since_id=None if backfill else st["since"].get(key),
                     start_time=start, archive=arch,
                     max_pages=10 if backfill else 3))
    time.sleep(1.2)

    # quote tweets of the root, and replies inside QT conversations that have
    # grown since the last look
    qts = {}
    try:
        for t in quote_tweets(env, ROOT_TWEET, max_pages=5 if backfill else 2):
            qts[t["id"]] = t
            if t["id"] not in seen:
                found[t["id"]] = t
    except XError as e:
        print(f"  quote_tweets: {e}", flush=True)

    convos = 0
    budget = 150 if backfill else MAX_QT_CONVOS
    for qid, t in qts.items():
        replies = (t.get("public_metrics") or {}).get("reply_count", 0)
        last = st["qt_replies"].get(qid, 0)
        if replies > last and convos < budget:
            take(f"qtc:{qid}", search(env, f"conversation_id:{qid}",
                                      start_time=start if backfill else None,
                                      archive=arch, max_pages=2))
            st["qt_replies"][qid] = replies
            convos += 1
            time.sleep(1.2)

    return list(found.values())


def process(env, st, tweets, dry=False):
    """Extract, classify, verify, route. Returns (auto_entries, notes)."""
    drains, _, _ = publish.parse_site()
    known_victims = {r[0] for r in drains["rows"]}

    with_addrs = []
    for t in tweets:
        addrs = extract_addrs(tweet_text(t))
        addrs = [a for a in addrs if a not in publish.ANCHORS]
        if addrs:
            t["_addrs"] = addrs
            with_addrs.append(t)
    print(f"  {len(tweets)} new tweets, {len(with_addrs)} carry addresses", flush=True)

    verdicts = {}
    for i in range(0, len(with_addrs), MAX_CLASSIFY):
        verdicts.update(classify(with_addrs[i:i + MAX_CLASSIFY]))

    auto, checked_now = [], set()
    for t in with_addrs:
        cls = verdicts.get(t["id"], {})
        url = f"https://x.com/i/status/{t['id']}"
        for addr in t["_addrs"]:
            if addr in checked_now:
                continue
            prev = st["checked"].get(addr)
            if prev and prev.get("status") in ("proven", "already_listed",
                                               "not_drained", "collector"):
                continue
            if prev and time.time() - prev.get("ts", 0) < RECHECK_SECS:
                continue
            checked_now.add(addr)

            v = publish.verify_addr(addr, known_victims)
            time.sleep(0.6)

            if v["status"] in ("proven", "pattern") and collector_shaped(addr):
                v["status"] = "collector"
                v["evidence"].append("address receives batched single-input sweeps: "
                                     "collector-shaped, not a victim wallet")
            st["checked"][addr] = {"status": v["status"], "ts": int(time.time()),
                                   "tweet": url}
            print(f"  {addr}: {v['status']}", flush=True)

            if v["status"] == "proven":
                v["tweet"] = url
                auto.append(v)
            elif v["status"] == "pattern":
                if addr not in st["pending"]:
                    v["tweet"] = url
                    v["ts"] = int(time.time())
                    v["claimed_by_author"] = bool(cls.get("victim_report"))
                    st["pending"][addr] = v
                    notify_pending(env, addr, v, cls, dry)
            elif v["status"] == "collector":
                key = f"collector_notified:{addr}"
                if not st.get(key):
                    st[key] = int(time.time())
                    notify_collector(env, addr, v, url, dry)
            elif v["status"] == "already_listed":
                st.setdefault("confirmed_reports", []).append(
                    {"addr": addr, "tweet": url, "ts": int(time.time())})
    return auto


def recheck_pending(env, st):
    """A pattern-tier candidate can become provable once the attacker moves the
    funds again. Quietly upgrade when that happens."""
    drains, _, _ = publish.parse_site()
    known_victims = {r[0] for r in drains["rows"]}
    upgraded = []
    for addr, p in list(st["pending"].items()):
        if time.time() - p.get("ts", p.get("time", 0) or 0) < RECHECK_SECS:
            continue
        v = publish.verify_addr(addr, known_victims)
        v["ts"] = int(time.time())
        time.sleep(0.6)
        if v["status"] == "proven":
            v["tweet"] = p.get("tweet")
            upgraded.append(v)
        elif v["status"] == "already_listed":
            st["pending"].pop(addr, None)
        else:
            p["ts"] = int(time.time())
    return upgraded


def notify_pending(env, addr, v, cls, dry):
    lines = ["POSSIBLE DRAIN REPORTED ON X", "",
             addr,
             f"  {v.get('sats', 0)/1e8:.8f} BTC left it"
             + (f" in block {v['height']}" if v.get("height") else ""),
             f"  reported: {v.get('tweet', '?')}"]
    if cls.get("summary"):
        lines.append(f"  the tweet: {cls['summary']}")
    lines.append("")
    lines += [f"  - {e}" for e in v.get("evidence", [])[:5]]
    lines += ["",
              "The sweep matches the drain pattern but does not connect to a known "
              "cluster, so nothing was published.",
              f"To publish: reply  approve {addr}",
              f"To dismiss: reply  reject {addr}",
              f"  https://mempool.space/address/{addr}"]
    publish.send_telegram("\n".join(lines), env, dry)


def notify_collector(env, addr, v, url, dry):
    lines = ["POSSIBLE NEW COLLECTOR MENTIONED ON X", "",
             addr,
             "  receives batched single-input sweeps; this looks like a thief's "
             "address, not a victim's.",
             f"  mentioned: {url}",
             f"  https://mempool.space/address/{addr}", "",
             "Nothing was published. If it proves out, its victims belong in the set."]
    publish.send_telegram("\n".join(lines), env, dry)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--backfill", action="store_true")
    a = ap.parse_args()

    env = publish.load_env()
    if not env.get("X_BEARER_TOKEN"):
        print("X_BEARER_TOKEN missing; cannot run", file=sys.stderr)
        return 1

    st = publish.load_state()
    print(time.strftime("%Y-%m-%d %H:%M:%S ")
          + ("backfill" if a.backfill else "run"), flush=True)

    tweets = gather(env, st, backfill=a.backfill)
    for t in tweets:
        st["seen_tweets"].append(t["id"])
    st["seen_tweets"] = st["seen_tweets"][-20000:]
    if not a.dry_run:
        publish.save_state(st)          # checkpoint before the slow part

    auto = process(env, st, tweets, dry=a.dry_run)
    auto += recheck_pending(env, st)

    if auto:
        entries = [{"addr": v["addr"], "sats": v["sats"], "height": v["height"],
                    "time": v["time"], "dest": v["dest"]} for v in auto]
        try:
            res = publish.publish(entries, env, dry=a.dry_run, source="x-watch", st=st)
            print(f"  published: {res}", flush=True)
        except Exception as e:
            print(f"  PUBLISH FAILED: {e}", file=sys.stderr, flush=True)
            publish.send_telegram(
                "Coldcard X watcher: verification passed for "
                f"{len(entries)} address(es) but publishing failed:\n{e}\n"
                "The candidates are kept and will retry next run.", env, a.dry_run)
            for v in auto:
                st["pending"][v["addr"]] = v

    if not a.dry_run:
        publish.save_state(st)
    print(f"  done | pending {len(st['pending'])} | "
          f"published total {len(st['published'])}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
