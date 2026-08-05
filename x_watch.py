#!/usr/bin/env python3
"""
x_watch.py — watch X for people reporting their own addresses drained, verify each
claim on-chain, and feed the publishing pipeline.

Runs from cron on the Hetzner box every 30 minutes, so it keeps watching with the
Mac off. The block scanner (watch_blocks.py) finds clusters from the chain side;
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

usage: x_watch.py [--dry-run] [--backfill] [--once-query "..."]
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

import claims
import publish

ROOT_TWEET = "2083331338522820667"          # the launch thread
SEED_CONVERSATIONS = [ROOT_TWEET, "2083545024231567362"]   # + @americanhodl8 thread
API = "https://api.x.com/2"
UA = {"User-Agent": "coldcard-x-watch/1.0"}

# Sources that are authoritative for THIS incident, followed by identity rather than by
# keyword. A keyword query can only match terms someone imagined in advance, and on
# 2026-08-03 that failed exactly as you would expect: Galaxy Research — the source the
# methodology page cites and every mainstream article is single-sourced to — reported
# "1,596 BTC ... across 3 confirmed waves + more 14 smaller incidents" while the site
# published 1,366.58, and no query matched it. Their whole timeline is now read, replies
# included, and every post runs through claims.assess. Add an account here rather than
# widening KEYWORD_QUERY when a new outlet becomes load-bearing.
# @intangiblecoins is on this list for a specific, stated reason. Galaxy's own thread says
# where their numbers come from: "73 individual victims have reached out to @intangiblecoins
# for help tracing their coins. With help from victim reports, we have identified 14
# additional footprints." Their edge is not better chain analysis — it is a human intake
# channel we do not have. He is the intake point AND he publishes address lists (the wave-4
# entry on this site came from a paste of his), so reading his timeline in full is the
# closest thing to that channel available from outside it.
WATCHED_ACCOUNTS = ["glxyresearch", "intangiblecoins"]

KEYWORD_QUERY = ('(coldcard OR "cold card" OR coinkite) '
                 '(drained OR drain OR stolen OR stole OR hacked OR swept OR sweep '
                 'OR theft OR victim OR "lost my" OR "my btc" OR "my bitcoin" '
                 'OR "my funds" OR "my coins") -is:retweet')
# BOTH hosts on purpose. Searching only the old one meant this found nothing at all once the
# site moved — nobody links coldcard-watch.vercel.app anymore — so new mentions of the
# real site went unseen. The old host stays in the query because 51 referring domains and 170
# links still point at it, and a post citing either one is a post about this site.
URL_QUERY = ('(url:"coldcardwatch.com" OR url:"coldcard-watch.vercel.app") '
             '-is:retweet')

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


def watched_ids(env, st):
    """Resolve WATCHED_ACCOUNTS to user ids, cached in state so the lookup is one call ever
    rather than one per run. A handle that cannot be resolved is skipped and reported, never
    silently dropped: a watchlist that quietly holds nothing is the failure this replaces."""
    cache = st.setdefault("watched_ids", {})
    missing = [h for h in WATCHED_ACCOUNTS if h.lower() not in cache]
    if missing:
        try:
            d = xget(env, "/users/by", {"usernames": ",".join(missing),
                                        "user.fields": "public_metrics,username"})
            for u in d.get("data", []):
                cache[u["username"].lower()] = u["id"]
            for err in d.get("errors", []) or []:
                print(f"  watched account unresolved: {err.get('value')} "
                      f"({err.get('detail', 'no detail')})", flush=True)
        except XError as e:
            print(f"  watched_ids: {e}", flush=True)
    out = {h: cache[h.lower()] for h in WATCHED_ACCOUNTS if h.lower() in cache}
    for h in WATCHED_ACCOUNTS:
        if h.lower() not in cache:
            print(f"  WATCHLIST GAP: @{h} is not being read", flush=True)
    return out


def user_timeline(env, uid, since_id=None, start_time=None, max_pages=3):
    """A watched account's own posts INCLUDING its replies.

    Replies matter more than the headline here: Galaxy's "potential Wave 4 ... 2055 BTC" was
    reply 2 of its own thread, and that reply never repeats the word "coldcard", so no
    keyword search could ever have returned it. Retweets are excluded (they carry someone
    else's text and would double-count), replies are not."""
    params = {"max_results": 100, "exclude": "retweets",
              "tweet.fields": TFIELDS.split("=", 1)[1]}
    if since_id:
        params["since_id"] = since_id
    elif start_time:
        params["start_time"] = start_time
    pages = 0
    while pages < max_pages:
        d = xget(env, f"/users/{uid}/tweets", params)
        for t in d.get("data", []):
            yield t
        nxt = (d.get("meta") or {}).get("next_token")
        if not nxt:
            break
        params["pagination_token"] = nxt
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

    # Watched sources first, and unconditionally: their posts must not depend on a keyword
    # or URL query returning them. Their threads are also registered as watched_threads so
    # follow_threads picks up later replies that never repeat the topic word.
    for handle, uid in watched_ids(env, st).items():
        key = f"acct:{handle}"
        before = len(found)
        take(key, user_timeline(env, uid,
                                since_id=None if backfill else st["since"].get(key),
                                start_time=start,
                                max_pages=10 if backfill else 3))
        print(f"  @{handle}: {len(found) - before} new", flush=True)
        for t in list(found.values()):
            cid = t.get("conversation_id")
            if cid and t.get("author_id") == uid:
                st.setdefault("watched_threads", {}).setdefault(cid, t["id"])
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


def candidate_tweets(st, tweets):
    """The tweets whose addresses may become candidates, and how many were dropped.

    An address only becomes a candidate if the post carrying it is about THIS incident. This
    lives in its own function rather than inline in process() so a test can drive it with the
    real off-topic posts: when it was inline, removing the gate broke no test at all.

    Without the gate the account watchlist is a firehose — a watched research account covers
    every incident there is, and on 2026-08-04 reading one full timeline put a dormant
    whale's address (5,907 BTC) and a US government transfer into the queue. The keyword and
    URL searches constrain topic by construction; a timeline read does not.
    """
    tset = topical_convos(st, tweets)
    with_addrs, off_topic = [], 0
    for t in tweets:
        if not is_topical(t, tset):
            off_topic += 1
            continue
        addrs = [a for a in extract_addrs(tweet_text(t)) if a not in publish.ANCHORS]
        if addrs:
            t["_addrs"] = addrs
            with_addrs.append(t)
    return with_addrs, off_topic


def process(env, st, tweets, dry=False):
    """Extract, classify, verify, route. Returns (auto_entries, notes)."""
    drains, _, _ = publish.parse_site()
    known_victims = {r[0] for r in drains["rows"]}

    # An address only becomes a candidate if the post carrying it is about THIS incident.
    #
    # Without this the account watchlist is a firehose: a watched research account covers
    # every incident there is, so reading its full timeline harvested a dormant whale's
    # address (5,907 BTC) and a US government transfer into the candidate queue on the first
    # run — 14 unrelated addresses in three minutes. The keyword and URL searches constrain
    # topic by construction; a timeline read does not, so the gate has to live here, at the
    # point where text becomes a candidate, rather than in any one detector.
    with_addrs, off_topic = candidate_tweets(st, tweets)
    print(f"  {len(tweets)} new tweets, {len(with_addrs)} carry addresses"
          + (f", {off_topic} skipped as off-topic" if off_topic else ""), flush=True)

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
    publish.note_internal("\n".join(lines), env, dry)


def notify_collector(env, addr, v, url, dry):
    lines = ["POSSIBLE NEW COLLECTOR MENTIONED ON X", "",
             addr,
             "  receives batched single-input sweeps; this looks like a thief's "
             "address, not a victim's.",
             f"  mentioned: {url}",
             f"  https://mempool.space/address/{addr}", "",
             "Nothing was published. If it proves out, its victims belong in the set."]
    publish.note_internal("\n".join(lines), env, dry)


# ---------------------------------------------------------------- new-wave alerts
# The confirmed side of the site comes from our own detectors. The Potential side is a
# credible account breaking a wave report our scan cannot yet confirm. This flags such a
# report and pings a person to investigate — it never adds anything to the site itself.
WAVE_RE = re.compile(r"\b(another wave|new wave|4th wave|fourth wave|wave\s*4|wave\s*5|"
                     r"ongoing (?:now|drain|attack)|happening now|drain(?:ing)? now|"
                     r"siphon|attack (?:now|occurring|is live))\b", re.I)
PASTE_RE = re.compile(r"(pastebin\.com|paste\.|gist\.github|justpaste|rentry\.co|dpaste|controlc\.com)", re.I)
COLD_RE = re.compile(r"coldcard|coinkite|cold card", re.I)
FOLLOWER_MIN = 1000            # a credible voice, not a fresh throwaway account


def users_by_id(env, ids):
    out = {}
    ids = [i for i in ids if i]
    for i in range(0, len(ids), 100):
        d = xget(env, "/users", {"ids": ",".join(ids[i:i + 100]),
                                 "user.fields": "public_metrics,username"})
        for u in d.get("data", []):
            out[u["id"]] = u
    return out


def detect_wave_reports(env, st, tweets, dry=False):
    st.setdefault("wave_alerts", [])
    cand = []
    for t in tweets:
        if t["id"] in st["wave_alerts"]:
            continue
        txt = tweet_text(t)
        if not (WAVE_RE.search(txt) and COLD_RE.search(txt)):
            continue
        # the report has to carry an address list to be actionable, not just a claim
        if not (PASTE_RE.search(txt) or len(ADDR_RE.findall(txt)) >= 8):
            continue
        cand.append(t)
    if not cand:
        return
    authors = users_by_id(env, [t.get("author_id") for t in cand])
    for t in cand:
        u = authors.get(t.get("author_id"), {})
        foll = (u.get("public_metrics") or {}).get("followers_count", 0)
        if foll < FOLLOWER_MIN:
            continue
        st["wave_alerts"].append(t["id"])
        url = f"https://x.com/{u.get('username', 'i')}/status/{t['id']}"
        publish.note_internal(
            f"POSSIBLE NEW WAVE reported by @{u.get('username', '?')} ({foll:,} followers):\n"
            f"{url}\n\n{tweet_text(t)[:280]}\n\n"
            "Nothing added. Investigate it on-chain, and if credible approve it into the "
            "Potential layer with potential.py --add. It shows on the toggle as unverified "
            "until our own convergence test proves it, then it graduates to Confirmed.",
            env, dry)
        print(f"  wave alert: @{u.get('username')} {foll} followers {url}", flush=True)
        # follow this thread from now on, so a later correction or revised count in it is
        # seen even if that follow-up never repeats a keyword the search keys on
        cid = t.get("conversation_id") or t["id"]
        st.setdefault("watched_threads", {}).setdefault(cid, t["id"])
    st["wave_alerts"] = st["wave_alerts"][-2000:]


def topical_convos(st, tweets):
    """Conversation ids that are about THIS incident, as a set.

    Topic is decided per conversation rather than per post, because substance lands in
    replies that do not repeat the subject: Galaxy's "potential Wave 4 ... 2055 BTC" never
    says coldcard. Any conversation holding one on-topic post is on-topic, and the verdict
    persists in state so a reply arriving in a later run still qualifies.

    This gate is what makes an account watchlist safe. A watched research account posts
    about every incident there is, so reading its whole timeline without a topic test pulls
    in addresses that have nothing to do with this theft — see the comment in process()."""
    tset = set(st.setdefault("topical_convos", []))
    for t in tweets:
        if COLD_RE.search(tweet_text(t)):
            tset.add(t.get("conversation_id") or t["id"])
    st["topical_convos"] = sorted(tset)[-4000:]
    return tset


def is_topical(t, tset):
    return bool(COLD_RE.search(tweet_text(t))) or (t.get("conversation_id") or t["id"]) in tset


def detect_site_behind(env, st, tweets, dry=False):
    """The detector that replaces guessing at wording: does a credible source state a total
    materially larger than the one the site publishes?

    This one DOES notify, because it is not an unanswerable question — it reports that the
    site's own published figure is understating the theft, which is a fact about the live
    site. It still publishes nothing: closing the gap needs our detectors to find the
    clusters on-chain, and that is the pipeline's job, not a decision to forward.

    Throttled on the claimed figure, so a source restating the same total on ten posts
    alerts once, while a revised total alerts immediately.
    """
    st.setdefault("behind_alerts", {})
    pub_btc, pub_addr = claims.published_totals()
    if not pub_btc:
        print("  site-behind: cannot read the published total, skipping", flush=True)
        return
    # The bar is the largest figure the site SHOWS, not the one it proved. Once Galaxy's
    # 1,596 and 2,055 are carried on the toggle, comparing against the verified 1,366 would
    # report the site as behind the very numbers it is already displaying, every run.
    carried = claims.carried_total()

    # This detector FETCHES ITS OWN WINDOW and does not use the new-tweet batch alone.
    #
    # That is not redundancy. gather() filters out anything already in seen_tweets, and this
    # check asks a question about the present ("is the site's published number lower than
    # what the source states?"), not about novelty. The distinction is load-bearing: when
    # this was first written to read only the new batch, it could not fire for the very
    # Galaxy posts that motivated it, because those posts were already seen. A detector that
    # cannot fire for its own origin case is decoration.
    #
    # Repetition is prevented by keying behind_alerts on the claimed figure, not on the
    # tweet, so re-reading the same window every run costs one API call and zero messages.
    ids = watched_ids(env, st)
    watched = {uid: h for h, uid in ids.items()}
    pool = {t["id"]: t for t in tweets if t.get("author_id") in watched}
    for handle, uid in ids.items():
        try:
            for t in user_timeline(env, uid, max_pages=1):
                pool[t["id"]] = t
        except XError as e:
            print(f"  site-behind: @{handle} timeline unavailable: {e}", flush=True)
    tweets = list(pool.values())
    tset = topical_convos(st, tweets)
    print(f"  site-behind: assessing {len(tweets)} watchlist post(s) against "
          f"{pub_btc:,.4f} BTC verified"
          + (f" and {carried:,.0f} BTC carried" if carried else ""), flush=True)

    # A topic gate is required, and it is NOT the wording-guessing this detector replaces:
    # the CLAIM is matched structurally, but an authoritative crypto account posts about
    # every incident there is. Without this, a dormant-whale move (5,908 BTC) and a US
    # government transfer (2,875 BTC) both read as "the site is 4,500 BTC behind" — both
    # verified false positives on @glxyresearch's real timeline.
    #
    # Topic is decided per CONVERSATION, not per post, because the substance lands in
    # replies that do not repeat the word: Galaxy's "potential Wave 4 ... 2055 BTC" never
    # says coldcard. So any conversation containing an on-topic post is on-topic, and that
    # verdict persists in state for replies that arrive in a later run.
    hits = {}
    for t in tweets:
        aid = t.get("author_id")
        handle = watched.get(aid)
        if not handle:
            continue                    # only sources we have decided are authoritative
        txt = tweet_text(t)
        cid = t.get("conversation_id") or t["id"]
        if not is_topical(t, tset):
            continue                    # a real claim, but about some other incident
        v = claims.assess(txt, pub_btc, pub_addr, carried_btc=carried)
        if v.get("revised_down"):
            # A figure from the source BELOW the one the site carries on their authority
            # would mean the site is overstating, and nothing on-chain would ever show it.
            # It is still a note rather than a message: a post about one earlier wave
            # carries a smaller total too, and telling a revision from a subtotal needs the
            # prose read, which is the wording-guessing this detector exists to avoid.
            # Nobody can action the ambiguity, so it goes to the log.
            publish.note_internal(
                f"@{handle} states {v['claim_btc']:,.0f} BTC while the site carries "
                f"{carried:,.0f}. Either a revision or a figure for part of the incident; "
                f"the difference is stated in prose this does not read.\n"
                f"  https://x.com/{handle}/status/{t['id']}", env, dry)
        if not v["behind"]:
            continue
        # One report is one event even when it spans a thread. Galaxy's headline carried the
        # address count and its reply carried the larger BTC total; merging the conversation
        # gives one message with the fullest picture instead of two partial ones.
        g = hits.setdefault(cid, {"handle": handle, "tid": t["id"], "v": v})
        if v["claim_btc"] > g["v"]["claim_btc"]:
            g["tid"], g["v"] = t["id"], dict(v)
        else:
            g["v"]["claims_btc"] = sorted(
                set(g["v"]["claims_btc"]) | set(v["claims_btc"]), reverse=True)
        if (v.get("claim_addresses") or 0) > (g["v"].get("claim_addresses") or 0):
            g["v"]["claim_addresses"] = v["claim_addresses"]
            g["v"]["gap_addresses"] = v["gap_addresses"]

    for cid, g in hits.items():
        handle, v = g["handle"], g["v"]
        # key on the figure, not the tweet: the same claim restated is one event, a revised
        # total is a new one
        key = f"{handle}:{v['claim_btc']:.0f}"
        if key in st["behind_alerts"]:
            print(f"  site-behind: already reported {key}", flush=True)
            continue
        url = f"https://x.com/{handle}/status/{g['tid']}"
        publish.notify_change(claims.describe(v, source=handle, url=url), env, dry)
        if not dry:
            st["behind_alerts"][key] = int(time.time())
        print(f"  SITE BEHIND: {handle} claims {v['claim_btc']:.0f} BTC vs "
              f"{pub_btc:.4f} published (gap {v['gap_btc']:.2f})", flush=True)


def follow_threads(env, st):
    """Pull new tweets on threads already being followed (a thread that produced a wave
    report or a Potential entry). A follow-up in an OLD thread — a correction, a revised
    count, a victim confirmation — is caught here even when it never repeats 'coldcard'
    and a keyword search would miss it entirely."""
    watched = st.setdefault("watched_threads", {})
    fresh = []
    for cid in list(watched):
        try:
            got = list(search(env, f"conversation_id:{cid}",
                              since_id=watched[cid] or None, max_pages=2))
        except XError as e:
            print(f"  follow_threads {cid}: {e}", flush=True)
            continue
        for t in got:
            if t["id"] not in st["seen_tweets"]:
                fresh.append(t)
        if got:
            watched[cid] = max([watched[cid] or "0"] + [t["id"] for t in got], key=int)
        time.sleep(1.0)
    return fresh


def alert_thread_updates(env, st, tweets, dry=False):
    """A substantive follow-up on a watched thread (a correction, a revised address/BTC
    count, a multisig discount, a victim confirmation) is surfaced to a person. It never
    changes the site on its own."""
    st.setdefault("thread_alerts", [])
    UPD = re.compile(r"\b(update|correct|erroneous|revis|impact|discount|multisig|"
                     r"victim|confirm|[\d][\d.,]*\s*BTC|[\d,]+\s*addr)", re.I)
    for t in tweets:
        if t["id"] in st["thread_alerts"]:
            continue
        txt = tweet_text(t)
        if not UPD.search(txt):
            continue
        st["thread_alerts"].append(t["id"])
        url = f"https://x.com/i/web/status/{t['id']}"
        publish.note_internal(
            f"UPDATE on a watched thread:\n{url}\n\n{txt[:300]}\n\n"
            "This continues a thread that produced a wave report or a Potential entry. "
            "Review whether it changes what should be shown; nothing was changed automatically.",
            env, dry)
        print(f"  thread-update alert: {url}", flush=True)
    st["thread_alerts"] = st["thread_alerts"][-2000:]


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
    # follow threads we already care about, catching follow-ups (corrections, revised
    # counts) that a keyword or url search would miss
    thread_new = []
    try:
        thread_new = follow_threads(env, st)
        tweets += thread_new
    except Exception as e:
        print(f"  follow_threads failed: {e}", file=sys.stderr, flush=True)
    for t in tweets:
        st["seen_tweets"].append(t["id"])
    st["seen_tweets"] = st["seen_tweets"][-20000:]

    # the site's own figure vs what an authoritative source states. This is the check that
    # would have caught the 2026-08-03 Galaxy report; it runs before the others because it
    # is the one that says the live site is wrong.
    try:
        detect_site_behind(env, st, tweets, dry=a.dry_run)
    except Exception as e:
        print(f"  site-behind detection failed: {e}", file=sys.stderr, flush=True)

    # flag a credible new-wave report for a person to investigate (adds nothing itself)
    try:
        detect_wave_reports(env, st, tweets, dry=a.dry_run)
    except Exception as e:
        print(f"  wave-report detection failed: {e}", file=sys.stderr, flush=True)
    # surface substantive updates on threads we already follow
    try:
        alert_thread_updates(env, st, thread_new, dry=a.dry_run)
    except Exception as e:
        print(f"  thread-update alert failed: {e}", file=sys.stderr, flush=True)

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
            publish.note_internal(
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
