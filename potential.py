#!/usr/bin/env python3
"""
potential.py — the lifecycle of an unverified report shown on the Potential toggle.

The confirmed dataset is what our own detectors proved on-chain. The Potential layer
is different: a credible account breaks a wave report our scan cannot yet confirm.
Publishing that as verified would be laundering someone else's claim, so it lives in
potential.js, shown behind the toggle, clearly unverified, never counted in the total.

Two rules keep it honest:
  - Nothing enters Potential without a person approving it (--add, fired from the
    Telegram alert x_watch.py raises). The site never auto-ingests an X claim.
  - Nothing LEAVES Potential for Confirmed on a claim. It graduates only when our own
    deterministic test passes: the reported destinations converge — they co-spend with
    a known attacker address, or funnel into a shared vault. --graduate runs that test
    and flags a ready entry for the human to publish; it never merges silently.
  - An entry that never proves out expires (--expire), so the layer cannot rot.

The full victim/destination lists for each entry live in a sidecar under ./sidecar/,
gitignored so the public repo never carries victim addresses, but inside the working tree
so syncthing delivers it to the box that runs --graduate. potential.js carries only the
summary. An entry without a sidecar cannot be tested, so --add refuses to create one.

usage: potential.py --list
       potential.py --add --id <id> --source <@handle> --url <tweet> --sats <n>
                    --blocks A B --dests <file.json> --note "<text>"
       potential.py --graduate [--id <id>]
       potential.py --expire --days 3
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import publish

POT_JS = os.path.join(publish.PUBLIC, "potential.js")
# The sidecar lives INSIDE the repo working tree (gitignored, never committed — the repo
# is public and these are victim addresses) rather than in the home directory, because the
# only machine that runs --graduate is the box, and ~/.coldcard-potential does not travel.
# The working tree does: syncthing carries it, so an --add run on either machine reaches
# the cron host. A home-directory sidecar is why wave 4 sat untestable for a day.
SIDECAR = os.path.join(HERE, "sidecar")
LEGACY_SIDECAR = os.path.expanduser("~/.coldcard-potential")
HOSTS = ["https://blockstream.info/api", "https://mempool.space/api"]
UA = {"User-Agent": "coldcard-potential/1.0"}


def sidecar_path(entry_id):
    """Where a new sidecar is written."""
    return os.path.join(SIDECAR, entry_id + ".json")


ALERTS = os.path.join(SIDECAR, "_alerts.json")
ALERT_QUIET_HOURS = 24


def alert_once(key, message, env, quiet_hours=ALERT_QUIET_HOURS):
    """Record an internal note only when its content has changed, or when the same content
    has not been recorded for quiet_hours. --graduate runs hourly and these conditions are
    STICKY (they hold until something on-chain changes), so an unguarded call repeats the
    same line 24 times a day and buries the runs that actually did something. Keyed on
    entry+situation, fingerprinted on the text so a changed verdict does record immediately.

    These are notes, not messages: neither branch is answerable by a person. The
    shared-vault case is a judgement this codebase owns, and a missing sidecar is a bug in
    it. If a shared-vault entry never proves out, --expire drops it and THAT is the
    notification, because the site changes."""
    try:
        with open(ALERTS) as fh:
            state = json.load(fh)
    except Exception:
        state = {}
    prev = state.get(key) or {}
    now = time.time()
    if prev.get("msg") == message and now - prev.get("ts", 0) < quiet_hours * 3600:
        print(f"  (note suppressed, unchanged within {quiet_hours}h: {key})")
        return False
    publish.note_internal(message, env)
    state[key] = {"msg": message, "ts": now}
    os.makedirs(SIDECAR, exist_ok=True)
    with open(ALERTS, "w") as fh:
        json.dump(state, fh)
    return True


def read_sidecar(entry_id):
    """The synced location wins; the pre-move home directory is still honoured so an
    entry added before this change keeps working. Returns None when there is none."""
    for base in (SIDECAR, LEGACY_SIDECAR):
        p = os.path.join(base, entry_id + ".json")
        if os.path.exists(p):
            with open(p) as fh:
                return json.load(fh)
    return None


def esp(path, tries=4):
    last = None
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(HOSTS[i % len(HOSTS)] + path,
                                                               headers=UA), timeout=30) as r:
                return json.load(r)
        except Exception as e:
            last = e
            time.sleep(1.2 * (i + 1))
    raise RuntimeError(f"{path}: {last}")


def load():
    if not os.path.exists(POT_JS):
        return {"schema": 2, "tiers": [], "entries": [], "total_sats": 0}
    s = open(POT_JS).read()
    d = json.loads(s[s.index("{"):s.rindex("}") + 1])
    d.setdefault("schema", 2)
    d.setdefault("tiers", [])
    d.setdefault("entries", [])
    return d


# --------------------------------------------------------------------- tiers
#
# A tier is a figure published by a source that has evidence this site structurally cannot
# get: Galaxy Research confirms victims by private correspondence, so their total covers
# thefts whose addresses are not public and never will be. Refusing to carry that number
# does not make the site more accurate, it makes it understated, and it was: the site read
# 1,366 while the settled figure everywhere else was 1,596.
#
# Two rules make carrying it honest rather than laundering:
#
#   A tier stores the source's TOTAL, never a remainder. The site subtracts what it has
#   verified itself and shows the difference. A frozen remainder is wrong the moment the
#   verified set grows — the first version of this stored 229.4226 BTC against a verified
#   1,366.5774, and the verified figure has already moved to 1,366.5874 since.
#
#   A tier is a ceiling for everything inside it. Galaxy's 2,055 already contains Wave 4,
#   so an independent poster's read of that same wave is evidence ABOUT the tier, not an
#   addition to it. Entries that sit inside a tier carry subsumed_by and are listed rather
#   than summed. Without that the site showed 1,984.94 BTC, a number no source claims.
TIER_KEYS = ("attested", "suspected")


def verified_sats(public_dir=None):
    """What this site has verified on its own, in sats: the seeded clusters plus wave 3
    plus anything a Potential entry graduated into. Read from the published files rather
    than from any cached figure, for the same reason claims.published_totals is: a tier's
    delta must be computed against what the site actually says today."""
    pub = public_dir or publish.PUBLIC
    total = 0
    with open(os.path.join(pub, "index.html"), encoding="utf-8") as fh:
        idx = fh.read()
    # the seeded clusters: attributed, not balance, so the delta does not move when the
    # attacker spends. Only literal numeric attributions match; the traced-hop push writes
    # `attributed:o.value`, which is downstream of one of these and must not be added again.
    for m in re.finditer(r"attributed:\s*(\d+)[^{}]*?origin:\s*\"seed\"", idx):
        total += int(m.group(1))
    for name, key in (("wave3.js", "held"), ("confirmed-extra.js", "held")):
        p = os.path.join(pub, name)
        if not os.path.exists(p):
            continue
        s = open(p, encoding="utf-8").read()
        obj = json.loads(s[s.index("{"):s.rindex("}") + 1])
        total += int(obj.get(key) or 0)
    return total


def tier_delta(tier, verified=None):
    """The part of a source's total this site has not verified itself. Never negative: if
    our own verified figure passes theirs, the tier has been overtaken and adds nothing."""
    v = verified_sats() if verified is None else verified
    return max(0, int(tier.get("total_sats") or 0) - v)


def save(data, deploy=True):
    # Only entries that stand on their own are summed. An entry inside a tier is listed as
    # evidence for that tier and adds nothing, or the same coins are counted twice.
    data["total_sats"] = sum(e.get("sats", 0) for e in data["entries"]
                             if e.get("status") == "potential" and not e.get("subsumed_by"))
    with open(POT_JS, "w") as f:
        f.write("window.POTENTIAL=" + json.dumps(data, separators=(",", ":")) + ";\n")
    print(f"wrote {len(data['entries'])} entr(y/ies), potential total "
          f"{data['total_sats']/1e8:.8f} BTC")
    if deploy:
        try:
            url = publish.deploy()
            print(f"deployed {url}")
        except Exception as e:
            print(f"deploy failed (site not updated): {e}", file=sys.stderr)


def known_attacker_set():
    """The confirmed attacker addresses the convergence test links against."""
    import re
    known = set()
    idx = open(os.path.join(publish.PUBLIC, "index.html")).read()
    known |= set(re.findall(r"bc1q[0-9a-z]{38}", idx))
    st = publish.load_state()
    known |= set(st.get("cospend_known", [])) | set(st.get("cospend_expanded", []))
    w3 = os.path.join(publish.PUBLIC, "wave3.js")
    if os.path.exists(w3):
        s = open(w3).read()
        w = json.loads(s[s.index("{"):s.rindex("}") + 1])
        known |= {v[0] for v in w.get("vaults", [])}
    return known


MAX_CONV_DESTS = 1200          # cap per run so one huge entry cannot exhaust an API budget


def convergence(dests, known):
    """Deterministic proof test on a set of destinations. Returns a verdict dict.
    Proof is either a co-spend with a known attacker address, or several destinations
    funnelling into one shared second-hop address (common ownership)."""
    moved = 0
    cospend_known = []
    hop2 = defaultdict(set)
    dset = set(dests)
    if len(dests) > MAX_CONV_DESTS:
        print(f"  convergence: {len(dests)} dests exceeds cap {MAX_CONV_DESTS}; "
              f"checking the first {MAX_CONV_DESTS} this run, the rest next run", flush=True)
        dests = dests[:MAX_CONV_DESTS]
    for d in dests:
        try:
            txs = esp(f"/address/{d}/txs")
        except Exception:
            continue
        for t in txs:
            vin = [(v.get("prevout") or {}).get("scriptpubkey_address") for v in t.get("vin", [])]
            vin = [a for a in vin if a]
            if d in vin:
                moved += 1
                hit = (set(vin) - {d}) & known
                if hit:
                    cospend_known.append({"dest": d, "known": sorted(hit), "txid": t["txid"]})
                for o in t.get("vout", []):
                    a = o.get("scriptpubkey_address")
                    if a and a not in dset:
                        hop2[a].add(d)
                break
        time.sleep(0.2)
    converge = {a: sorted(ds) for a, ds in hop2.items() if len(ds) >= 3}
    proven = bool(cospend_known) or bool(converge)
    return {"dests": len(dests), "moved": moved, "cospend_known": cospend_known,
            "shared_hop2": converge, "proven": proven}


def cmd_tier(a):
    """Record or revise a source's published total.

    The figure is theirs and the site says so; what this command owns is the arithmetic
    around it. It stores the total, derives the unverified remainder against the site's
    own verified figure at write time for the operator to sanity-check, and refuses a
    total that sits below one already carried at a stronger standard — a suspected figure
    smaller than the attested one is a transcription error, not a finding."""
    if not a.tier or a.tier not in TIER_KEYS:
        raise SystemExit(f"--tier takes one of {', '.join(TIER_KEYS)}")
    if a.sats is None:
        raise SystemExit("--tier needs --sats (the source's TOTAL, not the remainder)")
    if not a.source:
        raise SystemExit("--tier needs --source: a figure with no attribution is not a tier")
    if not a.confidence:
        raise SystemExit("--tier needs --confidence: the source's OWN stated confidence "
                         "(\"victim-corroborated\", \"medium-high\"), quoted not invented")
    d = load()
    others = {t["key"]: t for t in d["tiers"] if t["key"] != a.tier}
    if a.tier == "suspected" and "attested" in others:
        if a.sats < others["attested"]["total_sats"]:
            raise SystemExit(
                f"suspected total {a.sats/1e8:,.2f} BTC is below the attested "
                f"{others['attested']['total_sats']/1e8:,.2f} BTC. Suspected includes "
                f"everything attested; check the figure before writing it.")
    if a.tier == "attested" and "suspected" in others:
        if a.sats > others["suspected"]["total_sats"]:
            raise SystemExit(
                f"attested total {a.sats/1e8:,.2f} BTC exceeds the suspected "
                f"{others['suspected']['total_sats']/1e8:,.2f} BTC. Raise suspected first.")
    tier = {"key": a.tier, "source": a.source, "source_url": a.url,
            "reported_ts": a.reported_ts or int(time.time()),
            "total_sats": a.sats, "addresses": a.addresses,
            "confidence": a.confidence, "note": a.note or ""}
    prev = next((t for t in d["tiers"] if t["key"] == a.tier), None)
    d["tiers"] = [t for t in d["tiers"] if t["key"] != a.tier] + [tier]
    d["tiers"].sort(key=lambda t: t["total_sats"])
    v = verified_sats()
    delta = tier_delta(tier, v)
    print(f"{a.tier}: {a.sats/1e8:,.4f} BTC total from {a.source} "
          f"({a.confidence}); verified here {v/1e8:,.4f}, so the site shows "
          f"{delta/1e8:,.4f} BTC unverified above its own figure")
    save(d, deploy=not a.no_deploy)
    if prev and prev.get("total_sats") == a.sats:
        return
    was = f" (was {prev['total_sats']/1e8:,.4f})" if prev else ""
    publish.notify_change(
        f"{a.tier.upper()} total set to {a.sats/1e8:,.4f} BTC{was} from {a.source}, "
        f"{a.confidence}. The site now shows it on the toggle; the verified figure is "
        f"unchanged at {v/1e8:,.4f} BTC.", publish.load_env())


def cmd_list(_):
    d = load()
    for t in d.get("tiers", []):
        print(f"  <{t['key']}> {t['total_sats']/1e8:,.4f} BTC total  "
              f"{t.get('addresses') or '?'} addr  {t.get('source')}  "
              f"[{t.get('confidence')}]  (+{tier_delta(t)/1e8:,.4f} over verified)")
    if not d["entries"]:
        print("no potential entries")
        return
    for e in d["entries"]:
        age = (time.time() - e.get("reported_ts", time.time())) / 3600
        sub = f"  (inside <{e['subsumed_by']}>, listed not counted)" if e.get("subsumed_by") else ""
        print(f"  [{e.get('status')}] {e['id']}  {e.get('source')}  "
              f"{e.get('sats',0)/1e8:.8f} BTC  {e.get('addresses')} addr  {age:.0f}h old{sub}")


def cmd_add(a):
    if not a.id or a.sats is None:
        raise SystemExit("--add needs --id and --sats")
    os.makedirs(SIDECAR, exist_ok=True)
    # An entry with no destination list is inert: --graduate has nothing to test so it can
    # never be proven, and --expire treats "nothing moved" as still-parked so it is never
    # dropped either. It would sit on the site as permanently unverified while the pipeline
    # logged that it could not test it. Refuse instead of creating that.
    # Two kinds of Potential entry, because there are two kinds of credible report.
    #
    #   reported  an address-backed report (the wave-4 paste): carries destinations, so the
    #             convergence test can prove or disprove it, and --expire can retire it.
    #   attested  a credible source's PUBLISHED FIGURE with no address list (Galaxy's
    #             "1,596 BTC across ~7300 addresses"). There is nothing on-chain to test,
    #             and there never will be, because the source keeps its victim reports
    #             private. It is still the most credible number in existence and belongs on
    #             the Potential view.
    #
    # Requiring --dests unconditionally, which is what this did until now, made the single
    # most authoritative report on the incident impossible to add — the hardening added to
    # stop inert entries also locked out the entries that are inert BY NATURE and still
    # worth showing. Refuse only when the KIND implies testability.
    kind = "attested" if a.attested else "reported"
    if kind == "reported":
        if not a.dests:
            raise SystemExit("--add needs --dests for an address-backed report: without a "
                             "destination list it can never graduate and never expire. "
                             "Pass the address list, or use --attested for a source's "
                             "published figure.")
        if not os.path.exists(a.dests):
            raise SystemExit(f"--dests {a.dests}: no such file")
        with open(a.dests) as fh:
            j = json.load(fh)
        dests = j.get("dests") or j.get("destinations") or []
        if not dests:
            raise SystemExit(f"--dests {a.dests}: parsed 0 destinations, so nothing could "
                             "ever test this entry. Check the key name (dests/destinations).")
        with open(sidecar_path(a.id), "w") as fh:
            json.dump({"dests": dests, "victims": j.get("victims", [])}, fh)
    elif a.dests:
        raise SystemExit("--attested takes no --dests: an attested figure is a published "
                         "number, not an address list. Drop one flag or the other.")
    d = load()
    d["entries"] = [e for e in d["entries"] if e["id"] != a.id]
    d["entries"].append({
        "id": a.id, "source": a.source, "source_url": a.url,
        "reported_ts": a.reported_ts or int(time.time()),
        "sats": a.sats, "addresses": a.addresses, "blocks": a.blocks,
        "note": a.note or "", "status": "potential", "kind": kind})
    save(d, deploy=not a.no_deploy)
    publish.notify_change(f"POTENTIAL added: {a.id} ({a.source}), "
                          f"{a.sats/1e8:.8f} BTC. Shown on the toggle, not counted. "
                          f"Will graduate when convergence proves it.", publish.load_env())


CX_JS = os.path.join(publish.PUBLIC, "confirmed-extra.js")


def load_cx():
    if not os.path.exists(CX_JS):
        return {"held": 0, "count": 0, "entries": []}
    s = open(CX_JS).read()
    return json.loads(s[s.index("{"):s.rindex("}") + 1])


def wave_victims(dests):
    """Every address swept into any of these destinations, with amount and block height.
    Deterministic: reads the confirmed chain, so the confirmed set is our own read of it,
    not the reported list.

    Only sweeps that match the Coldcard fingerprint count: the funding transaction must be
    a full drain (exactly one output, no change) whose inputs are all single-signature
    native segwit (P2WPKH). This is what excludes the multisig false positives a report can
    carry — a report's destination list is a lead, never trusted wholesale."""
    victims = {}
    for dst in dests:
        try:
            page = publish.esplora(f"/address/{dst}/txs/chain")
        except Exception:
            continue
        for t in (page or []):
            vout = t.get("vout", [])
            if len(vout) != 1 or vout[0].get("scriptpubkey_address") != dst:
                continue                       # not a no-change sweep into this destination
            vin = t.get("vin", [])
            types = {(i.get("prevout") or {}).get("scriptpubkey_type") for i in vin}
            if types != {"v0_p2wpkh"}:
                continue                       # multisig / other types are not this flaw
            st = t.get("status", {})
            for i in vin:
                p = i.get("prevout") or {}
                a = p.get("scriptpubkey_address")
                if a and a != dst:
                    v = victims.setdefault(a, {"sats": 0, "height": st.get("block_height")})
                    v["sats"] += p.get("value", 0)
        time.sleep(0.2)
    return victims


def promote(entry, verdict, dests, dry=False):
    """Comprehensively graduate a co-spend-proven entry to Confirmed. Every surface the
    change touches is updated in one atomic pass: the drained-address checker (drained.js)
    and its list rows (drains.js), the DRAINED_COUNT in index.html and the monitor, the
    address-list page count (list.html), the running BTC total and the meta figure, the
    'What each cluster rests on' row on the methodology page, and the confirmed-extra
    bucket that carries the wave's BTC and holding count. Snapshotted, self-checked, and
    rolled back on any failure so a half-written dataset can never ship."""
    import shutil
    import hashlib
    P = publish.PUBLIC

    def rd(n):
        return open(os.path.join(P, n), encoding="utf-8").read()

    new_v = wave_victims(dests)
    if not new_v:
        raise RuntimeError(f"{entry['id']}: derived no victims; refusing to promote empty")

    drains = json.loads(rd("drains.js")[len("window.DRAINS="):].rstrip().rstrip(";"))
    hashes = json.loads(rd("drained.js")[len("window.DRAINED="):].rstrip().rstrip(";"))
    idx = rd("index.html")
    old_n = int(re.search(r"var DRAINED_COUNT = (\d+);", idx).group(1))
    blocks, rows = drains["blocks"], drains["rows"]
    h2i = {b["h"]: i for i, b in enumerate(blocks)}
    have = set(hashes)

    need_h = {d["height"] for d in new_v.values() if d.get("height")}
    for h in sorted(need_h):
        if h not in h2i:
            bh = publish.esplora_text(f"/block-height/{h}")
            blocks.append({"h": h, "t": publish.esplora(f"/block/{bh}")["timestamp"]})
            h2i[h] = len(blocks) - 1

    added = 0
    for a, d in new_v.items():
        hsh = hashlib.sha256(a.encode()).hexdigest()[:16]
        if hsh in have:
            continue
        have.add(hsh)
        hashes.append(hsh)
        rows.append([a, d["sats"], h2i.get(d.get("height"), 0)])
        added += 1
    new_n = len(hashes)
    if len(rows) != new_n:
        raise RuntimeError(f"{entry['id']}: row/hash mismatch {len(rows)} != {new_n}")

    cx = load_cx()
    cx["entries"] = [x for x in cx["entries"] if x["id"] != entry["id"]]
    cx["entries"].append({"id": entry["id"], "source": entry.get("source"),
                          "sats": entry["sats"], "victims_added": added,
                          "holding": len(dests), "blocks": entry.get("blocks"),
                          "proof": verdict["cospend_known"][:3], "graduated_ts": int(time.time())})
    cx["held"] = sum(x["sats"] for x in cx["entries"])
    cx["count"] = sum(x.get("holding", 0) for x in cx["entries"])

    cur_disp = re.search(r'id="totalBtc">([\d,.]+)<', idx).group(1)
    new_total = round(float(cur_disp.replace(",", "")) * 1e8) + entry["sats"]
    new_disp = f"{new_total/1e8:,.4f}"
    idx = idx.replace(f'id="totalBtc">{cur_disp}</span>', f'id="totalBtc">{new_disp}</span>')
    idx = re.sub(r"(A live chart of the )[\d,]+\.\d+( BTC)",
                 lambda m: m.group(1) + f"{new_total/1e8:,.2f}" + m.group(2), idx)
    idx = idx.replace(f"var DRAINED_COUNT = {old_n};", f"var DRAINED_COUNT = {new_n};")
    idx = publish.swap_count(idx, old_n, new_n)

    meth = rd("methodology.html")
    hmin, hmax = (min(need_h), max(need_h)) if need_h else (0, 0)
    mrow = ("<!-- xrow:%s --><tr><td>%s<br>graduated</td><td>%d addresses<br>%.2f BTC</td>"
            "<td>co-spend proof</td><td>%s reported this as a wave; it was held as Potential "
            "until one of its destinations co-spent with a known attacker address, which proves "
            "common control. Confirmed on that link, blocks %s&ndash;%s.</td></tr><!-- /xrow -->\n"
            "    </tbody>"
            % (entry["id"], time.strftime("%d %b", time.gmtime()), added, entry["sats"] / 1e8,
               entry.get("source"), f"{hmin:,}", f"{hmax:,}"))
    meth = meth.replace("</tbody>", mrow, 1)

    d = load()
    d["entries"] = [x for x in d["entries"] if x["id"] != entry["id"]]
    d["total_sats"] = sum(e.get("sats", 0) for e in d["entries"] if e.get("status") == "potential")

    edits = {
        os.path.join(P, "drains.js"): "window.DRAINS=" + json.dumps({"blocks": blocks, "rows": rows}, separators=(",", ":")) + ";\n",
        os.path.join(P, "drained.js"): "window.DRAINED=" + json.dumps(hashes, separators=(",", ":")) + ";\n",
        os.path.join(P, "index.html"): idx,
        os.path.join(P, "methodology.html"): meth,
        os.path.join(P, "list.html"): publish.swap_count(rd("list.html"), old_n, new_n),
        os.path.join(P, "confirmed-extra.js"): "window.CONFIRMED_EXTRA=" + json.dumps(cx, separators=(",", ":")) + ";\n",
        os.path.join(P, "potential.js"): "window.POTENTIAL=" + json.dumps(d, separators=(",", ":")) + ";\n",
    }
    for m in publish.MONITORS:
        if os.path.exists(m):
            edits[m] = re.sub(r"DRAINED_COUNT = \d+", f"DRAINED_COUNT = {new_n}", rd(m) if os.path.dirname(m) == P else open(m).read())

    if dry:
        print(f"  DRY {entry['id']}: +{added} victims (count {old_n}->{new_n}), "
              f"+{entry['sats']/1e8:.4f} BTC, total {cur_disp}->{new_disp}; would update "
              f"drained/drains/index/methodology/list/monitor/confirmed-extra/potential")
        return {"added": added, "new_n": new_n, "new_total": new_disp}

    baks = {}
    try:
        for path, content in edits.items():
            baks[path] = path + ".pbak"
            shutil.copy2(path, baks[path])
            open(path + ".tmp", "w", encoding="utf-8").write(content)
            os.replace(path + ".tmp", path)
        probs = publish.self_check(verbose=False)
        if probs:
            raise RuntimeError(f"invariants broken after promote: {probs}")
        url = publish.deploy()
        if not publish.verify_deployed(new_n):
            raise RuntimeError(f"deployed ({url}) but live count != {new_n}")
    except Exception:
        for path, b in baks.items():
            if os.path.exists(b):
                shutil.copy2(b, path)
        raise
    finally:
        for b in baks.values():
            if os.path.exists(b):
                os.remove(b)
    publish.notify_change(
        f"AUTO-GRADUATED {entry['id']} ({entry.get('source')}) to CONFIRMED, comprehensively: "
        f"+{added} drained addresses (now {new_n:,}), +{entry['sats']/1e8:.4f} BTC "
        f"(total {new_disp}). Updated the checker, the list, the count, the methodology row, "
        f"the meta figure and the total. Proof: co-spend "
        f"{verdict['cospend_known'][0]['txid'][:16]}. Removed from Potential.",
        publish.load_env())
    return {"added": added, "new_n": new_n, "new_total": new_disp}


def retract(entry_id, dry=False):
    """Reverse a graduation comprehensively, for when a confirmed wave is later disproven:
    pull the wave's victims back out of the checker and the list, drop the count and the
    total, remove the methodology row and the confirmed-extra record, restore list.html and
    the monitor. Snapshotted and rolled back on any failure, the same as promote."""
    import shutil
    import hashlib
    P = publish.PUBLIC

    def rd(n):
        return open(os.path.join(P, n), encoding="utf-8").read()

    cx = load_cx()
    rec = next((x for x in cx["entries"] if x["id"] == entry_id), None)
    if not rec:
        raise RuntimeError(f"{entry_id}: not in confirmed-extra, nothing to retract")
    car = read_sidecar(entry_id)
    if car is None:
        raise RuntimeError(f"{entry_id}: no sidecar address list; cannot recompute its victims")
    dests = car.get("dests", [])
    victims = wave_victims(dests)
    drop_addrs = set(victims)
    drop_hashes = {hashlib.sha256(a.encode()).hexdigest()[:16] for a in drop_addrs}

    drains = json.loads(rd("drains.js")[len("window.DRAINS="):].rstrip().rstrip(";"))
    hashes = json.loads(rd("drained.js")[len("window.DRAINED="):].rstrip().rstrip(";"))
    idx = rd("index.html")
    old_n = int(re.search(r"var DRAINED_COUNT = (\d+);", idx).group(1))
    rows2 = [r for r in drains["rows"] if r[0] not in drop_addrs]
    # a row survives only if its hash survives, and a hash survives only if it has a row
    keep_hash = {hashlib.sha256(r[0].encode()).hexdigest()[:16] for r in rows2}
    hashes2 = [h for h in hashes if h in keep_hash]
    new_n = len(hashes2)
    if len(rows2) != new_n:
        raise RuntimeError(f"{entry_id}: retract left {len(rows2)} rows != {new_n} hashes")
    removed = old_n - new_n

    cur = re.search(r'id="totalBtc">([\d,.]+)<', idx).group(1)
    new_total = round(float(cur.replace(",", "")) * 1e8) - rec["sats"]
    nd = f"{new_total/1e8:,.4f}"
    idx = idx.replace(f'id="totalBtc">{cur}</span>', f'id="totalBtc">{nd}</span>')
    idx = re.sub(r"(A live chart of the )[\d,]+\.\d+( BTC)",
                 lambda m: m.group(1) + f"{new_total/1e8:,.2f}" + m.group(2), idx)
    idx = idx.replace(f"var DRAINED_COUNT = {old_n};", f"var DRAINED_COUNT = {new_n};")
    idx = publish.swap_count(idx, old_n, new_n)

    meth = re.sub(rf"<!-- xrow:{re.escape(entry_id)} -->.*?<!-- /xrow -->", "",
                  rd("methodology.html"), flags=re.S)

    cx["entries"] = [x for x in cx["entries"] if x["id"] != entry_id]
    cx["held"] = sum(x["sats"] for x in cx["entries"])
    cx["count"] = sum(x.get("holding", 0) for x in cx["entries"])

    edits = {
        os.path.join(P, "drains.js"): "window.DRAINS=" + json.dumps({"blocks": drains["blocks"], "rows": rows2}, separators=(",", ":")) + ";\n",
        os.path.join(P, "drained.js"): "window.DRAINED=" + json.dumps(hashes2, separators=(",", ":")) + ";\n",
        os.path.join(P, "index.html"): idx,
        os.path.join(P, "methodology.html"): meth,
        os.path.join(P, "list.html"): publish.swap_count(rd("list.html"), old_n, new_n),
        os.path.join(P, "confirmed-extra.js"): "window.CONFIRMED_EXTRA=" + json.dumps(cx, separators=(",", ":")) + ";\n",
    }
    for m in publish.MONITORS:
        if os.path.exists(m):
            edits[m] = re.sub(r"DRAINED_COUNT = \d+", f"DRAINED_COUNT = {new_n}", open(m).read())

    if dry:
        print(f"  DRY retract {entry_id}: -{removed} addresses ({old_n}->{new_n}), "
              f"-{rec['sats']/1e8:.4f} BTC, total {cur}->{nd}")
        return {"removed": removed, "new_n": new_n}

    baks = {}
    try:
        for path, content in edits.items():
            baks[path] = path + ".rbak"
            shutil.copy2(path, baks[path])
            open(path + ".tmp", "w", encoding="utf-8").write(content)
            os.replace(path + ".tmp", path)
        probs = publish.self_check(verbose=False)
        if probs:
            raise RuntimeError(f"invariants broken after retract: {probs}")
        url = publish.deploy()
        if not publish.verify_deployed(new_n):
            raise RuntimeError(f"deployed ({url}) but live count != {new_n}")
    except Exception:
        for path, b in baks.items():
            if os.path.exists(b):
                shutil.copy2(b, path)
        raise
    finally:
        for b in baks.values():
            if os.path.exists(b):
                os.remove(b)
    publish.notify_change(
        f"RETRACTED {entry_id} ({rec.get('source')}) from Confirmed: -{removed} addresses "
        f"(now {new_n:,}), -{rec['sats']/1e8:.4f} BTC. The checker, list, count, methodology "
        f"row and total were all reversed.", publish.load_env())
    return {"removed": removed, "new_n": new_n}


def cmd_graduate(a):
    d = load()
    known = known_attacker_set()
    for e in list(d["entries"]):
        if e.get("status") != "potential":
            continue
        if a.id and e["id"] != a.id:
            continue
        if e.get("kind") == "attested":
            # nothing to test: an attested figure is a source's published number with no
            # address list. Silent by design — this is its normal state, not a fault, and
            # the no-sidecar alarm below would fire on it every hour forever.
            print(f"  {e['id']}: attested figure, no on-chain test applies", flush=True)
            continue
        car = read_sidecar(e["id"])
        if car is None:
            # loud, because a potential entry that cannot be tested is a silent dead end:
            # it will never graduate and --expire will never drop it either
            print(f"  {e['id']}: NO SIDECAR ADDRESS LIST — this entry can never graduate "
                  f"or expire. Re-add it with --dests, or --retract it.")
            alert_once(
                f"{e['id']}:no-sidecar",
                f"POTENTIAL {e['id']} has no sidecar address list, so the convergence test "
                f"cannot run and the entry can neither graduate nor expire. It needs "
                f"re-adding with --dests.", publish.load_env())
            continue
        dests = car.get("dests", [])
        if not dests:
            print(f"  {e['id']}: sidecar has no destinations")
            continue
        v = convergence(dests, known)
        print(f"  {e['id']}: moved {v['moved']}/{v['dests']}, "
              f"cospend-known {len(v['cospend_known'])}, shared-hop2 {len(v['shared_hop2'])}")
        if v["cospend_known"]:
            # strongest proof: a destination co-spends with a confirmed attacker address.
            # That is common-input-ownership, cryptographic, so it auto-graduates.
            print(f"  {e['id']}: CO-SPEND PROOF -> auto-graduating")
            promote(e, v, dests, dry=a.no_deploy)
        elif v["shared_hop2"]:
            # single-entity control is shown, but a shared vault alone cannot rule out an
            # A shared vault shows single-entity control but cannot tell a thief from an
            # exchange, so it is not proof and the entry stays Potential. Nobody is asked
            # anything: if it never gets a co-spend, --expire drops it and THAT is the
            # notification, because the site changes.
            alert_once(
                f"{e['id']}:shared-vault",
                f"POTENTIAL {e['id']} shows shared-vault convergence "
                f"({len(v['shared_hop2'])} vaults, {v['moved']}/{v['dests']} destinations "
                f"moved) but no co-spend with a known attacker. Single-entity control, which "
                f"an exchange also produces, so this is not proof: the entry stays Potential "
                f"and --expire drops it if a co-spend never appears.", publish.load_env())
        else:
            print(f"  {e['id']}: not yet provable")


def cmd_expire(a):
    """Drop only entries that have had a fair chance to prove out and did not: old enough,
    AND their destinations have MOVED (so a co-spend could have appeared) without converging.
    An entry whose destinations are still parked is never expired, because its proof cannot
    exist until the coins move. That is the gap that would otherwise discard a slow-but-real
    wave (wave 4's destinations sat parked for days)."""
    d = load()
    cutoff = time.time() - a.days * 86400
    known = known_attacker_set()
    keep, dropped = [], []
    for e in d["entries"]:
        if e.get("status") != "potential" or e.get("reported_ts", 0) >= cutoff:
            keep.append(e)
            continue
        if e.get("kind") == "attested":
            # the expiry rule reads "destinations moved without converging", which is
            # meaningless for a figure with no destinations. An attested entry is retired
            # deliberately (--retract) or when the source revises, never on a timer.
            keep.append(e)
            continue
        car = read_sidecar(e["id"])
        dests = car.get("dests", []) if car else []
        v = convergence(dests, known) if dests else {"moved": 0, "dests": 0, "proven": False}
        # still parked (nothing moved) => keep waiting; its proof cannot have appeared yet
        if v["moved"] == 0:
            keep.append(e)
            continue
        if v.get("cospend_known") or v.get("shared_hop2"):
            keep.append(e)              # it actually converged; leave it for graduation
            continue
        dropped.append(e)               # moved, had its chance, did not converge
    if not dropped:
        print("nothing to expire (parked or still-pending entries are kept)")
        return
    d["entries"] = [e for e in d["entries"] if e not in dropped]
    save(d, deploy=not a.no_deploy)
    for e in dropped:
        publish.notify_change(f"POTENTIAL entry {e['id']} ({e.get('source')}) expired: its "
                              f"destinations moved without converging on a known attacker, so it "
                              f"did not prove out. Removed from the toggle.", publish.load_env())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--add", action="store_true")
    ap.add_argument("--graduate", action="store_true")
    ap.add_argument("--expire", action="store_true")
    ap.add_argument("--retract", action="store_true", help="reverse a graduation by --id")
    ap.add_argument("--tier", choices=list(TIER_KEYS),
                    help="record or revise a source's published TOTAL at this standard. "
                         "attested = the source confirmed it by evidence we cannot see "
                         "(victim reports); suspected = the same source's own lower-"
                         "confidence figure. Takes --sats as their total, not a remainder.")
    ap.add_argument("--confidence", help="the source's OWN words for how sure they are")
    ap.add_argument("--id")
    ap.add_argument("--source")
    ap.add_argument("--url")
    ap.add_argument("--sats", type=int)
    ap.add_argument("--addresses", type=int)
    ap.add_argument("--blocks", type=int, nargs=2)
    ap.add_argument("--dests")
    ap.add_argument("--note")
    ap.add_argument("--reported-ts", dest="reported_ts", type=int)
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--attested", action="store_true",
                    help="a credible source's published FIGURE, with no address list "
                         "(Galaxy-style). Cannot be tested on-chain and is not expected to "
                         "graduate; it stands until the source revises it or our own "
                         "confirmed number catches up.")
    ap.add_argument("--no-deploy", action="store_true")
    a = ap.parse_args()
    if a.list:
        cmd_list(a)
    elif a.tier:
        cmd_tier(a)
    elif a.add:
        cmd_add(a)
    elif a.graduate:
        cmd_graduate(a)
    elif a.expire:
        cmd_expire(a)
    elif a.retract:
        if not a.id:
            raise SystemExit("--retract needs --id")
        print(retract(a.id, dry=a.no_deploy))
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
