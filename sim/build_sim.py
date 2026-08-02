#!/usr/bin/env python3
"""
build_sim.py — generate a local-only simulator of coldcard-watch.

Each scenario is the REAL public/index.html with a stub injected ahead of the page
script. The stub replaces fetch() and WebSocket so the page's own logic runs against
invented chain data. Nothing about the page's rendering is faked, so what you see is
what would actually happen.

Output goes to simsite/ which is never deployed (deploys run from public/).
"""
import json, os, re, shutil, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
PUB = os.path.join(ROOT, "public")
OUT = os.path.join(ROOT, "simsite")

V1 = "bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9r"   # main vault, 562.02
V2 = "bc1qx76cae2706qd5q576feh7xq8rfcsjpf2htfhe3"   # 398.48
V3 = "bc1q8jy96fe5lf8vfugydnte3cguk92gpev7kwtp3q"   # 89.62
C1 = "bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0"   # collector, 32.45

BASE = {
    V1: dict(bal=56202008836, recv=56202008836, ntx=7,   spent=0),
    V2: dict(bal=39847573857, recv=39847573857, ntx=1,   spent=0),
    V3: dict(bal=8962327890,  recv=8962327890,  ntx=1,   spent=0),
    C1: dict(bal=3245056320,  recv=59447723261, ntx=502, spent=341),
}

# plausible destination addresses, clearly labelled as invented in the UI banner
D_EXCH = "bc1qexampleexchangehotwallet000000000000q9k7yz"
D_PEEL = "bc1qexamplepeelhopaddress0000000000000000w3n2ac"
D_MIX  = "bc1qexamplemixerdepositaddr00000000000000h8t4rd"


def st(bal, recv, ntx, spent):
    return dict(bal=bal, recv=recv, ntx=ntx, spent=spent)


SCENARIOS = [
    dict(
        id="00-now",
        title="Right now",
        blurb="Nothing has moved. This is the live state as of today.",
        state=BASE, txs={}, extra={},
    ),
    dict(
        id="01-partial",
        title="They move part of it",
        blurb="The main vault sends 200 BTC to one new address and keeps the rest. "
              "The row goes red as “partly moved”, the destination is added and watched, "
              "and the timer restarts from the spend.",
        state={**BASE, V1: st(36202008836, 56202008836, 8, 1)},
        txs={V1: [dict(spend_from=V1, outs=[(D_PEEL, 20000000000), (V1, 36202008836)],
                       height=960700, time=1785560000)]},
        extra={D_PEEL: st(20000000000, 20000000000, 1, 0)},
    ),
    dict(
        id="02-exchange",
        title="They empty the vault into an exchange",
        blurb="All 562 BTC leaves in one transaction to a wallet already holding 9,000 BTC. "
              "The headline total does not jump, because only coins traced from the theft are counted.",
        state={**BASE, V1: st(0, 56202008836, 8, 4)},
        txs={V1: [dict(spend_from=V1, outs=[(D_EXCH, 56201962301)], height=960700, time=1785560000)]},
        extra={D_EXCH: st(900000000000, 900000000000, 4210, 0)},
    ),
    dict(
        id="03-everything",
        title="They move everything",
        blurb="All four addresses spend. Every row is red, three destinations are picked up, "
              "and the chart line falls to the floor.",
        state={V1: st(0, 56202008836, 8, 4), V2: st(0, 39847573857, 2, 1),
               V3: st(0, 8962327890, 2, 1), C1: st(0, 59447723261, 503, 342)},
        txs={
            V1: [dict(spend_from=V1, outs=[(D_EXCH, 56201962301)], height=960700, time=1785560000)],
            V2: [dict(spend_from=V2, outs=[(D_MIX, 39847000000)], height=960701, time=1785560600)],
            V3: [dict(spend_from=V3, outs=[(D_PEEL, 8962000000)], height=960701, time=1785560600)],
            C1: [dict(spend_from=C1, outs=[(D_PEEL, 3245000000)], height=960702, time=1785561200)],
        },
        extra={D_EXCH: st(900000000000, 900000000000, 4210, 0),
               D_MIX: st(39847000000, 39847000000, 1, 0),
               D_PEEL: st(12207000000, 12207000000, 2, 0)},
    ),
    dict(
        id="04-newdrain",
        title="They drain more wallets",
        blurb="Fresh victim funds land in a known collector a few seconds after load. Watch the "
              "Most recent drain card turn red and rewrite itself. A brand new collection address "
              "would NOT be seen, and the page says so.",
        state=BASE,
        after={C1: st(3745056320, 59947723261, 503, 341)},
        txs={}, extra={},
    ),
    dict(
        id="05-offline",
        title="The data sources go down",
        blurb="Every request fails. The page refuses to present its seeded numbers as live. "
              "Look at the indicator in the header, top right: it stops saying live and greys out.",
        state=BASE, txs={}, extra={}, fail_all=True,
    ),
    dict(
        id="06-listbroken",
        title="The address list fails to load",
        blurb="drained.js never arrives. Scroll to Was your address drained: the field is disabled and "
              "refuses to answer, rather than telling everyone they are safe.",
        state=BASE, txs={}, extra={}, break_dataset=True,
    ),
]


def stub_js(sc):
    st_all = dict(sc["state"]); st_all.update(sc.get("extra") or {})
    payload = {
        "state": {k: v for k, v in st_all.items()},
        "after": sc.get("after") or None,
        "txs": sc.get("txs") or {},
        "failAll": bool(sc.get("fail_all")),
        "tip": 960710,
        "price": 62949,
    }
    return """
<script>
/* simulator stub: replaces the network so the page's real logic renders a what-if state */
(function(){
  var SIM = %s;
  if (%s) { try { delete window.DRAINED; } catch(e){ window.DRAINED = undefined; } }

  function jsonRes(obj){
    return Promise.resolve({ ok:true, status:200,
      json:function(){ return Promise.resolve(obj); },
      text:function(){ return Promise.resolve(String(obj)); } });
  }
  function fail(){ return Promise.reject(new Error("simulated outage")); }

  // some states only exist on a LATER read (a fresh drain is a change, not a value),
  // so the stub serves phase 1 first and phase 2 once the page reads again
  var reads = 0;
  function cur(a){
    var base = SIM.state[a] || {bal:0,recv:0,ntx:0,spent:0};
    if (SIM.after && reads >= 2 && SIM.after[a]) return SIM.after[a];
    return base;
  }

  function esploraAddr(a){
    var s = cur(a);
    return {address:a,
      chain_stats:{funded_txo_count:s.ntx, funded_txo_sum:s.recv,
                   spent_txo_count:s.spent, spent_txo_sum:s.recv - s.bal, tx_count:s.ntx},
      mempool_stats:{funded_txo_count:0, funded_txo_sum:0, spent_txo_count:0, spent_txo_sum:0, tx_count:0}};
  }
  function esploraTxs(a){
    return (SIM.txs[a] || []).map(function(t){
      return {txid:"5111111111111111111111111111111111111111111111111111111111111111",
        vin:[{prevout:{scriptpubkey_address:t.spend_from, value:1}}],
        vout:t.outs.map(function(o){ return {scriptpubkey_address:o[0], value:o[1]}; }),
        status:{confirmed:true, block_height:t.height, block_time:t.time}};
    });
  }

  window.fetch = function(url){
    url = String(url);
    if (SIM.failAll) return fail();
    if (url.indexOf("blockchain.info/balance") > -1){
      reads++;
      var q = decodeURIComponent(url.split("active=")[1] || "");
      var out = {};
      q.split("|").forEach(function(a){
        var s = cur(a);
        out[a] = {final_balance:s.bal, n_tx:s.ntx, total_received:s.recv};
      });
      return jsonRes(out);
    }
    var m = url.match(/\\/address\\/([a-z0-9]+)\\/txs/i);
    if (m) return jsonRes(esploraTxs(m[1]));
    m = url.match(/\\/address\\/([a-z0-9]+)$/i);
    if (m) return jsonRes(esploraAddr(m[1]));
    if (url.indexOf("tip/height") > -1) return jsonRes(SIM.tip);
    if (url.indexOf("prices") > -1) return jsonRes({USD:SIM.price});
    if (url.indexOf("coinbase") > -1) return jsonRes({data:{amount:String(SIM.price)}});
    return fail();
  };

  window.WebSocket = function(){
    var self = this;
    self.readyState = 1;
    self.send = function(){}; self.close = function(){};
    if (SIM.after){
      setTimeout(function(){
        if (typeof self.onmessage === "function"){
          self.onmessage({data: JSON.stringify({"multi-address-transactions":{}})});
        }
      }, 2600);
    }
  };
})();
</script>
""" % (json.dumps(payload), "true" if sc.get("break_dataset") else "false")


def banner(sc, idx, total):
    prev = SCENARIOS[idx-1]["id"] if idx > 0 else None
    nxt = SCENARIOS[idx+1]["id"] if idx < total-1 else None
    nav = ""
    if prev: nav += '<a href="/%s.html">&larr; previous</a>' % prev
    nav += '<a href="/index.html">all scenarios</a>'
    if nxt: nav += '<a href="/%s.html">next &rarr;</a>' % nxt
    return """
<div id="simbar">
  <div class="sb-in">
    <span class="sb-tag">SIMULATION</span>
    <span class="sb-t">%s</span>
    <span class="sb-b">%s</span>
    <span class="sb-nav">%s</span>
  </div>
</div>
<style>
  #simbar{position:sticky;top:0;z-index:999;background:#3b1d05;border-bottom:1px solid #7a4a12;
    font-family:"DM Sans",system-ui,sans-serif}
  #simbar .sb-in{max-width:1180px;margin:0 auto;padding:10px 24px;display:flex;flex-wrap:wrap;
    gap:8px 16px;align-items:baseline}
  #simbar .sb-tag{font-size:.68rem;letter-spacing:.16em;color:#ffb454;border:1px solid #7a4a12;
    border-radius:999px;padding:2px 10px}
  #simbar .sb-t{color:#ffd9a8;font-weight:500;font-size:.95rem}
  #simbar .sb-b{color:#c9a075;font-size:.85rem;flex:1 1 320px;line-height:1.45}
  #simbar .sb-nav{margin-left:auto;display:flex;gap:14px}
  #simbar .sb-nav a{color:#ffb454;font-size:.82rem;text-decoration:none;border-bottom:1px solid #7a4a12}
</style>
""" % (sc["title"], sc["blurb"], nav)


def main():
    src = open(os.path.join(PUB, "index.html")).read()
    if os.path.isdir(OUT): shutil.rmtree(OUT)
    os.makedirs(OUT)
    for f in ("data.js", "drained.js", "drains.js", "bitcoin.svg", "list.html"):
        p = os.path.join(PUB, f)
        if os.path.exists(p): shutil.copy(p, OUT)

    for i, sc in enumerate(SCENARIOS):
        html = src
        # stub must run before the page script, and before drained.js for the broken case
        html = html.replace('<script src="/data.js"></script>', stub_js(sc) + '<script src="/data.js"></script>', 1)
        if sc.get("break_dataset"):
            html = html.replace('<script src="/drained.js"></script>', '<!-- drained.js blocked by the simulator -->', 1)
        html = html.replace("<body>", "<body>" + banner(sc, i, len(SCENARIOS)), 1)
        open(os.path.join(OUT, sc["id"] + ".html"), "w").write(html)

    cards = "".join(
        '<a class="card" href="/%s.html"><span class="t">%s</span><span class="b">%s</span></a>'
        % (s["id"], s["title"], s["blurb"]) for s in SCENARIOS)
    menu = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Coldcard Watch — what-if simulator</title>
<link rel="icon" href="/bitcoin.svg">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500&display=swap" rel="stylesheet">
<style>
body{margin:0;background:#0d0e11;color:#f2f4f7;font-family:"DM Sans",system-ui,sans-serif;line-height:1.6}
main{max-width:900px;margin:0 auto;padding:64px 24px}
h1{font-size:2rem;font-weight:500;letter-spacing:-.025em;margin:0 0 12px}
p.l{color:#c9cfd6;max-width:68ch;margin:0 0 40px}
.card{display:block;background:#14161a;border:1px solid #1e2128;border-radius:10px;padding:24px;
  margin-bottom:12px;text-decoration:none;transition:border-color .15s cubic-bezier(.32,.72,0,1)}
.card:hover{border-color:#8a5a12}
.card .t{display:block;color:#f7931a;font-weight:500;font-size:1.05rem}
.card .b{display:block;color:#a4acb6;font-size:.9rem;margin-top:6px}
code{background:#1a1d22;padding:1px 6px;border-radius:4px;font-family:inherit}
</style></head><body><main>
<h1>What the site does next</h1>
<p class="l">Each page below is the real dashboard running its own code against invented chain data.
Nothing is drawn by hand: the balances, colours, rows and chart are produced by the same logic that runs
in production. Destination addresses are placeholders and are not real.</p>
%s
</main></body></html>""" % cards
    open(os.path.join(OUT, "index.html"), "w").write(menu)
    print("built %d scenarios into %s" % (len(SCENARIOS), OUT))


if __name__ == "__main__":
    main()
