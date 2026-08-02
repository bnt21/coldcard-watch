import publish, json, time
# Scan wave-2 blocks for 1-in-1-out sweep destinations; find the one starting bc1qmd5m5kt
targets = {}
for h in range(960345, 960370):
    try:
        blk = publish.esplora(f"/block-height/{h}")  # returns hash as text? no
    except Exception:
        pass
# esplora block by height: /block-height/:h returns the hash (text). Use raw _get.
import urllib.request
def hash_at(h):
    for host in publish.ESPLORA_HOSTS:
        try:
            return publish._get(f"{host}/block-height/{h}", timeout=30).decode().strip()
        except Exception:
            continue
    raise RuntimeError("no host")

dest_tally = {}
for h in range(960345, 960370):
    bh = hash_at(h)
    # get all txids in block, then per-tx. Too slow. Use /block/:hash/txs paginated.
    txs = []
    start = 0
    while True:
        page = None
        for host in publish.ESPLORA_HOSTS:
            try:
                page = json.loads(publish._get(f"{host}/block/{bh}/txs/{start}", timeout=45))
                break
            except Exception:
                continue
        if not page:
            break
        txs.extend(page)
        if len(page) < 25:
            break
        start += 25
        time.sleep(0.2)
    for t in txs:
        vin, vout = t.get("vin", []), t.get("vout", [])
        if len(vin) == 1 and len(vout) == 1:
            dst = vout[0].get("scriptpubkey_address")
            if dst and dst.startswith("bc1qmd5m5k"):
                g = dest_tally.setdefault(dst, {"n": 0, "sats": 0})
                g["n"] += 1
                g["sats"] += (vin[0].get("prevout") or {}).get("value", 0)
    time.sleep(0.3)
    print(f"  block {h} done", flush=True)

for dst, g in dest_tally.items():
    print(f"FOUND {dst}  {g['n']} sweeps  {g['sats']/1e8:.8f} BTC")
