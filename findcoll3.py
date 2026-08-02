import json, urllib.request, time, sys
UA={"User-Agent":"cc-find/1.0"}
def get(u,t=45):
    for i in range(3):
        try: return urllib.request.urlopen(urllib.request.Request(u,headers=UA),timeout=t).read()
        except Exception:
            if i==2: raise
            time.sleep(2)
tally={}
lo,hi=int(sys.argv[1]),int(sys.argv[2])
for h in range(lo,hi):
    try:
        bh=get(f"https://blockstream.info/api/block-height/{h}").decode().strip()
        blk=json.loads(get(f"https://blockchain.info/rawblock/{bh}"))
    except Exception as e:
        print("blk",h,"FAIL",e,flush=True); continue
    for t in blk.get("tx",[]):
        ins,outs=t.get("inputs",[]),t.get("out",[])
        if len(ins)==1 and len(outs)==1:
            dst=outs[0].get("addr")
            if dst and dst.startswith("bc1qmd5m5k"):
                g=tally.setdefault(dst,{"n":0,"sats":0})
                g["n"]+=1; g["sats"]+=(ins[0].get("prev_out") or {}).get("value",0)
    print("blk",h,"done",flush=True)
json.dump(tally, open("/tmp/coll_tally.json","w"))
for dst,g in tally.items():
    print(f"COLLECTOR {dst} | {g['n']} | {g['sats']/1e8:.8f}")
