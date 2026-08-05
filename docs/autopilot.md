# Coldcard Watch: autopilot

Keeps coldcardwatch.com accurate on its own. Finds new attacker clusters from
the chain and adds them to the site with no human in the loop, but only where the
proof is strong enough that a human would add nothing. The site's whole worth is that
every address on it is true, so the autonomy is tiered by how a cluster is proven, and
the weakest tier is never auto-published.

## Why it exists

The block scanner already ran, but it missed a 30 BTC / 352-victim cluster (found by
Galaxy Research) for one reason: its theft signal was fee *magnitude*. It only flagged
batched sweeps that overpaid (≥20 sat/vB, ≥5× the block median), tuned on an earlier
cluster that overpaid ~58×. This cluster paid a normal 10 sat/vB and read as ordinary
consolidation. The fix is to key on fee *uniformity* instead: 92 of its 93 transactions
paid exactly 10.0–10.1 sat/vB, which no human wallet does. That is the machine, whatever
the absolute fee. Autopilot uses uniformity, not magnitude.

## The tiers

| Tier | Proof | Action |
|---|---|---|
| 1, co-spend | Two addresses that sign the same transaction share an owner. Walking outward from the known attacker addresses through shared inputs finds more of theirs with certainty. | **Auto-published.** Deterministic. |
| 2, fingerprint + source | A collector matches the drain fingerprint (uniform hardcoded fee, 100% no-change, fresh unspent vault, tight block window, not a service) AND a research account on the watchlist reports the incident. This is the bar waves 1–3 and 5 were added on. | **Notify first, then auto** (see `TIER2_AUTOPUBLISH`). |
| 3, fingerprint only | Matches the fingerprint but is neither co-spend-proven nor reported. A batched sweep at a normal fee is shape-identical to an owner moving to safety. | **Held.** Telegram, never a site edit. |
| 3, no-collector (wave-3 shape) | Many sweeps at ONE hardcoded fee rate paying many DIFFERENT fresh addresses, sharing nothing. Every tier above keys on a funnel, so this is the shape that hid wave 3 for two days. | **Held.** Telegram, never a site edit. |

### The no-collector tier

Waves 1, 2 and 5 funnel hundreds of victims into a handful of collectors, and every test
above keys on that funnel. Wave 3 deleted it: each drained wallet got its own fresh
address and its own fresh P2WSH vault, sharing nothing. The scanner ran the whole time
and saw nothing, because there was no collector to converge on.

What converges instead is the fee. The scan now buckets no-change sweeps by fee rate as
well as by destination, and flags any rate paying `WAVE3_MIN_DESTS` or more distinct fresh
addresses while sitting far above that block's own median. It reuses the same block fetch,
so it costs nothing extra.

It is the weakest signal in the file and it never publishes. Public block data omits the
funding height of each input, so the firmware-epoch floor cannot be applied here, and the
second hop into P2WSH is not checked either. The Telegram message therefore hands over the
exact `wave3.py` command to confirm a hit against a node, which does apply both.

Two accuracy guards that keep the auto tiers honest:
- **Only a clean unspent vault auto-publishes.** A co-spend-proven address whose funds have
  already peeled through further hops is *held*, because tracing where the money sits now
  is a judgement call (the next hop could be an exchange). The wave-4 cluster is this case.
- **The publish decision is code, not a model.** `claude -p` is used only to read a tweet
  and judge whether a source attributes the incident. Evidence, never the final say.

## Files

- `autopilot.py`: the orchestrator. Cron entry. Co-spend expansion, block-scan for
  fingerprint candidates, corroboration gate, tiered routing, audit log, rollback.
- `cluster.py`: `collector_victims()`, `cluster_fingerprint()`, `add_cluster()`: the
  deterministic resolve + atomic multi-surface add (reused by autopilot and by hand).
- `publish.py`: chain reads, `verify_addr`, atomic edit + deploy + deployed-byte verify,
  Telegram, the known-attacker `ANCHORS` set.

## Running it

```
python3 autopilot.py              # one cycle (what cron runs)
python3 autopilot.py --dry-run    # find + classify, never write
python3 autopilot.py --cospend-only
python3 autopilot.py --log        # print the audit trail
python3 autopilot.py --rollback <collector-or-timestamp>
```

Every auto-publish: appends a JSON line to `~/.coldcard-autopilot-log.jsonl`, snapshots
every coupled file to `~/.coldcard-rollback/<tag>/` first, and sends a Telegram receipt.
`--rollback` restores the snapshot and redeploys in one command, fully reversible.

## Turning tier 2 to full auto

`TIER2_AUTOPUBLISH = False` at the top of `autopilot.py`. While False, tier-2 candidates
are strong enough to auto-publish but instead Telegram you a "ready to add" message with a
one-line command. Watch a few land correctly, then set it `True`. Tier 1 is always auto.

## What it will not do

- Publish anything the chain doesn't support.
- Track an address that has emptied out (funds peeled onward). Held for review.
- Cluster through a service wallet (the freshness check stops co-spend at high-history
  addresses whose co-inputs are other people's money).
- Add a cluster on a fee *overpay* alone. It needs fee *uniformity*, which excludes the
  varying-overpay batched sweeps that are indistinguishable from rescues.

## Running on the box

Cron (on the always-on box): autopilot at `:15,:45`, x-watch at `:00,:30`, both on one shared
lock (`~/.coldcard-pipeline.lock`) because they share publish's state file, and the
lock serialises them so they never race. A run is co-spend (~17s, checkpointed) + a 20-block
fingerprint scan (~3 min via blockchain.info) + tiering. The scan advances forward and
checkpoints (`~/.coldcard-autopilot-scan.json`), catching up the historical range over a
few hours, then staying current.

**IPv4 is forced** (`publish.py`). On the Hetzner box, python's urllib intermittently picks
a dead IPv6 route to blockstream.info and hangs the full socket timeout (a single address
stalled the whole walk 45s), while curl's happy-eyeballs falls back to IPv4 instantly.
Preferring IPv4 removed it. mempool.space is slow from the box (10s timeouts) so it is only
a short-timeout fallback; blockstream.info is primary. The box cannot reach the fast Start9
node (LAN-only), so it uses the public explorers.

## Verified before shipping

- Co-spend expansion re-finds the wave-4 addresses from the original known set, and holds
  them (funds moved) rather than publishing.
- The fingerprint scanner finds the Galaxy collector from blocks 960352–960356 and rejects
  a high-activity wallet with varying fees.
- Tier-2 corroboration returns true for the Coldcard incident against the watchlist.
- Full add → rollback cycle restores the site to the exact prior state, self-check clean.
