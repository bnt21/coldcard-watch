# Coldcard Watch: X victim-report pipeline

Watches X for people reporting their own drained addresses, verifies each claim on
the chain, and adds the proven ones to coldcardwatch.com. Runs on the
always-on box so it keeps watching with the workstation off.

## Pieces

- `x_watch.py` is the scanner. Cron every 30 min on the box. Searches the tracked
  threads (replies, quotes, replies-to-quotes), posts linking the site, and a broad
  Coldcard-theft keyword query. Extracts addresses, classifies each tweet with a
  local `claude -p` call, then verifies on-chain and routes by proof.
- `publish.py` is the only writer. Verifies an address, edits every coupled site
  file in one atomic pass (with rollback), deploys via Vercel, reads the deployed
  bytes back, records state, sends a Telegram receipt. `x_watch.py` imports it; it
  also runs standalone for manual approve/reject.
- `watch_blocks.py` is the older chain-side scanner (unchanged). Finds clusters
  from the chain outward; `x_watch.py` finds them from the victim side.

## The two verification tiers

- A result is **proven** when the drained funds land in a known attacker address, directly or
  through one co-spend hop (the destination later spends together with an address
  already known to be the attacker's; common-input ownership is the proof). This is
  deterministic and is **published automatically**.
- A result is **pattern** when the sweep matches the drain fingerprint (1-in/1-out, no change, a
  known hardcoded fee rate, inside the drain window) but connects to nothing known.
  **Held for a person.** A Telegram message names the address and asks.
- A result is **collector** when the address receives batched single-input sweeps, so it looks like
  a thief's collector, not a victim. Never auto-published; flagged as a possible new
  operator address for review.
- Everything else (not_drained, unverifiable, already listed, a known attacker
  address) is recorded quietly and makes no noise.

## Approving or rejecting a held candidate

When a Telegram message says a drain was reported but only pattern-matched, the
decision is one command **on the Hetzner box**:

```
ssh <user>@<box>
cd ~/CLAUDE/personal/coldcard-watch
python3 publish.py --list-pending          # see everything waiting, with evidence
python3 publish.py --approve <ADDR>         # re-verifies, then publishes + deploys
python3 publish.py --reject  <ADDR>         # drops it
```

`--approve` re-runs the on-chain check before it publishes, so a candidate that has
since become provable is upgraded, and one that still does not hold up is refused.
Add `--dry-run` to `--approve` to see the edit without deploying.

The Telegram bot can run these too, so "approve `<addr>`" or
"reject `<addr>`" in the Telegram thread, and it runs the command on the box.

## Adding an address by hand

```
python3 publish.py --add <ADDR>             # verify + publish in one step
```

Anything the chain does not support is refused. A pattern-only address needs
`--approve` instead, which is the explicit human-judgement path.

## State and credentials

- State: `~/.coldcard-x-state.json` on the box (shared by both scripts). Outside the
  synced tree, so it never causes syncthing conflicts.
- Env: `~/.coldcard-x-env` (600) holds `X_BEARER_TOKEN`, `TELEGRAM_BOT_TOKEN`,
  `CC_ADMIN_ID`, `VERCEL_TOKEN`. On the Mac, the X token comes from Keychain
  (`x-bearer-token`) and the Vercel token from the logged-in CLI, so the env file is
  only needed on the box.
- The scripts sync to the box via syncthing (`~/CLAUDE`). The cron runs the synced
  copy.

## Health

```
python3 publish.py --self-check             # cross-file invariants (counts, hashes)
tail ~/logs/coldcard-x.log                  # on the box: cron output
```

`--self-check` proves drains.js rows, drained.js hashes, the DRAINED_COUNT in
index.html, the formatted counts in index/list, and the monitor's count all agree.
`apply_edits` runs it before and after every write and rolls back if it fails.

## What it deliberately cannot do

- Reach a private or deleted account.
- Read an address that appears only inside a screenshot (no OCR).
- Publish anything the chain does not support, however credible the tweet.
- Discover a cluster whose theft used a different tool or address type and that
  nobody has reported. That gap is the chain scanner's job, and it too has limits.

The token is Blockstream's content-engine X credential, used here at low volume.
