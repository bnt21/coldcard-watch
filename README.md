# Coldcard Sweep Watch

Tracks the bitcoin drained from Coldcard wallets whose seeds were generated with too
little randomness, and watches whether the attackers ever move it. Live at
[coldcardwatch.com](https://coldcardwatch.com).

The site's only value is that every address on it is true, so everything here is built
around one rule: an address is listed when its sweep converges with hundreds of others,
either on a shared destination or on a fee constant no independent party would land on,
and never on transaction shape alone. Shape alone cannot separate a theft from an owner
following the vendor advisory, because the advisory told owners to do the same thing.

## What is in here

| | |
|---|---|
| `wave3.py` | The no-collector detector. Two hops, keyed on the signing software rather than the destination. |
| `scan.py` | Block scan for the original shape: many single-input sweeps into one collector at one fee rate. |
| `scan_batched.py` | Block scan for batched sweeps, many victims in one transaction. |
| `co_spend.py` | Common-input-ownership. The only test here treated as proof. |
| `cluster.py` | Resolves a collector to its victims and checks it against the drain fingerprint. |
| `trace.py` | Follows the attacker's money forward and stops at the first transaction that pools or splits across a service, because past that the next hop belongs to that service's customers. |
| `autopilot.py` | Orchestrator. Tiers candidates by proof strength and decides what may publish. Runs on a schedule and includes a no-collector tier so the wave-3 shape cannot hide again. |
| `wave3_refresh.py` | Re-reads the 214 vault balances hourly, and shouts the first time one of them spends. |
| `tests/` | Pins the published numbers and every fingerprint predicate. Needs no node and no network. |
| `x_watch.py` | Watches for victims reporting their own address, then verifies each claim on-chain. |
| `publish.py` | Chain reads, atomic multi-file edits, deploy, and deployed-byte verification. |
| `nodeconf.py` | Where block data comes from, with no address hardcoded anywhere. |
| `public/` | The site itself, plus the published datasets. |

## Layout

```
wave3.py  scan.py  scan_batched.py  co_spend.py  cluster.py   the detectors
autopilot.py  x_watch.py  publish.py  wave3_refresh.py        the pipeline
nodeconf.py  check_clean.py                                   config and the leak gate
data/        the datasets, including the chains left off
docs/        autopilot and X-pipeline notes
scripts/     one-off migrations, kept for the record rather than for reuse
sim/         mockups of site states, used while designing the page
tests/       run with: python3 -m unittest discover -s tests
```

Python 3.9 or newer, standard library only. No dependencies to install.

## Running it

Nothing here needs a node to be useful, but a node makes the block scans roughly five
times faster and supplies one field the public APIs do not return cheaply: the block
height that funded each input, which the firmware-epoch test reads.

With no configuration, the scanners fall back to public block explorers. To point them at
a node, either export `CCW_NODE_ADDR` plus `CCW_NODE_HOST` and one of `CCW_NODE_KEYCHAIN`
or `CCW_NODE_RPC_PASSWORD`, or write `~/.coldcard-node.json`:

```json
{ "host": "your-node-hostname", "addr": "10.0.0.2", "keychain": "your-keychain-service" }
```

That file is gitignored and never enters the tree. Neither does any token: every
credential is read from the environment or from a file outside the repo.

```
python3 wave3.py --from 960396 --to 960471     # reconstruct wave 3
python3 wave3_diag.py                          # why a predicate rejected what it rejected
python3 wave3_publish_set.py                   # freeze the subset that clears the bar
python3 -m unittest discover -s tests -v       # the regression tests
python3 check_clean.py                         # refuse to ship a credential or a node address
```

## Tests

The published figures went up before any tests existed, so for a while the only thing
standing behind 200.33487536 BTC was that one run landed near a number Galaxy published.
`tests/` closes that. It re-derives the published set from the frozen report and requires
it to match the live dataset to the satoshi, asserts the canary chain is present and every
vault still unspent, and exercises each fingerprint predicate against hand-built blocks so
a loosened rule fails a test rather than shipping.

The most valuable one is `test_address_reuse_across_inputs_is_allowed`. Requiring every
input to sit at a distinct address silently dropped 63 sweeps on the first run, roughly a
fifth of the wave, because a victim wallet reuses addresses. That regression now has a
name.

## How wave 3 was reconstructed

The first three waves funnelled hundreds of victims into a handful of collectors, which is
what every detector here originally keyed on. Wave 3 removed the funnel: each drained
wallet was swept into its own fresh address and forwarded into its own fresh P2WSH vault,
sharing nothing. Both existing detectors were structurally blind to it.

What survives when the shared address is gone is the signer. A transaction carries the
fields its software chose, so `wave3.py` matches on those instead: version 2, locktime 0,
one nSequence across every input, exactly one output with no change, homogeneous P2WPKH
inputs, no input coin older than the block the vulnerable firmware shipped in, and a fee
far above the block's own median. Then it requires the second hop, a full no-change
forward into a fresh P2WSH that stays unspent.

The field list comes from [Clay Garrett at Block](https://x.com/clay_garrett), who found
the original pattern. Galaxy Research reported the wave and its totals; they published no
addresses, no dataset, and no code, so the addresses on the site come from this
reconstruction rather than from them.

Against Galaxy's figures for the same block range, this finds 293 vaults holding
207.72947587 BTC against their 207.73, agreeing to about two thousand satoshis. It also
finds the single wave-3 chain a third party published in full, which is the test that the
detector works at all. Sixteen further chains matched the shape but paid scattered fee
rates and were left off.

## The three standards

The address list is everything this project verified itself, and for six days it was the
only figure the site published: 1,366 BTC, while the settled figure everywhere else was
1,596. Galaxy Research confirm a theft by writing to the victim, so their set includes
losses whose addresses were never made public and never will be. Reading the chain cannot
reach those, so leaving the number off left the site 14% low rather than more accurate.

The dashboard now reads at three standards: **verified here**, which is the address list;
**attested**, which is Galaxy's victim-corroborated total; and **suspected**, their own
medium-confidence figure, which adds a fourth wave no victim has confirmed. The last
two are one number with their name on it and no addresses, drawn in their own colour, and
`public/methodology.html` sets out what warrants carrying them: their figures agree with
this project's independent reconstruction on all four things both can measure, and disagree
on none.

Two rules keep the arithmetic honest, and both are pinned by tests:

A tier stores the source's **total**, and the site derives the remainder against its own
verified figure at render time. A frozen remainder starts double-counting the moment
anything new is published, and the first version of this did exactly that.

Anything already inside a tier is **listed under it, never added to it**. An independent
report of the same fourth wave Galaxy already count is a second reading of one event, and
summing both put 1,984.94 BTC on the site, a total no source claims.

## Where the trail ends

`trace.py` follows the attacker's money forward and stops at the first transaction that
pools or splits across a service, recording that a service was reached rather than
expanding through it. An earlier walk without that rule grew from 456 pending addresses at
hop 5 to 1,034 at hop 6, because it had started enumerating an exchange's customers.

The predicate counts **distinct input addresses, not inputs**, and that is the whole of its
correctness. On real data the attacker's own consolidations run 491, 204 and 1,212 inputs
across one or two addresses, while a service's deposit sweep ran 902 inputs across 795. An
input threshold would have called the thief's own wallet a service and halted the walk on
the hop that mattered. Where every input address is already attributed to the attacker, the
merge test does not apply at all.

Thresholds come from a control arm rather than from taste: 495 non-coinbase transactions
sampled across five blocks spanning ~9,000 blocks give a median of 1 input and 2 outputs,
with a p99 of 10 and 18. The bar sits at 50, five times the input p99, and matches 0.2% of
ordinary traffic.

The site does not name the service. That needs off-chain address labelling this project
does not have, and a guess would carry the same authority as a verified address while
resting on nothing.

## What this cannot do

It cannot prove theft. What it proves is that coins left an address and arrived at
another, which is arithmetic anyone can repeat, plus the convergence that independent
owners are unable to produce between them. Getting from there to "a thief did this"
remains an inference, and the methodology page says so plainly.

Nobody has tested whether the drained addresses were in fact generated with weak entropy.
Galaxy state the same limitation about their own work.

## This is not a screening feed

Do not ingest these addresses into a compliance, screening, or risk-scoring system.

The list has **no measured false-positive rate**, because none can be measured: nobody has
tested whether any of these addresses was in fact generated with weak entropy, and the
vendor's own advisory told every affected owner to produce transactions that look exactly
like the ones the detector matches on. It is a research reconstruction published so that
it can be checked, and it carries the uncertainty described above and on the methodology
page. Treating it as a blocklist converts an inference into a consequence for someone who
has no idea they are on a list and no way to appeal to whoever ingested it.

If a screening product has already ingested this data, that is the single most important thing
to report. Open an issue.

## Corrections

**Getting an address wrong matters more than anything else in this project.** If one here
is yours, open a [dispute](../../issues/new?template=disputed-address.yml) with the address
and the transaction. No identity and nothing secret. It is checked against the chain, and a
listing that does not hold up comes off with the totals moved to match.

Everything else about contributing, including why address data is generated rather than
edited, is in [CONTRIBUTING.md](CONTRIBUTING.md).
