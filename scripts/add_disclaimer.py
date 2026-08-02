#!/usr/bin/env python3
"""
add_disclaimer.py — say out loud that this is not a blocklist.

Every address on this site is public, in plaintext, with an explorer link. That is
deliberate: the whole claim is that the work can be checked. It also means a screening
or compliance product can ingest the list, and once it does, an address here stops being
a research finding and starts being a consequence for whoever holds it.

The people most exposed are the ones the detector cannot see: an owner who followed
Coinkite's advisory, swept to a new wallet at an urgent fee, and produced the same shape
a thief does. They would never know they were listed and could not appeal to whoever
ingested it.

So the site says plainly what the list is not, and how to get an address removed. Adds
the same block to the methodology page and a short line above the address list.

usage: add_disclaimer.py [--dry-run] [--no-deploy]
"""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import publish

REPO_ISSUES = "https://github.com/bnt21/coldcard-watch/issues"

METH_ANCHOR = "  <h2>Telling a victim apart from a thief</h2>"
METH_BLOCK = """  <h2>This is not a blocklist</h2>
  <p>
    Every address here is published in full so the work can be checked. That is the point of
    the page. It also means this list can be copied into a screening or compliance system, and
    if that happens an address stops being a research finding and becomes a problem for whoever
    holds it, usually without them ever knowing why.
  </p>
  <p>
    Stated plainly: <strong>this is not a screening feed and it has no measured false-positive
    rate.</strong> None can be measured. Nobody has tested whether any of these addresses was
    in fact generated with weak entropy, and the vendor's own advisory told every affected owner
    to move their coins in a way that produces the same shape a theft does. The reasoning below
    is set out so it can be argued with, not so it can be automated against people.
  </p>
  <p>
    If an address here is yours, it comes off. No proof of identity is needed and nothing secret
    should ever be sent: the address and the transaction are enough to check it against the
    chain, and if the listing does not hold up the totals move with it. Report it
    <a href="%s" rel="noopener">here</a>. That request is handled before anything else on this
    project.
  </p>

""" % REPO_ISSUES

LIST_ANCHOR = "  <h1>Verified drained addresses</h1>"
LIST_BLOCK = """  <h1>Verified drained addresses</h1>
  <p class="tool-lede" style="max-width:70ch">
    This is a research reconstruction, not a screening feed, and it has no measured
    false-positive rate. Please do not load it into a compliance or risk-scoring system. If an
    address here is yours, <a href="%s" rel="noopener">say so</a> and it comes off.
  </p>""" % REPO_ISSUES


def main():
    dry = "--dry-run" in sys.argv
    if publish.conflict_guard():
        raise SystemExit("syncthing conflict copies present, refusing")
    if publish.self_check(verbose=False):
        raise SystemExit("site invariants broken before edit; aborting")

    edits = {}

    p = os.path.join(publish.PUBLIC, "methodology.html")
    s = open(p, encoding="utf-8").read()
    if "This is not a blocklist" in s:
        print("methodology already carries the disclaimer")
    else:
        if METH_ANCHOR not in s:
            raise SystemExit("could not find the methodology anchor")
        edits[p] = s.replace(METH_ANCHOR, METH_BLOCK + METH_ANCHOR, 1)

    p = os.path.join(publish.PUBLIC, "list.html")
    s = open(p, encoding="utf-8").read()
    if "not a screening feed" in s:
        print("list already carries the disclaimer")
    else:
        if LIST_ANCHOR not in s:
            raise SystemExit("could not find the list anchor")
        edits[p] = s.replace(LIST_ANCHOR, LIST_BLOCK, 1)

    if not edits:
        print("nothing to do")
        return 0
    if dry:
        print("dry run; would edit:", [os.path.basename(x) for x in edits])
        return 0

    baks = {}
    try:
        for path, content in edits.items():
            baks[path] = path + ".dbak"
            shutil.copy2(path, baks[path])
            tmp = path + ".tmp"
            open(tmp, "w", encoding="utf-8").write(content)
            os.replace(tmp, path)
        probs = publish.self_check(verbose=True)
        if probs:
            raise RuntimeError(f"invariants broken after edit: {probs}")
    except Exception:
        for path, bak in baks.items():
            shutil.copy2(bak, path)
        raise
    finally:
        for bak in baks.values():
            if os.path.exists(bak):
                os.remove(bak)

    if "--no-deploy" in sys.argv:
        print("edited, not deployed")
        return 0
    publish.deploy()
    print("deployed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
