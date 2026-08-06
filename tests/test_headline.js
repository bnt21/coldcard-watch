// The headline figure is the most public number this project produces, and it is
// computed in the browser, so the Python suite cannot reach it. This extracts the
// real effective() out of index.html and exercises the case that broke it.
//
// 2026-08-02: the page briefly showed 2,628.9556 BTC against a true 1,359.1829.
// follow() pushes a traced destination carrying only `attributed`, and the address
// it came from still held its pre-spend balance, so the same coins counted twice
// until refreshBalances() landed. It self-corrected, which is exactly why it was
// hard to catch.
const fs = require("fs");
const path = require("path");
const src = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8");
const m = src.match(/ {2}function effective\(w\)\{[\s\S]*?\n {2}\}/);
if (!m) { console.error("FAIL: could not find effective() in index.html"); process.exit(1); }
eval(m[0]);

const held = (W, w3) => W.reduce((t, w) => t + effective(w), 0) + w3;
let failed = 0;
function is(label, got, want) {
  const ok = got === want;
  if (!ok) failed++;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}${ok ? "" : `  got ${got}, want ${want}`}`);
}

const W3 = 20033487536;
const seed = { addr: "vault", attributed: 19153677, origin: "seed" };

is("a seeded wallet counts before any balance arrives",
   held([seed], W3), W3 + 19153677);

const traced = { addr: "dest", attributed: 19153677, origin: "traced", from: "vault" };
is("a traced destination counts NOTHING until its balance is read",
   held([seed, traced], W3), W3 + 19153677);

is("once balances land, the source drops and the destination carries it",
   held([{ ...seed, balance: 0 }, { ...traced, balance: 19153677 }], W3),
   W3 + 19153677);

is("a traced destination is capped at what was traced to it",
   effective({ addr: "d", attributed: 100, origin: "traced", balance: 9999999 }), 100);

is("a drained wallet contributes zero",
   effective({ addr: "d", attributed: 500, origin: "seed", balance: 0 }), 0);

// ---------------------------------------------------------------------------
// 2026-08-06: the page rendered 1,438.97 BTC against a published 1,405.04, and a
// different number on every refresh. follow() had walked out of the theft cluster: a
// collector holding 0.0755 BTC forwarded into a 0.0052 BTC dust hop, and from there the
// follower reached addresses holding 1,392 and 530 BTC — exchange wallets — and counted
// their outputs as stolen coins. It stops at MAX_TRACKED, so which addresses it reached
// depended on which fetches resolved first.
const rootSrc = src.match(/ {2}function rootOf\(w\)\{[\s\S]*?\n {2}\}/);
const heldSrc = src.match(/ {2}function heldTotal\(\)\{[\s\S]*?\n {2}\}/);
if (!rootSrc || !heldSrc) { console.error("FAIL: rootOf/heldTotal not found"); process.exit(1); }
let WALLETS = [], WAVE3 = { held: 0 }, CX = { held: 0 };
eval(rootSrc[0]); eval(heldSrc[0]);

(function chainCannotExceedWhatWasStolen(){
  // seed lost 100; the follower then wanders into an exchange holding 1,000
  WALLETS = [
    { addr: "seed", attributed: 100, balance: 0, origin: "seed" },
    { addr: "hop",  attributed: 100, balance: 5,    origin: "traced", from: "seed" },
    { addr: "exch", attributed: 900, balance: 1000, origin: "traced", from: "hop" },
  ];
  is("a chain never contributes more than the seed lost", heldTotal(), 100);
})();

(function aChainMayHoldLess(){
  // coins spent onward past the follower's reach: less is honest, more is not
  WALLETS = [
    { addr: "seed", attributed: 100, balance: 0,  origin: "seed" },
    { addr: "hop",  attributed: 100, balance: 30, origin: "traced", from: "seed" },
  ];
  is("a chain may hold less than was taken", heldTotal(), 30);
})();

(function seedsAreIndependent(){
  WALLETS = [
    { addr: "a", attributed: 50, balance: 50, origin: "seed" },
    { addr: "b", attributed: 70, balance: 70, origin: "seed" },
  ];
  is("separate seeds each count in full", heldTotal(), 120);
})();

(function anOrphanedHopIsItsOwnRoot(){
  WALLETS = [{ addr: "hop", attributed: 10, balance: 10, origin: "traced", from: "gone" }];
  is("a hop whose parent is untracked is capped by its own attribution", heldTotal(), 10);
})();

(function aCycleTerminates(){
  WALLETS = [
    { addr: "x", attributed: 10, balance: 10, origin: "traced", from: "y" },
    { addr: "y", attributed: 10, balance: 10, origin: "traced", from: "x" },
  ];
  is("a cycle in the chain does not hang", heldTotal(), 10);
})();

WAVE3 = { held: 7 }; CX = { held: 3 };
WALLETS = [{ addr: "s", attributed: 100, balance: 100, origin: "seed" }];
is("wave 3 and graduated extras are added outside the cap", heldTotal(), 110);

console.log(failed ? `\n${failed} failure(s)` : "\nheadline maths holds");
process.exit(failed ? 1 : 0);
