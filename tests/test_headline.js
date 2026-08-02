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

console.log(failed ? `\n${failed} failure(s)` : "\nheadline maths holds");
process.exit(failed ? 1 : 0);
