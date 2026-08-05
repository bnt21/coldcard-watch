// The site now publishes a figure it did not verify itself — Galaxy Research's total,
// which covers thefts confirmed by victim correspondence this project has no access to.
// Carrying someone else's number is only honest if the arithmetic around it is exact, so
// this pins that arithmetic against the real index.html and the real potential.js.
//
// The two failures it exists to prevent, both of which the site actually shipped:
//
//   1. Double counting. An independent post reported the same fourth wave Galaxy already
//      counts. Adding both produced 1,984.94 BTC, a total no source claims.
//   2. A frozen remainder. The first version stored "229.4226 BTC beyond ours" against a
//      verified figure of 1,366.5774. The verified figure has since moved to 1,366.5874,
//      so the stored remainder was already double-counting 0.01 BTC and would drift
//      further with every cluster published.
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const src = fs.readFileSync(path.join(ROOT, "public", "index.html"), "utf8");

// the real published data, not a fixture
const window = {};
eval(fs.readFileSync(path.join(ROOT, "public", "potential.js"), "utf8"));
eval(fs.readFileSync(path.join(ROOT, "public", "wave3.js"), "utf8"));
eval(fs.readFileSync(path.join(ROOT, "public", "confirmed-extra.js"), "utf8"));

// the real seeded clusters, lifted out of the page rather than retyped
const WALLETS = [];
const WSRC = src.match(/var WALLETS = \[[\s\S]*?\n {2}\];/);
if (!WSRC) { console.error("FAIL: could not find WALLETS in index.html"); process.exit(1); }
WSRC[0].replace(/attributed:\s*(\d+)[^{}]*?origin:\s*"seed"/g, (_, n) => {
  WALLETS.push({ attributed: +n, origin: "seed" });
  return _;
});

const WAVE3 = window.WAVE3;
const CX = window.CONFIRMED_EXTRA;
const nowSec = () => Math.floor(Date.now() / 1000);

// the block under test, extracted verbatim
const BLOCK = src.match(/ {2}var POT = \(window\.POTENTIAL[\s\S]*?\n {2}function stopCaption\(i\)\{[\s\S]*?\n {2}\}/);
if (!BLOCK) { console.error("FAIL: could not find the tier block in index.html"); process.exit(1); }
eval(BLOCK[0]);

let failed = 0;
function is(label, got, want) {
  const ok = got === want;
  if (!ok) failed++;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}${ok ? "" : `  got ${got}, want ${want}`}`);
}

const VERIFIED = 136658736354;          // 1,366.58736354 BTC
const ATTESTED = 159600000000;          // Galaxy, 1,596 BTC, victim-corroborated
const SUSPECTED = 205500000000;         // Galaxy, 2,055 BTC, medium-high

is("the verified basis is drained value, not the balance still held",
   verifiedDrained(), VERIFIED);

is("the verified view adds nothing", stopSats(0), 0);

is("attested adds exactly the part of their total we have not verified",
   stopSats(1), ATTESTED - VERIFIED);

is("suspected adds exactly the part of THEIR larger total we have not verified",
   stopSats(2), SUSPECTED - VERIFIED);

// the whole point of the headline: reading it at a standard reproduces that source's
// published figure to the satoshi, so nobody has to trust our arithmetic on top of theirs
is("the attested headline lands on the published 1,596 BTC",
   verifiedDrained() + stopSats(1), ATTESTED);
is("the suspected headline lands on the published 2,055 BTC",
   verifiedDrained() + stopSats(2), SUSPECTED);

// failure 1: the fourth wave is inside Galaxy's suspected total, so it is listed there
// and adds nothing. If this goes non-zero the site is claiming a total nobody published.
is("nothing outside a tier is being added on top", LOOSE_SATS, 0);
is("the fourth-wave report is marked as inside the suspected total",
   window.POTENTIAL.entries.filter(e => e.subsumed_by === "suspected").length, 1);
is("no entry is both counted and inside a tier",
   window.POTENTIAL.entries.filter(e => e.subsumed_by && !e.sats).length, 0);

// failure 2: the remainder is derived, so publishing more shrinks it instead of stacking
(function derivedNotFrozen() {
  const before = stopSats(1);
  WALLETS.push({ attributed: 10000000000, origin: "seed" });   // publish 100 BTC more
  const after = stopSats(1);
  is("verifying 100 more BTC shrinks the attested remainder by exactly 100 BTC",
     before - after, 10000000000);
  is("the attested headline is unchanged by what we verify",
     verifiedDrained() + stopSats(1), ATTESTED);
  WALLETS.pop();
})();

(function overtaken() {
  WALLETS.push({ attributed: 100000000000, origin: "seed" });  // pass their total
  is("a tier we have overtaken adds nothing rather than going negative", stopSats(1), 0);
  WALLETS.pop();
})();

// two standards that differ only in a caption get quoted as one number
is("suspected is drawn in its own colour", stopInk(2) === stopInk(1), false);
is("attested says it was not verified here", stopCaption(1), "attested, not verified here");
is("suspected says it is unconfirmed", stopCaption(2), "suspected, unconfirmed");

is("there is one stop per tier, plus our own", STOPS, window.POTENTIAL.tiers.length + 1);
is("the axis reserves room for the largest standard", MAX_ADD, SUSPECTED - VERIFIED);

console.log(failed ? `\n${failed} failure(s)` : "\ntier maths holds");
process.exit(failed ? 1 : 0);
