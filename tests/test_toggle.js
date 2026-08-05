// The toggle is the only place a reader meets the three standards, and it runs in the
// browser, so the Python suite cannot reach it. This evaluates the real viewToggle out
// of index.html against a stub DOM: no browser, no rendering, just proof that every
// identifier resolves, each press lands on the exact sats it should, and the note names
// the source, its own stated confidence, and the date the figure was taken down.
//
// It catches the class of bug that kills a page silently: one unresolved reference in a
// handler throws, and every line of script after it stops running.
const fs=require("fs"),path=require("path");
const ROOT=path.join(__dirname,"..");
const src=fs.readFileSync(path.join(ROOT,"public","index.html"),"utf8");
const window={};
eval(fs.readFileSync(path.join(ROOT,"public","potential.js"),"utf8"));
// the real tier block, not a stand-in, so the numbers the toggle lands on are the ones
// the page computes
eval(fs.readFileSync(path.join(ROOT,"public","wave3.js"),"utf8"));
eval(fs.readFileSync(path.join(ROOT,"public","confirmed-extra.js"),"utf8"));
const WAVE3=window.WAVE3, CX=window.CONFIRMED_EXTRA;
const WALLETS=[];
src.match(/var WALLETS = \[[\s\S]*?\n {2}\];/)[0]
   .replace(/attributed:\s*(\d+)[^{}]*?origin:\s*"seed"/g,(m,n)=>{WALLETS.push({attributed:+n,origin:"seed"});return m;});
const nowSec=()=>Math.floor(Date.now()/1000);
const TIERBLOCK=src.match(/ {2}var POT = \(window\.POTENTIAL[\s\S]*?\n {2}function stopCaption\(i\)\{[\s\S]*?\n {2}\}/);
if(!TIERBLOCK){console.error("FAIL: tier block not found");process.exit(1);}
eval(TIERBLOCK[0]);
let drawn=0;
const fmt=(n,d)=>n.toLocaleString("en-US",{minimumFractionDigits:d,maximumFractionDigits:d});
const btc=s=>s/1e8;
const draw=()=>{drawn++;};
const cancelAnimationFrame=()=>{};
let CLOCK=0;
const requestAnimationFrame=fn=>{CLOCK+=120;fn(CLOCK);return 1;};
const classes=new Set();
const body={classList:{toggle:(c,on)=>{on?classes.add(c):classes.delete(c);}}};
function mkBtn(t){const h={};return{getAttribute:k=>k==="data-tier"?t:h[k],
  setAttribute:(k,v)=>{h[k]=v;},remove(){},addEventListener:(e,f)=>{h.click=f;},
  fire(){h.click();},pressed:()=>h["aria-pressed"]};}
const buttons=[mkBtn("0"),mkBtn("1"),mkBtn("2")];
const noteBody={innerHTML:""};
const host={hidden:true,querySelectorAll:()=>buttons};
const el=id=>id==="measure"?host:(id==="potnoteBody"?noteBody:null);
const document={body};
const M=src.match(/ {2}\(function viewToggle\(\)\{[\s\S]*?\n {2}\}\)\(\);/);
if(!M){console.error("FAIL: viewToggle not found");process.exit(1);}
eval(M[0]);
let bad=0;
const check=(l,c)=>{console.log((c?"  ok    ":"  FAIL  ")+l);if(!c)bad++;};
check("control revealed", host.hidden===false);
check("note filled at boot", /verified here/i.test(noteBody.innerHTML));
buttons[1].fire();
check("attested press sets aria-pressed", buttons[1].pressed()==="true"&&buttons[0].pressed()==="false");
check("attested note names the source and its own confidence",
  noteBody.innerHTML.includes("glxyresearch")&&noteBody.innerHTML.includes("victim-corroborated"));
check("attested note dates the figure",
  /Recorded 3 August 2026\./.test(noteBody.innerHTML));
check("attested note states 1,596 and the unverified part",
  noteBody.innerHTML.includes("1,596 BTC")&&noteBody.innerHTML.includes("229.4126"));
check("the attested press reproduces their published total exactly",
  verifiedDrained()+ov===159600000000);
check("attested lists the fourth wave as inside, not added",
  noteBody.innerHTML.includes("listed rather than added")===false);
check("body marked potential, not suspected", classes.has("potential")&&!classes.has("suspected"));
check("overlay moved to the attested delta", ov===stopSats(1));
buttons[2].fire();
check("suspected note states 2,055", noteBody.innerHTML.includes("2,055 BTC"));
check("suspected lists the fourth-wave report inside it",
  noteBody.innerHTML.includes("listed rather than added")&&noteBody.innerHTML.includes("intangiblecoins"));
check("body marked suspected", classes.has("suspected"));
check("overlay moved to the suspected delta", ov===stopSats(2));
buttons[0].fire();
check("back to verified clears both classes", !classes.has("potential")&&!classes.has("suspected"));
check("overlay back to zero", ov===0);
check("every press redrew", drawn>=4);
POT_TIERS[0].reported_ts=Math.floor(Date.now()/1000)-9*86400;
buttons[0].fire();buttons[1].fire();
check("a tier nobody has restated for days says so",
  /and not restated since\. A revision would not show on the chain\./.test(noteBody.innerHTML));

console.log(bad?`\n${bad} failure(s)`:"\ntoggle runs clean");
process.exit(bad?1:0);
