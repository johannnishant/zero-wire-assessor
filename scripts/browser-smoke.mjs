// Browser regression checks use synthetic HTTP responses. DEMO_URL optionally adds public demo checks.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {createServer} from "node:http";
import {chromium} from "playwright";

const revision="a".repeat(64), previous="b".repeat(64);
const briefing={slug:"example",title:"Fixture advisory",revision,cves:["CVE-2000-1000"],
  summary:"Fictional advisory summary.",reviewed:"2026-11-18",actions:["Verify the version with the owner."]};
const stamp="2026-11-18T09:30:00.000Z";
const evidence={observed:stamp,zones:[{zone:"shop.example.org",managedExecutions:1,cloudflareManagedEntry:true}],
  workers:null,coverage:"partial",gaps:["Worker inventory unavailable."],ownerEvidence:[]};
const completed={created:stamp,state:"complete",briefing,evidence,
  report:{exposure:"Requires owner verification",note:"Example guidance.",evidence},logs:[{ts:stamp,note:"complete"}]};
const assets={"/":["index.html","text/html"],"/app.js":["app.js","text/javascript"],"/style.css":["style.css","text/css"]};
const csp="default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
const server=createServer((req,res)=>{
  const asset=assets[new URL(req.url,"http://localhost").pathname];
  if(!asset){res.writeHead(404).end();return;}
  res.writeHead(200,{"content-type":asset[1],"content-security-policy":csp});
  res.end(readFileSync(new URL(`../public/${asset[0]}`,import.meta.url)));
});

function parts(page){
  const btn=name=>page.getByRole("button",{name,exact:true});
  const row=key=>page.locator(`#desk details[data-detail="${key}"]`);
  const toggle=key=>row(key).locator("summary").click();
  const dialog=page.getByRole("dialog");
  const filter=page.getByRole("combobox",{name:"Filter advisories"});
  const saved=()=>page.getByText("Triage saved.",{exact:true}).waitFor();
  return {btn,row,toggle,dialog,filter,saved};
}

async function fixture(page,admin){
  let task=null,audit=[],runState=null;
  const old={id:"fixture-old",revision,created:stamp,state:"complete"};
  const edit=(fields)=>{task={revision,version:(task?.version??0)+1,status:"in-review",owner:"Fixture Team",due:"2020-01-02",note:"",...fields};
    audit.unshift({revision:task.revision,version:task.version,status:task.status,owner:task.owner,due:task.due,
      noteChanged:!!task.note,actor:"analyst@example.org",at:stamp});};
  await page.route("**/api/**",async route=>{
    const req=route.request(), path=new URL(req.url()).pathname;
    const send=(json,status=200)=>route.fulfill({json,status});
    if(path==="/api/overview")return send({admin,sync:stamp,counts:{complete:1},briefings:[{...briefing,state:runState||"complete",
      triageStatus:task?.status,triageOwner:task?.owner,triageDue:task?.due,triageRevision:task?.revision}]});
    if(path==="/api/briefings/example")return send({briefing,triage:task,audit,
      runs:[...(runState?[{...old,id:"fixture-new",state:runState}]:[]),old]});
    if(path==="/api/runs/fixture-old")return send(completed);
    if(path==="/api/runs/fixture-new")return send({...completed,state:runState,evidence:null,report:null,logs:[{ts:stamp,note:runState}]});
    if(path==="/api/triage/example"){
      assert.equal(req.headers()["x-console-action"],"1");
      const change=req.postDataJSON();
      if(change.version!==(task?.version??0) || change.revision!==revision)return send({error:"Triage changed."},409);
      edit({...change,version:change.version+1});
      return send({version:task.version});
    }
    if(path==="/api/assess/example"){runState="queued";return send({id:"fixture-new"},202);}
    if(path==="/api/stop/fixture-new"){runState="stopped";return send({ok:true});}
    if(path==="/api/sync")return send({first:false,queued:0});
    return send({error:"Unexpected fixture route"},404);
  });
  return {edit,run:(state)=>{runState=state;}};
}

async function verifyAdmin(page,url){
  const model=await fixture(page,true), {btn,row,toggle,dialog,filter,saved}=parts(page);
  await page.addInitScript(()=>Object.defineProperty(navigator.clipboard,"writeText",{value:async()=>{throw Error("Denied");}}));
  await page.goto(url);
  await page.getByRole("heading",{name:"Next action"}).waitFor();
  await page.getByText("Partial inventory. See Evidence.",{exact:true}).waitFor();
  assert.equal(await page.locator("#desk details[open]").count(),0);
  await filter.selectOption("overdue");
  await page.getByText("No matching advisories.").waitFor();
  await btn("Clear filters").click();
  assert.equal(await filter.inputValue(),"all");

  await toggle("triage");await btn("Edit triage").click();
  await dialog.getByLabel("Status").selectOption("closed");await btn("Save triage").click();
  await dialog.getByRole("alert").getByText("Closing requires an owner and a note.").waitFor();
  await dialog.getByLabel("Owner or team").fill("Unsaved draft");
  await dialog.getByLabel("Triage note").fill("Keep this through the conflict");
  model.edit({owner:"Other editor"});
  await btn("Save triage").click();
  await dialog.getByText("Triage changed.",{exact:true}).waitFor();
  assert.equal(await dialog.getByLabel("Triage note").inputValue(),"Keep this through the conflict");
  await btn("Discard draft and reload").click();
  await btn("Discard draft and reload").waitFor({state:"hidden"});
  assert.equal(await dialog.getByLabel("Owner or team").inputValue(),"Other editor");
  await dialog.getByLabel("Triage note").fill("<b>Plain text only</b>");
  await btn("Save triage").click();
  await saved();await dialog.waitFor({state:"hidden"});
  await row("triage").getByText("In review · Overdue").waitFor();
  assert.equal(await row("triage").locator(".detail-body b").count(),0);
  await filter.selectOption("overdue");
  await page.getByRole("searchbox").fill("Other editor");
  assert.equal(await page.locator("#advisories button").count(),1);

  await btn("Copy handoff").click();
  const text=await dialog.getByRole("textbox",{name:"Handoff text"}).inputValue();
  assert.match(text,/Triage: In review · Other editor/);
  assert.match(text,/fixture-old/);
  assert.doesNotMatch(text,/Plain text only/);
  await page.keyboard.press("Escape");await dialog.waitFor({state:"hidden"});
  await btn("Activity").click();await toggle("triage-audit");
  assert.equal(await row("triage-audit").getByText("analyst@example.org").count(),2);
  await btn("Evidence").click();await toggle("zones");
  await row("zones").getByText("shop.example.org").waitFor();
  await btn("Activity").click();assert.equal(await row("triage-audit").getAttribute("open"),"");

  model.edit({status:"closed",revision:previous,note:"Previous revision note."});
  await btn("Refresh").click();
  await row("triage").getByText("Review new revision").waitFor();
  await filter.selectOption("revised");assert.equal(await page.locator("#advisories button").count(),1);
  await btn("Edit triage").click();
  assert.equal(await dialog.getByLabel("Status").inputValue(),"in-review");
  assert.equal(await dialog.getByLabel("Triage note").inputValue(),"");
  await btn("Cancel").click();await dialog.waitFor({state:"hidden"});

  await btn("Sync feed").click();await page.getByText("Feed checked. No new revisions to assess.").waitFor();
  await btn("Run again").click();await btn("Stop run").waitFor();
  await toggle("progress");model.run("collecting");
  await page.locator('#desk [data-state="collecting"]').waitFor();
  assert.equal(await row("progress").getAttribute("open"),"");
  await btn("Stop run").click();await page.locator("#desk .panel > p").filter({hasText:/^Run stopped$/}).waitFor();
  await toggle("history");await page.getByRole("combobox",{name:"Run history"}).selectOption("fixture-old");
  await page.locator("#desk .panel > p").filter({hasText:/^Report saved$/}).waitFor();
}

async function verifyReader(page,url){
  const model=await fixture(page,false),{btn,row,toggle}=parts(page);
  model.edit({owner:"Read-only Fixture"});
  await page.goto(url);
  await row("triage").waitFor();await toggle("triage");
  await row("triage").getByText(/Read-only Fixture/).waitFor();
  for(const edit of ["Sync feed","Run again","Edit triage","Stop run"])assert.equal(await btn(edit).isVisible(),false);
  await btn("Activity").click();await toggle("triage-audit");
  await row("triage-audit").getByText("analyst@example.org").waitFor();
}

async function verifyDemo(page,url){
  const {btn,row,toggle,dialog,filter,saved}=parts(page);
  await page.goto(url);
  await row("triage").waitFor();
  await toggle("triage");await btn("Edit triage").click();
  await dialog.getByLabel("Owner or team").fill("Fictional Platform");
  await dialog.getByLabel("Due date (UTC)").fill("2020-01-02");
  await dialog.getByLabel("Triage note").fill("Fictional smoke test");
  await btn("Save triage").click();await saved();
  await filter.selectOption("overdue");await page.getByRole("searchbox").fill("Fictional Platform");
  assert.equal(await page.locator("#advisories button").count(),1);
  await btn("Activity").click();await toggle("triage-audit");
  await row("triage-audit").getByText("analyst@example.org").waitFor();
  await btn("Evidence").click();await toggle("zones");await row("zones").getByText("shop.example.org").waitFor();
  await btn("Reset demo").click();await page.getByText("Demo reset.",{exact:true}).waitFor();
  await row("triage").getByText("Unassigned").waitFor();
  assert.equal(await page.getByRole("searchbox").inputValue(),"");
  assert.equal(await filter.inputValue(),"all");
  assert.equal(await page.locator("#desk details[open]").count(),0);
}

let browser;
try{
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  const url=`http://127.0.0.1:${server.address().port}/`;
  browser=await chromium.launch(process.env.BROWSER_CHANNEL?{channel:process.env.BROWSER_CHANNEL}:{});
  const run=async(name,width,fn,target=url)=>{
    const context=await browser.newContext({viewport:{width,height:850}});
    try{
      const page=await context.newPage(),errors=[];
      page.setDefaultTimeout(12000);page.on("pageerror",err=>errors.push(err.message));
      await fn(page,target);
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
      assert.deepEqual(errors,[]);console.log(`${name} (${width}px) passed`);
    }finally{await context.close();}
  };
  const cases=[run("Admin browser flows",1440,verifyAdmin),run("Admin browser flows",320,verifyAdmin),run("Reader browser flows",390,verifyReader)];
  if(process.env.DEMO_URL)cases.push(run("Deployed demo",390,verifyDemo,process.env.DEMO_URL));
  const failed=(await Promise.allSettled(cases)).filter(r=>r.status==="rejected");
  if(failed.length)throw new AggregateError(failed.map(r=>r.reason),"Browser regressions");
}finally{
  await browser?.close();
  server.close();
}
