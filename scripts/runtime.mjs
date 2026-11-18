// Runs the deployed bundle on workerd with local-only synthetic upstreams.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {Miniflare,convertV4MiniflareOptions} from "miniflare";
import {setTimeout as delay} from "node:timers/promises";
import {generateKeyPair,exportJWK,SignJWT} from "jose";

const id="a".repeat(32);
let entries=["baseline"];
let prompt="";
let feedUnavailable=false;
const {publicKey,privateKey}=await generateKeyPair("RS256");
const jwk={...await exportJWK(publicKey),kid:"fixture",alg:"RS256"};
async function login(email){return new SignJWT({email}).setProtectedHeader({alg:"RS256",kid:"fixture"}).setIssuer("https://example.cloudflareaccess.com").setAudience("fixture").setSubject(email).setExpirationTime("10m").sign(privateKey);}
const rig=new Miniflare(convertV4MiniflareOptions({workers:[{
  name:"app",compatibilityDate:"2026-11-18",compatibilityFlags:["nodejs_compat"],
  modules:[{type:"ESModule",path:"driver.js",contents:`
    import app from "./bundle.js";export * from "./bundle.js";
    export default {async fetch(r,e){const p=new URL(r.url).pathname,s=e.LEDGER.getByName("account");
      if(p==="/sync"){await app.scheduled({},e);return Response.json(await s.overview())}
      if(p.startsWith("/detail/"))return Response.json(await s.detail(p.slice(8)));
       if(r.headers.get("fixture-dispatch-down")==="1")return app.fetch(r,{...e,RUNS:{async createBatch(){throw Error("Fixture unavailable");}}});
       return app.fetch(r,e);}};`},
  {type:"ESModule",path:"bundle.js",contents:readFileSync("dist/index.js","utf8")}],
  durableObjects:{LEDGER:{className:"Ledger",useSQLite:true},AssessmentAgent:{className:"AssessmentAgent",useSQLite:true}},
  workflows:{RUNS:{name:"assessments",className:"AssessmentWorkflow"}},
   bindings:{ACCESS_TEAM:"example",ACCESS_AUD:"fixture",ADMIN_EMAILS:"admin@example.org",INVENTORY_ACCOUNT_ID:id,INVENTORY_TOKEN:"fixture"},
  serviceBindings:{AI:"model",ASSETS:"assets"},
  outboundService:req=>{
     const u=new URL(req.url);
     if(u.href==="https://example.cloudflareaccess.com/cdn-cgi/access/certs")return Response.json({keys:[jwk]});
     if(u.origin==="https://radar.cloudflare.com")return feedUnavailable?new Response(null,{status:503}):Response.json({items:entries.map(slug=>({title:slug,_zero_wire:{slug,assessment_prompt:slug==="new"?prompt:""}}))});
    if(u.origin==="https://api.cloudflare.com")return Response.json({success:true,result:[]});
    throw Error("Unexpected outbound request");
  }
},{
  name:"model",compatibilityDate:"2026-11-18",modules:true,
   script:`import {WorkerEntrypoint} from "cloudflare:workers";export default class extends WorkerEntrypoint{async run(){await new Promise(r=>setTimeout(r,500));return {response:"Inspect origin inventory."}}}`
},{
   name:"assets",compatibilityDate:"2026-11-18",modules:true,
   script:`export default {fetch(){return new Response("fixture asset",{headers:{"content-type":"text/html"}})}}`
}]}));
try{
  const call=path=>rig.dispatchFetch(`https://example.org${path}`);
  for (const path of ["/","/app.js","/api/overview","/api/briefings/baseline","/agents/assessment-agent/abc"])assert.equal((await call(path)).status,401);
  assert.equal((await (await call("/sync")).json()).runs.length,0);
  entries.push("new");
  const [{id:run}]=(await (await call("/sync")).json()).runs;
  assert.equal((await (await call("/sync")).json()).runs.length,1);
  let detail;
  for(let i=0;i<60;i++){
    detail=await (await call(`/detail/${run}`)).json();
    if(["complete","failed"].includes(detail.state))break;
    await delay(200);
  }
  assert.equal(detail.state,"complete",JSON.stringify(detail.logs));
  assert.equal(detail.report.note,"Inspect origin inventory.");
  assert.deepEqual(detail.evidence,detail.report.evidence);assert.ok(detail.logs.some(e=>e.note==="Inventory snapshot saved"));
  const admin=await login("admin@example.org"),reader=await login("reader@example.org");
  const home=await rig.dispatchFetch("https://example.org/",{headers:{"cf-access-jwt-assertion":admin}});
  assert.equal(home.status,200);assert.equal(home.headers.get("cache-control"),"private, no-store");assert.equal(await home.text(),"fixture asset");
   const api=(path,token,method="GET",origin="https://example.org",payload,extra)=>rig.dispatchFetch(`https://example.org/api/${path}`,{
     method,headers:{"cf-access-jwt-assertion":token,origin,"x-console-action":"1",...(payload?{"content-type":"application/json"}:{}),...extra},
     ...(payload?{body:JSON.stringify(payload)}:{})
   });
  const overview=await api("overview",reader);assert.equal(overview.status,200);assert.equal((await overview.json()).admin,false);
  const advisory=await (await api("briefings/new",reader)).json();
   assert.equal(advisory.briefing.slug,"new");assert.equal(advisory.runs[0].id,run);assert.equal(advisory.runs[0].revision,detail.briefing.revision);
   assert.equal(advisory.triage,null);assert.deepEqual(advisory.audit,[]);
   const data={revision:advisory.briefing.revision,version:0,status:"closed",owner:"Fixture Ops",due:"2026-11-17",note:"Fixture owner checked the deployment."};
   const save=(body,token=admin,origin)=>api("triage/new",token,"POST",origin,body);
   assert.equal((await call("/api/triage/new")).status,401);
   assert.equal((await save(data,reader)).status,403);
   assert.equal((await save(data,admin,"https://other.example")).status,403);
   assert.equal((await save({...data,note:""})).status,400);
   assert.equal((await save({...data,note:"x".repeat(9000)})).status,413);
   const [first,second]=await Promise.all([save(data),save(data)]);
   assert.deepEqual([first.status,second.status].sort(),[200,409]);
   assert.equal((await save({...data,version:1})).status,200); // No-op: no new audit row.
   const tracked=await (await api("briefings/new",reader)).json();
   assert.equal(tracked.triage.version,1);assert.equal(tracked.triage.note,data.note);
   assert.equal(tracked.audit.length,1);
   assert.equal(tracked.audit[0].actor,"admin@example.org");assert.equal(tracked.audit[0].noteChanged,1);
   assert.ok(!Object.hasOwn(tracked.audit[0],"note"));
   assert.deepEqual((await (await api(`runs/${run}`,reader)).json()).report,detail.report);
  assert.equal((await api("briefings/missing",reader)).status,404);
  assert.equal((await api("sync",reader,"POST")).status,403);
  assert.equal((await api("sync",admin,"POST","https://other.example")).status,403);
  assert.equal((await api("sync",admin,"POST")).status,200);
  assert.equal((await api("assess/missing",admin,"POST")).status,404);
  const queued=await api("assess/baseline",admin,"POST");assert.equal(queued.status,202);const {id:manual}=await queued.json();
  assert.equal((await api(`stop/${manual}`,reader,"POST")).status,403);
  assert.equal((await api(`stop/${manual}`,admin,"POST")).status,200);
  await delay(700);
  const stopped=await (await api(`runs/${manual}`,reader)).json();assert.equal(stopped.state,"stopped");assert.equal(stopped.report,null);assert.ok(stopped.logs.some(e=>e.note==="stopped"));
  assert.equal((await api(`stop/${manual}`,admin,"POST")).status,409);
  assert.equal((await api(`stop/${run}`,admin,"POST")).status,409);
  const rerun=await api("assess/baseline",admin,"POST");assert.equal(rerun.status,202);assert.notEqual((await rerun.json()).id,manual);
  prompt="Updated owner checklist";
  assert.equal((await api("sync",admin,"POST")).status,200);
   const updated=await (await api("overview",admin)).json();assert.equal(updated.runs.filter(r=>r.title==="new").length,2);
   assert.equal(updated.lastAttempt.status,"ok");assert.equal(updated.lastAttempt.queued,1);assert.ok(updated.counts.complete>=1);
   const revised=updated.briefings.find(b=>b.slug==="new");
   assert.equal(revised.triageStatus,"closed");assert.notEqual(revised.revision,revised.triageRevision);
   assert.equal((await save({...data,version:1})).status,409);
   assert.equal((await save({...data,version:1,revision:revised.revision,status:"in-review",note:"Reviewing revised guidance."})).status,200);
   assert.deepEqual((await (await api("briefings/new",reader)).json()).audit.map(a=>a.version),[2,1]);
   // The automatic run for this revision may already exist. Use a new fixture slug
   // seeded while dispatch is offline, then verify requests converge on its outbox ID.
   entries.push("outbox");
   assert.equal((await api("sync",admin,"POST",undefined,undefined,{"fixture-dispatch-down":"1"})).status,503);
   const pendingRequest=()=>api("assess/outbox",admin,"POST",undefined,undefined,{"fixture-dispatch-down":"1"});
   const [p1,p2]=await Promise.all([pendingRequest(),pendingRequest()]);
   assert.equal(p1.status,202);assert.equal(p2.status,202);
   const [queued1,queued2]=await Promise.all([p1.json(),p2.json()]);
   assert.deepEqual(queued1,queued2);assert.equal(queued1.existing,true);assert.equal(queued1.dispatchDelayed,true);
   const beforeOutage=await (await api("overview",admin)).json();
   assert.equal(beforeOutage.runs.filter(r=>r.slug==="outbox").length,1);
   assert.equal(beforeOutage.runs.find(r=>r.id===queued1.id).state,"pending");
   feedUnavailable=true;
   assert.equal((await api("sync",admin,"POST")).status,503);
   const after=await (await api("overview",admin)).json();assert.equal(after.lastAttempt.stage,"feed");assert.equal(after.sync,beforeOutage.sync);
   assert.notEqual(after.runs.find(r=>r.id===queued1.id).state,"pending");
   console.log("Triage permissions, atomic edits and audit, revision review, active-run de-duplication and outbox recovery passed.");
  console.log("Signed admin/reader API, origin protection, manual sync, archival assessment, cancellation, event log and re-run passed.");
  console.log("Access gate, baseline, deduplication, Workflow → Agent → model binding and saved report passed.");
}finally{await rig.dispose();}
