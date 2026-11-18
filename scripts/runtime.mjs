// Runs the deployed bundle on workerd with local-only synthetic upstreams.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {Miniflare,convertV4MiniflareOptions} from "miniflare";
import {setTimeout as delay} from "node:timers/promises";
import {generateKeyPair,exportJWK,SignJWT} from "jose";

const id="a".repeat(32);
let entries=["baseline"];
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
      return app.fetch(r,e);}};`},
  {type:"ESModule",path:"bundle.js",contents:readFileSync("dist/index.js","utf8")}],
  durableObjects:{LEDGER:{className:"Ledger",useSQLite:true},AssessmentAgent:{className:"AssessmentAgent",useSQLite:true}},
  workflows:{RUNS:{name:"assessments",className:"AssessmentWorkflow"}},
   bindings:{ACCESS_TEAM:"example",ACCESS_AUD:"fixture",ADMIN_EMAILS:"admin@example.org",INVENTORY_ACCOUNT_ID:id,INVENTORY_TOKEN:"fixture"},
  serviceBindings:{AI:"model"},
  outboundService:req=>{
     const u=new URL(req.url);
     if(u.href==="https://example.cloudflareaccess.com/cdn-cgi/access/certs")return Response.json({keys:[jwk]});
    if(u.origin==="https://radar.cloudflare.com")return Response.json({items:entries.map(slug=>({title:slug,_zero_wire:{slug}}))});
    if(u.origin==="https://api.cloudflare.com")return Response.json({success:true,result:[]});
    throw Error("Unexpected outbound request");
  }
},{
  name:"model",compatibilityDate:"2026-11-18",modules:true,
   script:`import {WorkerEntrypoint} from "cloudflare:workers";export default class extends WorkerEntrypoint{async run(){await new Promise(r=>setTimeout(r,500));return {response:"Inspect origin inventory."}}}`
}]}));
try{
  const call=path=>rig.dispatchFetch(`https://example.org${path}`);
  for (const path of ["/","/app.js","/api/overview","/agents/assessment-agent/abc"])assert.equal((await call(path)).status,401);
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
  const admin=await login("admin@example.org"),reader=await login("reader@example.org");
  const api=(path,token,method="GET",origin="https://example.org")=>rig.dispatchFetch(`https://example.org/api/${path}`,{method,headers:{"cf-access-jwt-assertion":token,origin,"x-console-action":"1"}});
  const overview=await api("overview",reader);assert.equal(overview.status,200);assert.equal((await overview.json()).admin,false);
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
  console.log("Signed admin/reader API, origin protection, manual sync, archival assessment, cancellation, event log and re-run passed.");
  console.log("Access gate, baseline, deduplication, Workflow → Agent → model binding and saved report passed.");
}finally{await rig.dispose();}
