// Runs the deployed bundle on workerd with local-only synthetic upstreams.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {Miniflare,convertV4MiniflareOptions} from "miniflare";
import {setTimeout as delay} from "node:timers/promises";

const id="a".repeat(32);
let entries=["baseline"];
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
  bindings:{ACCESS_TEAM:"example",ACCESS_AUD:"fixture",INVENTORY_ACCOUNT_ID:id,INVENTORY_TOKEN:"fixture"},
  serviceBindings:{AI:"model"},
  outboundService:req=>{
    const u=new URL(req.url);
    if(u.origin==="https://radar.cloudflare.com")return Response.json({items:entries.map(slug=>({title:slug,_zero_wire:{slug}}))});
    if(u.origin==="https://api.cloudflare.com")return Response.json({success:true,result:[]});
    throw Error("Unexpected outbound request");
  }
},{
  name:"model",compatibilityDate:"2026-11-18",modules:true,
  script:`import {WorkerEntrypoint} from "cloudflare:workers";export default class extends WorkerEntrypoint{run(){return {response:"Inspect origin inventory."}}}`
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
  console.log("Access gate, baseline, deduplication, Workflow → Agent → model binding and saved report passed.");
}finally{await rig.dispose();}
