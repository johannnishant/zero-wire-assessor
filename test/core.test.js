import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPair,SignJWT,jwtVerify} from "jose";
import {normalize,boundedJSON} from "../src/feed.js";
import {inventory} from "../src/inventory.js";
import {identity} from "../src/auth.js";
import {ownerEvidence,verdict} from "../src/vex.js";
import {readTriage,validateTriage} from "../src/triage.js";

test("prompt edits alter a revision even without a date change; legacy records work",async()=>{
  const item={title:"Example",_zero_wire:{slug:"example",last_reviewed:"2026-01-01"}};
  const [a]=await normalize({items:[item]});assert.equal(a.prompt,"");
  item._zero_wire.assessment_prompt="Compare approved inventory";
  const [b]=await normalize({items:[item]});assert.notEqual(a.revision,b.revision);
  assert.deepEqual([b],await normalize({items:[item]}));
  await assert.rejects(boundedJSON(new Response("012345"),4));
});
test("inventory stays in the configured account, redacts raw rules, records missing access",async()=>{
  const account="a".repeat(32), own="b".repeat(32), other="c".repeat(32), hits=[];
  const snapshot=await inventory({INVENTORY_ACCOUNT_ID:account,INVENTORY_TOKEN:"test"},async(url,init)=>{
    hits.push(url);assert.equal(init.redirect,"manual");
    if(url.includes("workers/scripts"))return new Response(null,{status:403});
    if(url.includes("/zones?"))return Response.json({success:true,result:[{id:own,name:"example.org",account:{id:account}},{id:other,name:"ignored",account:{id:other}}],result_info:{total_pages:1}});
    return Response.json({success:true,result:{rules:[{action:"execute",expression:"private expression",action_parameters:{id:"efb7b8c949ac4650a09736fc376e9aee"}}]}});
  });
  assert.equal(snapshot.zones[0].cloudflareManagedEntry,true);assert.equal(snapshot.workers,null);
  assert.ok(snapshot.gaps.some(g=>g.includes("Worker inventory unavailable")));
  assert.equal(snapshot.coverage,"partial");
  assert.ok(!hits.join().includes(other));assert.ok(!JSON.stringify(snapshot).includes("private expression"));
});
test("inventory is bounded, keeps earlier pages on error and distinguishes blocked reads from empty lists",async()=>{
  const account="a".repeat(32), env={INVENTORY_ACCOUNT_ID:account,INVENTORY_TOKEN:"fixture"};
  const collect=async(fail=false)=>{
    const pages=[];let inFlight=0, peak=0;
    const s=await inventory(env,async url=>{
      const u=new URL(url);
      if(u.pathname.endsWith("/zones")){
        const p=Number(u.searchParams.get("page"));pages.push(p);
        assert.equal(u.searchParams.get("account.id"),account);
        if(fail && p===2)return new Response(null,{status:429});
        return Response.json({success:true,result_info:{total_pages:4},result:Array.from({length:10},(_,i)=>({
          name:`zone-${p}-${i}.example.org`,id:(p*10+i).toString(16).padStart(32,"0"),account:{id:account}
        }))});
      }
      if(u.pathname.endsWith("/entrypoint")){
        peak=Math.max(++inFlight,peak);
        await new Promise(resolve=>setImmediate(resolve));inFlight--;
        return Response.json({success:true,result:{rules:[]}});
      }
      return Response.json({success:true,result:[]});
    });
    assert.equal(peak,4);
    return {s,pages};
  };
  const bounded=await collect();
  assert.deepEqual(bounded.pages,[1,2,3]);assert.equal(bounded.s.zones.length,30);
  assert.match(bounded.s.gaps.join(),/truncated/);assert.equal(bounded.s.coverage,"partial");
  const interrupted=await collect(true);
  assert.deepEqual(interrupted.pages,[1,2]);assert.equal(interrupted.s.zones.length,10);
  assert.match(interrupted.s.gaps.join(),/page 2 unavailable.*rate limit/);assert.equal(interrupted.s.coverage,"partial");
  const blocked=await inventory(env,async()=>new Response(null,{status:403}));
  assert.equal(blocked.coverage,"unavailable");assert.equal(blocked.workers,null);
  const empty=await inventory(env,async()=>Response.json({success:true,result:[]}));
  assert.equal(empty.coverage,"available");assert.deepEqual(empty.workers,[]);
  assert.match(empty.gaps.join(),/Token visibility may be partial/);
});
test("access rejects forged, expired and wrong-audience JWTs; only allowlisted email is admin",async()=>{
  const {publicKey,privateKey}=await generateKeyPair("RS256");
  const env={ACCESS_TEAM:"example",ACCESS_AUD:"assessment",ADMIN_EMAILS:"admin@example.org"};
  const sign=(aud,exp,email)=>new SignJWT({email}).setProtectedHeader({alg:"RS256"}).setIssuer("https://example.cloudflareaccess.com").setAudience(aud).setExpirationTime(exp).setSubject("subject").sign(privateKey);
  const check=token=>identity(new Request("https://example.org",{headers:{"cf-access-jwt-assertion":token}}),env,(t,_k,opts)=>jwtVerify(t,publicKey,opts));
  assert.deepEqual(await check(await sign("assessment","1h","Admin@Example.org")),{admin:true,email:"admin@example.org"});
  assert.deepEqual(await check(await sign("assessment","1h","reader@example.org")),{admin:false,email:"reader@example.org"});
  assert.equal(await check(await sign("other","1h","admin@example.org")),null);
  assert.equal(await check(await sign("assessment",1,"admin@example.org")),null);
  assert.equal(await check("fake"),null);
});
test("triage validates a strict bounded JSON record and requires a valid date and closure rationale",async()=>{
  const payload={revision:"a".repeat(64),version:0,status:"closed",owner:" Platform ",due:"2028-02-29",note:" Done "};
  assert.deepEqual(validateTriage(payload),{...payload,owner:"Platform",note:"Done"});
  for(const patch of [{due:"2027-02-29"},{owner:" "},{note:" "},{owner:"x\nx"},{status:"resolved"},{version:-1},{actor:"not-accepted"},{revision:"a"}])
    assert.equal(validateTriage({...payload,...patch}),null);
  const req=(body,type="application/json")=>new Request("https://example.org",{method:"POST",headers:{"content-type":type},body});
  assert.equal((await readTriage(req(JSON.stringify(payload),"application/json; charset=utf-8"))).value.status,"closed");
  assert.equal((await readTriage(req("{}", "text/plain"))).status,415);
  assert.equal((await readTriage(req("{"))).status,400);
  assert.equal((await readTriage(req(" ".repeat(8193)))).status,413);
});
test("component verdicts require an exact CVE, explicit state and resolvable bom-ref",()=>{
  const bom={bomFormat:"CycloneDX",components:[{"bom-ref":"srv",name:"demo"}],vulnerabilities:[{id:"CVE-2000-1000",affects:[{ref:"srv"},{ref:"other"}],analysis:{state:"exploitable"}}]};
  const rows=ownerEvidence(JSON.stringify(bom),["CVE-2000-1000"]);assert.equal(rows.length,1);assert.match(verdict(rows),/^Affected/);
  assert.match(verdict(ownerEvidence(JSON.stringify(bom),["CVE-2000-1001"])),/verification/);
});
