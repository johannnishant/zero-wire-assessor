import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPair,SignJWT,jwtVerify} from "jose";
import {normalize,boundedJSON} from "../src/feed.js";
import {inventory} from "../src/inventory.js";
import {identity} from "../src/auth.js";
import {ownerEvidence,verdict} from "../src/vex.js";

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
    if(url.includes("/zones?"))return Response.json({success:true,result:[{id:own,name:"example.org",account:{id:account}},{id:other,name:"ignored",account:{id:other}}],result_info:{total_pages:2}});
    return Response.json({success:true,result:{rules:[{action:"execute",expression:"private expression",action_parameters:{id:"efb7b8c949ac4650a09736fc376e9aee"}}]}});
  });
  assert.equal(snapshot.zones[0].cloudflareManagedEntry,true);assert.equal(snapshot.workers,null);
  assert.ok(snapshot.gaps.some(g=>g.includes("Worker inventory unavailable")));
  assert.ok(!hits.join().includes(other));assert.ok(!JSON.stringify(snapshot).includes("private expression"));
});
test("access rejects forged, expired and wrong-audience JWTs; only allowlisted email is admin",async()=>{
  const {publicKey,privateKey}=await generateKeyPair("RS256");
  const env={ACCESS_TEAM:"example",ACCESS_AUD:"assessment",ADMIN_EMAILS:"admin@example.org"};
  const sign=(aud,exp,email)=>new SignJWT({email}).setProtectedHeader({alg:"RS256"}).setIssuer("https://example.cloudflareaccess.com").setAudience(aud).setExpirationTime(exp).setSubject("subject").sign(privateKey);
  const check=token=>identity(new Request("https://example.org",{headers:{"cf-access-jwt-assertion":token}}),env,(t,_k,opts)=>jwtVerify(t,publicKey,opts));
  assert.deepEqual(await check(await sign("assessment","1h","admin@example.org")),{admin:true});
  assert.deepEqual(await check(await sign("assessment","1h","reader@example.org")),{admin:false});
  assert.equal(await check(await sign("other","1h","admin@example.org")),null);
  assert.equal(await check(await sign("assessment",1,"admin@example.org")),null);
  assert.equal(await check("fake"),null);
});
test("component verdicts require an exact CVE, explicit state and resolvable bom-ref",()=>{
  const bom={bomFormat:"CycloneDX",components:[{"bom-ref":"srv",name:"demo"}],vulnerabilities:[{id:"CVE-2000-1000",affects:[{ref:"srv"},{ref:"other"}],analysis:{state:"exploitable"}}]};
  const rows=ownerEvidence(JSON.stringify(bom),["CVE-2000-1000"]);assert.equal(rows.length,1);assert.match(verdict(rows),/^Affected/);
  assert.match(verdict(ownerEvidence(JSON.stringify(bom),["CVE-2000-1001"])),/verification/);
});
