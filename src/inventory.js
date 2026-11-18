import { boundedJSON } from "./feed.js";

// Only fixed control-plane GETs. No URLs or identifiers supplied by a briefing or model.
export async function inventory(env, request = fetch) {
  const account = env.INVENTORY_ACCOUNT_ID;
  if (!/^[a-f0-9]{32}$/.test(account || "") || !env.INVENTORY_TOKEN) throw Error("Inventory credentials missing");
  async function get(path) {
    const response = await request(`https://api.cloudflare.com/client/v4${path}`, {
      headers:{Authorization:`Bearer ${env.INVENTORY_TOKEN}`}, redirect:"manual", signal:AbortSignal.timeout(10000)
    });
    if(response.status===401 || response.status===403)throw Error("access");
    if(response.status===404)throw Error("missing");
    if(response.status===429)throw Error("limit");
    const body = await boundedJSON(response, 1500000);
    if (body.success !== true) throw Error("Inventory unavailable");
    return body;
  }
  const why=err=>({access:"check token permissions and expiry",missing:"no entry point returned",limit:"Cloudflare API rate limit reached"})[err.message] ?? "Cloudflare API did not return usable data";
  const result = {observed:new Date().toISOString(), zones:[], workers:null, gaps:[], coverage:"available"};
  const gap=message=>{result.coverage="partial";result.gaps.push(message);};
  const seen=new Set(), scoped=[];
  let zoneListRead=false;
  for(let page=1;page<=3;page++){
    try{
      const {result:zones,result_info:info}=await get(`/zones?account.id=${account}&per_page=10&page=${page}&order=name&direction=asc`);
      if(!Array.isArray(zones))throw Error("Unexpected zone list");
      zoneListRead=true;
      for(const zone of zones.slice(0,10)){
        if(!zone || typeof zone.id!=="string" || !/^[a-f0-9]{32}$/.test(zone.id) || zone.account?.id!==account ||
          typeof zone.name!=="string" || !zone.name || zone.name.length>253){
          gap("A zone record outside the configured scope or with invalid fields was skipped.");continue;
        }
        if(seen.has(zone.id)){gap("The zone list changed during pagination; a duplicate was skipped.");continue;}
        seen.add(zone.id);scoped.push(zone);
      }
      const more=Number.isSafeInteger(info?.total_pages)?info.total_pages>page:zones.length>=10;
      if(zones.length>10 || (more && page===3)){gap("Zone inventory truncated at 30 zones.");break;}
      if(!more)break;
    }catch(err){gap(page===1?`Zone inventory unavailable: ${why(err)}.`:`Zone page ${page} unavailable: ${why(err)}.`);break;}
  }
  // Bound parallelism to stay under the Worker connection limit and preserve display order.
  for(let i=0;i<scoped.length;i+=4){
    const rows=await Promise.all(scoped.slice(i,i+4).map(async zone=>{
      const row = {zone:zone.name, managedExecutions:null, cloudflareManagedEntry:null};
      try {
        const {result:ruleset} = await get(`/zones/${zone.id}/rulesets/phases/http_request_firewall_managed/entrypoint`);
        row.managedExecutions = ruleset.rules.filter(r=>r.action==="execute" && r.enabled!==false).length;
        row.cloudflareManagedEntry = ruleset.rules.some(r=>r.action==="execute" && r.enabled!==false && r.action_parameters?.id==="efb7b8c949ac4650a09736fc376e9aee");
        return {row};
      }catch(err){return {row,error:`Managed WAF entry point unavailable for ${zone.name}: ${why(err)}.`};}
    }));
    for(const {row,error} of rows){result.zones.push(row);if(error)gap(error);}
  }
  try {
    const {result:scripts} = await get(`/accounts/${account}/workers/scripts`);
    if(!Array.isArray(scripts))throw Error("Unexpected Worker list");
    result.workers = scripts.slice(0,40).flatMap(s=>typeof s?.id==="string" && s.id.length>0 && s.id.length<=120 ? [s.id] : []);
    if(result.workers.length<Math.min(scripts.length,40))gap("Invalid Worker names were skipped.");
    if(scripts.length>40)gap("Worker list truncated to forty.");
  } catch(err) {gap(`Worker inventory unavailable: ${why(err)}.`);}
  if(!zoneListRead && result.workers===null)result.coverage="unavailable";
  result.gaps.push("Token visibility may be partial. No origin package, SBOM, running version, effective WAF action or traffic evidence.");
  return result;
}
