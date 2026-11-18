import { boundedJSON } from "./feed.js";

// Only fixed control-plane GETs. No URLs or identifiers supplied by a briefing or model.
export async function inventory(env, request = fetch) {
  const account = env.INVENTORY_ACCOUNT_ID;
  if (!/^[a-f0-9]{32}$/.test(account || "") || !env.INVENTORY_TOKEN) throw Error("Inventory credentials missing");
  async function get(path) {
    const response = await request(`https://api.cloudflare.com/client/v4${path}`, {
      headers:{Authorization:`Bearer ${env.INVENTORY_TOKEN}`}, redirect:"manual", signal:AbortSignal.timeout(10000)
    });
    const body = await boundedJSON(response, 1500000);
    if (body.success !== true) throw Error("Inventory unavailable");
    return body;
  }
  const result = {observed:new Date().toISOString(), zones:[], workers:null, gaps:[]};
  try {
    const {result:zones,result_info} = await get(`/zones?account.id=${account}&per_page=10&page=1`);
    if (result_info?.total_pages > 1) result.gaps.push("Only the first ten visible zones were assessed.");
    for (const zone of zones.slice(0,10)) {
      if (!/^[a-f0-9]{32}$/.test(zone.id) || zone.account?.id !== account) continue;
      const row = {zone:zone.name, managedExecutions:null, cloudflareManagedEntry:null};
      try {
        const {result:ruleset} = await get(`/zones/${zone.id}/rulesets/phases/http_request_firewall_managed/entrypoint`);
        row.managedExecutions = ruleset.rules.filter(r=>r.action==="execute" && r.enabled!==false).length;
        row.cloudflareManagedEntry = ruleset.rules.some(r=>r.action==="execute" && r.enabled!==false && r.action_parameters?.id==="efb7b8c949ac4650a09736fc376e9aee");
      } catch {result.gaps.push(`Managed WAF entry point unavailable for ${zone.name}.`);}
      result.zones.push(row);
    }
  } catch {result.gaps.push("Zone inventory unavailable.");}
  try {
    const {result:scripts} = await get(`/accounts/${account}/workers/scripts`);
    result.workers = scripts.slice(0,40).map(s=>s.id);
    if (scripts.length > 40) result.gaps.push("Worker list truncated to forty.");
  } catch {result.gaps.push("Worker inventory unavailable.");}
  result.gaps.push("Token visibility may be partial. No origin package, SBOM, running version, effective WAF action or traffic evidence.");
  return result;
}
