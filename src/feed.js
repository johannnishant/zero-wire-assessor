export const FEED = "https://radar.cloudflare.com/zero-wire/feed?format=json";

export async function boundedJSON(response, limit) {
  if (!response.ok || !response.body) throw Error("Upstream unavailable");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0, text = "";
  for (;;) {
    const {done, value} = await reader.read();
    if (done) break;
    if ((size += value.length) > limit) {
      await reader.cancel();
      throw Error("Response exceeds limit");
    }
    text += decoder.decode(value, {stream:true});
  }
  return JSON.parse(text + decoder.decode());
}

const str = (v, max) => typeof v === "string" ? v.slice(0,max) : "";
export async function normalize(feed) {
  if (!Array.isArray(feed.items) || !feed.items.length || feed.items.length > 300) throw Error("Unexpected feed");
  return Promise.all(feed.items.map(async item => {
    const z = item._zero_wire, slug = z?.slug;
    if (!/^[a-z0-9][a-z0-9-]{0,119}$/.test(slug ?? "") || !item.title) throw Error("Invalid briefing");
    const doc = {
      slug, title:str(item.title,300), url:`https://radar.cloudflare.com/zero-wire/${slug}`,
      reviewed:str(z.last_reviewed,10), summary:str(z.summary || item.summary,2000),
      cves:(z.cves || []).filter(c=>/^CVE-\d{4}-\d{4,}$/.test(c)).slice(0,40),
      prompt:str(z.assessment_prompt,14000), actions:(z.recommended_action_steps || []).slice(0,20).map(a=>str(a.text,1500)),
      coverage:str(z.product_coverage,4000), service:str(z.service_status,2500),
      updates:(z.updates || []).slice(0,12).map(u=>str(u.text,1000)),
      sources:(z.sources || []).flatMap(s=>s.links || []).map(l=>str(l.url,512)).filter(u=>/^https:\/\//.test(u)).slice(0,24)
    };
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(JSON.stringify(doc))));
    return {...doc, revision:Array.from(hash,x=>x.toString(16).padStart(2,"0")).join("")};
  }));
}
