// Optional owner-maintained CycloneDX VEX snapshot. Only exact CVE + component
// references are evidence. An unlisted CVE/resource never implies safety.
export function ownerEvidence(raw,cves) {
  if (!raw) return [];
  const bom=JSON.parse(raw);
  if(bom.bomFormat!=="CycloneDX" || !Array.isArray(bom.vulnerabilities))throw Error("Invalid owner VEX");
  const components=new Map((bom.components || []).map(c=>[c["bom-ref"],c]));
  return bom.vulnerabilities.filter(v=>cves.includes(v.id)).flatMap(v=>(v.affects || []).flatMap(a=>{
    const c=components.get(a.ref), state=v.analysis?.state;
    if(!c || !["exploitable","not_affected","resolved","in_triage"].includes(state))return [];
    return [{cve:v.id,asset:String(c.name).slice(0,150),version:String(c.version||"unknown").slice(0,80),state,asOf:bom.metadata?.timestamp || "undated"}];
  })).slice(0,60);
}
export function verdict(rows) {
  if(rows.some(x=>x.state==="exploitable"))return "Affected component reported by owner";
  if(rows.length)return "Owner evidence available for listed components only";
  return "Requires owner verification";
}
