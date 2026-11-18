const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>Object.assign(document.createElement(tag),{textContent:text,className:cls || ""});
const terminal=new Set(["complete","failed","stopped"]);
const names={pending:"Waiting to queue",queued:"Queued",collecting:"Reading inventory",assessing:"Writing assessment",complete:"Complete",failed:"Failed",stopped:"Stopped"};
let offset=0, selected=null, detailsVersion=0, overviewVersion=0;

async function data(path,write=false){
  const r=await fetch(path,write?{method:"POST",headers:{"x-console-action":"1"}}:{});
  const payload=await r.json().catch(()=>null);
  if(r.redirected || r.status===401 || (r.ok && !payload))throw Error("Session unavailable. Reload to sign in again.");
  if(!r.ok)throw Error(payload?.error || `Request failed (${r.status}).`);
  return payload;
}
function act(fn){return async e=>{
  const b=e.currentTarget;
  b.disabled=true;$("notice").textContent="";
  try{await fn();}catch(err){$("notice").textContent=err.message;}finally{b.disabled=false;}
};}
function button(text,fn){const b=el("button",text);b.type="button";b.onclick=act(fn);return b;}
function badge(state){const b=el("span",names[state] || state,"status");b.dataset.state=state;return b;}
function row(title,sub,controls){
  const wrap=el("div","","row"),label=el("div","");
  label.append(el("strong",title),sub);
  wrap.append(label);if(controls)wrap.append(controls);
  return wrap;
}
function disclosure(key,title,text,open=false){
  const d=el("details","");d.dataset.key=key;d.open=open;
  d.append(el("summary",title),el("pre",text));
  return d;
}
function setPicked(){
  for(const b of $("runs").querySelectorAll("[data-run]"))b.setAttribute("aria-pressed",String(b.dataset.run===selected));
}
async function inspect(id,scroll=true){
  const version=++detailsVersion;
  const d=await data(`/api/runs/${id}`);
  if(version!==detailsVersion)return;
  const box=$("report"), same=selected===id;
  const disclosures=new Map(Array.from(box.querySelectorAll("details"),x=>[x.dataset.key,x.open]));
  selected=id;setPicked();
  const title=el("h2",d.briefing.title);title.tabIndex=-1;
  const meta=el("p","","muted");meta.append(badge(d.state),` · ${id}`);
  box.replaceChildren(title,meta);
  if(d.report){
    const {evidence,note,exposure}=d.report;
    const observed=el("p",`${evidence.zones?.length ?? 0} zones listed · ${Array.isArray(evidence.workers)?`${evidence.workers.length} Workers listed`:"Worker inventory unavailable"}.`);
    box.append(el("h3",exposure),el("p",note),el("h3","Observed configuration"),observed);
    if(evidence.gaps?.length){
      const gaps=el("ul","");gaps.append(...evidence.gaps.map(g=>el("li",g)));
      box.append(el("h3","Coverage gaps"),gaps);
    }
    box.append(disclosure("evidence","Inventory details",JSON.stringify(evidence,null,2),same && disclosures.get("evidence")));
  }else{
    const message=d.state==="stopped"?"Run stopped before a report was saved.":d.state==="failed"?"No report was saved. See the event log.":"No report yet. Refresh to see the latest status.";
    box.append(el("p",message));
  }
  const link=el("a","Read the Radar briefing ↗");link.href=d.briefing.url;
  box.append(el("h3","Radar’s recommended steps"));
  if(d.briefing.actions.length){
    const steps=el("ul","");steps.append(...d.briefing.actions.map(s=>el("li",s)));box.append(steps);
  }
  box.append(link,disclosure("log","Event log",d.logs.map(e=>`${e.ts}  ${e.note}`).join("\n"),same?disclosures.get("log"):!d.report));
  $("detail").hidden=false;
  if(scroll){title.focus({preventScroll:true});$("detail").scrollIntoView({block:"start"});}
}
async function load(){
  const version=++overviewVersion;
  const d=await data(`/api/overview?offset=${offset}`);
  if(version!==overviewVersion)return;
  $("role").textContent=d.admin?"Administrator":"Read only";
  $("stamp").textContent=d.sync?`${d.briefings.length} briefings · Synced ${d.sync} UTC`:"No briefings synced yet.";
  $("sync").hidden=!d.admin;
  $("briefings").replaceChildren(...d.briefings.map(b=>row(b.title,el("small",b.reviewed?`Reviewed ${b.reviewed}`:"Review date unavailable"),d.admin && button("Assess",async()=>{
    const {id}=await data(`/api/assess/${b.slug}`,true);offset=0;await load();await inspect(id);
  }))));
  $("runs").replaceChildren(...d.runs.map(r=>{
    const controls=el("div","","row-actions"), inspectButton=button("Inspect",()=>inspect(r.id));
    inspectButton.dataset.run=r.id;controls.append(inspectButton);
    if(d.admin && !terminal.has(r.state))controls.append(button("Stop",async()=>{await data(`/api/stop/${r.id}`,true);await load();await inspect(r.id);}));
    const sub=el("small","");sub.append(badge(r.state),` · ${r.created} UTC`);
    return row(r.title,sub,controls);
  }));
  if(!d.runs.length)$("runs").append(el("p","No assessments on this page.","muted"));
  $("prev").hidden=!offset;$("next").hidden=d.runs.length<30;setPicked();
  if(selected)await inspect(selected,false);
}
$("sync").onclick=act(async()=>{await data("/api/sync",true);await load();});
$("refresh").onclick=act(load);
$("prev").onclick=act(async()=>{offset=Math.max(0,offset-30);await load();});
$("next").onclick=act(async()=>{offset+=30;await load();});
load().catch(e=>{$("notice").textContent=e.message;});
