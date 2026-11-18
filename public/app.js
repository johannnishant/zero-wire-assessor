const $=id=>document.getElementById(id);
const el=(tag,text)=>Object.assign(document.createElement(tag),{textContent:text});
const data=async(path,write=false)=>{
  const r=await fetch(path,write?{method:"POST",headers:{"x-console-action":"1"}}:{});
  if(!r.ok)throw Error(`${r.status}: ${(await r.json()).error || "Request failed"}`);
  return r.json();
};
let offset=0,selected=null;
function act(fn){return async e=>{const b=e.currentTarget;b.disabled=true;try{await fn();}catch(err){$("notice").textContent=err.message;}finally{b.disabled=false;}};}
function button(text,fn){const b=el("button",text);b.onclick=act(fn);return b;}
function row(title,sub,b){const wrap=el("div",""),label=el("div","");wrap.className="row";label.append(el("strong",title),el("small",sub));wrap.append(label);if(b)wrap.append(b);return wrap;}
async function inspect(id,scroll=true){
  const d=await data(`/api/runs/${id}`), box=$("report");selected=id;box.replaceChildren(el("h2",d.briefing.title),el("p",`${d.state} · ${id}`));
  if(d.report)box.append(el("h3",d.report.exposure),el("p",d.report.note),el("h3","Observed configuration"),el("pre",JSON.stringify(d.report.evidence,null,2)));
  box.append(el("h3","Radar’s recommended steps"),el("p",d.briefing.actions.join("\n\n")));
  const link=el("a","Read the Radar briefing and sources ↗");link.href=d.briefing.url;box.append(link);
  box.append(el("h3","Event log"),el("pre",d.logs.map(e=>`${e.ts}  ${e.note}`).join("\n")));
  $("detail").hidden=false;if(scroll)$("detail").scrollIntoView({block:"start"});
}
async function load(){
  const d=await data(`/api/overview?offset=${offset}`);$("role").textContent=d.admin?"Administrator":"Read only";
  $("stamp").textContent=d.sync?`Last synced ${d.sync} · ${d.briefings.length} briefings`:"No baseline yet. Sync the feed or wait for the scheduler.";
  $("sync").hidden=!d.admin;
  $("briefings").replaceChildren(...d.briefings.map(b=>row(b.title,b.reviewed,d.admin && button("Assess",async()=>{const {id}=await data(`/api/assess/${b.slug}`,true);offset=0;await load();await inspect(id); }))));
  $("runs").replaceChildren(...d.runs.map(r=>{
    const controls=el("div","");controls.append(button("Inspect",()=>inspect(r.id)));
    if(d.admin&&!["complete","failed","stopped"].includes(r.state))controls.append(button("Stop",async()=>{await data(`/api/stop/${r.id}`,true);await load();}));
    return row(r.title,`${r.state} · ${r.created}`,controls);
  }));
  if(!d.runs.length)$("runs").append(el("p","No assessments on this page."));
  $("prev").hidden=!offset;$("next").hidden=d.runs.length<30;
  if(selected)await inspect(selected,false);
}
$("sync").onclick=act(async()=>{await data("/api/sync",true);await load();});$("refresh").onclick=act(load);
$("prev").onclick=act(async()=>{offset=Math.max(0,offset-30);await load();});
$("next").onclick=act(async()=>{offset+=30;await load();});
load().catch(e=>{$("notice").textContent=e.message;});
