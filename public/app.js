const node=(tag,text="",cls="")=>Object.assign(document.createElement(tag),{textContent:text,className:cls});
const button=(text,fn,cls="")=>Object.assign(node("button",text,cls),{type:"button",onclick:fn});
const link=(text,url)=>Object.assign(node("a",text),{href:url});
const wrap=(cls,...children)=>{const el=node("div","",cls);el.append(...children);return el;};
const list=(tag,items)=>{const el=node(tag);el.append(...items.map(x=>node("li",x)));return el;};
const section=(title,...contents)=>{const el=node("section","","panel");el.append(node("h3",title),...contents);return el;};
const terminal=new Set(["complete","failed","stopped"]);
const active=s=>Boolean(s && !terminal.has(s));
const stateLabels={pending:"Waiting to queue",queued:"Queued",collecting:"Reading inventory",assessing:"Drafting guidance",complete:"Report ready",failed:"Failed",stopped:"Stopped"};
const stateLabel=s=>stateLabels[s] ?? "Not assessed";
const badge=state=>{const b=node("span",stateLabel(state),"badge");b.dataset.state=state ?? "none";return b;};
const utc=t=>t ? `${t.replace("T"," ").replace(/\.\d+Z$|Z$/,"").slice(0,19)} UTC` : "—";
const started=id=>id?.startsWith("auto-")?"Scheduled":"Manual";
const parseUtc=s=>Date.parse(s.includes("T")?s:s.replace(" ","T")+"Z");
const elapsed=(a,b)=>Math.max(0,Math.round((parseUtc(b)-parseUtc(a))/1000));
const stageNames=[
  ["Queued","Wait for a workflow slot."],
  ["Inventory","Read visible zones, managed WAF entries and Worker names."],
  ["Guidance","Draft a handoff from the inventory snapshot."],
  ["Report","Save the findings and event log."]
];
const stateStage={pending:0,queued:0,collecting:1,assessing:2,complete:3};
const rank={collecting:1,assessing:2,complete:3};

async function api(path,post=false){
  const response=await fetch(path,post?{method:"POST",headers:{"x-console-action":"1"}}:{});
  const data=await response.json().catch(()=>null);
  if(response.redirected || response.status===401 || (response.ok && !data))throw Error("Session expired. Reload to sign in again.");
  if(!response.ok)throw Error(data?.error || `Request failed (${response.status}).`);
  return data;
}

function table(headers,rows){
  const t=node("table"), head=node("thead"), body=node("tbody");
  const hr=node("tr");
  for(const h of headers){const cell=node("th",h);cell.scope="col";hr.append(cell);}
  head.append(hr);
  for(const row of rows){const r=node("tr");r.append(...row.map(v=>node("td",v)));body.append(r);}
  t.append(head,body);return wrap("table-scroll",t);
}
function advisoryLink(d){return link("Read on Radar ↗",`https://radar.cloudflare.com/zero-wire/${encodeURIComponent(d.slug)}`);}
function recommendations(doc,evidence){
  const result=[];
  if(evidence?.ownerEvidence?.some(x=>x.state==="exploitable"))result.push(["Service owner","Confirm which deployments run the affected component recorded in your VEX snapshot. Prioritize the vendor fix and verify the running version after rollout."]);
  else result.push(["Service owner",doc.cves?.length?"Identify deployments that use the affected component. Verify the running version or configuration against the vendor advisory.":"Confirm whether your organization uses the affected product or service. Validate the relevant configuration against the advisory."]);
  if(evidence?.zones?.some(z=>z.managedExecutions!==null))result.push(["Edge security","If relying on a WAF mitigation, confirm the affected hostnames, matching scope and effective rule action. A managed ruleset entry does not establish coverage."]);
  if(evidence && (evidence.workers===null || !evidence.zones?.length || evidence.gaps?.some(g=>/unavailable|truncated/i.test(g))))result.push(["Cloudflare administrator","Review the coverage gaps. Confirm the token scope and fill any missing inventory before closing triage."]);
  return result;
}
function reportText(doc,detail){
  const e=detail.evidence ?? detail.report?.evidence;
  return [doc.title,doc.cves?.join(", "),`Exposure: ${detail.report?.exposure ?? "Not determined"}`,
    `Run: ${stateLabel(detail.state)}`,e?.observed&&`Inventory captured: ${utc(e.observed)}`,
    e&&`Observed: ${e.zones.length} zones listed; ${e.workers?.length ?? "unavailable"} Worker names.`,
    e?.gaps?.length&&`Coverage gaps:\n${e.gaps.map(g=>"- "+g).join("\n")}`,
    `Owner handoff:\n${recommendations(doc,e).map(([owner,text])=>`- ${owner}: ${text}`).join("\n")}`,
    doc.actions?.length&&`Radar recommendations:\n${doc.actions.map(a=>"- "+a).join("\n")}`,
    `Source: https://radar.cloudflare.com/zero-wire/${doc.slug}`].filter(Boolean).join("\n\n");
}

export function mountWorkspace(transport,{demo=false}={}){
  const root=document.getElementById("workspace");
  root.innerHTML=`<div class="intro"><div><p class="eyebrow">Vulnerability triage</p><h1>Assessment workspace</h1><p>Read the advisory. Check your inventory. Hand off what needs verification.</p></div><div class="toolbar" id="controls"></div></div>
  <div class="metrics" id="metrics" aria-label="Workspace status"></div><div class="notice" id="notice" role="status" hidden></div>
  <div class="workspace-grid"><aside class="inbox" aria-label="Advisory inbox"><div class="inbox-head"><h2>Advisories</h2><label class="sr" for="find-advisory">Search advisories</label><input id="find-advisory" type="search" placeholder="Search title or CVE"><label class="sr" for="filter-state">Filter advisories</label><select id="filter-state"><option value="all">All statuses</option><option value="none">Not assessed</option><option value="active">In progress</option><option value="complete">Report ready</option><option value="attention">Failed or stopped</option></select></div><div id="advisories"></div></aside>
  <div id="desk" class="desk"><section class="panel"><p>Loading advisories…</p></section></div></div>
  <footer><span>Read-only checks · UTC timestamps</span><a href="https://radar.cloudflare.com/zero-wire">Cloudflare Radar ↗</a></footer>`;
  const $=id=>document.getElementById(id);
  let view, current, runId, generation=0, overviewRequest=0, timer, busy=false, lastState, lastAlert, tab="handoff", followLatest=true, renderedKey;
  const alert=(text,tone="")=>{
    if(lastAlert===text && $("notice").dataset.tone===tone)return;
    lastAlert=text;$("notice").textContent=text;$("notice").dataset.tone=tone;$("notice").hidden=!text;
  };
  const refreshBtn=button("Refresh",()=>change(async()=>{await refresh();alert("Workspace refreshed.");}));
  const mainBtn=button(demo?"Reset demo":"Sync feed",()=>change(async()=>{
    if(demo){await transport.reset();current=null;runId=null;lastState=null;followLatest=true;tab="handoff";await refresh();alert("Demo reset.");}
    else {const sync=await transport.sync();await refresh();alert(sync.first?`${sync.count} briefings cataloged. Choose one to assess.`:sync.queued?`${sync.queued} new or revised briefings queued.`:"Feed checked. No new revisions to assess.");}
  }));
  $("controls").append(refreshBtn,mainBtn);
  mainBtn.hidden=!demo;
  async function change(fn,b){
    if(busy)return;
    busy=true;if(b)b.disabled=true;
    alert("");
    try{await fn();}catch(err){alert(err.message,"error");}
    finally{busy=false;if(b)b.disabled=false;poll();}
  }
  function metrics(){
    const attempts=view.lastAttempt;
    const totals=view.counts ?? {};
    const running=Object.entries(totals).filter(([s])=>active(s)).reduce((n,[,count])=>n+count,0);
    const stale=view.sync && Date.now()-parseUtc(view.sync)>35*60*1000;
    const feed=demo?"Demo snapshot":attempts?.status==="error"?(attempts.stage==="dispatch"?"Dispatch failed":"Feed check failed"):stale?"Feed is stale":view.sync?"Feed checked":"Not synced";
    $("metrics").replaceChildren(...[
      ["Radar feed",feed,demo?"Public advisory snapshot":view.sync?`Last successful sync: ${utc(view.sync)}`:"Run a sync to load advisories."],
      ["In progress",String(running),"Queued, reading inventory or drafting"],
      ["Reports ready",String(totals.complete ?? 0),"Completed runs, not a safety verdict"]
    ].map(([label,value,sub])=>wrap("metric",node("span",label),node("strong",value),node("small",sub))));
    mainBtn.hidden=!view.admin && !demo;
  }
  function inbox(){
    const q=$("find-advisory").value.trim().toLowerCase(), filter=$("filter-state").value;
    const matched=view.briefings.filter(b=>[b.title,...b.cves].join(" ").toLowerCase().includes(q) &&
      (filter==="all"||filter==="none"&&!b.state||filter==="active"&&active(b.state)||filter==="complete"&&b.state==="complete"||filter==="attention"&&["failed","stopped"].includes(b.state)));
    const focus=document.activeElement.dataset?.slug;
    $("advisories").replaceChildren(...matched.map(b=>{
      const a=button("",()=>void change(async()=>{current=b.slug;runId=null;followLatest=true;tab="handoff";lastState=null;inbox();await refreshDesk(true);}),"advisory");
      a.dataset.slug=b.slug;
      if(b.slug===current)a.setAttribute("aria-current","true");
      a.append(node("strong",b.title),wrap("advisory-meta",node("small",b.cves[0] || "Radar briefing"),badge(b.state)));
      return a;
    }));
    if(!matched.length)$("advisories").append(node("p",view.briefings.length?"No matching advisories.":"No advisories yet.","empty"));
    if(focus)Array.from($("advisories").children).find(x=>x.dataset.slug===focus)?.focus({preventScroll:true});
  }
  function timeline(detail){
    const stages=node("ol","","stages");
    const currentStage=stateStage[detail.state]??Math.max(0,...detail.logs.map(e=>rank[e.note]??0));
    for(const [i,[name,description]] of stageNames.entries()){
      const item=node("li");
      const step=detail.state==="complete"||i<currentStage?"done":i===currentStage?(terminal.has(detail.state)?"ended":"current"):"later";
      item.dataset.step=step;
      if(step==="current")item.setAttribute("aria-current","step");
      item.append(node("span",step==="done"?"✓":String(i+1),"step-no"),wrap("",node("strong",name),node("small",description)));
      stages.append(item);
    }
    return stages;
  }
  function handoff(doc,detail){
    const e=detail?.evidence ?? detail?.report?.evidence;
    const ready=detail?.report;
    const decision=ready?.exposure ?? (detail ? "Exposure not determined" : "Not assessed");
    const status=ready?(detail.briefing.revision!==doc.revision?"This report used an older revision. Start a new assessment before relying on it.":"A completed run is not proof that an origin is safe."):
      detail?.state==="failed"?"No report was saved. Check Activity for the failing stage.":detail?.state==="stopped"?"The run was stopped. Any inventory already captured remains available.":detail?"Follow the run stages below. The workspace updates automatically.":"Start a read-only assessment to collect account evidence.";
    const card=section("Exposure decision",node("strong",decision,"decision"),node("p",status));
    card.classList.add("decision-card");
    if(!detail)return [card,section("Radar’s recommended steps",doc.actions?.length?list("ol",doc.actions):node("p","Open Radar for guidance."),advisoryLink(doc))];
    if(!ready && !terminal.has(detail.state))return [card,...(e?[section("Evidence captured",node("p",`${e.zones.length} zones listed · ${e.workers?.length ?? "No"} Worker names available. See Evidence for details.`))]:[])];
    const source=detail.briefing;
    const actions=section("Owner handoff",...recommendations(source,e).map(([owner,text])=>wrap("handoff-row",node("strong",owner),node("p",text))));
    actions.append(button("Copy handoff",()=>void change(async()=>{await navigator.clipboard.writeText(reportText(source,detail));alert("Handoff copied.");}),"quiet"));
    return [card,actions,...(ready?.note?[section("Agent guidance",node("p",demo?"Example output · No model was called.":"Workers AI draft · Verify against the evidence and vendor advisory.","muted"),node("p",ready.note,"agent-note"))]:[]),
      section("Radar’s recommended steps",source.actions?.length?list("ol",source.actions):node("p","Open Radar for guidance."),advisoryLink(source))];
  }
  function evidence(detail){
    const e=detail?.evidence ?? detail?.report?.evidence;
    if(!e)return [section("No inventory snapshot",node("p",detail?"This run has not saved inventory. Check Activity for progress.":"Start an assessment to see the inventory it actually read."))];
    return [section("Observed configuration",node("p",`Snapshot · ${utc(e.observed)}`,"muted"),
      e.zones?.length?table(["Zone","Managed entries","Cloudflare Managed Ruleset"],e.zones.map(z=>[z.zone,z.managedExecutions===null?"Not verified":String(z.managedExecutions),z.cloudflareManagedEntry===null?"Not verified":z.cloudflareManagedEntry?"Entry present":"No enabled entry observed"])):node("p","No zones in this snapshot."),
      node("p","These are configuration observations, not effective rule actions or proof of patching.","muted")),
      section("Worker inventory",node("p",e.workers===null?"Worker inventory unavailable.":`${e.workers.length} names captured. Code and dependencies were not checked.`),...(e.workers?.length?[(()=>{const d=node("details");d.append(node("summary","Show Worker names"),list("ul",e.workers));return d;})()]:[])),
      section("Coverage gaps",e.gaps?.length?list("ul",e.gaps):node("p","No additional gaps recorded. Origin exposure is not inferred.")),
      ...(e.ownerEvidence?.length?[section("Owner-supplied VEX",table(["CVE","Component","Version","State","As of"],e.ownerEvidence.map(r=>[r.cve,r.asset,r.version,r.state,r.asOf])))]:[])];
  }
  function activity(detail){
    if(!detail)return [section("No run history",node("p","Choose Assess to start the first run."))];
    const log=node("ol","","event-log");
    const translations={Queued:"Run requested",queued:"Workflow queued",collecting:"Inventory read started",assessing:"Guidance draft started",complete:"Report saved",failed:"Run failed",stopped:"Run stopped"};
    for(const e of detail.logs){const item=node("li");item.append(node("time",utc(e.ts)),node("span",translations[e.note] ?? e.note));log.append(item);}
    return [section("Event log",log),section("Run reference",node("p",`${started(runId)} run · ${runId}`,"identifier"),
      node("p",`Advisory revision: ${detail.briefing.revision?.slice(0,12) ?? "—"}`,"muted"))];
  }
  function render(doc,runs,detail,focus){
    const old=document.activeElement.dataset?.deskFocus;
    const select=node("select");select.setAttribute("aria-label","Run history");select.dataset.deskFocus="run";
    select.append(new Option(runs.length?"Select a run":"No runs yet",""));
    for(const [i,r] of runs.entries())select.append(new Option(`${i===0?"Latest · ":""}${stateLabel(r.state)} · ${started(r.id)} · ${utc(r.created)}`,r.id));
    select.value=runId??"";select.onchange=()=>{if(select.value)void change(async()=>{runId=select.value;followLatest=runId===runs[0]?.id;lastState=null;await refreshDesk();});};
    const action=wrap("toolbar");
    if(view.admin){
      if(detail && active(detail.state)){
        const stop=button("Stop run",e=>void change(async()=>{await transport.stop(runId);await refresh();alert("Stop requested. See Activity for the outcome.");},e.currentTarget),"danger");stop.dataset.deskFocus="action";action.append(stop);
      }else{
        const assess=button(runs.length?"Run again":demo?"Simulate assessment":"Assess",e=>void change(async()=>{const r=await transport.assess(doc.slug);runId=r.id;followLatest=true;lastState=null;await refresh();alert(demo?"Simulated run queued.":"Assessment queued.");},e.currentTarget),"primary");
        assess.dataset.deskFocus="action";action.append(assess);
      }
    }
    action.append(advisoryLink(doc));
    const h=node("h2",doc.title);h.tabIndex=-1;
    const head=section("");head.replaceChildren(wrap("briefing-head",wrap("",node("p","Selected advisory","eyebrow"),h),action),
      node("p",doc.summary || "Read the source on Radar for technical details.","summary"),
      wrap("metadata",...doc.cves.map(c=>node("span",c,"cve")),node("span",doc.reviewed?`Reviewed ${doc.reviewed}`:"Review date unavailable","muted")));
    const parts=[head];
    if(runs.length || detail){
      const bar=wrap("heading",wrap("",node("p","Assessment run","eyebrow"),badge(detail?.state)),select);
      const panel=section("");panel.replaceChildren(bar);
      if(detail){
        const since=detail.created?` · Started ${utc(detail.created)}`:"";
        const duration=detail.created && terminal.has(detail.state) && detail.logs.length?` · ${elapsed(detail.created,detail.logs.at(-1).ts)}s elapsed`:"";
        panel.append(node("p",`${started(runId)}${since}${duration}`,"muted"),timeline(detail));
        if(detail.briefing.revision!==doc.revision)panel.append(node("p","This run used an older advisory revision.","inline-warning"));
      }
      parts.push(panel);
    }
    const tabs=wrap("views");tabs.setAttribute("aria-label","Report views");
    for(const [key,label] of [["handoff","Decision & handoff"],["evidence","Evidence"],["activity","Activity"]]){
      const b=button(label,()=>{tab=key;render(doc,runs,detail,false);},"view-button");
      b.dataset.deskFocus=key;b.setAttribute("aria-pressed",String(tab===key));tabs.append(b);
    }
    parts.push(tabs,...(tab==="evidence"?evidence(detail):tab==="activity"?activity(detail):handoff(doc,detail)));
    $("desk").replaceChildren(...parts);
    if(focus){h.focus({preventScroll:true});if(matchMedia("(max-width: 820px)").matches)h.scrollIntoView({block:"start"});}
    else if(old)Array.from($("desk").querySelectorAll("[data-desk-focus]")).find(x=>x.dataset.deskFocus===old)?.focus({preventScroll:true});
  }
  async function refreshDesk(focus=false){
    const seq=++generation;
    if(!current){$("desk").replaceChildren(section("No advisory selected",node("p","Sync the feed to populate the advisory inbox.")));return;}
    const {briefing,runs}=await transport.briefing(current);
    if(seq!==generation)return;
    if(followLatest || !runId || !runs.some(r=>r.id===runId))runId=runs[0]?.id;
    const detail=runId?await transport.run(runId):null;
    if(seq!==generation)return;
    if(lastState && detail && lastState!==detail.state)alert(stateLabel(detail.state)+".");
    lastState=detail?.state;
    const key=JSON.stringify([briefing.revision,runs,runId,detail?.state,detail?.logs.length,view.admin,tab]);
    if(key!==renderedKey || focus){render(briefing,runs,detail,focus);renderedKey=key;}
  }
  async function refresh(){
    const seq=++overviewRequest, data=await transport.overview();
    if(seq!==overviewRequest)return;
    const inboxChanged=JSON.stringify(view?.briefings)!==JSON.stringify(data.briefings);
    view=data;
    current??=view.briefings[0]?.slug;
    metrics();if(inboxChanged)inbox();await refreshDesk();
  }
  for(const [id,event] of [["find-advisory","input"],["filter-state","change"]])$(id).addEventListener(event,()=>{if(view)inbox();});
  function poll(){
    clearTimeout(timer);timer=setTimeout(async()=>{
      try{if(!document.hidden && !busy)await refresh();}
      catch(err){alert(err.message,"error");}
      finally{poll();}
    }, active(lastState)?(demo?900:2500):15000);
  }
  const ready=refresh().catch(err=>{alert(err.message,"error");$("desk").replaceChildren(section("Workspace unavailable",node("p","Use Refresh to try again.")));}).finally(poll);
  return ready;
}
if(document.body.dataset.mode==="live")void mountWorkspace({
  overview:()=>api("/api/overview"),briefing:slug=>api("/api/briefings/"+encodeURIComponent(slug)),
  run:id=>api("/api/runs/"+encodeURIComponent(id)),assess:slug=>api("/api/assess/"+encodeURIComponent(slug),true),
  stop:id=>api("/api/stop/"+encodeURIComponent(id),true),sync:()=>api("/api/sync",true)
});
