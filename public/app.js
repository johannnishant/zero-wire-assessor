const node=(tag,text="",cls="")=>Object.assign(document.createElement(tag),{textContent:text,className:cls});
const button=(text,fn,cls="")=>Object.assign(node("button",text,cls),{type:"button",onclick:fn});
const link=(text,url)=>Object.assign(node("a",text),{href:url});
const wrap=(cls,...children)=>{const el=node("div","",cls);el.append(...children);return el;};
const list=(tag,items)=>{const el=node(tag);el.append(...items.map(x=>node("li",x)));return el;};
const section=(title,...contents)=>{const el=node("section","","panel");el.append(node("h3",title),...contents);return el;};
function disclosure(key,title,meta,...contents){
  const row=node("details","","disclosure");row.dataset.detail=key;
  const label=node("summary");label.dataset.deskFocus=`detail-${key}`;
  label.append(node("span",title),...(meta?[node("small",meta)]:[]));
  row.append(label,wrap("detail-body",...contents));return row;
}
const terminal=new Set(["complete","failed","stopped"]);
const active=s=>Boolean(s && !terminal.has(s));
const stateLabels={pending:"Waiting to queue",queued:"Queued",collecting:"Reading inventory",assessing:"Drafting guidance",complete:"Report ready",failed:"Failed",stopped:"Stopped"};
const stateLabel=s=>stateLabels[s] ?? "Not assessed";
const badge=state=>{const b=node("span",stateLabel(state),"badge");b.dataset.state=state ?? "none";return b;};
const utc=t=>t ? `${t.replace("T"," ").replace(/\.\d+Z$|Z$/,"").slice(0,19)} UTC` : "—";
const started=id=>id?.startsWith("auto-")?"Scheduled":"Manual";
const parseUtc=s=>Date.parse(s.includes("T")?s:s.replace(" ","T")+"Z");
const elapsed=(a,b)=>Math.max(0,Math.round((parseUtc(b)-parseUtc(a))/1000));
const stageNames=["Queue","Inventory","Guidance","Report"];
const stateStage={pending:0,queued:0,collecting:1,assessing:2,complete:3};
const rank={collecting:1,assessing:2,complete:3};
const triageLabels={open:"Open","in-review":"In review",closed:"Closed"};
const coverageLabels={available:"Scoped reads succeeded",partial:"Partial inventory",unavailable:"Inventory unavailable"};
const today=()=>new Date().toISOString().slice(0,10);
const overdue=(status,due,date=today())=>status!=="closed"&&!!due&&due<date;

async function api(path,post=false,payload){
  const options=post?{method:"POST",headers:{"x-console-action":"1"}}:{};
  if(payload){options.headers["content-type"]="application/json";options.body=JSON.stringify(payload);}
  const response=await fetch(path,options);
  const data=await response.json().catch(()=>null);
  if(response.redirected || response.status===401 || (response.ok && !data))throw Error("Session expired. Reload to sign in again.");
  if(!response.ok)throw Object.assign(Error(data?.error || `Request failed (${response.status}).`),{status:response.status});
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
  if(evidence?.ownerEvidence?.some(x=>x.state==="exploitable"))result.push(["Service owner","Find deployments of the affected VEX component. Apply the vendor fix and verify the running version."]);
  else result.push(["Service owner",doc.cves?.length?"Verify the deployed version or configuration against the vendor advisory.":"Confirm you use the affected product, then check its configuration against the advisory."]);
  if(evidence?.zones?.some(z=>z.managedExecutions!==null))result.push(["Edge security","Before relying on WAF, verify hostname scope and the effective rule action."]);
  if(evidence && (["partial","unavailable"].includes(evidence.coverage) || evidence.workers===null || !evidence.zones?.length || evidence.gaps?.some(g=>/unavailable|truncated/i.test(g))))result.push(["Cloudflare administrator","Check token scope and fill the inventory gaps."]);
  return result;
}
function reportText(doc,detail,id,triage){
  const e=detail.evidence ?? detail.report?.evidence;
  return [doc.title,doc.cves?.join(", "),`Exposure: ${detail.report?.exposure ?? "Not determined"}`,
    `Run: ${stateLabel(detail.state)} · ${id}`,`Advisory revision: ${doc.revision}`,
    triage?.revision===doc.revision&&`Triage: ${triageLabels[triage.status]} · ${triage.owner || "Unassigned"}${triage.due?` · Due ${triage.due} UTC`:""}`,
    e?.observed&&`Inventory captured: ${utc(e.observed)}`,
    e&&`Observed: ${e.zones.length} zones listed; ${e.workers?.length ?? "unavailable"} Worker names.`,
    e?.gaps?.length&&`Coverage gaps:\n${e.gaps.map(g=>"- "+g).join("\n")}`,
    `Owner handoff:\n${recommendations(doc,e).map(([owner,text])=>`- ${owner}: ${text}`).join("\n")}`,
    doc.actions?.length&&`Radar recommendations:\n${doc.actions.map(a=>"- "+a).join("\n")}`,
    `Source: https://radar.cloudflare.com/zero-wire/${doc.slug}`].filter(Boolean).join("\n\n");
}

export function mountWorkspace(transport,{demo=false}={}){
  const root=document.getElementById("workspace");
  root.innerHTML=`<div class="intro"><h1>Assessments</h1><div class="toolbar" id="controls"></div></div>
  <div class="metrics" id="metrics" aria-label="Workspace status"></div><div class="notice" id="notice" role="status" hidden></div>
  <div class="workspace-grid"><aside class="inbox" aria-label="Advisory inbox"><div class="inbox-head"><h2>Advisories</h2><label class="sr" for="find-advisory">Search advisories</label><input id="find-advisory" type="search" placeholder="Search title, CVE or owner"><label class="sr" for="filter-state">Filter advisories</label><select id="filter-state"><option value="all">All advisories</option><optgroup label="Triage"><option value="follow-up">Open follow-up</option><option value="overdue">Overdue follow-up</option><option value="revised">Needs revision review</option><option value="closed">Closed triage</option></optgroup><optgroup label="Run status"><option value="none">Not assessed</option><option value="active">In progress</option><option value="complete">Report ready</option><option value="attention">Failed or stopped</option></optgroup></select></div><div id="advisories"></div></aside>
  <div id="desk" class="desk"><section class="panel"><p>Loading advisories…</p></section></div></div>
  <dialog id="desk-dialog" aria-labelledby="desk-dialog-title"></dialog>
  <footer><span>Read-only checks · UTC timestamps</span><a href="https://radar.cloudflare.com/zero-wire">Cloudflare Radar ↗</a></footer>`;
  const $=id=>document.getElementById(id);
  let view, current, runId, generation=0, overviewRequest=0, timer, busy=false, lastState, lastAlert, tab="handoff", followLatest=true, renderedKey, inboxDate;
  const openDetails=new Map();
  const alert=(text,tone="")=>{
    if(lastAlert===text && $("notice").dataset.tone===tone)return;
    lastAlert=text;$("notice").textContent=text;$("notice").dataset.tone=tone;$("notice").hidden=!text;
  };
  const refreshBtn=button("Refresh",()=>change(async()=>{await refresh();alert("Workspace refreshed.");}));
  const mainBtn=button(demo?"Reset demo":"Sync feed",()=>change(async()=>{
    if(demo){
      await transport.reset();openDetails.clear();delete $("desk").dataset.detailScope;current=null;runId=null;lastState=null;
      followLatest=true;tab="handoff";renderedKey=null;
      $("find-advisory").value="";$("filter-state").value="all";
      for(const row of document.querySelectorAll(".sample details, #metrics details"))row.open=false;
      await refresh();alert("Demo reset.");
    }
    else {const sync=await transport.sync();await refresh();alert(sync.first?`${sync.count} briefings cataloged. Choose one to assess.`:sync.queued?`${sync.queued} new or revised briefings queued.`:"Feed checked. No new revisions to assess.");}
  }));
  const lock=el=>{el.dataset.workspaceLock="";el.disabled=busy;return el;};
  function setBusy(value){
    busy=value;
    for(const el of root.querySelectorAll("[data-workspace-lock]"))el.disabled=value;
  }
  lock(refreshBtn);lock(mainBtn);
  $("controls").append(refreshBtn,mainBtn);
  mainBtn.hidden=!demo;
  async function change(fn){
    if(busy)return;
    setBusy(true);
    alert("");
    try{await fn();}catch(err){alert(err.message,"error");}
    finally{setBusy(false);poll();}
  }
  function metrics(){
    const attempts=view.lastAttempt;
    const totals=view.counts ?? {};
    const running=Object.entries(totals).filter(([s])=>active(s)).reduce((n,[,count])=>n+count,0);
    const stale=view.sync && Date.now()-parseUtc(view.sync)>35*60*1000;
    const feed=demo?"Demo snapshot":attempts?.status==="error"?(attempts.stage==="dispatch"?"Dispatch failed":"Feed check failed"):stale?"Feed is stale":view.sync?"Feed checked":"Not synced";
    const feedStatus=disclosure("feed-details",feed,"",node("p",demo?"Public Radar snapshot.":view.sync?`Last successful sync: ${utc(view.sync)}`:"Sync the feed to load advisories."),
      ...(attempts?.status==="error"?[node("p",`Last check failed: ${utc(attempts.at)}`)]:[]));
    const previous=$("metrics").querySelector("details");feedStatus.open=Boolean(previous?.open);
    const feedFocused=previous?.contains(document.activeElement);
    $("metrics").replaceChildren(wrap("metric",node("span","Radar feed"),feedStatus),
      ...[["In progress",running],["Reports ready",totals.complete ?? 0]].map(([label,value])=>wrap("metric",node("span",label),node("strong",String(value)))));
    if(feedFocused)feedStatus.querySelector("summary").focus({preventScroll:true});
    mainBtn.hidden=!view.admin && !demo;
  }
  function inbox(){
    const q=$("find-advisory").value.trim().toLowerCase(), filter=$("filter-state").value;
    inboxDate=today();
    const matched=view.briefings.filter(b=>[b.title,...b.cves,b.triageOwner].join(" ").toLowerCase().includes(q) &&
      (filter==="all"||filter==="none"&&!b.state||filter==="active"&&active(b.state)||filter==="complete"&&b.state==="complete"||filter==="attention"&&["failed","stopped"].includes(b.state)||
       filter==="follow-up"&&b.triageStatus&&b.triageStatus!=="closed"||filter==="overdue"&&overdue(b.triageStatus,b.triageDue,inboxDate)||
       filter==="revised"&&b.triageRevision&&b.triageRevision!==b.revision||filter==="closed"&&b.triageStatus==="closed"&&b.triageRevision===b.revision));
    const focus=document.activeElement.dataset?.slug;
    $("advisories").replaceChildren(...matched.map(b=>{
      const a=button("",()=>void change(async()=>{current=b.slug;runId=null;followLatest=true;tab="handoff";lastState=null;inbox();await refreshDesk(true);}),"advisory");
      a.dataset.slug=b.slug;
      if(b.slug===current)a.setAttribute("aria-current","true");
      a.append(node("strong",b.title),wrap("advisory-meta",node("small",b.cves[0] || "Radar briefing"),badge(b.state)));
      if(b.triageStatus)a.append(node("small",b.triageRevision!==b.revision?"Review new revision":overdue(b.triageStatus,b.triageDue,inboxDate)?"Follow-up overdue":triageLabels[b.triageStatus],"muted"));
      return a;
    }));
    if(!matched.length){
      const empty=wrap("empty",node("p",view.briefings.length?"No matching advisories.":"No advisories yet."));
      if(view.briefings.length)empty.append(button("Clear filters",()=>{$("find-advisory").value="";$("filter-state").value="all";inbox();$("find-advisory").focus();}));
      $("advisories").append(empty);
    }
    if(focus)Array.from($("advisories").children).find(x=>x.dataset.slug===focus)?.focus({preventScroll:true});
  }
  function timeline(detail){
    const stages=node("ol","","stages");
    const currentStage=stateStage[detail.state]??Math.max(0,...detail.logs.map(e=>rank[e.note]??0));
    for(const [i,name] of stageNames.entries()){
      const item=node("li");
      const step=detail.state==="complete"||i<currentStage?"done":i===currentStage?(terminal.has(detail.state)?"ended":"current"):"later";
      item.dataset.step=step;
      if(step==="current")item.setAttribute("aria-current","step");
      item.append(node("span",step==="done"?"✓":String(i+1),"step-no"),node("strong",name));
      stages.append(item);
    }
    return stages;
  }
  function editTriage(doc,triage){
    const dialog=$("desk-dialog"), form=node("form","","triage-form");
    const revised=Boolean(triage && triage.revision!==doc.revision);
    const status=node("select");
    for(const [k,v] of Object.entries(triageLabels))status.append(new Option(v,k));
    status.value=revised?"in-review":triage?.status??"open";
    const owner=Object.assign(node("input"),{type:"text",maxLength:120,value:triage?.owner??""});
    const due=Object.assign(node("input"),{type:"date",min:"1000-01-01",max:"9999-12-31",value:triage?.due??""});
    const note=Object.assign(node("textarea"),{rows:4,maxLength:1200,value:revised?"":triage?.note??""});
    const field=(name,input)=>{const label=node("label",name);label.append(input);return label;};
    const error=node("p","","inline-warning");error.hidden=true;error.setAttribute("role","alert");
    const title=node("h3","Edit triage");title.id="desk-dialog-title";
    const cancel=button("Cancel",()=>dialog.close());
    const save=Object.assign(node("button","Save triage","primary"),{type:"submit"});
    const reload=button("Discard draft and reload",()=>void (async()=>{
      reload.disabled=true;
      try{
        const latest=await transport.briefing(doc.slug);
        if(!latest?.briefing)throw Error("Advisory is no longer available.");
        editTriage(latest.briefing,latest.triage);
      }catch(err){error.textContent=err.message;reload.disabled=false;}
    })());reload.hidden=true;
    form.append(title,node("p",doc.title,"muted"),
      ...(revised?[node("p","Radar revised this advisory. Record a new review before closing it.","inline-warning")]:[]),
      field("Status",status),field("Owner or team",owner),field("Due date (UTC)",due),field("Triage note",note),
      node("p","Closing requires an owner and a note. Don’t include credentials.","muted"),error,
      wrap("toolbar",save,cancel,reload));
    form.onsubmit=e=>{
      e.preventDefault();
      if(busy || save.disabled)return;
      if(status.value==="closed" && (!owner.value.trim() || !note.value.trim())){
        error.textContent="Closing requires an owner and a note.";error.hidden=false;return;
      }
      void (async()=>{
        setBusy(true);save.disabled=cancel.disabled=true;error.hidden=true;
        try{
          await transport.saveTriage(doc.slug,{revision:doc.revision,version:triage?.version??0,status:status.value,owner:owner.value,due:due.value,note:note.value});
          try{await refresh();alert("Triage saved.");}catch{alert("Triage saved. Use Refresh to update the workspace.","error");}
          dialog.close();
        }catch(err){
          error.textContent=err.message;error.hidden=false;
          if(err.status===409){reload.hidden=false;save.hidden=true;}
        }finally{
          setBusy(false);save.disabled=cancel.disabled=false;poll();
          if(!dialog.open)$("desk").querySelector('[data-desk-focus="edit-triage"]')?.focus({preventScroll:true});
        }
      })();
    };
    dialog.oncancel=e=>{if(save.disabled)e.preventDefault();};
    dialog.replaceChildren(form);
    if(!dialog.open)dialog.showModal();else status.focus();
  }
  function triagePanel(doc,triage,audit){
    const revised=Boolean(triage && triage.revision!==doc.revision);
    const late=!revised&&overdue(triage?.status,triage?.due);
    const summary=revised?"Review new revision":triage?`${triageLabels[triage.status]}${late?" · Overdue":""}`:"Unassigned";
    const details=[];
    if(triage){
      if(revised)details.push(node("p","Previous revision’s triage. Recheck the new advisory.","inline-warning"));
      details.push(node("p",`${triage.owner||"Unassigned"}${triage.due?` · Due ${triage.due} UTC`:""}`));
      if(triage.note)details.push(node("p",triage.note,"agent-note"));
    }else details.push(node("p","No owner or follow-up recorded.","muted"));
    if(view.admin){
      const edit=lock(button("Edit triage",()=>editTriage(doc,triage)));
      edit.dataset.deskFocus="edit-triage";details.push(wrap("triage-actions",edit));
    }
    return disclosure("triage","Team triage",summary,...details);
  }
  function triageAudit(audit){
    if(!audit?.length)return [];
    return [disclosure("triage-audit","Triage history",`${audit.length===20?"Latest ":""}${audit.length}`,table(
      ["Time","Changed by","Status","Owner","Due (UTC)","Revision","Note"],audit.map(r=>[utc(r.at),r.actor,triageLabels[r.status],r.owner||"—",r.due||"—",r.revision.slice(0,12),r.noteChanged?"Updated":"—"])))];
  }
  async function copyHandoff(text){
    try{await navigator.clipboard.writeText(text);alert("Handoff copied.");}
    catch{
      const dialog=$("desk-dialog");
      const title=node("h3","Copy handoff");title.id="desk-dialog-title";
      const textBox=Object.assign(node("textarea"),{value:text,readOnly:true,rows:8});
      textBox.setAttribute("aria-label","Handoff text");
      dialog.oncancel=null;
      dialog.replaceChildren(wrap("triage-form",title,node("p","Clipboard unavailable. Copy the selected text."),textBox,button("Close",()=>dialog.close())));
      dialog.showModal();textBox.focus();textBox.select();
      dialog.addEventListener("close",()=>$("desk").querySelector('[data-desk-focus="copy"]')?.focus({preventScroll:true}),{once:true});
    }
  }
  function handoff(doc,detail,triage){
    const e=detail?.evidence ?? detail?.report?.evidence;
    const ready=detail?.report;
    const decision=ready?.exposure ?? (detail ? "Exposure not determined" : "Not assessed");
    const status=ready?"Cloudflare inventory alone can’t establish origin exposure.":
      detail?.state==="failed"?"See Activity for the failure.":detail?.state==="stopped"?(e?"The saved snapshot is in Evidence.":"No inventory was saved."):detail?"This run updates automatically.":"Assess to collect read-only inventory.";
    const card=section("Exposure",node("strong",decision,"decision"),node("p",status));
    card.classList.add("decision-card");
    if(["partial","unavailable"].includes(e?.coverage))card.append(node("p",`${coverageLabels[e.coverage]}. See Evidence.`,"inline-warning"));
    const radar=source=>disclosure("radar","Radar recommendations",source.actions?.length?`${source.actions.length} steps`:"",source.actions?.length?list("ol",source.actions):node("p","See source for guidance."),advisoryLink(source));
    if(!detail)return [card,radar(doc)];
    if(!ready && !terminal.has(detail.state))return [card,...(e?[node("p","Inventory saved. See Evidence.","muted")]:[])];
    const source=detail.briefing;
    const [[owner,next],...other]=recommendations(source,e);
    const copy=lock(button("Copy handoff",()=>void change(()=>copyHandoff(reportText(source,detail,runId,triage)))));
    copy.dataset.deskFocus="copy";
    const actions=section("Next action");
    actions.replaceChildren(wrap("heading",node("h3","Next action"),copy),node("p",`${owner}: ${next}`));
    return [card,actions,...(other.length?[disclosure("additional","Other owner checks",`${other.length}`, ...other.map(([name,text])=>wrap("handoff-row",node("strong",name),node("p",text))))]:[]),
      ...(ready?.note?[disclosure("agent","Agent guidance",demo?"Example":"AI draft",node("p",demo?"Example output. No model was called.":"Verify against the evidence and vendor advisory.","muted"),node("p",ready.note,"agent-note"))]:[]),radar(source)];
  }
  function evidence(detail){
    const e=detail?.evidence ?? detail?.report?.evidence;
    if(!e)return [section("No inventory snapshot",node("p",detail?"Check run activity.":"Start an assessment to collect inventory."))];
    return [section("Inventory snapshot",...(e.coverage?[node("p",coverageLabels[e.coverage],e.coverage==="available"?"muted":"inline-warning")]:[]),
      node("p",`${e.zones.length} zones · ${e.workers===null?"Workers unavailable":`${e.workers.length} Workers`}`),
      node("p",`Captured ${utc(e.observed)}. Origin versions and effective WAF actions were not checked.`,"muted")),
      disclosure("gaps","Coverage gaps",String(e.gaps?.length ?? 0),e.gaps?.length?list("ul",e.gaps):node("p","No additional gaps recorded.")),
      disclosure("zones","Zone and WAF observations",String(e.zones.length),
        e.zones.length?table(["Zone","Managed entries","Cloudflare Managed Ruleset"],e.zones.map(z=>[z.zone,z.managedExecutions===null?"Not verified":String(z.managedExecutions),z.cloudflareManagedEntry===null?"Not verified":z.cloudflareManagedEntry?"Entry present":"No enabled entry observed"])):node("p","No zones in this snapshot.")),
      disclosure("workers","Worker inventory",e.workers===null?"Unavailable":String(e.workers.length),node("p",e.workers===null?"See coverage gaps.":"Names only. Code and dependencies were not checked."),...(e.workers?.length?[list("ul",e.workers)]:[])),
      ...(e.ownerEvidence?.length?[disclosure("vex","Owner-supplied VEX",String(e.ownerEvidence.length),table(["CVE","Component","Version","State","As of"],e.ownerEvidence.map(r=>[r.cve,r.asset,r.version,r.state,r.asOf])))]:[])];
  }
  function activity(detail){
    if(!detail)return [section("No run history",node("p","Choose Assess to start the first run."))];
    const log=node("ol","","event-log");
    const translations={Queued:"Run requested",queued:"Workflow queued",collecting:"Inventory read started",assessing:"Guidance draft started",complete:"Report saved",failed:"Run failed",stopped:"Run stopped"};
    for(const e of detail.logs){const item=node("li");item.append(node("time",utc(e.ts)),node("span",translations[e.note] ?? e.note));log.append(item);}
    const last=detail.logs.at(-1);
    const failure=detail.state==="failed"&&detail.logs.findLast(e=>e.note.startsWith("Failed during"));
    return [section("Latest activity",node("p",failure?.note??translations[last?.note]??last?.note??stateLabel(detail.state)),...(last?[node("p",utc(last.ts),"muted")]:[])),
      disclosure("events","Event log",`${detail.logs.length} events`,log),
      disclosure("reference","Run reference",started(runId),node("p",runId,"identifier"),node("p",`Advisory revision: ${detail.briefing.revision?.slice(0,12) ?? "—"}`,"muted"))];
  }
  function render(doc,runs,detail,focus,triage,audit){
    const old=document.activeElement.dataset?.deskFocus;
    const scope=`${doc.slug}/${runId??""}`;
    const desk=$("desk");
    const previous=openDetails.get(desk.dataset.detailScope);
    if(previous)for(const row of desk.querySelectorAll("details[data-detail]")){
      if(row.open)previous.add(row.dataset.detail);else previous.delete(row.dataset.detail);
    }
    if(!openDetails.has(scope) && openDetails.size>=80)openDetails.delete(openDetails.keys().next().value);
    const expanded=openDetails.get(scope)??new Set();
    openDetails.set(scope,expanded);
    const select=node("select");select.setAttribute("aria-label","Run history");select.dataset.deskFocus="run";
    select.append(new Option(runs.length?"Select a run":"No runs yet",""));
    for(const [i,r] of runs.entries())select.append(new Option(`${i===0?"Latest · ":""}${stateLabel(r.state)} · ${started(r.id)} · ${utc(r.created)}`,r.id));
    select.value=runId??"";select.onchange=()=>{if(select.value)void change(async()=>{runId=select.value;followLatest=runId===runs[0]?.id;lastState=null;await refreshDesk();});};
    lock(select);
    const action=wrap("toolbar");
    if(view.admin){
      if(detail && active(detail.state)){
        const stop=lock(button("Stop run",()=>void change(async()=>{await transport.stop(runId);await refresh();alert("Stop requested. See Activity for the outcome.");}),"danger"));stop.dataset.deskFocus="action";action.append(stop);
      }else{
        const assess=lock(button(runs.length?"Run again":demo?"Simulate assessment":"Assess",()=>void change(async()=>{const r=await transport.assess(doc.slug);runId=r.id;followLatest=!r.existing;lastState=null;await refresh();alert(r.dispatchDelayed?"Run saved. Dispatch delayed; the scheduler will retry.":r.existing?"Showing the existing run.":demo?"Simulated run queued.":"Assessment queued.");}),"primary"));
        assess.dataset.deskFocus="action";action.append(assess);
      }
    }
    const h=node("h2",doc.title);h.tabIndex=-1;
    const head=section("");head.replaceChildren(wrap("briefing-head",h,action),
      wrap("metadata",...doc.cves.map(c=>node("span",c,"cve"))),
      disclosure("advisory","Advisory details",doc.reviewed?`Reviewed ${doc.reviewed}`:"",node("p",doc.summary||"See Radar for details."),advisoryLink(doc)),
      triagePanel(doc,triage));
    const parts=[head];
    if(runs.length || detail){
      const bar=wrap("heading",wrap("toolbar",node("h3","Run"),badge(detail?.state)));
      const panel=section("");panel.replaceChildren(bar);
      if(detail){
        const since=detail.created?` · Started ${utc(detail.created)}`:"";
        const duration=detail.created && terminal.has(detail.state) && detail.logs.length?` · ${elapsed(detail.created,detail.logs.at(-1).ts)}s elapsed`:"";
        if(active(detail.state))panel.append(timeline(detail));
        panel.append(disclosure("progress","Run details",started(runId),node("p",`${started(runId)}${since}${duration}`,"muted"),...(!active(detail.state)?[timeline(detail)]:[])));
        if(detail.briefing.revision!==doc.revision)panel.append(node("p","This run used an older advisory revision.","inline-warning"));
      }
      if(runs.length>1)panel.append(disclosure("history","Run history",String(runs.length),select));
      parts.push(panel);
    }
    const tabs=wrap("views");tabs.setAttribute("aria-label","Report views");
    for(const [key,label] of [["handoff","Handoff"],["evidence","Evidence"],["activity","Activity"]]){
      const b=button(label,()=>{tab=key;render(doc,runs,detail,false,triage,audit);},"view-button");
      b.dataset.deskFocus=key;b.setAttribute("aria-pressed",String(tab===key));tabs.append(b);
    }
    parts.push(tabs,...(tab==="evidence"?evidence(detail):tab==="activity"?[...activity(detail),...triageAudit(audit)]:handoff(doc,detail,triage)));
    desk.replaceChildren(...parts);
    desk.dataset.detailScope=scope;
    for(const row of desk.querySelectorAll("details[data-detail]"))row.open=expanded.has(row.dataset.detail);
    if(focus){h.focus({preventScroll:true});if(matchMedia("(max-width: 820px)").matches)h.scrollIntoView({block:"start"});}
    else if(old)Array.from($("desk").querySelectorAll("[data-desk-focus]")).find(x=>x.dataset.deskFocus===old)?.focus({preventScroll:true});
  }
  async function refreshDesk(focus=false){
    const seq=++generation;
    if(!current){$("desk").replaceChildren(section("No advisory selected",node("p","Sync the feed to populate the advisory inbox.")));return;}
    const {briefing,runs,triage,audit}=await transport.briefing(current);
    if(seq!==generation)return;
    if(followLatest || !runId || !runs.some(r=>r.id===runId))runId=runs[0]?.id;
    const detail=runId?await transport.run(runId):null;
    if(seq!==generation)return;
    if(lastState && detail && lastState!==detail.state)alert(stateLabel(detail.state)+".");
    lastState=detail?.state;
    const key=JSON.stringify([briefing.revision,runs,runId,detail?.state,detail?.logs.length,triage?.version,view.admin,tab,today()]);
    if(key!==renderedKey || focus){render(briefing,runs,detail,focus,triage,audit);renderedKey=key;}
  }
  async function refresh(){
    const seq=++overviewRequest, data=await transport.overview();
    if(seq!==overviewRequest)return;
    const inboxChanged=JSON.stringify(view?.briefings)!==JSON.stringify(data.briefings);
    view=data;
    current??=view.briefings[0]?.slug;
    metrics();if(inboxChanged||inboxDate!==today())inbox();await refreshDesk();
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
  stop:id=>api("/api/stop/"+encodeURIComponent(id),true),sync:()=>api("/api/sync",true),
  saveTriage:(slug,change)=>api("/api/triage/"+encodeURIComponent(slug),true,change)
});
