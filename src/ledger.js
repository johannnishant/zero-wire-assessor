import { DurableObject } from "cloudflare:workers";
export class Ledger extends DurableObject {
  constructor(ctx,env) {
    super(ctx,env);
    this.db=ctx.storage.sql;
    this.db.exec(`CREATE TABLE IF NOT EXISTS docs(rev TEXT PRIMARY KEY,slug TEXT NOT NULL,title TEXT NOT NULL,doc TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS catalog(slug TEXT PRIMARY KEY,rev TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, rev TEXT NOT NULL, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      state TEXT NOT NULL DEFAULT 'pending', result TEXT);
      CREATE TABLE IF NOT EXISTS events(n INTEGER PRIMARY KEY,id TEXT NOT NULL,note TEXT NOT NULL,ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
      CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT);
      CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY, evidence TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS docs_slug ON docs(slug);
      CREATE INDEX IF NOT EXISTS runs_rev ON runs(rev);
      CREATE INDEX IF NOT EXISTS events_run ON events(id,n);`);
  }
  ingest(docs) {
    return this.ctx.storage.transactionSync(()=>{
      const first=!this.db.exec("SELECT 1 FROM meta WHERE k='sync'").toArray().length;
      let queued=0;
      for (const d of docs) {
        const seen=this.db.exec("SELECT 1 FROM docs WHERE rev=?",d.revision).toArray().length;
        this.db.exec("INSERT OR IGNORE INTO docs VALUES(?,?,?,?)",d.revision,d.slug,d.title,JSON.stringify(d));
        this.db.exec("INSERT OR REPLACE INTO catalog VALUES(?,?)",d.slug,d.revision);
        if (!first && !seen) { this.newRun(d.revision,`auto-${d.revision}`); queued++; }
      }
      this.db.exec("INSERT OR REPLACE INTO meta VALUES('sync',CURRENT_TIMESTAMP)");
      return {first,queued,count:docs.length};
    });
  }
  newRun(rev,id) {
    this.db.exec("INSERT OR IGNORE INTO runs(id,rev) VALUES(?,?)",id,rev);
    this.log(id,"Queued");
    return id;
  }
  manual(slug) {
    const doc=this.db.exec("SELECT rev FROM catalog WHERE slug=?",slug).toArray()[0];
    return doc ? this.newRun(doc.rev,crypto.randomUUID()) : null;
  }
  pending(){return this.db.exec("SELECT id FROM runs WHERE state='pending' ORDER BY created LIMIT 10").toArray();}
  doc(id){return JSON.parse(this.db.exec("SELECT d.doc FROM runs r JOIN docs d ON r.rev=d.rev WHERE r.id=?",id).one().doc);}
  log(id,note){this.db.exec("INSERT INTO events(id,note) VALUES(?,?)",id,note);}
  saveEvidence(id,evidence){
    if(this.state(id)!=="collecting")return false;
    this.db.exec("INSERT OR REPLACE INTO snapshots VALUES(?,?)",id,JSON.stringify(evidence));
    this.log(id,"Inventory snapshot saved");
    return true;
  }
  recordSync(status,source,info){
    this.db.exec("INSERT OR REPLACE INTO meta VALUES('lastAttempt',?)",JSON.stringify({status,source,at:new Date().toISOString(),...info}));
  }
  mark(id,state,result=null) {
    const guard=state==="queued" ? "AND state='pending'" : "AND state NOT IN ('stopped','complete','failed')";
    const rows=this.db.exec(`UPDATE runs SET state=?,result=? WHERE id=? ${guard} RETURNING id`,state,result && JSON.stringify(result),id).toArray();
    if (rows.length) this.log(id,state);
    return !!rows.length;
  }
  state(id){return this.db.exec("SELECT state FROM runs WHERE id=?",id).toArray()[0]?.state;}
  overview(offset=0) {
    return {sync:this.db.exec("SELECT v FROM meta WHERE k='sync'").toArray()[0]?.v,
      lastAttempt:JSON.parse(this.db.exec("SELECT v FROM meta WHERE k='lastAttempt'").toArray()[0]?.v ?? "null"),
      counts:Object.fromEntries(this.db.exec("SELECT state,count(*) n FROM runs GROUP BY state").toArray().map(r=>[r.state,r.n])),
      briefings:this.db.exec(`SELECT d.slug,d.title,d.rev revision,json_extract(d.doc,'$.reviewed') reviewed,
        json_extract(d.doc,'$.cves') cves,
        (SELECT r.state FROM runs r WHERE r.rev=d.rev ORDER BY r.created DESC,r.rowid DESC LIMIT 1) state
        FROM docs d JOIN catalog c ON c.rev=d.rev ORDER BY reviewed DESC,title`).toArray().map(r=>({...r,cves:JSON.parse(r.cves ?? "[]")})),
      runs:this.db.exec("SELECT id,title,slug,runs.rev revision,created,state FROM runs JOIN docs ON runs.rev=docs.rev ORDER BY created DESC,runs.rowid DESC LIMIT 30 OFFSET ?",offset).toArray()};
  }
  briefing(slug){
    const row=this.db.exec("SELECT doc FROM docs JOIN catalog USING(rev) WHERE catalog.slug=?",slug).toArray()[0];
    if(!row)return null;
    return {briefing:JSON.parse(row.doc), runs:this.db.exec(`SELECT id,runs.rev revision,created,state FROM runs JOIN docs ON runs.rev=docs.rev
      WHERE docs.slug=? ORDER BY created DESC,runs.rowid DESC LIMIT 15`,slug).toArray()};
  }
  detail(id) {
    const r=this.db.exec("SELECT state,result,created FROM runs WHERE id=?",id).toArray()[0];
    if(!r)return null;
    const report=JSON.parse(r.result);
    return {state:r.state,created:r.created,briefing:this.doc(id),report,evidence:report?.evidence ?? JSON.parse(this.db.exec("SELECT evidence FROM snapshots WHERE id=?",id).toArray()[0]?.evidence ?? "null"),logs:this.db.exec("SELECT ts,note FROM events WHERE id=? ORDER BY n",id).toArray()};
  }
}
