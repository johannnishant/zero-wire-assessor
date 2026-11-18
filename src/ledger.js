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
      CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT);`);
  }
  ingest(docs) {
    this.ctx.storage.transactionSync(()=>{
      const first=!this.db.exec("SELECT 1 FROM meta WHERE k='sync'").toArray().length;
      for (const d of docs) {
        const seen=this.db.exec("SELECT 1 FROM docs WHERE rev=?",d.revision).toArray().length;
        this.db.exec("INSERT OR IGNORE INTO docs VALUES(?,?,?,?)",d.revision,d.slug,d.title,JSON.stringify(d));
        this.db.exec("INSERT OR REPLACE INTO catalog VALUES(?,?)",d.slug,d.revision);
        if (!first && !seen) this.newRun(d.revision,`auto-${d.revision}`);
      }
      this.db.exec("INSERT OR REPLACE INTO meta VALUES('sync',CURRENT_TIMESTAMP)");
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
  mark(id,state,result=null) {
    const guard=state==="queued" ? "AND state='pending'" : "AND state NOT IN ('stopped','complete','failed')";
    const rows=this.db.exec(`UPDATE runs SET state=?,result=? WHERE id=? ${guard} RETURNING id`,state,result && JSON.stringify(result),id).toArray();
    if (rows.length) this.log(id,state);
    return !!rows.length;
  }
  state(id){return this.db.exec("SELECT state FROM runs WHERE id=?",id).toArray()[0]?.state;}
  overview(offset=0) {
    return {sync:this.db.exec("SELECT v FROM meta WHERE k='sync'").toArray()[0]?.v,
      briefings:this.db.exec("SELECT d.slug,d.title,json_extract(d.doc,'$.reviewed') reviewed FROM docs d JOIN catalog c ON c.rev=d.rev ORDER BY reviewed DESC,title").toArray(),
      runs:this.db.exec("SELECT id,title,created,state FROM runs JOIN docs ON runs.rev=docs.rev ORDER BY created DESC,runs.rowid DESC LIMIT 30 OFFSET ?",offset).toArray()};
  }
  detail(id) {
    const r=this.db.exec("SELECT state,result FROM runs WHERE id=?",id).toArray()[0];
    return r && {state:r.state,briefing:this.doc(id),report:JSON.parse(r.result),logs:this.db.exec("SELECT ts,note FROM events WHERE id=? ORDER BY n",id).toArray()};
  }
}
