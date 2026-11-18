const fields=["revision","version","status","owner","due","note"];
const maxBytes=8192;

export function validateTriage(value) {
  if(!value || typeof value!=="object" || Array.isArray(value) ||
    Object.keys(value).length!==fields.length || !fields.every(k=>Object.hasOwn(value,k))) return null;
  const {revision,version,status,owner,due,note}=value;
  if(typeof revision!=="string" || !/^[a-f0-9]{64}$/.test(revision) ||
    !Number.isSafeInteger(version) || version<0 || !["open","in-review","closed"].includes(status))return null;
  if(typeof owner!=="string" || owner.length>120 || /[\u0000-\u001f\u007f]/.test(owner) ||
    typeof note!=="string" || note.length>1200 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(note))return null;
  if(typeof due!=="string" || (due && (!/^[1-9]\d{3}-\d\d-\d\d$/.test(due) ||
    !Number.isFinite(Date.parse(due)) || new Date(due).toISOString().slice(0,10)!==due)))return null;
  if(status==="closed" && (!owner.trim() || !note.trim()))return null;
  return {revision,version,status,owner:owner.trim(),due,note:note.trim()};
}

export async function readTriage(req) {
  if(req.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json")return {status:415};
  if(!req.body)return {status:400};
  if(Number(req.headers.get("content-length"))>maxBytes)return {status:413};
  const reader=req.body.getReader(), decoder=new TextDecoder("utf-8",{fatal:true});
  let size=0,text="";
  try{
    for(;;){
      const {done,value}=await reader.read();
      if(done)break;
      if((size+=value.byteLength)>maxBytes){await reader.cancel();return {status:413};}
      text+=decoder.decode(value,{stream:true});
    }
    const value=validateTriage(JSON.parse(text+decoder.decode()));
    return value?{value}:{status:400};
  }catch{
    await reader.cancel().catch(()=>{});
    return {status:400};
  }
}
