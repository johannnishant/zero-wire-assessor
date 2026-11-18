import {createRemoteJWKSet, jwtVerify} from "jose";
let cached;
export async function identity(req, env, verify = jwtVerify) {
  const team = env.ACCESS_TEAM, aud = env.ACCESS_AUD;
  const token = req.headers.get("cf-access-jwt-assertion");
  if (!token || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(team || "") || !aud) return null;
  const issuer = `https://${team}.cloudflareaccess.com`;
  if (cached?.issuer !== issuer) cached = {issuer, key:createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`))};
  try {
    const {payload} = await verify(token,cached.key,{issuer,audience:aud,algorithms:["RS256"],requiredClaims:["exp","sub"]});
    if (typeof payload.email !== "string" || !payload.email.trim()) return null;
    const email=payload.email.toLowerCase();
    return {admin:(env.ADMIN_EMAILS || "").toLowerCase().split(",").map(x=>x.trim()).includes(email)};
  } catch {return null;}
}
