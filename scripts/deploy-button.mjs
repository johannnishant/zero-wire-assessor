// Stamp the README after choosing the public origin. No API token required.
import {readFileSync,writeFileSync} from "node:fs";
const url=new URL(process.argv[2] ?? "invalid");
if(!["github.com","gitlab.com"].includes(url.host)||url.protocol!=="https:"||url.username||url.password||url.search||url.hash||!/^\/[\w.-]+(?:\/[\w.-]+)+$/.test(url.pathname))throw Error("Expected a public HTTPS GitHub or GitLab repository URL");
const badge=`[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=${url.href})`;
const path=new URL("../README.md",import.meta.url);
writeFileSync(path,readFileSync(path,"utf8").replace(/<!-- badge -->[\s\S]*?<!-- end badge -->/,`<!-- badge -->\n${badge}\n<!-- end badge -->`));
