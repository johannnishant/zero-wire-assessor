# Zero Wire Assessment Desk

A self-hosted Cloudflare Worker that turns [Radar Zero Wire](https://radar.cloudflare.com/zero-wire) briefings into read-only assessments of one Cloudflare account. Licensed under MIT. Independent project.

<!-- badge -->
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/johannnishant/zero-wire-assessor)
<!-- end badge -->

### How it works

Every 15 minutes the Worker reads the public JSON feed. The first sync builds a library without spending AI credits on the backlog. Each subsequent new or changed briefing queues a Workflow with a stable revision ID; unchanged polls do nothing. Administrators can also run any archived briefing against current inventory.

The Workflow snapshots visible zones, managed WAF entry points and Worker names, then calls a separate Cloudflare Agents SDK instance for that run. Workers AI receives the curated briefing, its assessment prompt when available, and the scoped observations. The dashboard shows the evidence, the model's interpretation, Radar's recommended actions, and a timestamped event log. Reference URLs are for human readers; the model cannot request URLs, run commands, change settings, or test origins.

**Interpreting a result:** a zone with a managed WAF entry point is a configuration observation. It does not prove that a specific rule blocks traffic or that a backend is patched. Missing permissions, unsupported resource types and absent origin versions remain unknown. Optional owner-provided CycloneDX VEX evidence can establish a reported affected component; it never clears the entire account.

### Install in your account

1. Use a Cloudflare account with Workers, Cron Triggers, SQLite Durable Objects, Workflows, Workers AI and Zero Trust Access available. Workflow execution, storage and inference are metered. Use the deploy button when published, or use Node 24 and the pinned Wrangler CLI:

   ```sh
   npm ci
   npx wrangler login
   npm run deploy
   ```

2. Protect the **entire dashboard hostname**, including all paths, with a [self-hosted Access application](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/). For a `workers.dev` deployment you can enable Access under the Worker's Domains & Routes. Allow only the intended readers via your identity provider. Do not add a Bypass policy. The Worker also verifies the JWT signature, expiry, issuer and application audience before serving any route or static asset. Until configured it responds `401`.

   If the deploy form requires values before you have an Access application, use `setup-pending` in the required fields, then replace them in step 3 before the first sync. If the Git integration reports expired authorization, use the Wrangler install above to deploy without changing an existing GitHub App installation.

3. Set the following Worker secrets via the deployment form, dashboard or `npx wrangler secret put NAME`:

   | Name | Value |
   |---|---|
   | `ACCESS_TEAM` | Team name only: `example` for `example.cloudflareaccess.com` |
   | `ACCESS_AUD` | Application Audience (AUD) tag of this specific Access application |
   | `ADMIN_EMAILS` | Comma-separated verified Access user emails permitted to sync, assess and stop. Other allowed users can read all reports. |
   | `INVENTORY_ACCOUNT_ID` | ID of the single account to inventory |
   | `INVENTORY_TOKEN` | Separate read-only API token scoped to that account and the intended zones. Grant Account → Workers Scripts → Read, Zone → Zone → Read, and Zone → Zone WAF → Read. Do not use a global key or deployment credentials. |

4. Sign in as an administrator, click **Sync feed**, then **Assess** an older briefing. Click **Refresh** and **Inspect** for status, evidence and events. **Stop** terminates a queued/running Workflow; an already-issued read or inference may finish. A manual re-run gets a new ID. Confirm a reader cannot trigger runs and anonymous requests cannot load `/api/overview`.

Optional: provide a compact CycloneDX VEX JSON document as the `OWNER_VEX` secret (`npx wrangler secret put OWNER_VEX < private-vex.json`, from a file **outside the repo**). Include `metadata.timestamp`, `components` with `bom-ref`, name and version, and `vulnerabilities` with exact CVE `id`, `analysis.state` and `affects[].ref`. Use a current, owner-reviewed snapshot small enough for a Worker secret. Each report identifies the data as owner evidence.

### Operations and data

- Reports and events are private to the deploying account. Visible zone names, Worker names, scoped VEX findings and WAF counts are processed by Workers AI and stored with the report. No raw tokens, DNS record values, WAF expressions or Worker source are sent to the model. Application data is retained until the operator removes storage; there is no automatic expiry yet.
- Each snapshot checks at most ten visible zones and forty Worker names. Review coverage gaps before making decisions. The Worker only reads the feed, Access signing keys and fixed Cloudflare control-plane endpoints.
- Check **Last synced** for a stale feed, **Inspect → Event log** for stage errors, and Workflows in the Cloudflare dashboard for platform retries/failures. Use `npx wrangler tail` for operational troubleshooting. No raw payloads are written to application debug logs.
- To suspend scheduled assessments, remove the cron entry in `wrangler.jsonc` and redeploy. Stop individual in-flight runs in the dashboard. Rotate/revoke the inventory token independently. One installation per account by default; choose distinct Worker and Workflow names for additional deployments.

### Development and publication

```sh
npm ci
npm test
npm run test:runtime
```

The runtime smoke test bundles the actual Worker and runs it in workerd with synthetic upstreams; no account or AI credits are needed. For interactive development `npm run dev` uses the same Access gate as production.

To publish the template, choose a **public github.com or gitlab.com repository**, run `node scripts/deploy-button.mjs https://github.com/YOUR-ORG/YOUR-REPO`, then commit the stamped README and push. The [Deploy to Cloudflare button](https://developers.cloudflare.com/workers/platform/deploy-buttons/) needs the real public repository URL. The button deploys the Worker and bindings; Access policy and read-only inventory credentials are tenant-specific.

See [AGENTS.md](AGENTS.md) for implementation decisions and handoff.
