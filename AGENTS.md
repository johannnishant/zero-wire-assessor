# Handoff — 2026-11-18

**Start here:** read README, run `npm ci`, `npm test`, `npm run test:runtime`. This repository is the installer, not the public demo. Use public documentation and synthetic test inputs only. Do not copy account exports, real Access assertions, identity data or demo domain settings into the source. Never point the runtime tests at a real account.

| Location | Responsibility |
|---|---|
| `src/feed.js` | Bounded public feed reader and normalized content digest |
| `src/ledger.js` | Single-account SQLite catalog, immutable revisions, persistent dispatch outbox, event log and reports |
| `src/index.js` | Cron, Access-gated router, read-only workflow steps, per-run agent and Workers AI |
| `src/auth.js` | Access JWT verification; server-side admin role |
| `src/inventory.js`, `src/vex.js` | Fixed, scoped API reads; origin evidence and verdict policy |
| `public/` | Text-only rendering of untrusted strings; no direct client access to agents |
| `scripts/runtime.mjs` | Local end-to-end run with a mock model and strict outbound allowlist |

**Feed findings:** reviewed all nine items in the [public JSON feed](https://radar.cloudflare.com/zero-wire/feed?format=json). Java4Shell, RSC typed-array RCE, OpenSSH/musl, php2shell and Linux IPv4 TCP had `_zero_wire.assessment_prompt`. eMudhra, node2shell, NetScaler and WordPress did not. Some briefings cover several CVEs; one concerns certificates. The [public extension schema](https://radar.cloudflare.com/zero-wire/feed/schema.json) says prompt edits need not change timestamps. Keep the revision hash and missing-prompt behavior. Do not treat Cloudflare's own service status as customer evidence.

**Verified:** Local workerd tests cover Access admin/reader roles, protected assets, account filtering, VEX, baseline, new and revised items, deduplication, reruns, cancellation and report storage. A separate live Wrangler installation also verified anonymous Access redirect, administrator sign-in, baseline sync, account inventory, real Workers AI output, report and event log rendering, rerun and cancellation. No live account data is part of this repository.

**Next release tasks:** verify the deploy button in an account with a working Git integration. Repository discovery succeeded, but Cloudflare returned error `8000121` (GitHub authorization expired) when creating the deployment repository in the test account; do not reinstall an existing account-wide GitHub App just to run this test. Add configurable retention and paginated connector coverage for larger accounts. If expanding evidence, prefer owner-supplied SBOM/deployment manifests. Never add probing, model-controlled fetch, shell execution, or automatic remediation. Model guidance cannot override structured exposure status. Preserve immutable run snapshots across storage migrations; add migration tags rather than editing previous ones.
