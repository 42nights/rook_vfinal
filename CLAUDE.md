# Rook — working notes for Claude Code

Rook is a **local-only AI security scanner**: an AI red-teamer that reasons about
attack paths through a repo, then **proves every finding with a real, working HTTP
exploit** before claiming it. Next.js 16 (App Router) + better-sqlite3, TypeScript
strict, fully local models via LM Studio. Fully homemade, **zero cloud touch by
default.**

## Commands
- `npm run scan -- <owner/repo | url | /local/path>` — run a full scan from the CLI
- `npm run dev` — dev server
- `npm run typecheck` — `tsc --noEmit` (must stay clean)
- `npm run test` — vitest (must stay green)
- `npm run build` — production build
- `npm run migrate` — apply DB schema
- Fixture target for end-to-end checks: `npm run scan -- ./fixtures/vulnerable-app`

## Hard constraints
- **Zero false positives.** A finding is only `validated` if an exploit actually
  fired. Confirmation is deterministic where possible (`deterministicConfirm` in
  `lib/scanner/exploit.ts`): unfakeable signatures only (`id` output, `/etc/passwd`
  contents, exact-payload XSS reflection), plus anti-reflection and baseline-diff
  guards so a target that merely echoes the payload or surfaces its own uid/gid
  can't false-confirm. Ambiguous cases fall through to an LLM judge. Never loosen
  these into reflection-confirmable checks.
- **Exploit execution is host-locked.** `lib/sandbox/runner.ts` runs HTTP only —
  no host shell, no RCE. `buildUrl` forces the target host. Don't add shell exec.
- **OSV advisories are never claimed as exploit-verified.** They ship with
  `status:"advisory"`, counted separately from `validated`.
- **Secret scrubbing at every egress.** Repo source AND HTTP response bodies are
  untrusted. `lib/code/scrubber.ts` runs on stored code, finding title/summary,
  enrichment fields, and the exploit transcript output before any of it reaches
  the DB / GitHub issue / Otis handoff. Any new egress path must scrub first.
- **Mode-aware (cloud or local).** Configured default is `ROOK_MODE=cloud` → all
  reasoning runs on the **Anthropic API** (`ANTHROPIC_API_KEY`); Rook has no
  embeddings, so cloud mode needs nothing local. `ROOK_MODE=local` still works
  (on-device model); in local mode `lib/local-mode.ts` patches fetch to block
  off-box egress (allowing only configured OTIS_URL / GitHub hosts). Local-path
  scanning is gated by `ROOK_LOCAL_ROOTS` in both modes. Keep both modes working.

## Architecture — the 6-phase pipeline (`lib/scan-runner.ts`)
1. **bootstrap** — clone, detect framework, start the target app in an ephemeral
   sandbox home (`lib/scanner/bootstrap.ts`)
2. **threat-model** — infer ingress points (`lib/scanner/threat-model.ts`)
3. **static fan-out** — per-class vuln candidate scan, grounded against the corpus
   (`lib/scanner/static-scan.ts`, `corpus.ts`)
4. **exploit** — synthesize + execute + confirm (`lib/scanner/exploit.ts`)
5. **enrich** — title/summary/impact/fix + CVSS + git blame (`lib/scanner/enrich.ts`)
6. **report + OSV** — supply-chain advisories, persist counts
- `lib/otis.ts` — Send-to-Otis bridge (finding → GitHub issue + failing exploit)
- `app/` — App Router pages + API routes (scan, stream, findings/replay, findings/otis, webhook)

## Deploy as a Castle template

Rook ships as a Castle template: each customer gets their own Railway service + `data/rook.db`, isolated by default.

**Tenant env contract**

| Var | Purpose |
|---|---|
| `ROOK_TENANT_SLUG` | Activates tenant mode; used as Anthropic `metadata.user_id` for cost attribution |
| `ROOK_TENANT_DISPLAY_NAME` | White-label name in the UI (default: "Rook") |
| `ROOK_TENANT_PUBLIC_URL` | Public base URL for PR comment deeplinks |
| `ROOK_LOGO_URL` | Favicon override |
| `ROOK_PRIMARY_COLOR` | CSS color overriding the default coral `--accent` |
| `CASTLE_DEPLOYMENT_ID` | Castle deployment ID for event backlinks + budget admin URL |
| `CASTLE_API_URL` | Castle API for deployment events (`scan_started`, `scan_completed`, `budget_exceeded`) |
| `CASTLE_WEBHOOK_SECRET` | HMAC secret on `x-castle-secret` header |
| `ROOK_DAILY_BUDGET_USD` | Daily spend cap; gate fires before any scan (default 50) |

**Pattern A — per-tenant Railway service + data/rook.db**

Each tenant is a separate Railway deployment of this repo. Set `ROOK_TENANT_SLUG` and the Castle vars. The SQLite database at `data/rook.db` is tenant-local with no cross-tenant data.

**GitHub App via Castle redirect**

Castle provisions a shared GitHub App and redirects the OAuth install to the tenant's webhook endpoint. No per-tenant App registration needed.

**Daily budget cap**

`ROOK_DAILY_BUDGET_USD` (default 50) gates every PR scan. When the limit is hit, Rook posts a review comment explaining the block and emits a `budget_exceeded` Castle event. Raise the cap at `admin.42nights.dev/deployments/<CASTLE_DEPLOYMENT_ID>`.

**Local-model option**

Regulated customers who need zero cloud touch set `ROOK_MODE=local`. See `docs/self-hosted.md`.

## Conventions
- TypeScript strict, no `any`/`@ts-ignore`. Tailwind. Match existing file style.
- Global singletons (scan/replay port allocators, inflight sets, opening-issue
  map) live on `globalThis` so they survive HMR; release ports/queue depth in
  `finally`.
- `lib/code/scrubber.ts` is synced verbatim with the Atlas copy — change both.
- Hardened over 9 rounds of adversarial QA (see git history). Regression tests
  live in `test/`; keep them green and add one for any security/correctness fix.
