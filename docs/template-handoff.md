# Rook — Template Handoff

Everything a new tenant deployment needs to know.

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ROOK_MODE` | No | `local` | `cloud` uses Anthropic API; `local` uses LM Studio |
| `ANTHROPIC_API_KEY` | Cloud mode | — | Anthropic API key (cloud mode only) |
| `ROOK_DAILY_BUDGET_USD` | No | `50` | Daily LLM spend cap in USD; 0 disables all scans |
| `OTIS_URL` | No | — | 42n-bot base URL; unset = Otis CTA suppressed automatically |
| `ROOK_OTIS_CTA` | No | `true` | Set `false` to force-suppress the "Have Otis fix this" CTA |
| `ROOK_LOCAL_ROOTS` | No | — | Colon-separated paths that the API (not CLI) is allowed to scan locally |
| `GITHUB_APP_ID` | No | — | GitHub App ID for PR scanning + issue opening |
| `GITHUB_APP_PRIVATE_KEY_PATH` | No | — | Path to the App's `.pem` private key |
| `GITHUB_WEBHOOK_SECRET` | No | — | Webhook HMAC secret for the GitHub App |
| `GITHUB_TOKEN` | No | — | Personal token fallback for opening GitHub issues |
| `ROOK_TENANT_SLUG` | Tenant mode | — | Short slug identifying the tenant (e.g. `acme`); activates tenant mode |
| `ROOK_TENANT_DISPLAY_NAME` | No | `Rook` | Name shown in the UI header and page title |
| `ROOK_TENANT_PUBLIC_URL` | Tenant mode | — | Public base URL of this deployment |
| `ROOK_LOGO_URL` | No | — | URL for the favicon override |
| `ROOK_PRIMARY_COLOR` | No | — | CSS color value overriding the default coral accent (e.g. `#4f46e5`) |
| `CASTLE_DEPLOYMENT_ID` | Tenant mode | — | Castle deployment ID used in event backlinks |
| `CASTLE_API_URL` | Tenant mode | — | Castle API base URL for deployment events |
| `CASTLE_WEBHOOK_SECRET` | No | — | Shared secret sent as `x-castle-secret` on Castle events |

**Tenant mode** activates when `ROOK_TENANT_SLUG` is set or `TENANT_MODE=tenant`. In tenant mode, `ROOK_TENANT_PUBLIC_URL`, `CASTLE_DEPLOYMENT_ID`, and `CASTLE_API_URL` become required — startup throws listing any that are missing.

## First 60 Seconds

1. Install the GitHub App on the target repo (Castle provides a redirect URL). This gives Rook permission to read the repo and post review comments.
2. Open a pull request on that repo.
3. The webhook fires `POST /api/github/webhook`. Rook clones the PR diff, runs the 6-phase pipeline, and posts inline review comments for every exploit-confirmed finding plus a summary review.
4. Open the Rook dashboard (`ROOK_TENANT_PUBLIC_URL`) to see findings, replay exploits, and hand off to Otis.

## Failure Modes

**Sandbox cold start (dynamic phase skipped).** If the target app's `npm start` takes more than the scan timeout, Rook logs "skipping dynamic phase" and falls back to static analysis only. Raise `LLM_TIMEOUT_MS` or give the target a faster start command.

**Budget exceeded.** When `ROOK_DAILY_BUDGET_USD` is hit, Rook posts a review comment to the PR explaining the gate and skips the scan. Raise the budget at `admin.42nights.dev/deployments/<CASTLE_DEPLOYMENT_ID>` or increase `ROOK_DAILY_BUDGET_USD`.

**Local mode needs LM Studio.** With `ROOK_MODE=local`, Rook expects an OpenAI-compatible model server at `LOCAL_LLM_URL` (default `http://127.0.0.1:1234/v1`). If it's unreachable, scans error out. See `docs/self-hosted.md` for setup.

**No GitHub credential.** If neither a GitHub App nor `GITHUB_TOKEN` is configured, Rook cannot post review comments. It still runs the scan and stores findings in the dashboard, but `pr_comment_state` will be `failed`.

**Webhook HMAC mismatch.** If `GITHUB_WEBHOOK_SECRET` doesn't match what's configured in the GitHub App, all webhook deliveries return 401. Rook logs `webhook sig mismatch`.

## First Call

For questions about this deployment: `idan@kestenbom.com`
