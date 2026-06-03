# Self-Hosting Rook

For regulated environments where no scan data leaves the building.

## Two model options

**Option A — Anthropic API (cloud reasoning, local data)**

Set `ROOK_MODE=cloud` and `ANTHROPIC_API_KEY`. All LLM calls go to `api.anthropic.com`; your code and findings never leave your network otherwise. Rook has no embeddings, so this is the only cloud touch point.

**Option B — LM Studio (fully on-device, zero cloud)**

Set `ROOK_MODE=local`. Start [LM Studio](https://lmstudio.ai) with a compatible model (tested: `qwen/qwen3.5-9b`) and enable the OpenAI-compatible local server on port 1234.

```
LOCAL_LLM_URL=http://127.0.0.1:1234/v1
LOCAL_LLM_MODEL=qwen/qwen3.5-9b
```

In local mode, `lib/local-mode.ts` monkey-patches `fetch` to block all non-localhost requests except explicitly configured integration hosts (GitHub, Otis, OSV, Castle). A stray cloud key in the env is warned about but never used.

## Docker

A `Dockerfile` and `docker-compose.yml` are included. The image bundles Node.js and the scanner; the SQLite database lives at `/data/rook.db` (mount a volume to persist it).

```sh
docker compose up
```

Or build and run manually:

```sh
docker build -t rook .
docker run -p 3000:3000 \
  -v $(pwd)/data:/data \
  -e ROOK_MODE=cloud \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  rook
```

For local-model mode, pass `LOCAL_LLM_URL` pointing at a reachable LM Studio instance (use the host's IP, not `127.0.0.1`, when running inside Docker).

## GitHub Actions workflow option

If you prefer a CI-triggered scan rather than a persistent service, Rook can run as a GitHub Actions step. The `npm run scan-pr` script accepts the same PR context the webhook handler uses.

```yaml
- name: Rook security scan
  run: npx tsx scripts/scan-pr.ts
  env:
    ROOK_MODE: cloud
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The Action passes `GITHUB_TOKEN` as the comment credential; no GitHub App installation is required for the self-hosted workflow path.

## Data residency

- The SQLite database (`data/rook.db`) holds all findings, scan logs, and cost records. It never leaves your host unless you move it.
- In cloud mode, prompt content (repo code snippets, threat model text) is sent to Anthropic. Apply `ROOK_CORPUS_MAX_CHARS` to cap corpus size if needed.
- In local mode, nothing leaves the machine.
- Exploit transcripts (HTTP request/response bodies) are scrubbed for secrets before storage (`lib/code/scrubber.ts`).
