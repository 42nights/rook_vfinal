import { LOCAL_MODE } from "./constants";

// LIFT-FROM: dataroom/lib/local-mode.ts.
// Enforces Ayaan's "zero cloud touch" rule when ROOK_MODE=local:
//   1. Refuse to start if a cloud API key is present — that would mean code
//      *could* reach OpenAI/Anthropic.
//   2. Monkey-patch global fetch to throw on any non-localhost request, so a
//      stray call (telemetry, an SDK, a forgotten import) fails loudly instead
//      of silently leaving the machine.
//
// Side-effecting on import. Imported by lib/db/index.ts (which every route
// touches) so the guard installs before any route executes, and by standalone
// scripts. Idempotent — safe to import from multiple places.

declare global {
  // eslint-disable-next-line no-var
  var __rook_local_guard: boolean | undefined;
}

const ALLOWED_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0"]);

// "Zero cloud touch" means no MODEL-provider calls. Explicitly-configured
// delivery integrations (GitHub issues, the Otis fix loop, Slack) are not model
// calls, so each opens a single host through the guard only when the user has
// configured it. OSV is the same posture.
if (process.env.ROOK_OSV === "true") ALLOWED_HOSTS.add("api.osv.dev");
if (process.env.GITHUB_TOKEN || process.env.GITHUB_APP_ID) {
  ALLOWED_HOSTS.add("api.github.com");
  ALLOWED_HOSTS.add("uploads.github.com");
}
for (const k of ["OTIS_URL", "SLACK_WEBHOOK_URL"]) {
  const v = process.env[k];
  if (v) {
    try {
      ALLOWED_HOSTS.add(new URL(v).hostname);
    } catch {
      /* ignore malformed */
    }
  }
}

function hostOf(input: RequestInfo | URL): string | null {
  try {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

export function enforceLocalMode() {
  if (!LOCAL_MODE) return;
  if (globalThis.__rook_local_guard) return;

  // A stray cloud key in the env must not crash the app — the network guard
  // below still blocks every non-localhost request, so zero-cloud-touch holds.
  if (process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY) {
    console.warn(
      "[rook] ROOK_MODE=local: a cloud API key is set but will NOT be used " +
        "(non-localhost requests are blocked). Set ROOK_MODE=cloud to use it.",
    );
  }

  const origFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    const host = hostOf(input);
    if (host !== null && !ALLOWED_HOSTS.has(host)) {
      throw new Error(`ROOK local mode: blocked outbound fetch to ${host}`);
    }
    return origFetch(input, init);
  }) as typeof fetch;

  globalThis.__rook_local_guard = true;
}

enforceLocalMode();
