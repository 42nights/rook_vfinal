import { createAppAuth } from "@octokit/auth-app";
import { Octokit } from "@octokit/rest";

// GitHub App auth for Rook. Optional — Rook works without any GitHub App.
// When configured, the App enables webhook-triggered scans and private-repo
// clones (installation tokens are injected into the clone URL).
// LIFT-FROM pattern: 42n-bot/src/github (App SDK + webhook).

export type GitHubAppConfig = {
  appId: string;
  privateKey: string;
  webhookSecret: string;
};

export function githubAppConfig(): GitHubAppConfig | null {
  const appId = process.env.GITHUB_APP_ID;
  const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;
  let privateKey = process.env.GITHUB_APP_PRIVATE_KEY;
  if (!privateKey && process.env.GITHUB_APP_PRIVATE_KEY_PATH) {
    try {
      privateKey = require("node:fs").readFileSync(process.env.GITHUB_APP_PRIVATE_KEY_PATH, "utf8");
    } catch {
      /* ignore */
    }
  }
  if (!appId || !privateKey || !webhookSecret) return null;
  return { appId, privateKey: privateKey.replace(/\\n/g, "\n"), webhookSecret };
}

export function isAppConfigured(): boolean {
  return githubAppConfig() !== null;
}


export function appOctokit(installationId: number): Octokit | null {
  const cfg = githubAppConfig();
  if (!cfg) return null;
  return new Octokit({
    authStrategy: createAppAuth,
    auth: { appId: cfg.appId, privateKey: cfg.privateKey, installationId },
  });
}

// Mint a short-lived installation access token (1h TTL, managed by the SDK) for
// authenticating a `git fetch` of a private repo. Never stored; passed only into
// the clone URL and scrubbed from any error. Returns null if the App isn't set up.
export async function installationToken(installationId: number): Promise<string | null> {
  const cfg = githubAppConfig();
  if (!cfg) return null;
  try {
    const auth = createAppAuth({ appId: cfg.appId, privateKey: cfg.privateKey, installationId });
    const { token } = await auth({ type: "installation" });
    return token;
  } catch {
    return null;
  }
}
