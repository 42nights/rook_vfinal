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
