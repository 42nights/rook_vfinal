import type { FindingRow } from "./scans";
import { getRepo } from "./repos";
import { updateFinding, getFinding, getScan } from "./scans";
import { openIssue } from "./github/issues";
import { buildSyntheticIssue } from "./github/synthetic-issue";
import { safeParse } from "./utils";

export type OtisHandoff = {
  repo: string;
  owner: string;
  name: string;
  issue_number: number;
  issue_url: string | null;
  title: string;
  body: string;
  failingTest: { kind: "exploit"; command: string; expectFailNow: string };
  finding: { id: string; category: string; severity: string; file: string | null; line: number | null };
};

declare global {
  // eslint-disable-next-line no-var
  var __rook_opening_issue: Map<string, Promise<void>> | undefined;
  // eslint-disable-next-line no-var
  var __rook_opened_issue_url: Map<string, string> | undefined;
}
function openingIssue(): Map<string, Promise<void>> {
  return (globalThis.__rook_opening_issue ??= new Map());
}
function openedIssueUrl(): Map<string, string> {
  return (globalThis.__rook_opened_issue_url ??= new Map());
}

export async function buildOtisHandoff(finding: FindingRow): Promise<OtisHandoff | null> {
  const repo = await getRepo(finding.repo_id);
  if (!repo) return null;
  const transcript = finding.exploit_transcript_json ? safeParse<{ command?: string; evidence?: string }>(finding.exploit_transcript_json) : null;
  const scan = await getScan(finding.scan_id);
  const prNumber = scan?.pr_number ?? null;
  const issueBody = buildSyntheticIssue(finding, prNumber);

  let issueUrl: string | null = finding.issue_url ?? openedIssueUrl().get(finding._id) ?? null;
  let issueNumber = finding._id.length; // synthetic fallback
  if (!issueUrl) {
    const prior = openingIssue().get(finding._id);
    if (prior) {
      await prior.catch(() => {});
      const fresh = await getFinding(finding._id);
      issueUrl = openedIssueUrl().get(finding._id) ?? fresh?.issue_url ?? null;
    }
    if (!issueUrl) {
      let resolve!: () => void;
      const gate = new Promise<void>((r) => (resolve = r));
      openingIssue().set(finding._id, gate);
      try {
        const opened = await openIssue(repo.owner, repo.name, finding, scan?.installation_id ?? undefined, issueBody);
        if (opened) {
          issueUrl = opened.url;
          issueNumber = opened.number;
          openedIssueUrl().set(finding._id, opened.url);
          try {
            await updateFinding(finding._id, { issue_url: opened.url });
          } catch (e) {
            console.error("[rook] updateFinding issue_url failed:", e);
          }
        }
      } finally {
        resolve();
        openingIssue().delete(finding._id);
      }
    }
  }

  return {
    repo: `${repo.owner}/${repo.name}`,
    owner: repo.owner,
    name: repo.name,
    issue_number: issueNumber,
    issue_url: issueUrl,
    title: `Fix: ${finding.title}`,
    body: issueBody,
    failingTest: {
      kind: "exploit",
      command: finding.exploit_script ?? transcript?.command ?? "",
      expectFailNow: transcript?.evidence ?? "the exploit currently confirms the vulnerability",
    },
    finding: { id: finding._id, category: finding.category, severity: finding.severity, file: finding.file_path, line: finding.start_line },
  };
}

export async function sendToOtis(finding: FindingRow): Promise<{ ok: boolean; url?: string; payload: OtisHandoff | null; note: string }> {
  const payload = await buildOtisHandoff(finding);
  if (!payload) return { ok: false, payload: null, note: "repo not found" };
  const otisUrl = process.env.OTIS_URL;
  if (!otisUrl) {
    return { ok: false, payload, note: "OTIS_URL not configured — showing the handoff Otis would receive. Set OTIS_URL to the 42n-bot base URL to wire the implementer." };
  }
  const syntheticNote = payload.issue_url ? "" : " (synthetic issue number — set GITHUB_TOKEN so Rook can open the real issue first)";
  try {
    const res = await fetch(`${otisUrl.replace(/\/$/, "")}/api/issues/fix`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ owner: payload.owner, repo: payload.name, issue_number: payload.issue_number, rook: payload }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, payload, note: `Otis returned ${res.status}: ${data.error ?? ""}${syntheticNote}` };
    return { ok: true, url: payload.issue_url ?? data.url, payload, note: `handed off to Otis — it will label the issue bot-please and dispatch its implementer${syntheticNote}` };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, payload, note: `Otis unreachable at ${otisUrl}: ${msg}` };
  }
}
