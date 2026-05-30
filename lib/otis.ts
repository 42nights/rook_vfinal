import type { FindingRow } from "./scans";
import { getRepo } from "./repos";
import { updateFinding, getFinding } from "./scans";
import { buildFindingReport } from "./scanner/report";
import { openIssue } from "./github/issues";
import { safeParse } from "./utils";

// The "Send to Otis" bridge (spec §7.3). A Rook finding carries a working
// exploit; we hand Otis (42n-bot) the finding as a GitHub Issue + the exploit as
// a failing test so its implementer pipeline ships the fix and verifies the
// exploit no longer fires.
//
// 42n-bot's real intake is POST /api/issues/fix with {owner, repo, issue_number}
// — it labels the issue `bot-please` and dispatches its coordinator. So the loop
// is: (1) open the GitHub Issue with the finding+exploit, (2) tell Otis to fix
// that issue. Without a GitHub token we can't open a real issue, so we transmit
// the handoff with a synthetic issue ref and say so.

export type OtisHandoff = {
  repo: string;
  owner: string;
  name: string;
  issue_number: number;
  issue_url: string | null;
  title: string;
  body: string;
  failingTest: { kind: "exploit"; command: string; expectFailNow: string };
  finding: { id: number; category: string; severity: string; file: string | null; line: number | null };
};

// Serialize handoffs per finding so two concurrent "Send to Otis" clicks can't
// both see issue_url=null and open duplicate GitHub issues. Hoisted to globalThis
// so Next.js dev HMR reloads don't reset the Map mid-request.
declare global {
  // eslint-disable-next-line no-var
  var __rook_opening_issue: Map<number, Promise<void>> | undefined;
  // eslint-disable-next-line no-var
  var __rook_opened_issue_url: Map<number, string> | undefined;
}
function openingIssue(): Map<number, Promise<void>> {
  return (globalThis.__rook_opening_issue ??= new Map());
}
// In-memory record of successfully-opened issue URLs. If updateFinding throws
// after openIssue succeeds, this ensures a retry never re-opens a duplicate.
function openedIssueUrl(): Map<number, string> {
  return (globalThis.__rook_opened_issue_url ??= new Map());
}

export async function buildOtisHandoff(finding: FindingRow): Promise<OtisHandoff | null> {
  const repo = getRepo(finding.repo_id);
  if (!repo) return null;
  const transcript = finding.exploit_transcript_json ? safeParse(finding.exploit_transcript_json) : null;

  // Open the GitHub Issue if we can (token / app configured). Otherwise carry a
  // synthetic issue number so the wire to Otis is still well-formed.
  let issueUrl: string | null = finding.issue_url ?? openedIssueUrl().get(finding.id) ?? null;
  let issueNumber = finding.id;
  if (!issueUrl) {
    // Wait for any in-flight open for this finding, then re-read state.
    const prior = openingIssue().get(finding.id);
    if (prior) {
      await prior.catch(() => {});
      // Check in-memory record first (covers the case where updateFinding threw
      // after openIssue succeeded), then fall back to the DB row.
      const fresh = getFinding(finding.id);
      issueUrl = openedIssueUrl().get(finding.id) ?? fresh?.issue_url ?? null;
    }
    if (!issueUrl) {
      let resolve!: () => void;
      const gate = new Promise<void>((r) => (resolve = r));
      openingIssue().set(finding.id, gate);
      try {
        const opened = await openIssue(repo.owner, repo.name, finding);
        if (opened) {
          issueUrl = opened.url;
          issueNumber = opened.number;
          // Persist to in-memory dedup BEFORE the DB write so a concurrent retry
          // that races past the gate still sees the opened URL and won't re-open.
          openedIssueUrl().set(finding.id, opened.url);
          try {
            updateFinding(finding.id, { issue_url: opened.url });
          } catch (e) {
            // DB write failed — log it but the in-memory record above prevents
            // a duplicate issue on retry.
            console.error("[rook] updateFinding issue_url failed:", e);
          }
        }
      } finally {
        resolve();
        openingIssue().delete(finding.id);
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
    body:
      buildFindingReport(finding) +
      "\n\n---\n**For Otis:** the exploit below currently succeeds. Implement a fix, then verify the exploit no longer demonstrates the vulnerability.",
    failingTest: {
      kind: "exploit",
      command: finding.exploit_script ?? transcript?.command ?? "",
      expectFailNow: transcript?.evidence ?? "the exploit currently confirms the vulnerability",
    },
    finding: { id: finding.id, category: finding.category, severity: finding.severity, file: finding.file_path, line: finding.start_line },
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
    // 42n-bot's real contract: POST /api/issues/fix {owner, repo, issue_number}.
    // We include the rich handoff as extra fields; the handler reads only the
    // three required keys, the rest is forward-compatible context.
    const res = await fetch(`${otisUrl.replace(/\/$/, "")}/api/issues/fix`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ owner: payload.owner, repo: payload.name, issue_number: payload.issue_number, rook: payload }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, payload, note: `Otis returned ${res.status}: ${data.error ?? ""}${syntheticNote}` };
    return { ok: true, url: payload.issue_url ?? data.url, payload, note: `handed off to Otis — it will label the issue bot-please and dispatch its implementer${syntheticNote}` };
  } catch (e: any) {
    return { ok: false, payload, note: `Otis unreachable at ${otisUrl}: ${e?.message ?? e}` };
  }
}

