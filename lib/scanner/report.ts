import type { FindingRow } from "../scans";
import { safeParse } from "../utils";
import { mdText, codeSpan, fence } from "../github/md";

// Phase 6 — Detail-style finding report (markdown), with the security-specific
// exploit transcript. Serves as the openIssue fallback body and is downloadable
// from the UI. Section order per spec §4.6. All untrusted fields (LLM-derived
// title/summary/impact/fix/consistency, git author, file path) are routed through
// the shared md.ts sanitizers so this can never become a comment-injection vector.

const SEV_EMOJI: Record<string, string> = { critical: "🟥", high: "🟧", medium: "🟨", low: "🟦", info: "⬜" };

export function buildFindingReport(f: FindingRow): string {
  const sev = (f.severity ?? "medium").toUpperCase();
  const transcript = f.exploit_transcript_json ? safeParse<{ command?: string; output?: string; evidence?: string; outcome?: string }>(f.exploit_transcript_json) : null;
  const history = f.history_json ? safeParse<{ commit?: string; author?: string; date?: string }>(f.history_json) : null;

  const out: string[] = [];
  out.push(`# ${SEV_EMOJI[f.severity] ?? ""} ${mdText(f.title)}`);
  out.push("");
  out.push(`**Severity:** ${sev}${f.cvss_score != null ? ` (CVSS ${f.cvss_score})` : ""} · **Category:** ${codeSpan(f.category)} · **Status:** ${f.status}`);

  if (history?.commit) {
    out.push("");
    out.push(`> Introduced in commit ${codeSpan(history.commit)}${history.author ? ` by ${mdText(history.author)}` : ""}${history.date ? ` on ${history.date}` : ""}.`);
  }

  out.push("");
  out.push("## Summary");
  out.push(mdText(f.summary ?? ""));
  if (f.impact) {
    out.push("");
    out.push("**Impact.** " + mdText(f.impact));
  }

  if (f.vulnerable_code) {
    out.push("");
    out.push(`## Vulnerable code — ${codeSpan(f.file_path ?? "?")}${f.start_line ? ` (lines ${f.start_line}-${f.end_line})` : ""}`);
    out.push(fence("", "🔴 " + f.vulnerable_code.split("\n").join("\n🔴 ")));
  }

  if (f.exploit_script) {
    out.push("");
    out.push("## Working exploit");
    out.push(fence("bash", f.exploit_script));
  }

  if (transcript) {
    out.push("");
    out.push("## Exploit transcript");
    out.push(fence("", `$ ${transcript.command ?? ""}\n\n${(transcript.output ?? "").slice(0, 1500)}`));
    out.push(`**Outcome:** ${mdText(transcript.evidence ?? transcript.outcome ?? "confirmed")}`);
  }

  if (f.cvss_vector) {
    out.push("");
    out.push("## CVSS");
    out.push(codeSpan(f.cvss_vector) + (f.cvss_score != null ? ` → **${f.cvss_score}** (${f.severity})` : ""));
  }

  if (f.consistency_note) {
    out.push("");
    out.push("## Codebase consistency");
    out.push(mdText(f.consistency_note));
  }

  if (f.recommended_fix) {
    out.push("");
    out.push("## Recommended fix");
    out.push(fence("diff", f.recommended_fix));
  }

  out.push("");
  out.push("---");
  const exploitClaim =
    f.exploit_script && f.category !== "secrets-in-source"
      ? " · ships with a working exploit"
      : f.category === "secrets-in-source"
        ? " · statically proven"
        : "";
  out.push(`_Found and verified by **Rook**${exploitClaim}. Run locally, no cloud._`);
  return out.join("\n");
}
