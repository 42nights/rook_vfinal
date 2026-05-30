import type { FindingRow } from "../scans";
import { safeParse } from "../utils";

// Phase 6 — Detail-style finding report (markdown), with the security-specific
// exploit transcript. Used as the GitHub Issue body and downloadable from the UI.
// Section order per spec §4.6.

const SEV_EMOJI: Record<string, string> = { critical: "🟥", high: "🟧", medium: "🟨", low: "🟦", info: "⬜" };

export function buildFindingReport(f: FindingRow): string {
  const sev = (f.severity ?? "medium").toUpperCase();
  const transcript = f.exploit_transcript_json ? safeParse(f.exploit_transcript_json) : null;
  const history = f.history_json ? safeParse(f.history_json) : null;

  const out: string[] = [];
  out.push(`# ${SEV_EMOJI[f.severity] ?? ""} ${f.title}`);
  out.push("");
  out.push(`**Severity:** ${sev}${f.cvss_score != null ? ` (CVSS ${f.cvss_score})` : ""} · **Category:** \`${f.category}\` · **Status:** ${f.status}`);

  if (history) {
    out.push("");
    out.push(`> Introduced in commit \`${history.commit}\` by ${history.author} on ${history.date}.`);
  }

  out.push("");
  out.push("## Summary");
  out.push(f.summary ?? "");
  if (f.impact) {
    out.push("");
    out.push("**Impact.** " + f.impact);
  }

  if (f.vulnerable_code) {
    out.push("");
    out.push(`## Vulnerable code — \`${f.file_path}\`${f.start_line ? ` (lines ${f.start_line}-${f.end_line})` : ""}`);
    out.push("```");
    out.push("🔴 " + (f.vulnerable_code ?? "").split("\n").join("\n🔴 "));
    out.push("```");
  }

  if (f.exploit_script) {
    out.push("");
    out.push("## Working exploit");
    out.push("```bash");
    out.push(f.exploit_script);
    out.push("```");
  }

  if (transcript) {
    out.push("");
    out.push("## Exploit transcript");
    out.push("```");
    out.push(`$ ${transcript.command}`);
    out.push("");
    out.push((transcript.output ?? "").slice(0, 1500));
    out.push("```");
    out.push(`**Outcome:** ${transcript.evidence ?? transcript.outcome ?? "confirmed"}`);
  }

  if (f.cvss_vector) {
    out.push("");
    out.push("## CVSS");
    out.push("`" + f.cvss_vector + "`" + (f.cvss_score != null ? ` → **${f.cvss_score}** (${f.severity})` : ""));
  }

  if (f.consistency_note) {
    out.push("");
    out.push("## Codebase consistency");
    out.push(f.consistency_note);
  }

  if (f.recommended_fix) {
    out.push("");
    out.push("## Recommended fix");
    out.push("```diff");
    out.push(f.recommended_fix);
    out.push("```");
  }

  out.push("");
  out.push("---");
  const exploitClaim = f.exploit_script && f.category !== "secrets-in-source"
    ? " · ships with a working exploit"
    : f.category === "secrets-in-source"
      ? " · statically proven"
      : "";
  out.push(`_Found and verified by **Rook**${exploitClaim}. Run locally, no cloud._`);
  return out.join("\n");
}

