// Markdown-safety primitives for anything posted to GitHub (PR comments, review
// bodies, issue bodies). Untrusted text reaches these surfaces from two sources:
// LLM output (titles/summaries/fixes, derived from attacker-controlled repo
// source) and git metadata (author names) / filesystem paths. EVERY interpolation
// of such text into a GitHub markdown surface must go through one of these.

// Neutralize a ``` so it can't open/close a fence and garble the rest. (Single
// backticks in prose are harmless — they're not inside a span.)
export function noFence(s: string): string {
  return s.replace(/```/g, "ʼʼʼ");
}

// Stop an @mention from pinging a real user/team: a zero-width space after the @
// is visually identical but breaks the mention. Covers @user, @org/team, and
// emails (harmless there).
export function noMention(s: string): string {
  return s.replace(/@(?=[A-Za-z0-9_/-])/g, "@​");
}

// Untrusted free text rendered as inline PROSE: kill fences + mentions.
export function mdText(s: string): string {
  return noMention(noFence(s));
}

// Untrusted text rendered INSIDE an inline `code span` (file path, git author):
// neutralize all backticks (one would close the span). A code span already
// suppresses @mentions.
export function codeSpan(s: string): string {
  return "`" + s.replace(/`/g, "ʼ") + "`";
}

// A fenced code block. Body has ``` neutralized; single backticks are fine inside
// a fence and GitHub does not parse @mentions inside fences.
export function fence(lang: string, body: string): string {
  return "```" + lang + "\n" + noFence(body) + "\n```";
}
