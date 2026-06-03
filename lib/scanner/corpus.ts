import fs from "node:fs";
import { walkRepo } from "../code/walker";
import { langForPath } from "../code/langs";

// Build a line-numbered source corpus for the LLM phases. Prioritizes files most
// likely to hold attack surface (servers, routes, api, handlers, controllers),
// caps total size to fit the local model's context.

export type CorpusFile = { path: string; content: string; lineCount: number };
export type Corpus = { text: string; files: CorpusFile[]; truncated: boolean };

const INTEREST = /(server|route|api|handler|controller|app|index|main|auth|login|admin|query|db|model|view|endpoint|middleware|upload|payment|user|account)/i;

function score(path: string): number {
  let s = 0;
  if (INTEREST.test(path)) s += 5;
  if (/\/(src|app|lib|api|server|routes?|controllers?)\//i.test("/" + path)) s += 3;
  if (/\.(ts|js|tsx|jsx|py|go|rb|php|java)$/i.test(path)) s += 2;
  if (/test|spec|\.d\.ts$/i.test(path)) s -= 4;
  return s;
}

function numbered(content: string): string {
  return content
    .split("\n")
    .map((l, i) => `${i + 1}| ${l}`)
    .join("\n");
}

export function buildCorpus(
  dir: string,
  opts: { maxChars?: number; maxPerFile?: number; only?: string[] } = {},
): Corpus {
  // Bigger budget than the original 14k so large repos aren't mostly missed.
  // Tunable via ROOK_CORPUS_MAX_CHARS; kept under the local model's context.
  const maxChars = opts.maxChars ?? Number(process.env.ROOK_CORPUS_MAX_CHARS ?? 40000);
  const maxPerFile = opts.maxPerFile ?? 8000;
  // PR-focused mode passes `only` (repo-relative changed paths) to restrict the
  // corpus to the diff. Paths are normalized so a leading "./" or stray
  // separators don't cause a miss against walkRepo's relative paths.
  const onlySet = opts.only
    ? new Set(opts.only.map((p) => p.replace(/^\.\//, "").replace(/\\/g, "/")))
    : null;

  const walked = walkRepo(dir)
    .filter((f) => {
      const info = langForPath(f.path);
      return info && !info.isDoc; // code files only
    })
    .filter((f) => !onlySet || onlySet.has(f.path.replace(/\\/g, "/")))
    .map((f) => ({ ...f, score: score(f.path) }))
    .sort((a, b) => b.score - a.score);

  const files: CorpusFile[] = [];
  const blocks: string[] = [];
  let total = 0;
  let truncated = false;

  for (const f of walked) {
    if (total >= maxChars) {
      truncated = true;
      break;
    }
    let content: string;
    try {
      content = fs.readFileSync(f.abs, "utf8");
    } catch {
      continue;
    }
    if (content.length > maxPerFile) {
      // Truncate at a line boundary so the model never sees a half-line (and the
      // displayed line numbers stay meaningful).
      const cut = content.slice(0, maxPerFile);
      const lastNl = cut.lastIndexOf("\n");
      content = (lastNl > 0 ? cut.slice(0, lastNl) : cut) + "\n… (truncated)";
      truncated = true;
    }
    const lineCount = content.split("\n").length;
    const block = `===== FILE: ${f.path} =====\n${numbered(content)}\n`;
    blocks.push(block);
    files.push({ path: f.path, content, lineCount });
    total += block.length;
  }

  return { text: blocks.join("\n"), files, truncated };
}
