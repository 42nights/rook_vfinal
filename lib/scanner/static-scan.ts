import { z } from "zod";
import { generateJSON } from "../llm";
import { vulnScannerSystem, vulnScannerUser } from "./prompts";
import type { VulnClass } from "./vuln-classes";
import type { Corpus } from "./corpus";

const FindingsSchema = z.object({
  findings: z
    .array(
      z.object({
        file: z.string(),
        startLine: z.coerce.number().default(1),
        endLine: z.coerce.number().default(1),
        code: z.string().default(""),
        title: z.string().default(""),
        description: z.string().default(""),
        endpoint: z.string().default(""),
        confidence: z.coerce.number().default(0.5),
      }),
    )
    .default([]),
});

export type Candidate = {
  category: string;
  categoryLabel: string;
  exploitable: boolean;
  file: string;
  startLine: number;
  endLine: number;
  code: string;
  title: string;
  description: string;
  endpoint: string;
  confidence: number;
};

const norm = (s: string) => s.replace(/\s+/g, " ").toLowerCase().trim();

// Drop candidates that don't actually point at code in the corpus (the model
// hallucinated a file/snippet). Keeps Rook's false-positive rate honest.
function validate(c: Candidate, corpus: Corpus): boolean {
  const f = corpus.files.find((x) => x.path === c.file || x.path.endsWith(c.file) || c.file.endsWith(x.path));
  if (!f) return false;
  // Require a real, verbatim code location. A candidate with no snippet can't be
  // precisely exploited and is indistinguishable from a hallucination — drop it.
  if (!c.code.trim()) return false;
  // Strip the corpus line-number prefix (`42| `) from EVERY line of the snippet
  // before normalizing — the model often echoes the prefixed form verbatim, and a
  // leftover mid-snippet prefix would never match the raw file (false negative).
  // Validate the WHOLE snippet, not a 120-char prefix: otherwise a model could
  // ground a real prefix and append a hallucinated tail that then flows into
  // exploit synthesis. (A snippet that doesn't appear verbatim is dropped.)
  const needle = norm(c.code.replace(/^\s*\d+\|\s?/gm, ""));
  return needle.length >= 12 && norm(f.content).includes(needle);
}

export async function scanClass(vc: VulnClass, threatText: string, corpus: Corpus): Promise<Candidate[]> {
  const result = await generateJSON(
    vulnScannerSystem(),
    vulnScannerUser(vc, threatText, corpus.text),
    FindingsSchema,
    { think: false, maxTokens: 3000 },
  );
  if (!result) return [];
  const out: Candidate[] = [];
  for (const f of result.findings) {
    const file = corpus.files.find((x) => x.path === f.file || x.path.endsWith(f.file) || f.file.endsWith(x.path));
    const path = file?.path ?? f.file;
    const c: Candidate = {
      category: vc.id,
      categoryLabel: vc.label,
      exploitable: vc.exploitable,
      file: path,
      startLine: Math.max(1, f.startLine),
      endLine: Math.max(f.startLine, f.endLine),
      code: f.code,
      title: f.title || `${vc.label} in ${path}`,
      description: f.description,
      endpoint: f.endpoint,
      confidence: Math.min(1, Math.max(0, f.confidence)),
    };
    if (validate(c, corpus)) out.push(c);
  }
  return out;
}

export async function staticScan(
  classes: VulnClass[],
  threatText: string,
  corpus: Corpus,
  onProgress?: (done: number, total: number, label: string) => void,
): Promise<Candidate[]> {
  const all: Candidate[] = [];
  // Sequential — a single local model serializes anyway; keeps memory bounded.
  for (let i = 0; i < classes.length; i++) {
    onProgress?.(i, classes.length, classes[i].label);
    const cands = await scanClass(classes[i], threatText, corpus);
    all.push(...cands);
  }
  onProgress?.(classes.length, classes.length, "done");
  return all;
}
