import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { buildCorpus } from "../lib/scanner/corpus";

let dir: string;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "rook-corpus-"));
  // A small handler-ish file (prioritized) + a huge file to force truncation.
  fs.writeFileSync(path.join(dir, "server.js"), "function handler(req,res){ return res.end('ok'); }\n");
  const bigLines = Array.from({ length: 5000 }, (_, i) => `const line${i} = ${i};`).join("\n");
  fs.writeFileSync(path.join(dir, "big.ts"), bigLines + "\n");
});

afterAll(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("buildCorpus", () => {
  it("line-numbers files and includes the interesting handler file", () => {
    const c = buildCorpus(dir, { maxChars: 50000, maxPerFile: 8000 });
    expect(c.files.some((f) => f.path === "server.js")).toBe(true);
    expect(c.text).toContain("1| function handler");
  });

  it("truncates a large file at a LINE boundary (never mid-line)", () => {
    const c = buildCorpus(dir, { maxChars: 50000, maxPerFile: 2000 });
    const big = c.files.find((f) => f.path === "big.ts")!;
    expect(big.content.length).toBeLessThanOrEqual(2100);
    expect(big.content).toContain("… (truncated)");
    // every retained content line is a complete `const lineN = N;` statement
    for (const line of big.content.split("\n")) {
      if (line.startsWith("const")) expect(line).toMatch(/^const line\d+ = \d+;$/);
    }
    expect(c.truncated).toBe(true);
  });
});
