import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { buildCorpus } from "../lib/scanner/corpus";

let dir: string;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "rook-pronly-"));
  fs.mkdirSync(path.join(dir, "src"));
  fs.writeFileSync(path.join(dir, "src", "changed.js"), "function handler(req,res){ res.end(req.query.x); }\n");
  fs.writeFileSync(path.join(dir, "src", "untouched.js"), "function other(){ return 1; }\n");
  fs.writeFileSync(path.join(dir, "src", "also-untouched.js"), "const z = 2;\n");
  // A non-JS language the old hard-coded changedCode regex missed (round-2 #2).
  fs.writeFileSync(path.join(dir, "src", "handler.rs"), "fn handler(q: &str) -> String { format!(\"{}\", q) }\n");
});

afterAll(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("buildCorpus PR-focused (only)", () => {
  it("restricts the corpus to the changed files", () => {
    const c = buildCorpus(dir, { only: ["src/changed.js"] });
    expect(c.files.map((f) => f.path)).toEqual(["src/changed.js"]);
    expect(c.text).toContain("handler");
    expect(c.text).not.toContain("function other");
  });

  it("an empty `only` list yields an empty corpus (PR touched no code → no findings)", () => {
    const c = buildCorpus(dir, { only: [] });
    expect(c.files).toHaveLength(0);
  });

  it("normalizes a leading ./ in changed paths", () => {
    const c = buildCorpus(dir, { only: ["./src/changed.js"] });
    expect(c.files.map((f) => f.path)).toEqual(["src/changed.js"]);
  });

  it("recognizes non-JS languages (Rust) as scannable code — round-2 #2", () => {
    const c = buildCorpus(dir, { only: ["src/handler.rs"] });
    expect(c.files.map((f) => f.path)).toEqual(["src/handler.rs"]);
  });

  it("without `only`, scans the whole repo (full-scan behavior unchanged)", () => {
    const c = buildCorpus(dir);
    expect(c.files.length).toBe(4); // 3 js + 1 rs
  });
});
