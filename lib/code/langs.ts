// Extension → language id + tree-sitter grammar (filename stem under
// node_modules/tree-sitter-wasms/out/tree-sitter-<grammar>.wasm).

export type LangInfo = {
  lang: string; // human label / id
  grammar: string | null; // tree-sitter grammar stem, or null (no AST)
  isDoc?: boolean;
};

const MAP: Record<string, LangInfo> = {
  // TypeScript / JavaScript
  ts: { lang: "typescript", grammar: "typescript" },
  mts: { lang: "typescript", grammar: "typescript" },
  cts: { lang: "typescript", grammar: "typescript" },
  tsx: { lang: "tsx", grammar: "tsx" },
  js: { lang: "javascript", grammar: "javascript" },
  mjs: { lang: "javascript", grammar: "javascript" },
  cjs: { lang: "javascript", grammar: "javascript" },
  jsx: { lang: "javascript", grammar: "javascript" },
  // Python
  py: { lang: "python", grammar: "python" },
  pyi: { lang: "python", grammar: "python" },
  // Go
  go: { lang: "go", grammar: "go" },
  // Rust
  rs: { lang: "rust", grammar: "rust" },
  // Java / Kotlin / Scala
  java: { lang: "java", grammar: "java" },
  kt: { lang: "kotlin", grammar: "kotlin" },
  kts: { lang: "kotlin", grammar: "kotlin" },
  scala: { lang: "scala", grammar: "scala" },
  // C / C++
  c: { lang: "c", grammar: "c" },
  h: { lang: "c", grammar: "c" },
  cc: { lang: "cpp", grammar: "cpp" },
  cpp: { lang: "cpp", grammar: "cpp" },
  cxx: { lang: "cpp", grammar: "cpp" },
  hpp: { lang: "cpp", grammar: "cpp" },
  hh: { lang: "cpp", grammar: "cpp" },
  // C#
  cs: { lang: "csharp", grammar: "c_sharp" },
  // Ruby
  rb: { lang: "ruby", grammar: "ruby" },
  // PHP
  php: { lang: "php", grammar: "php" },
  // Swift
  swift: { lang: "swift", grammar: "swift" },
  // Other code with grammars (chunked structurally where possible)
  lua: { lang: "lua", grammar: "lua" },
  zig: { lang: "zig", grammar: "zig" },
  ex: { lang: "elixir", grammar: "elixir" },
  exs: { lang: "elixir", grammar: "elixir" },
  dart: { lang: "dart", grammar: "dart" },
  sol: { lang: "solidity", grammar: "solidity" },
  vue: { lang: "vue", grammar: "vue" },
  // Docs / config — chunked as markdown/text, no symbol extraction.
  md: { lang: "markdown", grammar: null, isDoc: true },
  mdx: { lang: "markdown", grammar: null, isDoc: true },
  markdown: { lang: "markdown", grammar: null, isDoc: true },
  rst: { lang: "rst", grammar: null, isDoc: true },
  txt: { lang: "text", grammar: null, isDoc: true },
  json: { lang: "json", grammar: null, isDoc: true },
  yaml: { lang: "yaml", grammar: null, isDoc: true },
  yml: { lang: "yaml", grammar: null, isDoc: true },
  toml: { lang: "toml", grammar: null, isDoc: true },
};

export function langForPath(p: string): LangInfo | null {
  const base = p.split("/").pop() ?? p;
  const ext = base.includes(".") ? base.split(".").pop()!.toLowerCase() : "";
  return MAP[ext] ?? null;
}

// Files we always treat as docs regardless of extension.
const DOC_BASENAMES = new Set([
  "readme",
  "contributing",
  "changelog",
  "license",
  "code_of_conduct",
  "security",
]);

export function isDocFile(p: string): boolean {
  const base = (p.split("/").pop() ?? p).toLowerCase();
  const stem = base.split(".")[0];
  return DOC_BASENAMES.has(stem) || base.endsWith(".md") || base.endsWith(".mdx") || base.endsWith(".rst");
}
