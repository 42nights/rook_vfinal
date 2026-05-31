// Rook runs local-first. ROOK_MODE=local (default) routes generation to
// on-device models (LM Studio / Ollama) and the network guard in
// lib/local-mode.ts forbids any non-localhost fetch. ROOK_MODE=cloud opts into
// Anthropic for higher-quality analysis.
export const ROOK_MODE = (process.env.ROOK_MODE ?? "local").toLowerCase();
export const LOCAL_MODE = ROOK_MODE !== "cloud";

// --- Generation -------------------------------------------------------------
// Anthropic model used in cloud mode. Override with GENERATION_MODEL (e.g.
// claude-sonnet-4-6 for faster/cheaper scans — a scan makes many LLM calls).
export const GENERATION_MODEL = process.env.GENERATION_MODEL ?? "claude-opus-4-7";

export const LOCAL_LLM_URL =
  process.env.LOCAL_LLM_URL ?? "http://127.0.0.1:1234/v1";
export const LOCAL_LLM_MODEL =
  process.env.LOCAL_LLM_MODEL ?? "qwen/qwen3.5-9b";

// Local reasoning models (qwen, deepseek-r1, gpt-oss) emit a hidden reasoning
// channel before the answer; give generous headroom so reasoning AND the JSON
// payload both fit. Empirically 1-4k reasoning tokens is common.
export const LOCAL_MAX_TOKENS = Number(process.env.LOCAL_MAX_TOKENS ?? 6000);

// Skip files bigger than this when ingesting (minified bundles, lockfiles, etc.)
export const MAX_FILE_BYTES = 400 * 1024;
