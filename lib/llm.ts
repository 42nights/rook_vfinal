import "./local-mode";
import { z, type ZodType } from "zod";
import {
  LOCAL_MODE,
  LOCAL_LLM_MODEL,
  LOCAL_LLM_URL,
  LOCAL_MAX_TOKENS,
  GENERATION_MODEL,
} from "./constants";
import { tenant } from "./tenant";

// LIFT-FROM: dataroom/lib/llm.ts + anthropic.ts, generalized into three call
// shapes Atlas needs: free text (mermaid, prose), structured JSON (wiki pages),
// and the grounded submit_answer (chat). One local path, one cloud path.

export type ChatMsg = { role: "user" | "assistant"; content: string };
export type ChatHistory = ChatMsg[];

// --- Low-level transport ----------------------------------------------------

// A hung model server must never hang the whole request/scan. Every model fetch
// is bounded; tune via LLM_TIMEOUT_MS.
const LLM_TIMEOUT_MS = Number(process.env.LLM_TIMEOUT_MS ?? 180000);

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs = LLM_TIMEOUT_MS): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } catch (e: any) {
    if (e?.name === "AbortError") throw new Error(`model request timed out after ${timeoutMs}ms`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

type LMMessage = { content: string | null; reasoning_content?: string | null };

async function localChat(
  system: string,
  user: string,
  history: ChatHistory,
  maxTokens: number,
  think = true,
): Promise<string> {
  // Reasoning models (qwen3, deepseek-r1) burn large token budgets on a hidden
  // reasoning channel. For summarization-style work (wiki generation) we don't
  // need it, so we disable thinking to ~3-5x throughput. Two mechanisms, applied
  // together so whichever the server honors wins: the Qwen `/no_think` soft
  // switch in the prompt, and the `enable_thinking` chat-template kwarg.
  const sys = think ? system : `${system}\n/no_think`;
  const body: Record<string, unknown> = {
    model: LOCAL_LLM_MODEL,
    temperature: 0,
    max_tokens: think ? maxTokens : Math.min(maxTokens, 2400),
    messages: [
      { role: "system", content: sys },
      ...history.map((m) => ({ role: m.role, content: m.content })),
      { role: "user", content: user },
    ],
  };
  if (!think) body.chat_template_kwargs = { enable_thinking: false };
  const res = await fetchWithTimeout(`${LOCAL_LLM_URL}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`local llm ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
  const json = (await res.json()) as { choices?: Array<{ message?: LMMessage }> };
  return json.choices?.[0]?.message?.content?.trim() ?? "";
}

// Anthropic via fetch (avoids the SDK pulling its own transport; honors the
// network guard which is a no-op in cloud mode).
async function cloudChat(
  system: string,
  user: string,
  history: ChatHistory,
  maxTokens: number,
): Promise<string> {
  if (!process.env.ANTHROPIC_API_KEY) throw new Error("ANTHROPIC_API_KEY is not set");
  const res = await fetchWithTimeout("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": process.env.ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: GENERATION_MODEL,
      max_tokens: maxTokens,
      system,
      messages: [
        ...history.map((m) => ({ role: m.role, content: m.content })),
        { role: "user", content: user },
      ],
      ...(tenant.slug ? { metadata: { user_id: tenant.slug } } : {}),
    }),
  });
  if (!res.ok) {
    throw new Error(`anthropic ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
  const json = (await res.json()) as { content?: Array<{ type: string; text?: string }> };
  return (json.content ?? [])
    .filter((b) => b.type === "text")
    .map((b) => b.text ?? "")
    .join("\n")
    .trim();
}

async function chat(
  system: string,
  user: string,
  history: ChatHistory = [],
  maxTokens = LOCAL_MAX_TOKENS,
  think = true,
): Promise<string> {
  return LOCAL_MODE
    ? localChat(system, user, history, maxTokens, think)
    : cloudChat(system, user, history, Math.min(maxTokens, 8192));
}

// --- Public: structured JSON ------------------------------------------------

const JSON_NUDGE = `
OUTPUT FORMAT — STRICT: respond with ONLY a single minified-or-pretty JSON object
that matches the requested schema. No prose, no explanation, no markdown fences
before or after. Reasoning belongs in your hidden channel, never in the output.`;

export async function generateJSON<T>(
  system: string,
  user: string,
  schema: ZodType<T, any, any>,
  opts: { maxTokens?: number; retries?: number; think?: boolean } = {},
): Promise<T | null> {
  const retries = opts.retries ?? 1;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const nudge = attempt === 0 ? JSON_NUDGE : `${JSON_NUDGE}\nYour previous reply was not valid JSON for the schema. Return ONLY the JSON object now.`;
    const raw = await chat(`${system}\n\n${nudge}`, user, [], opts.maxTokens ?? LOCAL_MAX_TOKENS, opts.think ?? true);
    const obj = extractJson(raw);
    if (obj !== undefined) {
      const parsed = schema.safeParse(obj);
      if (parsed.success) return parsed.data;
    }
  }
  return null;
}

// --- JSON extraction --------------------------------------------------------
// Local models wrap JSON in ```fences``` or surround it with prose. Pull the
// first BALANCED {...} (or [...]) value out — scanning depth while respecting
// string literals — so JSON followed by trailing text, or text containing
// braces, parses correctly (a naive lastIndexOf picks the wrong boundary).
export function extractJson(s: string): unknown | undefined {
  if (!s) return undefined;
  const trimmed = s.trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "");
  const direct = safeJson(trimmed);
  if (direct !== undefined) return direct;
  // Try whichever value opens first — an object inside an array (or vice versa)
  // must not be extracted ahead of the outer value it lives in.
  const oi = trimmed.indexOf("{");
  const ai = trimmed.indexOf("[");
  const arrayFirst = ai !== -1 && (oi === -1 || ai < oi);
  const order = arrayFirst
    ? ([["[", "]"], ["{", "}"]] as const)
    : ([["{", "}"], ["[", "]"]] as const);
  for (const [open, close] of order) {
    const slice = balancedSlice(trimmed, open, close);
    if (slice) {
      const obj = safeJson(slice);
      if (obj !== undefined) return obj;
    }
  }
  return undefined;
}

function balancedSlice(s: string, open: string, close: string): string | undefined {
  const start = s.indexOf(open);
  if (start === -1) return undefined;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < s.length; i++) {
    const ch = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === open) depth++;
    else if (ch === close) {
      depth--;
      if (depth === 0) return s.slice(start, i + 1);
    }
  }
  return undefined;
}

function safeJson(s: string): unknown | undefined {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

// re-export so callers can build their own schemas alongside
export { z };
