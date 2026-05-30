import { z } from "zod";
import { generateJSON } from "../llm";
import { THREAT_MODEL_PROMPT, THREAT_MODEL_SCHEMA_HINT } from "./prompts";
import type { Corpus } from "./corpus";

const ThreatSchema = z.object({
  summary: z.string().default(""),
  auth_surfaces: z.array(z.object({ where: z.string(), protocol: z.string().default("") })).default([]),
  authz_boundaries: z.array(z.object({ where: z.string(), ifBypassed: z.string().default("") })).default([]),
  ingress: z.array(z.object({ endpoint: z.string(), method: z.string().default(""), inputs: z.string().default("") })).default([]),
  sensitive_ops: z.array(z.object({ what: z.string(), where: z.string().default("") })).default([]),
  integrations: z.array(z.object({ name: z.string(), trustBoundary: z.string().default("") })).default([]),
  attacker_goals: z.array(z.string()).default([]),
});

export type ThreatModel = z.infer<typeof ThreatSchema>;

export async function inferThreatModel(corpus: Corpus): Promise<ThreatModel> {
  const tm = await generateJSON(
    `${THREAT_MODEL_PROMPT}\n\n${THREAT_MODEL_SCHEMA_HINT}`,
    `Source files:\n${corpus.text}`,
    ThreatSchema,
    { think: false, maxTokens: 3500 },
  );
  return tm ?? ThreatSchema.parse({});
}

export function threatModelToText(tm: ThreatModel): string {
  const lines: string[] = [];
  if (tm.summary) lines.push(tm.summary);
  if (tm.ingress.length) lines.push("Ingress: " + tm.ingress.map((i) => `${i.method} ${i.endpoint} (${i.inputs})`).join("; "));
  if (tm.auth_surfaces.length) lines.push("Auth: " + tm.auth_surfaces.map((a) => `${a.where} [${a.protocol}]`).join("; "));
  if (tm.authz_boundaries.length) lines.push("Authz: " + tm.authz_boundaries.map((a) => `${a.where}`).join("; "));
  if (tm.sensitive_ops.length) lines.push("Sensitive: " + tm.sensitive_ops.map((s) => `${s.what} @ ${s.where}`).join("; "));
  if (tm.attacker_goals.length) lines.push("Attacker goals: " + tm.attacker_goals.join("; "));
  return lines.join("\n") || "No structured threat model produced.";
}
