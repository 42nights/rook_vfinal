import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const getById = query({
  args: { id: v.id("findings") },
  handler: async (ctx, { id }) => {
    return await ctx.db.get(id);
  },
});

export const listByScan = query({
  args: { scan_id: v.string() },
  handler: async (ctx, { scan_id }) => {
    const rows = await ctx.db
      .query("findings")
      .withIndex("by_scan", (q) => q.eq("scan_id", scan_id))
      .collect();
    // Sort by rank_score desc, then cvss_score desc (nulls last)
    return rows.sort((a, b) => {
      if (b.rank_score !== a.rank_score) return b.rank_score - a.rank_score;
      return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
    });
  },
});

export const insert = mutation({
  args: {
    scan_id: v.string(),
    repo_id: v.string(),
    category: v.string(),
    title: v.string(),
    severity: v.string(),
    status: v.string(),
    confidence: v.number(),
    file_path: v.optional(v.string()),
    start_line: v.optional(v.number()),
    end_line: v.optional(v.number()),
    vulnerable_code: v.optional(v.string()),
    summary: v.optional(v.string()),
    impact: v.optional(v.string()),
    cvss_vector: v.optional(v.string()),
    cvss_score: v.optional(v.number()),
    exploit_script: v.optional(v.string()),
    exploit_transcript_json: v.optional(v.string()),
    disconfirm_reason: v.optional(v.string()),
    recommended_fix: v.optional(v.string()),
    consistency_note: v.optional(v.string()),
    history_json: v.optional(v.string()),
    rank_score: v.number(),
    source: v.string(),
    issue_url: v.optional(v.string()),
    created_at: v.number(),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("findings", args);
  },
});

export const patch = mutation({
  args: {
    id: v.id("findings"),
    patchJson: v.string(),
  },
  handler: async (ctx, { id, patchJson }) => {
    const fields = JSON.parse(patchJson) as Record<string, unknown>;
    await ctx.db.patch(id, fields);
  },
});
