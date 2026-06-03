import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const getById = query({
  args: { id: v.id("scans") },
  handler: async (ctx, { id }) => {
    return await ctx.db.get(id);
  },
});

export const list = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db
      .query("scans")
      .withIndex("by_created_at")
      .order("desc")
      .collect();
  },
});

export const listForRepo = query({
  args: { repo_id: v.string() },
  handler: async (ctx, { repo_id }) => {
    return await ctx.db
      .query("scans")
      .withIndex("by_repo", (q) => q.eq("repo_id", repo_id))
      .order("desc")
      .collect();
  },
});

export const latestDoneThreatModel = query({
  args: { repo_id: v.string() },
  handler: async (ctx, { repo_id }) => {
    const rows = await ctx.db
      .query("scans")
      .withIndex("by_repo", (q) => q.eq("repo_id", repo_id))
      .order("desc")
      .collect();
    // Full scans only (pr_number absent), done, with a threat model
    const match = rows.find(
      (r) =>
        r.status === "done" &&
        r.pr_number === undefined &&
        r.threat_model_json !== undefined,
    );
    return match?.threat_model_json ?? null;
  },
});

export const priorPostedPrScan = query({
  args: {
    repo_id: v.string(),
    pr_number: v.number(),
    pr_head_sha: v.string(),
  },
  handler: async (ctx, { repo_id, pr_number, pr_head_sha }) => {
    const rows = await ctx.db
      .query("scans")
      .withIndex("by_repo_pr", (q) =>
        q.eq("repo_id", repo_id).eq("pr_number", pr_number),
      )
      .collect();
    return rows.some(
      (r) =>
        r.pr_head_sha === pr_head_sha && r.pr_comment_state === "posted",
    );
  },
});

export const insert = mutation({
  args: {
    repo_id: v.string(),
    created_at: v.number(),
    updated_at: v.number(),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("scans", {
      repo_id: args.repo_id,
      status: "pending",
      progress: 0,
      findings_count: 0,
      candidate_count: 0,
      verified_count: 0,
      false_positive_count: 0,
      created_at: args.created_at,
      updated_at: args.updated_at,
    });
  },
});

export const patch = mutation({
  args: {
    id: v.id("scans"),
    patchJson: v.string(),
  },
  handler: async (ctx, { id, patchJson }) => {
    const fields = JSON.parse(patchJson) as Record<string, unknown>;
    await ctx.db.patch(id, fields);
  },
});

export const getFindingCounts = query({
  args: { scan_id: v.string() },
  handler: async (ctx, { scan_id }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_scan", (q) => q.eq("scan_id", scan_id))
      .collect();
    let shipped = 0;
    let verified = 0;
    let dropped = 0;
    for (const f of findings) {
      if (f.status === "validated" || f.status === "advisory") shipped++;
      if (f.status === "validated") verified++;
      if (f.status === "disconfirmed") dropped++;
    }
    return { shipped, verified, dropped };
  },
});
