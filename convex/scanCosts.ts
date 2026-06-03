import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const todaySpend = query({
  args: {
    tenant: v.optional(v.string()),
    since: v.number(),
  },
  handler: async (ctx, { tenant, since }) => {
    const rows = await ctx.db
      .query("scan_costs")
      .withIndex("by_tenant_day", (q) =>
        q.eq("tenant", tenant).gte("created_at", since),
      )
      .collect();
    return rows.reduce((sum, r) => sum + (r.cost_usd ?? 0), 0);
  },
});

export const insert = mutation({
  args: {
    scan_id: v.string(),
    tenant: v.optional(v.string()),
    cost_usd: v.optional(v.number()),
    created_at: v.number(),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("scan_costs", args);
  },
});
