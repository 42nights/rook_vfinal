import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const insert = mutation({
  args: {
    scan_id: v.string(),
    ts: v.number(),
    level: v.string(),
    message: v.string(),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("scan_log", args);
  },
});

export const listByScan = query({
  args: { scan_id: v.string() },
  handler: async (ctx, { scan_id }) => {
    return await ctx.db
      .query("scan_log")
      .withIndex("by_scan_ts", (q) => q.eq("scan_id", scan_id))
      .order("asc")
      .collect();
  },
});
