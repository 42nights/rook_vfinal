import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const list = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db
      .query("repos")
      .withIndex("by_updated_at")
      .order("desc")
      .collect();
  },
});

export const getById = query({
  args: { id: v.id("repos") },
  handler: async (ctx, { id }) => {
    return await ctx.db.get(id);
  },
});

export const getByFullName = query({
  args: { full_name: v.string() },
  handler: async (ctx, { full_name }) => {
    return await ctx.db
      .query("repos")
      .withIndex("by_full_name", (q) => q.eq("full_name", full_name))
      .unique();
  },
});

export const insert = mutation({
  args: {
    owner: v.string(),
    name: v.string(),
    full_name: v.string(),
    source_url: v.string(),
    created_at: v.number(),
    updated_at: v.number(),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("repos", {
      ...args,
      default_branch: undefined,
      head_sha: undefined,
      framework: undefined,
    });
  },
});

export const patch = mutation({
  args: {
    id: v.id("repos"),
    patchJson: v.string(),
  },
  handler: async (ctx, { id, patchJson }) => {
    const fields = JSON.parse(patchJson) as Record<string, unknown>;
    await ctx.db.patch(id, fields);
    return await ctx.db.get(id);
  },
});
