import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  repos: defineTable({
    owner: v.string(),
    name: v.string(),
    full_name: v.string(),
    source_url: v.string(),
    default_branch: v.optional(v.string()),
    head_sha: v.optional(v.string()),
    framework: v.optional(v.string()),
    created_at: v.number(),
    updated_at: v.number(),
  })
    .index("by_full_name", ["full_name"])
    .index("by_updated_at", ["updated_at"]),

  scans: defineTable({
    repo_id: v.string(), // Convex Id<"repos"> stored as string
    status: v.string(), // pending|bootstrap|threat-model|scanning|exploiting|enriching|reporting|done|error
    phase: v.optional(v.string()),
    progress: v.number(),
    error_message: v.optional(v.string()),
    threat_model_json: v.optional(v.string()),
    framework: v.optional(v.string()),
    target_url: v.optional(v.string()),
    pr_number: v.optional(v.number()),
    pr_base_sha: v.optional(v.string()),
    pr_head_sha: v.optional(v.string()),
    installation_id: v.optional(v.number()),
    pr_comment_state: v.optional(v.string()), // posted|failed
    findings_count: v.number(),
    candidate_count: v.number(),
    verified_count: v.number(),
    false_positive_count: v.number(),
    created_at: v.number(),
    updated_at: v.number(),
  })
    .index("by_repo", ["repo_id"])
    .index("by_status", ["status"])
    .index("by_created_at", ["created_at"])
    .index("by_repo_pr", ["repo_id", "pr_number"]),

  findings: defineTable({
    scan_id: v.string(), // Convex Id<"scans"> stored as string
    repo_id: v.string(), // Convex Id<"repos"> stored as string
    category: v.string(),
    title: v.string(),
    severity: v.string(), // critical|high|medium|low|info
    status: v.string(), // candidate|validated|disconfirmed|inconclusive|advisory
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
    source: v.string(), // agent|osv
    issue_url: v.optional(v.string()),
    created_at: v.number(),
  })
    .index("by_scan", ["scan_id"])
    .index("by_status", ["status"])
    .index("by_scan_rank", ["scan_id", "rank_score"]),

  scan_log: defineTable({
    scan_id: v.string(), // Convex Id<"scans"> stored as string
    ts: v.number(),
    level: v.string(),
    message: v.string(),
  }).index("by_scan_ts", ["scan_id", "ts"]),

  scan_costs: defineTable({
    scan_id: v.string(), // Convex Id<"scans"> stored as string
    tenant: v.optional(v.string()),
    cost_usd: v.optional(v.number()),
    created_at: v.number(),
  })
    .index("by_tenant_day", ["tenant", "created_at"])
    .index("by_scan", ["scan_id"]),
});
