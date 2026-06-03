import { convex, api } from "./db/convex-client";
import type { Id } from "../convex/_generated/dataModel";

export const now = () => Date.now();

export type RepoRow = {
  _id: string;
  owner: string;
  name: string;
  full_name: string;
  source_url: string;
  default_branch: string | null;
  head_sha: string | null;
  framework: string | null;
  created_at: number;
  updated_at: number;
};

type ConvexRepoDoc = {
  _id: Id<"repos">;
  owner: string;
  name: string;
  full_name: string;
  source_url: string;
  default_branch?: string;
  head_sha?: string;
  framework?: string;
  created_at: number;
  updated_at: number;
};

function toRow(doc: ConvexRepoDoc): RepoRow {
  return {
    _id: doc._id as unknown as string,
    owner: doc.owner,
    name: doc.name,
    full_name: doc.full_name,
    source_url: doc.source_url,
    default_branch: doc.default_branch ?? null,
    head_sha: doc.head_sha ?? null,
    framework: doc.framework ?? null,
    created_at: doc.created_at,
    updated_at: doc.updated_at,
  };
}

export function normalizeFullName(owner: string, name: string): string {
  return `${owner}/${name}`.toLowerCase();
}

export async function getRepo(id: string): Promise<RepoRow | null> {
  // A malformed / wrong-table id string fails Convex's v.id("repos") validation
  // and throws rather than returning null; treat that as not-found so callers'
  // null guards run instead of surfacing a 500.
  let doc;
  try {
    doc = await convex.query(api.repos.getById, { id: id as Id<"repos"> });
  } catch {
    return null;
  }
  return doc ? toRow(doc as ConvexRepoDoc) : null;
}

export async function getRepoByName(
  owner: string,
  name: string,
): Promise<RepoRow | null> {
  const doc = await convex.query(api.repos.getByFullName, {
    full_name: normalizeFullName(owner, name),
  });
  return doc ? toRow(doc as ConvexRepoDoc) : null;
}

export async function createRepo(args: {
  owner: string;
  name: string;
  sourceUrl: string;
}): Promise<RepoRow> {
  const full_name = normalizeFullName(args.owner, args.name);
  const existing = await convex.query(api.repos.getByFullName, { full_name });
  if (existing) return toRow(existing as ConvexRepoDoc);
  const ts = now();
  const id = await convex.mutation(api.repos.insert, {
    owner: args.owner,
    name: args.name,
    full_name,
    source_url: args.sourceUrl,
    created_at: ts,
    updated_at: ts,
  });
  return (await getRepo(id as unknown as string))!;
}

export async function updateRepo(
  id: string,
  fields: Partial<Omit<RepoRow, "_id">>,
): Promise<void> {
  const patch: Record<string, unknown> = { updated_at: now() };
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined) patch[k] = v ?? undefined;
  }
  await convex.mutation(api.repos.patch, {
    id: id as Id<"repos">,
    patchJson: JSON.stringify(patch),
  });
}

export async function listRepos(): Promise<RepoRow[]> {
  const docs = await convex.query(api.repos.list, {});
  return (docs as ConvexRepoDoc[]).map(toRow);
}
