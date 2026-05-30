import "@/lib/local-mode";
import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";

// LIFT-FROM: dataroom/lib/db/index.ts.
const DATA_DIR = path.resolve(process.cwd(), "data");
const DB_PATH = path.join(DATA_DIR, "rook.db");
const WORKSPACES_DIR = path.join(DATA_DIR, "workspaces");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(WORKSPACES_DIR)) fs.mkdirSync(WORKSPACES_DIR, { recursive: true });

declare global {
  // eslint-disable-next-line no-var
  var __rook_db: Database.Database | undefined;
}

function openDb(): Database.Database {
  const d = new Database(DB_PATH);
  d.pragma("journal_mode = WAL");
  d.pragma("foreign_keys = ON");
  d.pragma("wal_autocheckpoint = 1000");
  d.pragma("busy_timeout = 5000");
  applySchema(d);
  return d;
}

function applySchema(d: Database.Database) {
  const schema = fs.readFileSync(
    path.join(process.cwd(), "lib/db/schema.sql"),
    "utf8",
  );
  d.exec(schema);
}

export const db: Database.Database = globalThis.__rook_db ?? openDb();
if (!globalThis.__rook_db) globalThis.__rook_db = db;

export const PATHS = { DATA_DIR, DB_PATH, WORKSPACES_DIR };
