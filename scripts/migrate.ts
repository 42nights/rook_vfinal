import { db } from "../lib/db";
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as { name: string }[];
console.log("Rook DB ready. Tables:");
for (const t of tables) console.log("  -", t.name);
