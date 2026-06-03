import { defineConfig } from "vitest/config";
import path from "node:path";

// Map the `@/` path alias (used in app/lib imports) so tests can import modules
// whose transitive deps reference `@/lib/...`.
export default defineConfig({
  test: { include: ["test/**/*.test.ts"], environment: "node" },
  resolve: { alias: { "@": path.resolve(__dirname, ".") } },
});
