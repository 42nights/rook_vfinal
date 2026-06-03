import { ConvexHttpClient } from "convex/browser";
import { api } from "../../convex/_generated/api";

if (!process.env.NEXT_PUBLIC_CONVEX_URL) {
  throw new Error("NEXT_PUBLIC_CONVEX_URL is not set");
}

declare global {
  // eslint-disable-next-line no-var
  var __rook_convex: ConvexHttpClient | undefined;
}

function makeClient(): ConvexHttpClient {
  return new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);
}

export const convex: ConvexHttpClient =
  globalThis.__rook_convex ?? makeClient();
if (!globalThis.__rook_convex) globalThis.__rook_convex = convex;

export { api };
