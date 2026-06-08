import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "node:crypto";

// Shared-secret gate for the write APIs (/api/scan, findings replay, findings
// otis). These routes clone + RUN untrusted repo code and burn LLM credits, so
// they must not be open to the public internet. Rook stays unauthenticated for
// local-first single-user use; set ROOK_API_SECRET to require a bearer token
// once the deployment is network-reachable.
//
//   - ROOK_API_SECRET unset  → allowed (local/trusted-network default).
//   - ROOK_API_SECRET set    → require `Authorization: Bearer <secret>`
//                              (or `x-rook-secret: <secret>`); fail closed.
export function checkApiAuth(req: NextRequest): NextResponse | null {
  const secret = process.env.ROOK_API_SECRET;
  if (!secret) return null;

  const header = req.headers.get("authorization");
  const bearer = header?.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : null;
  const provided = bearer ?? req.headers.get("x-rook-secret");
  if (provided && constantTimeEqual(provided, secret)) return null;

  return NextResponse.json({ error: "unauthorized" }, { status: 401 });
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
