import { NextRequest } from "next/server";
import { getScan } from "@/lib/scans";
import { subscribe, lastProgress, type ProgressEvent } from "@/lib/progress";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const scanId = req.nextUrl.searchParams.get("scanId") ?? "";
  const scan = await getScan(scanId);
  if (!scan) return new Response("not found", { status: 404 });

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      const send = (e: ProgressEvent) => controller.enqueue(encoder.encode(`data: ${JSON.stringify(e)}\n\n`));
      const last = lastProgress(scanId);
      if (last) send(last);
      else if (scan.status === "done") send({ scanId, status: "done", phase: "Done", progress: 1, done: true });

      let closed = false;
      const close = () => {
        if (closed) return;
        closed = true;
        unsub();
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      };
      const unsub = subscribe(scanId, (e) => {
        send(e);
        if (e.done) setTimeout(close, 150);
      });
      if (scan.status === "done" || scan.status === "error") setTimeout(close, 300);
      req.signal.addEventListener("abort", close);
    },
  });

  return new Response(stream, {
    headers: { "content-type": "text/event-stream", "cache-control": "no-cache, no-transform", connection: "keep-alive" },
  });
}
