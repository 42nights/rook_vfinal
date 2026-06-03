// In-process progress bus for scans. The scan pipeline publishes
// {phase, progress, message} events keyed by SCAN id; the SSE route and any
// in-process waiter subscribe. Survives module reloads via globalThis.

export type ProgressEvent = {
  scanId: string;
  status: string;
  phase: string;
  progress: number; // 0..1
  message?: string;
  done?: boolean;
  error?: string;
};

type Listener = (e: ProgressEvent) => void;

declare global {
  // eslint-disable-next-line no-var
  var __rook_progress:
    | {
        listeners: Map<string, Set<Listener>>;
        last: Map<string, ProgressEvent>;
      }
    | undefined;
}

function bus() {
  if (!globalThis.__rook_progress) {
    globalThis.__rook_progress = { listeners: new Map(), last: new Map() };
  }
  return globalThis.__rook_progress;
}

export function publish(e: ProgressEvent) {
  const b = bus();
  b.last.set(e.scanId, e);
  const set = b.listeners.get(e.scanId);
  if (set) for (const l of set) l(e);
  if (e.done) {
    setTimeout(() => {
      if (!b.listeners.get(e.scanId)?.size) b.last.delete(e.scanId);
    }, 60000);
  }
  if (b.last.size > 500) {
    for (const k of [...b.last.keys()].slice(0, 250)) {
      if (!b.listeners.get(k)?.size) b.last.delete(k);
    }
  }
}

export function lastProgress(scanId: string): ProgressEvent | null {
  return bus().last.get(scanId) ?? null;
}

export function subscribe(scanId: string, l: Listener): () => void {
  const b = bus();
  let set = b.listeners.get(scanId);
  if (!set) {
    set = new Set();
    b.listeners.set(scanId, set);
  }
  set.add(l);
  return () => {
    set!.delete(l);
    if (set!.size === 0) b.listeners.delete(scanId);
  };
}
