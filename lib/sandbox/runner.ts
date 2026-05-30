// Exploit execution. SECURITY POSTURE: Rook acts on model-generated input, and
// the target's own source code feeds the prompts — so exploit "commands" are
// attacker-influenced. We therefore NEVER run a host shell on them. An exploit
// is a STRUCTURED HTTP request that Rook builds and sends via fetch, HOST-LOCKED
// to the scan target. There is no shell, no host process, and no way to reach
// another host or touch the filesystem, in any mode.
//
// This covers every HTTP vuln class Rook validates (cmd-injection, path-
// traversal, ssrf, xss, idor, auth-bypass, open-redirect, ssti, info-leak): the
// payload lives in the URL/query/header/body, which is exactly where the
// vulnerability triggers — inside the TARGET, not on our host.

export type ExploitRun = {
  command: string; // rendered curl, for display / transcript / Otis handoff
  stdout: string;
  stderr: string;
  exitCode: number | null;
  durationMs: number;
  status?: number;
  blocked?: string;
};

export type ExploitSpec = {
  method?: string;
  path?: string; // path on the target, e.g. "/api/file" (absolute URLs are host-rewritten to the target)
  query?: Record<string, string> | string;
  headers?: Record<string, string>;
  body?: string;
  confirmIf?: string;
};

const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

// POSIX single-quote escape: wrap in single quotes and escape any embedded ' as '"'"'
export function shq(s: string): string {
  return `'${s.replace(/'/g, "'\"'\"'")}'`;
}

// Build the request URL, HOST-LOCKED to the target. Even if the model supplies a
// full URL to another host in `path`, we force protocol+host back to the target,
// so an exploit can never reach anything but the app under test.
export function buildUrl(targetUrl: string, spec: ExploitSpec): URL {
  const target = new URL(targetUrl);
  // Take ONLY the path+query+hash from whatever the model supplied — its scheme
  // and host never survive. An absolute URL (http://evil/x, file:///etc/passwd)
  // is reduced to its path; protocol-relative (//host/x) leading slashes are
  // collapsed so the authority can't be hijacked.
  let pathPart = (spec.path || "/").trim();
  try {
    const parsed = new URL(pathPart);
    pathPart = parsed.pathname + parsed.search + parsed.hash;
  } catch {
    /* relative path */
  }
  if (!pathPart.startsWith("/")) pathPart = "/" + pathPart;
  pathPart = pathPart.replace(/^\/+/, "/");
  const u = new URL(pathPart, target);
  u.protocol = target.protocol;
  u.host = target.host;
  if (spec.query && typeof spec.query === "object") {
    for (const [k, v] of Object.entries(spec.query)) u.searchParams.set(k, String(v));
  } else if (typeof spec.query === "string" && spec.query.trim()) {
    u.search = spec.query.startsWith("?") ? spec.query : `?${spec.query}`;
  }
  return u;
}

export function renderCurl(targetUrl: string, spec: ExploitSpec): string {
  const u = buildUrl(targetUrl, spec);
  const method = (spec.method || "GET").toUpperCase();
  let display = u.toString();
  try {
    display = decodeURIComponent(u.toString());
  } catch {
    /* keep encoded */
  }
  const parts = ["curl", "-s"];
  if (method !== "GET") parts.push("-X", method);
  for (const [k, v] of Object.entries(spec.headers ?? {})) parts.push("-H", shq(`${k}: ${v}`));
  if (spec.body) parts.push("--data", shq(spec.body));
  parts.push(shq(display));
  return parts.join(" ");
}

export async function runHttpExploit(
  targetUrl: string,
  spec: ExploitSpec,
  opts: { timeoutMs?: number } = {},
): Promise<ExploitRun> {
  const timeout = opts.timeoutMs ?? 8000;
  const t0 = Date.now();
  const command = renderCurl(targetUrl, spec);
  const method = (spec.method || "GET").toUpperCase();
  if (!ALLOWED_METHODS.has(method)) {
    return { command, stdout: "", stderr: "", exitCode: null, durationMs: 0, blocked: `method ${method} not allowed` };
  }
  let u: URL;
  try {
    u = buildUrl(targetUrl, spec);
  } catch (e: any) {
    return { command, stdout: "", stderr: String(e?.message ?? e), exitCode: null, durationMs: Date.now() - t0, blocked: "bad url" };
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(u, {
      method,
      headers: spec.headers,
      body: method === "GET" || method === "HEAD" ? undefined : spec.body,
      redirect: "manual",
      signal: ctrl.signal,
    });
    const text = (await res.text()).slice(0, 8000);
    const loc = res.headers.get("location");
    const ctype = res.headers.get("content-type") ?? "";
    return {
      command,
      status: res.status,
      // Surface content-type so the judge can tell e.g. an XSS payload reflected
      // in text/html (real) from one echoed in a JSON/plain response (not XSS).
      stdout: `HTTP ${res.status}  Content-Type: ${ctype}${loc ? `  Location: ${loc}` : ""}\n${text}`,
      stderr: "",
      exitCode: 0,
      durationMs: Date.now() - t0,
    };
  } catch (e: any) {
    return { command, stdout: "", stderr: `request failed: ${e?.message ?? e}`, exitCode: null, durationMs: Date.now() - t0 };
  } finally {
    clearTimeout(timer);
  }
}
