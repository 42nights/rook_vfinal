import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";

// Phase 1 — bootstrap. Detect the framework and start the target app so the
// dynamic exploit phase has something to hit. Lift of the 42n-bot dev-server
// lifecycle pattern (start → wait for port → expose URL → teardown). Uses
// node:child_process (no execa) to stay tsx/CJS-friendly.

export type Framework = "next" | "express" | "fastify" | "node" | "fastapi" | "flask" | "django" | "rails" | "unknown";

export function detectFramework(dir: string): Framework {
  const pkgPath = path.join(dir, "package.json");
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps.next) return "next";
      if (deps.express) return "express";
      if (deps.fastify) return "fastify";
      return "node";
    } catch {
      /* ignore */
    }
  }
  const req = readSafe(path.join(dir, "requirements.txt")) + readSafe(path.join(dir, "pyproject.toml"));
  if (/fastapi/i.test(req)) return "fastapi";
  if (/flask/i.test(req)) return "flask";
  if (/django/i.test(req)) return "django";
  if (fs.existsSync(path.join(dir, "config.ru")) || fs.existsSync(path.join(dir, "Gemfile"))) return "rails";
  return "unknown";
}

const MAX_READ_BYTES = 2 * 1024 * 1024;
function readSafe(p: string): string {
  try {
    if (fs.statSync(p).size > MAX_READ_BYTES) return "";
    return fs.readFileSync(p, "utf8");
  } catch {
    return "";
  }
}

// Heuristic guard for a repo's own start/dev/smoke script. We run untrusted repo
// code on the host (default, non-container mode), so an obviously-malicious start
// script (`curl … | sh`, reverse shells, reads of ~/.ssh / .env) must NOT execute.
// This is a blast-radius reducer, not a sandbox — real isolation is
// ROOK_SANDBOX=docker / running Rook in a disposable VM.
//
// We deliberately DO allow benign `&&` / `;` chaining: legitimate start scripts
// routinely chain build+start (`next build && next start`,
// `node build/server.js && echo ready`). Blocking all chaining silently skipped
// the dynamic phase for those repos. So we only block genuinely dangerous shapes:
// pipe-to-shell, reverse shells, and reads of credential files.
const DANGEROUS_START_PATTERNS: RegExp[] = [
  /\|\s*(sh|bash|zsh|node|python\d?)\b/i, // pipe-to-interpreter (curl … | sh, … | bash)
  /\b(curl|wget)\b[^|]*\|\s*\w/i, // fetch piped onward (curl … | <anything>) — exfil/run
  /\bbash\s+-i\b|\/dev\/tcp\/|\b(nc|ncat)\s+-e\b/i, // reverse shells
  /\.ssh\b|\.aws\/credentials|\/etc\/passwd|\.env\b/i, // reads of credential files
];

function isStartScriptSafe(command: string): boolean {
  return !DANGEROUS_START_PATTERNS.some((re) => re.test(command));
}

function startCommand(
  dir: string,
  fw: Framework,
  port: number,
  onLog: (s: string) => void = () => {},
): { cmd: string; args: string[]; env: Record<string, string> } | null {
  const pkgPath = path.join(dir, "package.json");
  const env = { PORT: String(port), HOST: "127.0.0.1" };
  if (fs.existsSync(pkgPath)) {
    let pkg: Record<string, unknown>;
    try {
      pkg = JSON.parse(readSafe(pkgPath) || "{}");
    } catch {
      return null;
    }
    const scripts = (pkg.scripts as Record<string, string> | undefined) ?? {};
    for (const name of ["bot:smoke", "start", "dev"] as const) {
      const body = scripts[name];
      if (!body) continue;
      if (!isStartScriptSafe(body)) {
        onLog(`refusing to run "${name}" — script looks unsafe to execute on the host; skipping dynamic phase`);
        return null;
      }
      return { cmd: "npm", args: ["run", name], env };
    }
  }
  if (fw === "flask") return { cmd: "python3", args: ["-m", "flask", "run", "--port", String(port)], env };
  if (fw === "fastapi") return { cmd: "python3", args: ["-m", "uvicorn", "main:app", "--port", String(port)], env };
  if (fw === "django") return { cmd: "python3", args: ["manage.py", "runserver", `127.0.0.1:${port}`], env };
  return null;
}

export type TargetServer = { url: string; stop: () => void; cleanup: () => void; logs: () => string };

async function probe(url: string): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 1500);
    await fetch(url, { signal: ctrl.signal });
    clearTimeout(t);
    return true;
  } catch (e: any) {
    // Connection refused → not up yet; any HTTP response (even error) → up.
    return !/fetch failed|ECONNREFUSED|aborted/i.test(e?.message ?? "");
  }
}

// We run code from an UNTRUSTED cloned repo (install + start). Two hardening
// rules, always:
//   1. npm install runs with --ignore-scripts, so a malicious preinstall/
//      postinstall/prepare lifecycle hook cannot execute on the host.
//   2. child processes get a MINIMAL env (never ...process.env), so the repo's
//      start script can't exfiltrate ANTHROPIC_API_KEY / GITHUB_TOKEN / etc.
// For fully-untrusted repos, run Rook itself inside a disposable container/VM
// so a malicious start script is contained at the deployment boundary.
// A SANDBOXED home so the untrusted child can't read the operator's ~/.npmrc
// (registry auth tokens), ~/.aws/credentials, ~/.ssh, etc. We never pass the
// real HOME, and the home is EPHEMERAL PER scan (a fresh mkdtemp) so one
// scanned repo can't poison config/binaries for the next.
function freshSandboxHome(): string {
  try {
    return fs.mkdtempSync(path.join(os.tmpdir(), "rook-sbx-"));
  } catch {
    return path.join(os.tmpdir(), "rook-sandbox-home");
  }
}

// A minimal PATH: just the runtime's own bin dir (so node/npm resolve) plus the
// standard system dirs. We deliberately DROP the operator's user-specific PATH
// entries (~/.bun/bin, ~/.cargo/bin, ~/.local/bin, …) — those both reveal the
// username and hand the untrusted child extra tooling to exfiltrate with. (On an
// nvm-style setup the runtime bin dir is itself under the home; that residual is
// inherent to running an untrusted app on the host — run Rook in a disposable
// container/VM for real isolation.)
function minimalPath(): string {
  const nodeBin = path.dirname(process.execPath);
  const system = ["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];
  return [nodeBin, ...system].filter((p, i, a) => a.indexOf(p) === i).join(path.delimiter);
}

function minimalEnv(home: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    PATH: minimalPath(),
    HOME: home,
    NODE_ENV: "development",
    npm_config_userconfig: path.join(home, ".npmrc"),
    npm_config_globalconfig: path.join(home, ".npmrc-global"),
    npm_config_cache: path.join(home, ".npm"),
    ...extra,
  };
}

function run(cmd: string, args: string[], cwd: string, timeoutMs: number, env: NodeJS.ProcessEnv): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, stdio: "ignore", env });
    const t = setTimeout(() => {
      child.kill("SIGKILL");
      resolve(false);
    }, timeoutMs);
    child.on("exit", (code) => {
      clearTimeout(t);
      resolve(code === 0);
    });
    child.on("error", () => {
      clearTimeout(t);
      resolve(false);
    });
  });
}

async function ensureInstalled(dir: string, home: string, onLog: (s: string) => void) {
  const pkgPath = path.join(dir, "package.json");
  if (!fs.existsSync(pkgPath)) return;
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(readSafe(pkgPath) || "{}");
  } catch {
    onLog("malformed package.json, skipping dependency install");
    return;
  }
  const hasDeps = Object.keys({ ...(pkg.dependencies as object | undefined), ...(pkg.devDependencies as object | undefined) }).length > 0;
  const scripts = pkg.scripts as Record<string, unknown> | undefined;
  const lifecycle = ["preinstall", "install", "postinstall", "prepare", "prepack"].filter((s) => scripts?.[s]);
  if (lifecycle.length) onLog(`note: repo declares lifecycle scripts (${lifecycle.join(", ")}) — running install with --ignore-scripts`);
  if (hasDeps && !fs.existsSync(path.join(dir, "node_modules"))) {
    onLog("installing dependencies (--ignore-scripts)…");
    const useCi = fs.existsSync(path.join(dir, "package-lock.json"));
    const base = useCi ? ["ci"] : ["install", "--no-audit", "--no-fund"];
    const ok = await run("npm", [...base, "--ignore-scripts"], dir, 180000, minimalEnv(home));
    if (!ok) onLog("dependency install failed, continuing best-effort");
  }
}

export async function startTarget(
  dir: string,
  fw: Framework,
  opts: { port?: number; onLog?: (s: string) => void } = {},
): Promise<TargetServer | null> {
  const port = opts.port ?? 4599;
  const onLog = opts.onLog ?? (() => {});
  // Defense-in-depth toggle (advertised in the settings UI): ROOK_SANDBOX=off/none
  // disables running the untrusted target on the host entirely — the static and
  // exploit-synthesis phases still run, only the live-target dynamic phase is
  // skipped. Default (unset / "local") keeps the guarded host subprocess.
  const sandbox = (process.env.ROOK_SANDBOX ?? "local").toLowerCase();
  if (sandbox === "off" || sandbox === "none") {
    onLog("ROOK_SANDBOX=off — skipping host target startup (no untrusted code run on host)");
    return null;
  }
  const spec = startCommand(dir, fw, port, onLog);
  if (!spec) {
    onLog("no start command detected, skipping dynamic phase");
    return null;
  }
  // Fresh ephemeral home for THIS scan's install + start — no cross-scan reuse.
  const home = freshSandboxHome();
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* ignore */ }
  };
  // Install is best-effort: a malformed package.json or npm failure must not
  // leak the sandbox home or crash the scan.
  try {
    await ensureInstalled(dir, home, onLog);
  } catch (e: any) {
    onLog(`dependency install error: ${e?.message ?? e}`);
  }

  onLog(`starting target: ${spec.cmd} ${spec.args.join(" ")} (PORT=${port})`);
  let logBuf = "";
  let child: ChildProcess;
  try {
    // Minimal env only — never spread process.env into the untrusted repo's
    // start script (it would leak ANTHROPIC_API_KEY / GITHUB_TOKEN / etc.).
    child = spawn(spec.cmd, spec.args, { cwd: dir, env: minimalEnv(home, spec.env) });
    const onData = (d: Buffer) => {
      logBuf += d.toString();
      if (logBuf.length > 20000) logBuf = logBuf.slice(-20000);
    };
    child.stdout?.on("data", onData);
    child.stderr?.on("data", onData);
    child.on("error", (e) => onLog(`target error: ${e.message}`));
  } catch (e: any) {
    onLog(`failed to start target: ${e?.message ?? e}`);
    cleanup();
    return null;
  }

  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 50; i++) {
    if (await probe(url)) {
      onLog(`target up at ${url}`);
      return { url, stop: () => child.kill("SIGTERM"), cleanup, logs: () => logBuf };
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  onLog("target did not come up in time, skipping dynamic phase");
  child.kill("SIGTERM");
  cleanup();
  return null;
}
