// Deliberately vulnerable demo app for Rook to scan + exploit. Zero deps (Node
// http only) so it starts without an install. DO NOT deploy this. Each route
// has a planted, real, exploitable vulnerability.
const http = require("node:http");
const { exec } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const url = require("node:url");

// Hardcoded secret (secrets-in-source). Rook should flag this.
const API_KEY = "sk_live_rook_demo_51HxConfidential000ExampleKey";

const NOTES = [
  { id: 1, owner: "alice", text: "alice public note" },
  { id: 2, owner: "alice", text: "alice PRIVATE: bank pin 4821", private: true },
  { id: 3, owner: "bob", text: "bob PRIVATE: ssn 123-45-6789", private: true },
];

function send(res, code, body, type = "text/plain") {
  res.writeHead(code, { "content-type": type });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const q = parsed.query;

  // 1) Command injection — exec with untrusted input.
  if (parsed.pathname === "/api/ping") {
    const host = q.host || "127.0.0.1";
    exec(`ping -c 1 ${host}`, { timeout: 4000 }, (err, stdout, stderr) => {
      send(res, 200, `ping result for ${host}:\n${stdout || stderr || String(err)}`);
    });
    return;
  }

  // 2) Path traversal — file path built from user input, no normalization.
  if (parsed.pathname === "/api/file") {
    const name = q.name || "welcome.txt";
    fs.readFile(path.join(__dirname, "public", name), "utf8", (err, data) => {
      if (err) return send(res, 404, `not found: ${err.message}`);
      send(res, 200, data);
    });
    return;
  }

  // 3) IDOR — returns any note by id with no owner/auth check.
  if (parsed.pathname === "/api/notes") {
    const id = Number(q.id || 1);
    const note = NOTES.find((n) => n.id === id);
    if (!note) return send(res, 404, "no such note");
    return send(res, 200, JSON.stringify(note), "application/json");
  }

  // 4) Reflected XSS — user input echoed unescaped into HTML.
  if (parsed.pathname === "/search") {
    const term = q.q || "";
    send(res, 200, `<html><body><div>You searched: ${term}</div></body></html>`, "text/html");
    return;
  }

  // 5) SSRF — server fetches a user-controlled URL.
  if (parsed.pathname === "/api/fetch") {
    const target = q.url;
    if (!target) return send(res, 400, "missing url");
    http
      .get(target, (r) => {
        let body = "";
        r.on("data", (c) => (body += c));
        r.on("end", () => send(res, 200, `fetched ${target}:\n${body.slice(0, 500)}`));
      })
      .on("error", (e) => send(res, 502, `fetch error: ${e.message}`));
    return;
  }

  send(res, 200, "vulnerable-app: try /api/ping /api/file /api/notes /search /api/fetch");
});

// Bind to loopback ONLY — this app is deliberately vulnerable and must never be
// reachable from the network.
const PORT = process.env.PORT || 4599;
server.listen(PORT, "127.0.0.1", () => console.log(`vulnerable-app listening on http://127.0.0.1:${PORT}`));
