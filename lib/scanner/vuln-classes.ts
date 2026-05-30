// Vulnerability classes Rook scans for (OWASP Top 10 + API Top 10 + what the OSS
// repos cover). Each is one static-analysis scanner prompt + a budget cap.
// Spec §4.3. Day-3 we ship the highest-impact ~12; the rest are wired in.

export type VulnClass = {
  id: string;
  label: string;
  probes: string;
  exploitable: boolean; // can a dynamic exploit confirm it against a running app?
};

export const VULN_CLASSES: VulnClass[] = [
  { id: "injection-cmd", label: "Command Injection", probes: "exec/eval/system/Runtime.exec/child_process with untrusted input; shell metacharacters reaching a command.", exploitable: true },
  { id: "injection-sql", label: "SQL Injection", probes: "string-interpolated SQL, ORM raw queries, dynamic table names, query built by concatenation.", exploitable: true },
  { id: "path-traversal", label: "Path Traversal", probes: "file paths built from user input without normalization; fs.readFile/sendFile with req params; '../' reaching the filesystem.", exploitable: true },
  { id: "ssrf", label: "SSRF", probes: "fetch/http.get/requests with a user-controlled URL; server-side requests to attacker-chosen hosts.", exploitable: true },
  { id: "xss", label: "Cross-Site Scripting", probes: "unescaped output in HTML responses, dangerouslySetInnerHTML, raw v-html, template strings echoing user input into markup.", exploitable: true },
  { id: "idor", label: "IDOR / Broken Object-Level Auth", probes: "resource IDs from user input fed to a lookup without an owner/tenant check; objects returned regardless of who asks.", exploitable: true },
  { id: "auth-bypass", label: "Auth Bypass", probes: "auth middleware ordering errors; routes that skip checks; missing authentication on sensitive endpoints.", exploitable: true },
  { id: "open-redirect", label: "Open Redirect", probes: "res.redirect(req.query.next) and friends without an allowlist.", exploitable: true },
  { id: "secrets-in-source", label: "Secrets in Source", probes: "API keys, tokens, DB creds, private keys hardcoded in source.", exploitable: false },
  { id: "crypto-weak", label: "Weak Cryptography", probes: "MD5/SHA1 for security, ECB mode, Math.random for tokens, hardcoded IVs/secrets.", exploitable: false },
  { id: "deserialization-rce", label: "Unsafe Deserialization", probes: "pickle.loads, unserialize, node-serialize, yaml.load on untrusted input.", exploitable: false },
  { id: "ssti", label: "Template Injection", probes: "user input concatenated into a template (Jinja2, Handlebars, EJS) before render.", exploitable: true },
  { id: "prototype-pollution", label: "Prototype Pollution", probes: "Object.assign({}, JSON.parse(req.body)) / recursive merge of user input into objects.", exploitable: false },
  { id: "jwt-misconfig", label: "JWT Misconfiguration", probes: "alg:none accepted, signature not verified, weak/hardcoded secrets.", exploitable: false },
  { id: "cors-misconfig", label: "CORS Misconfiguration", probes: "wildcard origin with allow-credentials, reflected Origin without validation.", exploitable: true },
  { id: "info-leak", label: "Information Leak", probes: "stack traces in responses, verbose errors exposing schema/paths, debug endpoints.", exploitable: true },
  { id: "mass-assignment", label: "Mass Assignment", probes: "Model.create({...req.body}) without an allow-list of fields.", exploitable: false },
  { id: "rate-limit-missing", label: "Missing Rate Limiting", probes: "auth/password-reset/expensive endpoints without rate limits.", exploitable: false },
  { id: "webhook-sig-missing", label: "Missing Webhook Verification", probes: "endpoints accepting webhook payloads without signature verification.", exploitable: false },
  { id: "csrf", label: "CSRF", probes: "state-changing endpoints without CSRF tokens / SameSite protection.", exploitable: false },
  { id: "xxe", label: "XXE", probes: "XML parsers with external entity processing enabled on untrusted input.", exploitable: false },
  { id: "race-condition", label: "Race Condition", probes: "read-modify-write on shared state, double-spend windows, TOCTOU.", exploitable: false },
];

// The highest-impact set scanned by default (Day 3 picks 10+; spec §8.3).
export const DEFAULT_CLASS_IDS = [
  "injection-cmd", "injection-sql", "path-traversal", "ssrf", "xss",
  "idor", "auth-bypass", "open-redirect", "secrets-in-source", "ssti",
  "crypto-weak", "info-leak",
];

export function defaultClasses(): VulnClass[] {
  return VULN_CLASSES.filter((c) => DEFAULT_CLASS_IDS.includes(c.id));
}
