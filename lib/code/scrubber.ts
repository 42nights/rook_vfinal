// Secret scrubbing for code chunks before they're embedded / stored / shown.
// LIFT-FROM: dataroom/lib/scrubber.ts, retargeted for source code. Redacts
// high-confidence secrets so a private repo's keys don't end up in the index or
// a wiki page. Conservative: only patterns that are almost certainly secrets.

type Rule = { name: string; re: RegExp };

const RULES: Rule[] = [
  { name: "aws-access-key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "aws-secret", re: /\b(?<=aws_secret_access_key\s*[=:]\s*["']?)[A-Za-z0-9/+]{40}\b/gi },
  { name: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  { name: "github-pat", re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g },
  { name: "openai-key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "stripe-key", re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b/g },
  { name: "private-key-block", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: "stripe-webhook", re: /\bwhsec_[A-Za-z0-9]{20,}\b/g },
  { name: "stripe-restricted", re: /\brk_(?:live|test)_[A-Za-z0-9]{20,}\b/g },
  { name: "sendgrid", re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g },
  { name: "twilio", re: /\bSK[0-9a-fA-F]{32}\b/g },
  { name: "npm-token", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { name: "huggingface", re: /\bhf_[A-Za-z0-9]{34,}\b/g },
  { name: "gitlab-pat", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  // credentials embedded in a connection string (postgres://user:pass@host AND
  // password-only forms like redis://password@host). Username segment optional.
  { name: "conn-string", re: /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|rediss|https?):\/\/(?:[^:\s/@]+:)?)([^@\s/]{4,})(@)/gi },
  // secret-named fields in a JSON body (HTTP response, config). Catches the
  // camelCase cloud-metadata creds the snake_case aws-secret rule misses:
  // "SecretAccessKey":"…", "Token":"…", "AccessKeyId":"…".
  { name: "json-secret-field", re: /("[A-Za-z0-9_]*(?:secret|password|passwd|credential|token|api[_]?key|access[_]?key|private[_]?key|secret[_]?key)[A-Za-z0-9_]*"\s*:\s*")([^"]{8,})(")/gi },
  // quoted secret-named assignments (lowercase-ish keyword names)
  { name: "secret-assignment", re: /\b((?:api[_-]?key|secret|password|passwd|token|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|bearer[_-]?token|private[_-]?key)\s*[=:]\s*["'])([^"'\n]{8,})(["'])/gi },
  // QUOTED ALL-CAPS credential-named assignments (VERCEL_TOKEN='…', HF_TOKEN='…').
  // The unquoted rule below stops at the quote and the lowercase rule above won't
  // match an ALL-CAPS name whose keyword is preceded by '_' (\b fails), so this
  // closes that gap.
  { name: "secret-assignment-caps-quoted", re: /\b([A-Z0-9_]*(?:KEY|SECRET|PASSWORD|PASSWD|TOKEN|CREDENTIAL|DATABASE_URL|DSN)[A-Z0-9_]*\s*[=:]\s*["'])([^"'\n]{8,})(["'])/g },
  // UNQUOTED secret-named assignments (env-file / yaml style: DATABASE_URL=...)
  { name: "secret-assignment-unquoted", re: /\b([A-Z0-9_]*(?:KEY|SECRET|PASSWORD|PASSWD|TOKEN|CREDENTIAL|DATABASE_URL|DSN)[A-Z0-9_]*\s*[=:]\s*)([^\s"'#`,;)]{8,})/g },
];

export function scrubSecrets(text: string): { text: string; found: number } {
  let out = text;
  let found = 0;
  for (const rule of RULES) {
    out = out.replace(rule.re, (match, ...groups) => {
      // Assignment-style rules keep the var name and redact only the value.
      if (rule.name === "secret-assignment") {
        const [pre, _val, post] = groups as string[];
        found++;
        return `${pre}«redacted»${post}`;
      }
      if (rule.name === "secret-assignment-caps-quoted") {
        const [pre, val, post] = groups as string[];
        // Redact only CREDENTIAL-like values. Architecture config
        // (TOKEN_BUCKET_ALGO='leaky-bucket', AUTH_TOKEN_EXPIRY='30minutes') and
        // pure-numeric TTLs are not secrets: require length>=16, both a digit and
        // a letter, and NOT a lowercase kebab/snake dictionary phrase.
        const credentialLike =
          val.length >= 16 && /[0-9]/.test(val) && /[a-zA-Z]/.test(val) && !/^[a-z0-9]+(?:[-_][a-z0-9]+)+$/.test(val);
        if (!credentialLike) return match;
        found++;
        return `${pre}«redacted»${post}`;
      }
      if (rule.name === "json-secret-field") {
        const [pre, val, post] = groups as string[];
        if (!/[A-Za-z]/.test(val)) return match; // skip numeric ("tokenCount":"12345678")
        found++;
        return `${pre}«redacted»${post}`;
      }
      if (rule.name === "secret-assignment-unquoted") {
        const [pre, val] = groups as string[];
        // A SECRET-named knob whose value is pure numeric/punctuation (e.g.
        // MAX_TOKENS=40000000, TOKEN_TTL=123456789) is config, not a credential.
        // Only redact when the value actually contains a letter.
        if (!/[A-Za-z]/.test(val)) return match;
        found++;
        return `${pre}«redacted»`;
      }
      if (rule.name === "conn-string") {
        const [pre, _pass, at] = groups as string[];
        found++;
        return `${pre}«redacted»${at}`;
      }
      found++;
      return `«redacted:${rule.name}»`;
    });
  }
  return { text: out, found };
}
