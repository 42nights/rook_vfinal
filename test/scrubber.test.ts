import { describe, it, expect } from "vitest";
import { scrubSecrets } from "../lib/code/scrubber";

describe("scrubSecrets", () => {
  it("redacts AWS keys, tokens, and secret assignments", () => {
    const src = [
      'const AWS = "AKIAIOSFODNN7EXAMPLE";',
      'const gh = "ghp_1234567890123456789012345678901234abcd";',
      'apiKey: "super-secret-value-1234"',
    ].join("\n");
    const { text, found } = scrubSecrets(src);
    expect(found).toBeGreaterThanOrEqual(3);
    expect(text).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(text).not.toContain("ghp_1234567890123456789012345678901234abcd");
    expect(text).not.toContain("super-secret-value-1234");
    expect(text).toContain("«redacted");
  });

  it("redacts unquoted env-style assignments and connection strings", () => {
    const src = [
      "DATABASE_URL=postgres://app:s3cr3tpass@db.internal:5432/prod",
      "STRIPE_WEBHOOK=whsec_aBcDeF1234567890aBcDeF1234567890",
      "API_TOKEN=abcdef0123456789ghijkl",
    ].join("\n");
    const { text } = scrubSecrets(src);
    expect(text).not.toContain("s3cr3tpass");
    expect(text).not.toContain("whsec_aBcDeF1234567890aBcDeF1234567890");
    expect(text).not.toContain("abcdef0123456789ghijkl");
    // the variable names remain (value redacted)
    expect(text).toContain("DATABASE_URL=");
    expect(text).toContain("API_TOKEN=");
    expect(text).toContain("«redacted");
  });

  it("leaves ordinary code untouched", () => {
    const src = "function add(a, b) { return a + b; }";
    const { text, found } = scrubSecrets(src);
    expect(found).toBe(0);
    expect(text).toBe(src);
  });

  it("does NOT redact numeric config that happens to be SECRET-named", () => {
    const src = ["MAX_TOKENS=40000000", "TOKEN_TTL=123456789", "SESSION_KEY_ROTATION=86400000"].join("\n");
    const { text, found } = scrubSecrets(src);
    expect(found).toBe(0);
    expect(text).toBe(src);
  });

  it("still redacts SECRET-named assignments whose value contains letters", () => {
    const src = "JWT_TOKEN=ab12cd34ef56gh78";
    const { text } = scrubSecrets(src);
    expect(text).not.toContain("ab12cd34ef56gh78");
    expect(text).toContain("JWT_TOKEN=");
    expect(text).toContain("«redacted");
  });

  it("redacts QUOTED ALL-CAPS credential assignments (round-8 gap)", () => {
    const src = ["VERCEL_TOKEN = 'abc123XYZvercel456789'", 'HF_TOKEN: "hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"'].join("\n");
    const { text } = scrubSecrets(src);
    expect(text).not.toContain("abc123XYZvercel456789");
    expect(text).not.toContain("hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789");
    expect(text).toContain("VERCEL_TOKEN");
    expect(text).toContain("«redacted");
  });

  it("redacts modern prefixed token formats (HuggingFace, GitLab)", () => {
    const src = ["const a = 'hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab'", "let b = 'glpat-xZ12abCD34efGH56ijKLmn'"].join("\n");
    const { text } = scrubSecrets(src);
    expect(text).not.toContain("hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab");
    expect(text).not.toContain("glpat-xZ12abCD34efGH56ijKLmn");
  });

  it("redacts camelCase cloud-metadata credentials in a JSON response (SSRF/IMDS)", () => {
    const imds = '{"AccessKeyId":"ASIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY","Token":"AQoEXAMPLEH4aoAH0gNCAPyJxz3BlbftokenvaluedAAAAAAAAA"}';
    const { text } = scrubSecrets(imds);
    expect(text).not.toContain("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY");
    expect(text).not.toContain("AQoEXAMPLEH4aoAH0gNCAPyJxz3BlbftokenvaluedAAAAAAAAA");
    expect(text).toContain("«redacted»");
  });

  it("does NOT redact architecture config in TOKEN/KEY-named vars (round-9 over-redaction)", () => {
    const src = ["TOKEN_BUCKET_ALGO = 'leaky-bucket'", "AUTH_TOKEN_EXPIRY = '30minutes'", "SIGNING_KEY_ALGO = 'ecdsa-p256'"].join("\n");
    const { text, found } = scrubSecrets(src);
    expect(found).toBe(0);
    expect(text).toBe(src);
  });

  it("redacts password-only connection strings (no username segment)", () => {
    const { text } = scrubSecrets("redis://s3cr3tpassword@cache.internal:6379");
    expect(text).not.toContain("s3cr3tpassword");
    expect(text).toContain("redis://");
  });

  it("fully redacts a connection-string password containing '@' (round-10)", () => {
    const { text } = scrubSecrets("postgresql://admin:p@ssw0rd@prod.internal/db");
    expect(text).not.toContain("ssw0rd");
    expect(text).not.toContain("p@ssw0rd");
    expect(text).toContain("@prod.internal/db");
  });

  it("redacts Azure Storage AccountKey and SAS sig (round-10)", () => {
    const acct = "DefaultEndpointsProtocol=https;AccountName=store;AccountKey=dGVzdGtleXZhbHVlMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGRw==;EndpointSuffix=core.windows.net";
    const out1 = scrubSecrets(acct).text;
    expect(out1).not.toContain("dGVzdGtleXZhbHVlMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGRw==");
    expect(out1).toContain("AccountKey=");
    const sas = "https://store.blob.core.windows.net/c/b?sv=2021&sig=abcDEF123ghiJKL456mnoPQR789stu%2BvwX&se=2026";
    const out2 = scrubSecrets(sas).text;
    expect(out2).not.toContain("abcDEF123ghiJKL456mnoPQR789stu%2BvwX");
    expect(out2).toContain("sig=");
  });

  it("scrub-then-cap leaves no partial secret at a truncation boundary", () => {
    // Simulates the enrich clean() invariant: a secret near the cap must be fully
    // redacted, never sliced into an unmatched prefix. scrubSecrets handles the
    // full string; callers slice the REDACTED output.
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const src = "x".repeat(40) + " " + secret;
    const scrubbed = scrubSecrets(src).text;
    expect(scrubbed).not.toContain(secret);
    expect(scrubbed.slice(0, 50)).not.toContain("AKIA");
  });
});
