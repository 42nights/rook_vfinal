import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { verifySignature } from "../lib/github/webhook";

const secret = "test-webhook-secret";
const sign = (body: string, s = secret) => "sha256=" + crypto.createHmac("sha256", s).update(body).digest("hex");

describe("verifySignature (webhook HMAC)", () => {
  const body = JSON.stringify({ repository: { full_name: "a/b" } });

  it("accepts a correct signature", () => {
    expect(verifySignature(body, sign(body), secret)).toBe(true);
  });

  it("rejects a wrong-secret signature", () => {
    expect(verifySignature(body, sign(body, "wrong"), secret)).toBe(false);
  });

  it("rejects a tampered body", () => {
    expect(verifySignature(body + " ", sign(body), secret)).toBe(false);
  });

  it("rejects a missing or malformed signature", () => {
    expect(verifySignature(body, null, secret)).toBe(false);
    expect(verifySignature(body, "", secret)).toBe(false);
    expect(verifySignature(body, "sha256=deadbeef", secret)).toBe(false);
    expect(verifySignature(body, "not-a-sig", secret)).toBe(false);
  });
});
