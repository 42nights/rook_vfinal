import { describe, it, expect } from "vitest";
import { renderCurl, shq } from "../lib/sandbox/runner";

// Inverse of shq: strip the wrapping single quotes and turn the POSIX escape
// sequence '"'"' back into a literal '. If this recovers the original string,
// the quoting is lossless and the value can't break out of its argument.
function unwrapShq(token: string): string {
  return token.slice(1, -1).replace(/'"'"'/g, "'");
}

describe("shq POSIX single-quote escaping", () => {
  it("round-trips a single-quote shell-injection payload losslessly", () => {
    const evil = "foo' --upload-file ~/.ssh/id_rsa '";
    const quoted = shq(evil);
    expect(unwrapShq(quoted)).toBe(evil);
    // every literal quote is armored as the canonical escape, never left bare
    expect(quoted.includes(`'"'"'`)).toBe(true);
  });

  it("leaves quote-free values as a simple wrapped literal", () => {
    expect(shq("X-H: bar")).toBe("'X-H: bar'");
  });
});

describe("renderCurl wiring", () => {
  it("escapes an LLM-derived header value containing a quote", () => {
    const cmd = renderCurl("http://t.local", {
      method: "GET",
      path: "/x",
      headers: { "X-Evil": "a'b" },
    });
    // header value made it through shq (escaped), not raw
    expect(cmd).toContain(`'X-Evil: a'"'"'b'`);
  });
});
