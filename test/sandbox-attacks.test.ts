import { describe, it, expect } from "vitest";
import { buildUrl, renderCurl, type ExploitSpec } from "../lib/sandbox/runner";

// The exploit executor is HOST-LOCKED: no matter what the model puts in the
// spec, the request can only ever reach the scan target. This is the security
// guarantee that replaces "run arbitrary shell" — proven here without a server.

const TARGET = "http://127.0.0.1:4599";

describe("HTTP exploit executor — host locking", () => {
  it("keeps a normal exploit on the target host", () => {
    const u = buildUrl(TARGET, { path: "/api/file", query: { name: "../../../etc/passwd" } });
    expect(u.host).toBe("127.0.0.1:4599");
    expect(u.pathname).toBe("/api/file");
  });

  it("rewrites an attacker-supplied absolute URL back to the target host", () => {
    const evil: ExploitSpec = { path: "http://evil.com/steal", query: { data: "secrets" } };
    const u = buildUrl(TARGET, evil);
    expect(u.host).toBe("127.0.0.1:4599");
    expect(u.hostname).not.toContain("evil");
    expect(renderCurl(TARGET, evil)).toContain("127.0.0.1:4599");
    expect(renderCurl(TARGET, evil)).not.toContain("evil.com");
  });

  it("ignores a scheme-changing host", () => {
    const u2 = buildUrl(TARGET, { path: "file:///etc/passwd" });
    expect(u2.host).toBe("127.0.0.1:4599");
    expect(u2.protocol).toBe("http:");
  });

  it("carries injection payloads as query values (they trigger in the target, not our host)", () => {
    const u = buildUrl(TARGET, { path: "/api/ping", query: { host: "127.0.0.1;id" } });
    expect(u.searchParams.get("host")).toBe("127.0.0.1;id");
    expect(u.host).toBe("127.0.0.1:4599");
  });

  it("renders a readable curl for the transcript", () => {
    const curl = renderCurl(TARGET, { path: "/api/file", query: { name: "../../../etc/passwd" } });
    expect(curl.startsWith("curl")).toBe(true);
    expect(curl).toContain("/api/file");
    expect(curl).toContain("../../../etc/passwd");
  });
});
