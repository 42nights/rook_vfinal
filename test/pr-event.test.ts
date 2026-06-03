import { describe, it, expect } from "vitest";
import { parsePullRequestTrigger } from "../lib/github/pr-event";

function payload(over: Record<string, any> = {}) {
  return {
    action: "opened",
    repository: { full_name: "acme/widgets" },
    pull_request: { number: 482, head: { sha: "head123" }, base: { sha: "base456" } },
    installation: { id: 99 },
    ...over,
  };
}

describe("parsePullRequestTrigger", () => {
  it("parses an opened PR into a scan trigger", () => {
    const t = parsePullRequestTrigger(payload());
    expect(t.kind).toBe("scan");
    if (t.kind !== "scan") throw new Error("expected scan");
    expect(t.input).toEqual({
      owner: "acme",
      name: "widgets",
      prNumber: 482,
      headSha: "head123",
      baseSha: "base456",
      installationId: 99,
    });
  });

  it("handles synchronize + reopened", () => {
    expect(parsePullRequestTrigger(payload({ action: "synchronize" })).kind).toBe("scan");
    expect(parsePullRequestTrigger(payload({ action: "reopened" })).kind).toBe("scan");
  });

  it("ignores non-scan actions (closed, edited, labeled)", () => {
    for (const action of ["closed", "edited", "labeled", ""]) {
      const t = parsePullRequestTrigger(payload({ action }));
      expect(t.kind).toBe("ignore");
    }
  });

  it("ignores malformed payloads (missing shas / repo)", () => {
    expect(parsePullRequestTrigger(payload({ pull_request: { number: 1, head: {}, base: { sha: "b" } } })).kind).toBe("ignore");
    expect(parsePullRequestTrigger(payload({ repository: {} })).kind).toBe("ignore");
    expect(parsePullRequestTrigger({}).kind).toBe("ignore");
  });

  it("treats a missing installation as undefined (self-hosted / token path)", () => {
    const t = parsePullRequestTrigger(payload({ installation: undefined }));
    if (t.kind !== "scan") throw new Error("expected scan");
    expect(t.input.installationId).toBeUndefined();
  });
});
