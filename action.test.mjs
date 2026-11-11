import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The published surface. Everything asserted here is a rule that, once broken, ships to every
 * customer that repins — and none of them are visible from a unit test of the logic.
 */
const DIR = import.meta.dirname;
const manifest = readFileSync(resolve(DIR, "action.yml"), "utf8");

/** Comments name the channels this action refuses to use, so they are stripped before scanning. */
function code(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

const sources = readdirSync(DIR)
  .filter((f) => f.endsWith(".mjs") && !f.endsWith(".test.mjs"))
  .map((f) => [f, code(readFileSync(resolve(DIR, f), "utf8"))]);

describe("action.yml", () => {
  it("is a JavaScript action, so `post:` exists at all", () => {
    // A composite action has no `post:`, which would force the credential across a step boundary
    // through a step output or a file to reach the revoke.
    expect(manifest).toMatch(/using:\s*node24/);
    expect(manifest).toMatch(/main:\s*main\.mjs/);
    expect(manifest).toMatch(/post:\s*post\.mjs/);
  });

  it("revokes after a failed build too", () => {
    expect(manifest).toMatch(/post-if:\s*always\(\)/);
  });

  it("takes the audience and the command, and nothing a default could answer", () => {
    for (const input of ["audience:", "run:", "api-origin:", "files:"]) {
      expect(manifest).toContain(input);
    }
    expect(manifest).toContain("default: https://penv.cloud");
  });
});

describe("the rules this action exists to hold", () => {
  it("never uses a third-party action", () => {
    expect(manifest).not.toMatch(/^\s*-?\s*uses:/m);
  });

  it("never writes a value to GITHUB_ENV or job-wide env", () => {
    // `GITHUB_ENV` is a documented RCE primitive and reaches every later step in the job. The one
    // place the name may appear is the list of variables REMOVED from the child's environment.
    const scrubList = /const SCRUBBED = new Set\(\[[\s\S]*?\]\);/;
    for (const [file, raw] of sources) {
      const source = raw.replace(scrubList, "");
      expect(source, file).not.toContain("GITHUB_ENV");
      expect(source, file).not.toContain("GITHUB_OUTPUT");
    }
    expect(manifest).not.toContain("GITHUB_ENV");
  });

  it("never writes anything under GITHUB_WORKSPACE", () => {
    for (const [file, source] of sources) {
      expect(source, file).not.toContain("GITHUB_WORKSPACE");
    }
  });

  it("writes files only under RUNNER_TEMP, at 0600, and removes them", () => {
    const deliver = code(readFileSync(resolve(DIR, "deliver.mjs"), "utf8"));
    expect(deliver).toContain("mode: 0o600");
    expect(deliver).toContain("join(runnerTemp");
    expect(deliver).toMatch(/finally\s*\{/);
  });

  it("depends on nothing but Node's own modules", () => {
    // A package here would be a package in every customer's pipeline. CVE-2025-30066 is that,
    // via a moved tag on an action nobody re-read.
    for (const [file, source] of sources) {
      for (const match of source.matchAll(/from "([^"]+)"/g)) {
        expect(match[1], `${file} imports ${match[1]}`).toMatch(/^(node:|\.\/)/);
      }
    }
  });
});
