import { describe, expect, it } from "vitest";
import { mask, maskCandidates } from "./mask.mjs";

function collect(value, label = "A value") {
  const emitted = [];
  const warnings = [];
  mask(
    value,
    label,
    (line) => emitted.push(line),
    (message) => warnings.push(message),
  );
  return { emitted, warnings };
}

describe("maskCandidates", () => {
  it("registers the whole value AND every line", () => {
    const key = "-----BEGIN KEY-----\nMIIBOgIBAAJBAK\n-----END KEY-----";
    expect(maskCandidates(key)).toEqual(
      expect.arrayContaining(["-----BEGIN KEY-----", "MIIBOgIBAAJBAK", "-----END KEY-----"]),
    );
  });

  it("registers a single-line value whole", () => {
    expect(maskCandidates("pck_abcdefghijklmnop")).toEqual(["pck_abcdefghijklmnop"]);
  });

  it("never registers a multi-line value as one entry", () => {
    // `::add-mask::` reads to the end of a line, so an entry containing a newline would register
    // only the first line while claiming to cover the blob.
    expect(maskCandidates("alpha\nbravo").some((c) => c.includes("\n"))).toBe(false);
  });

  it("registers every leaf of a JSON document, not the document", () => {
    const blob = JSON.stringify({ client_email: "svc@example.com", private_key: "abcd1234" });
    expect(maskCandidates(blob)).toEqual(
      expect.arrayContaining(["svc@example.com", "abcd1234", blob]),
    );
  });

  it("reaches leaves nested in objects and arrays", () => {
    const blob = JSON.stringify({ creds: [{ token: "nested-secret-value" }] });
    expect(maskCandidates(blob)).toContain("nested-secret-value");
  });

  it("orders longest first, so a substring cannot shred the entry that contains it", () => {
    const lengths = maskCandidates(
      JSON.stringify({ a: "short-one", b: "a-considerably-longer-one" }),
    ).map((c) => c.length);
    expect(lengths).toEqual([...lengths].sort((x, y) => y - x));
  });

  it("drops candidates too short to mask without redacting unrelated output", () => {
    expect(maskCandidates("ab")).toEqual([]);
  });
});

describe("mask", () => {
  it("escapes the workflow-command data, so an embedded %0A is not un-escaped into a newline", () => {
    // Unescaped, the runner would register two lines and mask neither of them correctly.
    const { emitted } = collect("secret%0Avalue%25here");
    expect(emitted).toEqual(["::add-mask::secret%250Avalue%2525here"]);
  });

  it("escapes a carriage return", () => {
    const { emitted } = collect("alpha\rbravo");
    expect(emitted[0]).toBe("::add-mask::alpha%0Dbravo");
  });

  it("refuses to mask a value too short to mask, and says so", () => {
    const { emitted, warnings } = collect("ab", "DB_PORT");
    expect(emitted).toEqual([]);
    expect(warnings).toEqual([expect.stringContaining("was NOT masked")]);
    expect(warnings[0]).toContain("DB_PORT");
  });

  it("warns that masking a short value means very little, but still masks it", () => {
    const { emitted, warnings } = collect("abc123", "API_KEY");
    expect(emitted).toEqual(["::add-mask::abc123"]);
    expect(warnings).toEqual([expect.stringContaining("means very little")]);
  });

  it("says nothing about a value long enough for masking to matter", () => {
    const { warnings } = collect("pck_a-long-enough-credential");
    expect(warnings).toEqual([]);
  });
});
