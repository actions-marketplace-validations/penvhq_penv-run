import { afterEach, describe, expect, it, vi } from "vitest";
import { readValue } from "./api.mjs";

const PARAMETER = { path: "db", name: "url" };

function answer(status, body) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(body), { status })),
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("readValue", () => {
  it("returns the value the server opened", async () => {
    answer(200, { value: "postgres://a-value", version: 3 });
    expect(await readValue("https://penv.cloud", "pck_x", PARAMETER)).toBe("postgres://a-value");
  });

  it("returns null for a 404 not_found, the one answer that means no stored value", async () => {
    answer(404, { error: "not_found" });
    expect(await readValue("https://penv.cloud", "pck_x", PARAMETER)).toBeNull();
  });

  it("throws on a server failure, so an unopenable value is never read as absent", async () => {
    answer(500, { error: "internal" });
    await expect(readValue("https://penv.cloud", "pck_x", PARAMETER)).rejects.toThrow(
      /answered 500 \(internal\)/,
    );
  });

  it("throws on a 404 that is not the not_found code", async () => {
    answer(404, {});
    await expect(readValue("https://penv.cloud", "pck_x", PARAMETER)).rejects.toThrow(/404/);
  });

  it("throws on a dynamic address rather than calling it empty", async () => {
    answer(409, { error: "dynamic" });
    await expect(readValue("https://penv.cloud", "pck_x", PARAMETER)).rejects.toThrow(/dynamic/);
  });
});
