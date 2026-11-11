import { describe, expect, it, vi } from "vitest";
import { revokePost } from "./revoke.mjs";

function harness(env, revokeSelf) {
  const emitted = [];
  const warnings = [];
  return {
    emitted,
    warnings,
    run: () =>
      revokePost({
        env,
        api: { revokeSelf },
        emit: (line) => emitted.push(line),
        warn: (message) => warnings.push(message),
      }),
  };
}

const STATE = { STATE_credential: "pck_delivered", STATE_origin: "https://penv.cloud" };

describe("the end-of-job revoke", () => {
  it("spends the credential the delivery step saved", async () => {
    const revokeSelf = vi.fn(async () => ({ revoked: true }));
    const h = harness(STATE, revokeSelf);
    await h.run();
    expect(revokeSelf).toHaveBeenCalledWith("https://penv.cloud", "pck_delivered");
    expect(h.emitted).toEqual(["Revoked this run's penv-cloud credential."]);
  });

  it("warns instead of failing when it cannot reach us", async () => {
    // The build may already have succeeded. Correctness is the server's TTL, not this hook, so
    // turning a green run red here would be trading a real outcome for a cosmetic one.
    const h = harness(STATE, async () => ({ revoked: false, reason: "network down." }));
    await expect(h.run()).resolves.toBeUndefined();
    expect(h.warnings[0]).toContain("expires on its own within minutes");
  });

  it("does nothing at all when delivery never minted a credential", async () => {
    const revokeSelf = vi.fn();
    const h = harness({}, revokeSelf);
    await h.run();
    expect(revokeSelf).not.toHaveBeenCalled();
    expect(h.emitted).toEqual([]);
    expect(h.warnings).toEqual([]);
  });
});
