/**
 * The end-of-job revoke. THIS FILE IS PUBLISHED — it runs inside every customer's pipeline.
 *
 * It is a LATENCY OPTIMISATION, not the mechanism that makes delivery safe. No in-job hook is
 * guaranteed to run: a force-cancel through the REST API skips even `always()`, a killed runner
 * executes nothing further because `post:` runs in the process that just died, and the server
 * terminates everything five minutes after a cancellation regardless. What bounds a delivered
 * credential's life is the server's short TTL. This just makes the usual case shorter.
 *
 * So it never fails the job. A build that already succeeded must not turn red because a revoke
 * could not reach the network, and an already-revoked credential is answered as success by the
 * server for the same reason.
 */
export async function revokePost({ env, api, emit, warn }) {
  const credential = env.STATE_credential;
  const origin = env.STATE_origin;
  // Delivery threw before it minted anything. There is nothing to revoke and nothing to say.
  if (!credential || !origin) return;

  const result = await api.revokeSelf(origin, credential);
  if (result.revoked) {
    emit("Revoked this run's penv-cloud credential.");
    return;
  }
  warn(
    `Could not revoke this run's penv-cloud credential: ${result.reason} It expires on its own within minutes.`,
  );
}
