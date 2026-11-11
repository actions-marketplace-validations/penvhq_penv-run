/**
 * The wire. THIS FILE IS PUBLISHED — it runs inside every customer's pipeline.
 *
 * Dependency-free on purpose: `fetch` is a Node built-in, and a package here would be a package in
 * every customer's supply chain. No third-party code, the same rule `.github/workflows/connect.yml`
 * already holds.
 *
 * Nothing in this file ever puts a token or a value into a thrown message, a URL path, or a query
 * string. An error names the status and the endpoint, and stops there.
 */

/** Every call is on a build's critical path, so none of them may hang. */
const TIMEOUT_MS = 15_000;

async function request(url, init, what) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response;
  try {
    // `redirect: "error"` so a 3xx cannot replay a credential-bearing request at another origin.
    response = await fetch(url, { ...init, signal: controller.signal, redirect: "error" });
  } catch (cause) {
    throw new Error(`penv-cloud: ${what} could not be reached.`, { cause });
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(
      `penv-cloud: ${what} answered ${response.status} (${body.error ?? "no code"}).`,
    );
    // The status and the code, so a caller can tell a genuine absence from everything else.
    error.status = response.status;
    error.code = typeof body.error === "string" ? body.error : undefined;
    throw error;
  }
  return response.json();
}

/** The runner mints this on demand; it exists only because the job asked for `id-token: write`. */
export async function mintIdToken(requestUrl, requestToken, audience) {
  const url = `${requestUrl}&audience=${encodeURIComponent(audience)}`;
  const body = await request(
    url,
    { headers: { authorization: `bearer ${requestToken}` } },
    "the runner's OIDC token endpoint",
  );
  if (typeof body.value !== "string" || !body.value) {
    throw new Error("penv-cloud: the runner returned no OIDC token.");
  }
  return body.value;
}

export async function exchangeForDelivery(origin, idToken) {
  const body = await request(
    `${origin}/api/v1/auth/oidc/delivery`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: idToken }),
    },
    "the delivery exchange",
  );
  if (typeof body.credential !== "string" || !body.credential) {
    throw new Error("penv-cloud: the delivery exchange returned no credential.");
  }
  return body.credential;
}

/** Names only — listing reveals nothing. A dynamic address has no stored value to deliver. */
export async function listParameters(origin, credential) {
  const body = await request(
    `${origin}/api/v1/secrets`,
    { headers: { authorization: `Bearer ${credential}` } },
    "the parameter list",
  );
  return (body.parameters ?? []).filter((p) => p.kind !== "dynamic");
}

/** The value, or `null` when this address holds no stored value (a 404 `not_found`). */
export async function readValue(origin, credential, parameter) {
  const address = [parameter.path, parameter.name]
    .filter(Boolean)
    .join("/")
    .split("/")
    .map(encodeURIComponent)
    .join("/");
  let body;
  try {
    body = await request(
      `${origin}/api/v1/secrets/${address}`,
      { headers: { authorization: `Bearer ${credential}` } },
      `reading ${parameter.name}`,
    );
  } catch (error) {
    // A declared key that was never given a value in this environment: listed, and genuinely
    // empty. `null` is that absence and nothing else — a value the server holds but cannot open
    // answers 5xx and still throws, because "cannot decrypt" is never "no value".
    if (error.status === 404 && error.code === "not_found") return null;
    throw error;
  }
  if (typeof body.value !== "string") {
    throw new Error(`penv-cloud: ${parameter.name} returned no value.`);
  }
  return body.value;
}

/**
 * Best effort, and it says so by never throwing. Correctness is the server's short TTL; this only
 * shortens the window. A build that already succeeded must not be failed by a revoke that could
 * not reach the network.
 */
export async function revokeSelf(origin, credential) {
  try {
    await request(
      `${origin}/api/v1/auth/revoke`,
      { method: "POST", headers: { authorization: `Bearer ${credential}` } },
      "the revoke endpoint",
    );
    return { revoked: true };
  } catch (error) {
    return { revoked: false, reason: error.message };
  }
}
