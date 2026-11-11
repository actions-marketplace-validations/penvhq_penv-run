import { randomBytes } from "node:crypto";
import { appendFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { mask } from "./mask.mjs";
import { addressOf, parseFileMap, planVariables } from "./names.mjs";

/**
 * Delivery. THIS FILE IS PUBLISHED — it runs inside every customer's pipeline.
 *
 * Values reach the customer's command through the CHILD PROCESS ENVIRONMENT and nowhere else.
 * Every other channel a GitHub Action could use is closed on purpose, and none of these are style:
 *
 *  - `GITHUB_ENV` is a documented remote-code-execution primitive (`LD_PRELOAD`, `NODE_OPTIONS`)
 *    and would hand the value to every later step in the job.
 *  - Job-wide `env:` does the same thing more quietly.
 *  - Step and job outputs are read by later steps, and a secret-tainted JOB output is silently
 *    DROPPED by the runner rather than masked — which is why delivery is an action in the caller's
 *    own job and not a reusable workflow.
 *  - argv is world-readable through `ps x -w` for as long as the process lives.
 *  - `GITHUB_WORKSPACE` is the ArtiPACKED and cache-poisoning blast radius: it gets uploaded as an
 *    artifact and saved into caches by steps that have no idea what is in it.
 *
 * A file is written only where a tool cannot read an environment variable — a kubeconfig, a PEM, an
 * `.npmrc`. It goes to `$RUNNER_TEMP` with mode 0600 and is removed before this step ends.
 *
 * None of this defends against a malicious step in the SAME JOB. Co-location is disclosure:
 * CVE-2025-30066's payload read `Runner.Worker` process memory, lifted the runner's own secret
 * table and double-base64'd it past the masker. That is not a gap being closed here, and the
 * documentation says so rather than implying otherwise.
 */

/**
 * What the runner handed THIS step that the customer's command has no use for, and that a
 * hijacked command could turn into more than it was given: the OIDC request token mints a fresh
 * id-token for any audience; the runtime token reaches the cache and artifact services; the state
 * file holds this run's credential for the post step; and the env, output and path files reach
 * every later step in the job (the channels the header above closes). `INPUT_*` and `STATE_*` are
 * this action's own.
 */
const SCRUBBED = new Set([
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  "ACTIONS_ID_TOKEN_REQUEST_URL",
  "ACTIONS_RUNTIME_TOKEN",
  "ACTIONS_RUNTIME_URL",
  "ACTIONS_RESULTS_URL",
  "ACTIONS_CACHE_URL",
  "ACTIONS_CACHE_SERVICE_V2",
  "GITHUB_STATE",
  "GITHUB_ENV",
  "GITHUB_OUTPUT",
  "GITHUB_PATH",
]);
const SCRUBBED_PREFIXES = ["INPUT_", "STATE_"];

/** The child's environment: the job's, minus what only this step needed, plus the values. */
export function childEnvironment(env, values) {
  const child = {};
  for (const [name, value] of Object.entries(env)) {
    if (SCRUBBED.has(name) || SCRUBBED_PREFIXES.some((p) => name.startsWith(p))) continue;
    child[name] = value;
  }
  return { ...child, ...values };
}

/** Matches the shell GitHub gives a `run:` step, so a customer's command behaves as it would there. */
const SHELL_ARGS = ["--noprofile", "--norc", "-eo", "pipefail", "-c"];

/**
 * The API origin, with no trailing slash. https only, except the loopback a local server runs on:
 * the delivered credential is sent here, and plain http would hand it to the network.
 */
export function checkedOrigin(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`penv-cloud: api-origin ${raw} is not a URL. Leave it unset for penv.cloud.`);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error(
      `penv-cloud: api-origin ${url.origin} is not https, and the credential only travels over https.`,
    );
  }
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error(
      `penv-cloud: api-origin must be an origin such as https://penv.cloud, with no path, user or query.`,
    );
  }
  return url.origin;
}

function requireEnv(env, name, why) {
  const value = env[name];
  if (!value) throw new Error(`penv-cloud: ${name} is not set. ${why}`);
  return value;
}

/**
 * Run the customer's command with penv-cloud values in its environment.
 *
 * `api`, `emit`, `warn` and `spawnChild` are injected so every rule above is provable without a
 * runner — a test that could not see the child's environment could not prove the child is the only
 * thing that gets one.
 */
export async function deliver({ env, api, emit, warn, spawnChild }) {
  if (env.RUNNER_OS === "Windows") {
    throw new Error(
      "penv-cloud: this action supports Linux and macOS runners. Windows has no 0600 and no bash, so neither rule this action depends on would hold.",
    );
  }

  const audience = requireEnv(env, "INPUT_AUDIENCE", "It is your penv-cloud org id.");
  const command = requireEnv(env, "INPUT_RUN", "It is the command to run with your secrets.");
  const origin = checkedOrigin(env["INPUT_API-ORIGIN"] || "https://penv.cloud");
  const runnerTemp = requireEnv(env, "RUNNER_TEMP", "This action must run on a GitHub runner.");
  const statePath = requireEnv(
    env,
    "GITHUB_STATE",
    "Without it the end-of-job revoke has no credential to spend.",
  );
  const requestUrl = requireEnv(
    env,
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "Grant `id-token: write` to this job — it does not inherit.",
  );
  const requestToken = requireEnv(
    env,
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "Grant `id-token: write` to this job — it does not inherit.",
  );

  const idToken = await api.mintIdToken(requestUrl, requestToken, audience);
  mask(idToken, "The OIDC token", emit, warn);
  const credential = await api.exchangeForDelivery(origin, idToken);
  mask(credential, "The penv-cloud credential", emit, warn);
  // The post step's only copy. It is exposed as `STATE_credential` on that step alone, never to
  // the customer's command and never to another step.
  await appendFile(statePath, `credential=${credential}\n`);
  await appendFile(statePath, `origin=${origin}\n`);

  const parameters = await api.listParameters(origin, credential);
  const plan = planVariables(parameters, parseFileMap(env.INPUT_FILES));

  const values = {};
  const written = [];
  try {
    let delivered = 0;
    for (const [variable, { parameter, mode }] of plan) {
      const value = await api.readValue(origin, credential, parameter);
      if (value === null) {
        // A file the customer named explicitly is a requirement, not a nicety.
        if (mode === "file") {
          throw new Error(
            `penv-cloud: \`files\` names ${addressOf(parameter)}, which has no stored value in this environment. Set one with penv set, or remove it from \`files\`.`,
          );
        }
        // Named, never silently dropped: the others still load, as native penv does.
        warn(
          `${addressOf(parameter)} has no stored value in this environment, so ${variable} is not set. Set one with penv set.`,
        );
        continue;
      }
      delivered += 1;
      mask(value, addressOf(parameter), emit, warn);
      if (mode === "value") {
        values[variable] = value;
        continue;
      }
      // Never `GITHUB_WORKSPACE`: a file there is uploaded by the next artifact step and saved by
      // the next cache step, by people who never knew it was there.
      const path = join(runnerTemp, `penv-${randomBytes(12).toString("hex")}`);
      await writeFile(path, value, { mode: 0o600, flag: "wx" });
      written.push(path);
      values[variable] = path;
    }

    emit(`Delivered ${delivered} secret(s) to this command and nothing else.`);
    return await spawnChild("bash", [...SHELL_ARGS, command], {
      env: childEnvironment(env, values),
      stdio: "inherit",
    });
  } finally {
    // Same step, always — including when the command failed or threw. A file that outlives this
    // block is a file the rest of the job can read.
    for (const path of written) await rm(path, { force: true });
  }
}
