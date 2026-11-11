import { mkdtemp, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { deliver } from "./deliver.mjs";

const VALUES = {
  "db/url": "postgres://user:a-long-password@host/db",
  "k8s/config": "apiVersion: v1\nclusters: []\n",
};

let temp;
let statePath;
let emitted;
let warnings;
let spawned;

function api(overrides = {}) {
  return {
    mintIdToken: async () => "header.payload.signature-of-an-id-token",
    exchangeForDelivery: async () => "pck_a-delivered-credential",
    listParameters: async () => [
      { path: "db", name: "url" },
      { path: "k8s", name: "config" },
    ],
    readValue: async (_origin, _credential, parameter) =>
      VALUES[`${parameter.path}/${parameter.name}`],
    ...overrides,
  };
}

function environment(extra = {}) {
  return {
    INPUT_AUDIENCE: "1a2b3c4d-0000-4000-8000-000000000000",
    INPUT_RUN: "npm run deploy",
    "INPUT_API-ORIGIN": "https://penv.cloud",
    RUNNER_TEMP: temp,
    GITHUB_STATE: statePath,
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://runner/token?x=1",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-request-token",
    PATH: "/usr/bin",
    ...extra,
  };
}

function run(extra = {}, overrides = {}) {
  return deliver({
    env: environment(extra),
    api: api(overrides),
    emit: (line) => emitted.push(line),
    warn: (message) => warnings.push(message),
    spawnChild: async (command, args, options) => {
      spawned.push({ command, args, options });
      return 0;
    },
  });
}

beforeEach(async () => {
  temp = await mkdtemp(join(tmpdir(), "penv-run-"));
  statePath = join(temp, "state");
  await writeFile(statePath, "");
  emitted = [];
  warnings = [];
  spawned = [];
});

describe("the child process is the only thing that gets a value", () => {
  it("puts every value in the child's environment", async () => {
    await run();
    expect(spawned[0].options.env.DB_URL).toBe(VALUES["db/url"]);
    expect(spawned[0].options.env.K8S_CONFIG).toBe(VALUES["k8s/config"]);
  });

  it("never puts a value in argv", async () => {
    await run();
    // `ps x -w` reads another process's argv across the whole job.
    const argv = JSON.stringify(spawned[0].args);
    for (const value of Object.values(VALUES)) expect(argv).not.toContain(value);
    expect(spawned[0].args.at(-1)).toBe("npm run deploy");
  });

  it("never hands the credential to the child", async () => {
    await run();
    expect(JSON.stringify(spawned[0].options.env)).not.toContain("pck_a-delivered-credential");
  });

  it("hands the child none of the runner's step-only channels or tokens", async () => {
    await run({
      GITHUB_ENV: "/runner/env",
      GITHUB_OUTPUT: "/runner/output",
      GITHUB_PATH: "/runner/path",
      ACTIONS_RUNTIME_TOKEN: "runtime-token",
      ACTIONS_RESULTS_URL: "https://results",
      STATE_credential: "pck_left-over",
      GITHUB_SHA: "abc123",
    });
    const child = spawned[0].options.env;
    for (const name of [
      "ACTIONS_ID_TOKEN_REQUEST_URL",
      "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
      "ACTIONS_RUNTIME_TOKEN",
      "ACTIONS_RESULTS_URL",
      "GITHUB_STATE",
      "GITHUB_ENV",
      "GITHUB_OUTPUT",
      "GITHUB_PATH",
      "INPUT_AUDIENCE",
      "INPUT_RUN",
      "STATE_credential",
    ]) {
      expect(child[name], name).toBeUndefined();
    }
    // What the command legitimately reads from the job still reaches it.
    expect(child.PATH).toBe("/usr/bin");
    expect(child.GITHUB_SHA).toBe("abc123");
    expect(JSON.stringify(child)).not.toContain("runner-request-token");
  });

  it("refuses a parameter that would set NODE_OPTIONS before opening any value", async () => {
    let read = 0;
    await expect(
      run(
        {},
        {
          listParameters: async () => [
            { path: "db", name: "url" },
            { path: "node", name: "options" },
          ],
          readValue: async () => {
            read += 1;
            return "--require /tmp/evil.js";
          },
        },
      ),
    ).rejects.toThrow(/node\/options maps to NODE_OPTIONS/);
    expect(read).toBe(0);
    expect(spawned).toHaveLength(0);
  });

  it("writes nothing to the workspace", async () => {
    await run({ GITHUB_WORKSPACE: join(temp, "workspace") });
    // ArtiPACKED: the next artifact-upload or cache-save step takes the workspace with it.
    await expect(readdir(join(temp, "workspace"))).rejects.toThrow();
  });

  it("runs the command through the same shell a `run:` step would use", async () => {
    await run();
    expect(spawned[0].command).toBe("bash");
    expect(spawned[0].args.slice(0, -1)).toEqual([
      "--noprofile",
      "--norc",
      "-eo",
      "pipefail",
      "-c",
    ]);
  });

  it("returns the child's exit code so a failing command fails the step", async () => {
    const code = await deliver({
      env: environment(),
      api: api(),
      emit: () => {},
      warn: () => {},
      spawnChild: async () => 17,
    });
    expect(code).toBe(17);
  });
});

describe("masking", () => {
  it("registers the credential, the OIDC token and every value before the command runs", async () => {
    await run();
    const masks = emitted.filter((line) => line.startsWith("::add-mask::"));
    expect(masks).toContain("::add-mask::pck_a-delivered-credential");
    expect(masks).toContain("::add-mask::header.payload.signature-of-an-id-token");
    expect(masks).toContain(`::add-mask::${VALUES["db/url"]}`);
  });

  it("registers each line of a multi-line value", async () => {
    await run();
    expect(emitted).toContain("::add-mask::apiVersion: v1");
    expect(emitted).toContain("::add-mask::clusters: []");
  });

  it("warns when a value is too short for masking to mean anything", async () => {
    await run({}, { readValue: async () => "80" });
    expect(warnings.some((w) => w.includes("was NOT masked"))).toBe(true);
  });
});

describe("file mode", () => {
  const files = { INPUT_FILES: "KUBECONFIG=k8s/config" };

  it("hands the child a path, not the value", async () => {
    await run(files);
    const path = spawned[0].options.env.KUBECONFIG;
    expect(path.startsWith(temp)).toBe(true);
    expect(spawned[0].options.env.K8S_CONFIG).toBeUndefined();
  });

  it("writes the file under RUNNER_TEMP and removes it before the step ends", async () => {
    let contentDuringRun;
    let pathDuringRun;
    await deliver({
      env: environment(files),
      api: api(),
      emit: () => {},
      warn: () => {},
      spawnChild: async (_c, _a, options) => {
        pathDuringRun = options.env.KUBECONFIG;
        contentDuringRun = await readFile(pathDuringRun, "utf8");
        return 0;
      },
    });
    expect(contentDuringRun).toBe(VALUES["k8s/config"]);
    await expect(stat(pathDuringRun)).rejects.toThrow();
  });

  it("removes the file even when the command throws", async () => {
    let pathDuringRun;
    await expect(
      deliver({
        env: environment(files),
        api: api(),
        emit: () => {},
        warn: () => {},
        spawnChild: async (_c, _a, options) => {
          pathDuringRun = options.env.KUBECONFIG;
          throw new Error("the command blew up");
        },
      }),
    ).rejects.toThrow("the command blew up");
    await expect(stat(pathDuringRun)).rejects.toThrow();
  });

  it.skipIf(process.platform === "win32")("writes it 0600", async () => {
    let mode;
    await deliver({
      env: environment(files),
      api: api(),
      emit: () => {},
      warn: () => {},
      spawnChild: async (_c, _a, options) => {
        mode = (await stat(options.env.KUBECONFIG)).mode & 0o777;
        return 0;
      },
    });
    expect(mode).toBe(0o600);
  });
});

describe("what it refuses", () => {
  it("hands the post step the credential through GITHUB_STATE and nothing else", async () => {
    await run();
    const state = await readFile(statePath, "utf8");
    expect(state).toContain("credential=pck_a-delivered-credential");
    expect(state).toContain("origin=https://penv.cloud");
  });

  it("names the missing permission when the runner minted no token endpoint", async () => {
    await expect(
      deliver({
        env: { ...environment(), ACTIONS_ID_TOKEN_REQUEST_URL: undefined },
        api: api(),
        emit: () => {},
        warn: () => {},
        spawnChild: async () => 0,
      }),
    ).rejects.toThrow(/id-token: write/);
  });

  it("refuses a Windows runner rather than pretending 0600 held", async () => {
    await expect(run({ RUNNER_OS: "Windows" })).rejects.toThrow(/Linux and macOS/);
  });

  it("never reaches the exchange when the audience is missing", async () => {
    let exchanged = false;
    await expect(
      run({ INPUT_AUDIENCE: undefined }, { exchangeForDelivery: async () => (exchanged = true) }),
    ).rejects.toThrow(/INPUT_AUDIENCE/);
    expect(exchanged).toBe(false);
  });
});

describe("a declared key with no stored value", () => {
  // `readValue` answers `null` only for the server's 404 `not_found`, which is genuine absence.
  const unwritten = {
    readValue: async (_origin, _credential, parameter) =>
      parameter.name === "url" ? null : VALUES[`${parameter.path}/${parameter.name}`],
  };

  it("is named in a warning while the others still reach the command", async () => {
    await run({}, unwritten);
    expect(spawned[0].options.env.DB_URL).toBeUndefined();
    expect(spawned[0].options.env.K8S_CONFIG).toBe(VALUES["k8s/config"]);
    expect(warnings.some((w) => w.includes("db/url has no stored value"))).toBe(true);
    expect(emitted).toContain("Delivered 1 secret(s) to this command and nothing else.");
  });

  it("fails the step when `files` asked for it by name", async () => {
    await expect(run({ INPUT_FILES: "DB_FILE=db/url" }, unwritten)).rejects.toThrow(
      /files` names db\/url, which has no stored value/,
    );
    expect(spawned).toHaveLength(0);
  });

  it("is never how an unopenable value is read: that failure still stops the step", async () => {
    const undecryptable = {
      readValue: async () => {
        throw new Error("penv-cloud: reading url answered 500 (internal).");
      },
    };
    await expect(run({}, undecryptable)).rejects.toThrow(/500/);
    expect(spawned).toHaveLength(0);
  });
});

describe("the API origin", () => {
  it("drops a trailing slash so every route is one path", async () => {
    await run({ "INPUT_API-ORIGIN": "https://cloud.example.test/" });
    expect(await readFile(statePath, "utf8")).toContain("origin=https://cloud.example.test\n");
  });

  it("refuses plain http before any token is minted", async () => {
    let minted = false;
    await expect(
      run(
        { "INPUT_API-ORIGIN": "http://cloud.example.test" },
        { mintIdToken: async () => (minted = true) },
      ),
    ).rejects.toThrow(/not https/);
    expect(minted).toBe(false);
  });

  it("allows plain http to the loopback a local server runs on", async () => {
    await run({ "INPUT_API-ORIGIN": "http://127.0.0.1:3000" });
    expect(spawned).toHaveLength(1);
  });

  it("refuses an origin carrying a path or a user", async () => {
    await expect(run({ "INPUT_API-ORIGIN": "https://penv.cloud/api" })).rejects.toThrow(
      /no path, user or query/,
    );
    await expect(run({ "INPUT_API-ORIGIN": "https://u@penv.cloud" })).rejects.toThrow(
      /no path, user or query/,
    );
  });
});
