import { describe, expect, it } from "vitest";
import { envNameFor, parseFileMap, planVariables, reservedReason } from "./names.mjs";

describe("envNameFor", () => {
  it("joins the path into the name so two environments' addresses stay distinct", () => {
    expect(envNameFor("db/primary", "url")).toBe("DB_PRIMARY_URL");
    expect(envNameFor("", "stripe-secret-key")).toBe("STRIPE_SECRET_KEY");
  });

  it("prefixes a leading digit, which is not a legal variable name", () => {
    expect(envNameFor("", "2fa-secret")).toBe("_2FA_SECRET");
  });
});

describe("parseFileMap", () => {
  it("reads one NAME=address per line, ignoring blanks and comments", () => {
    expect(parseFileMap("# a note\nKUBECONFIG=k8s/config\n\n NPM_TOKEN_FILE = npm/token ")).toEqual(
      [
        { variable: "KUBECONFIG", address: "k8s/config" },
        { variable: "NPM_TOKEN_FILE", address: "npm/token" },
      ],
    );
  });

  it("is empty when the input is absent", () => {
    expect(parseFileMap(undefined)).toEqual([]);
  });

  it("refuses a line that is not NAME=address", () => {
    expect(() => parseFileMap("k8s/config")).toThrow(/NAME=path\/name/);
    expect(() => parseFileMap("=k8s/config")).toThrow(/NAME=path\/name/);
  });

  it("refuses a name a shell could not carry", () => {
    expect(() => parseFileMap("MY-VAR=k8s/config")).toThrow(/not a usable environment variable/);
  });
});

const PARAMETERS = [
  { path: "db", name: "url" },
  { path: "", name: "stripe-key" },
  { path: "k8s", name: "config" },
];

describe("planVariables", () => {
  it("delivers every readable parameter as a value by default", () => {
    const plan = planVariables(PARAMETERS, []);
    expect([...plan.keys()]).toEqual(["DB_URL", "STRIPE_KEY", "K8S_CONFIG"]);
    expect([...plan.values()].every((v) => v.mode === "value")).toBe(true);
  });

  it("moves an address named in `files` to file mode under the name asked for", () => {
    const plan = planVariables(PARAMETERS, [{ variable: "KUBECONFIG", address: "k8s/config" }]);
    expect(plan.get("KUBECONFIG")).toEqual({ parameter: PARAMETERS[2], mode: "file" });
    // ...and it is not ALSO delivered as a value under its derived name.
    expect(plan.has("K8S_CONFIG")).toBe(false);
  });

  it("refuses a collision instead of silently picking a winner", () => {
    // A build deploying with the wrong database credential is worse than one that will not start.
    expect(() =>
      planVariables(
        [
          { path: "db", name: "url" },
          { path: "", name: "db-url" },
        ],
        [],
      ),
    ).toThrow(/both map to DB_URL/);
  });

  it("refuses a derived name that collides with one `files` asked for", () => {
    expect(() =>
      planVariables(PARAMETERS, [{ variable: "DB_URL", address: "k8s/config" }]),
    ).toThrow(/both map to DB_URL/);
  });

  it("refuses `files` naming an address this identity cannot read", () => {
    expect(() =>
      planVariables(PARAMETERS, [{ variable: "KUBECONFIG", address: "k8s/other" }]),
    ).toThrow(/cannot read/);
  });

  it("refuses the same variable twice in `files`", () => {
    expect(() =>
      planVariables(PARAMETERS, [
        { variable: "KUBECONFIG", address: "k8s/config" },
        { variable: "KUBECONFIG", address: "db/url" },
      ]),
    ).toThrow(/sets KUBECONFIG twice/);
  });
});

describe("names no delivered value may set", () => {
  const DANGEROUS = [
    ["node", "options", "NODE_OPTIONS"],
    ["", "ld_preload", "LD_PRELOAD"],
    ["ld", "audit", "LD_AUDIT"],
    ["", "bash_env", "BASH_ENV"],
    ["", "env", "ENV"],
    ["", "shellopts", "SHELLOPTS"],
    ["", "ps4", "PS4"],
    ["", "path", "PATH"],
    ["", "ifs", "IFS"],
    ["", "pythonpath", "PYTHONPATH"],
    ["python", "startup", "PYTHON_STARTUP"],
    ["", "perl5opt", "PERL5OPT"],
    ["", "rubyopt", "RUBYOPT"],
    ["java", "tool_options", "JAVA_TOOL_OPTIONS"],
    ["git", "ssh_command", "GIT_SSH_COMMAND"],
    ["git/config", "key_0", "GIT_CONFIG_KEY_0"],
    ["", "dyld_insert_libraries", "DYLD_INSERT_LIBRARIES"],
    ["github", "env", "GITHUB_ENV"],
    ["actions", "id_token_request_url", "ACTIONS_ID_TOKEN_REQUEST_URL"],
    ["runner", "temp", "RUNNER_TEMP"],
    ["npm_config", "script_shell", "NPM_CONFIG_SCRIPT_SHELL"],
    ["", "glibc_tunables", "GLIBC_TUNABLES"],
    ["", "gconv_path", "GCONV_PATH"],
    // Package managers: an index or registry URL is code the next install runs.
    ["pip", "index_url", "PIP_INDEX_URL"],
    ["uv", "default_index", "UV_DEFAULT_INDEX"],
    ["yarn", "npm_registry_server", "YARN_NPM_REGISTRY_SERVER"],
    ["bundle", "mirror__https://rubygems.org", "BUNDLE_MIRROR__HTTPS___RUBYGEMS_ORG"],
    ["cargo", "registries_crates_io_index", "CARGO_REGISTRIES_CRATES_IO_INDEX"],
    ["poetry", "repositories_x_url", "POETRY_REPOSITORIES_X_URL"],
  ];

  it.each(DANGEROUS)("refuses %s/%s, which would become %s", (path, name, variable) => {
    expect(envNameFor(path, name)).toBe(variable);
    expect(reservedReason(variable)).toMatch(/change how your command runs/);
    expect(() => planVariables([{ path, name }], [])).toThrow(
      new RegExp(`maps to ${variable}, which would change how your command runs`),
    );
  });

  it("refuses the same names through `files`, in any case", () => {
    const params = [{ path: "k8s", name: "config" }];
    for (const variable of ["LD_PRELOAD", "ld_preload", "Bash_Env", "NODE_OPTIONS"]) {
      expect(() => planVariables(params, [{ variable, address: "k8s/config" }])).toThrow(
        new RegExp(`sets ${variable}, which would change how your command runs`),
      );
    }
  });

  it("refuses a name that is not a variable at all", () => {
    expect(reservedReason("A-B")).toMatch(/not a usable/);
    expect(reservedReason("")).toMatch(/not a usable/);
    expect(reservedReason("A\nB")).toMatch(/not a usable/);
  });

  it("leaves ordinary secret names alone", () => {
    for (const variable of [
      "DATABASE_URL",
      "AWS_SECRET_ACCESS_KEY",
      "NODE_ENV",
      "NODE_AUTH_TOKEN",
      "NPM_TOKEN",
      "KUBECONFIG",
      "GH_TOKEN",
      "STRIPE_API_KEY",
      "PATH_PREFIX",
    ]) {
      expect(reservedReason(variable), variable).toBeNull();
    }
  });

  it("names the address and the fix, and nothing else, in a refusal", () => {
    expect(() => planVariables([{ path: "", name: "node_options" }], [])).toThrow(
      /node_options maps to NODE_OPTIONS.*Rename the parameter/,
    );
  });
});
