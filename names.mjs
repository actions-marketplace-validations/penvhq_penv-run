/**
 * Turning a penv-cloud address into the environment variable a build reads.
 *
 * THIS FILE IS PUBLISHED — it runs inside every customer's pipeline.
 *
 * The mapping is total and deterministic, and a collision is an ERROR rather than a winner. Two
 * addresses that both want `DATABASE_URL` mean one of them silently would not arrive, and a build
 * deploying with the wrong database credential is worse than a build that refuses to start.
 */

/** `db/primary` + `url` → `DB_PRIMARY_URL`. A leading digit is not a legal variable name. */
export function envNameFor(path, name) {
  const address = path ? `${path}/${name}` : name;
  const upper = address.toUpperCase().replace(/[^A-Z0-9_]/g, "_");
  return /^[0-9]/.test(upper) ? `_${upper}` : upper;
}

/**
 * Variables no delivered value may set, because each one changes what the customer's command
 * RUNS rather than what it reads. Whoever can write a secret is usually far less trusted than
 * whoever can edit the workflow, and without this list `secret:write` would be code execution in
 * the job that holds the OIDC token: a parameter named `node/options` becomes `NODE_OPTIONS`.
 *
 * Exact names, compared after upper-casing (a `files:` entry may be lower case, and `http_proxy`
 * style lower-case variables are honoured by some tools).
 */
const RESERVED_NAMES = new Set([
  // Shells: startup files, tracing, prompts, word splitting and lookup.
  "BASH_ENV",
  "ENV",
  "SHELLOPTS",
  "BASHOPTS",
  "PS1",
  "PS2",
  "PS3",
  "PS4",
  "PROMPT_COMMAND",
  "IFS",
  "CDPATH",
  "GLOBIGNORE",
  "EXECIGNORE",
  "FPATH",
  "ZDOTDIR",
  "SHELL",
  "PATH",
  "HOME",
  "XDG_CONFIG_HOME",
  "XDG_CONFIG_DIRS",
  "XDG_DATA_DIRS",
  // The C library's own "unsecure" list (glibc unsecvars.h): ignored for setuid, honoured here.
  "GCONV_PATH",
  "GETCONF_DIR",
  "GLIBC_TUNABLES",
  "HOSTALIASES",
  "LOCALDOMAIN",
  "LOCPATH",
  "NIS_PATH",
  "NLSPATH",
  "RESOLV_HOST_CONF",
  "RES_OPTIONS",
  "TMPDIR",
  "TZDIR",
  // Node.
  "NODE_OPTIONS",
  "NODE_PATH",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "NODE_EXTRA_CA_CERTS",
  "NODE_REPL_EXTERNAL_MODULE",
  "NODE_V8_COVERAGE",
  "NODE_ICU_DATA",
  "NODE_REDIRECT_WARNINGS",
  "NODE_COMPILE_CACHE",
  "COREPACK_NPM_REGISTRY",
  "COREPACK_HOME",
  // Ruby, JVM, .NET, Lua, R, PHP, Tcl.
  "RUBYOPT",
  "RUBYLIB",
  "RUBYSHELL",
  "JAVA_TOOL_OPTIONS",
  "_JAVA_OPTIONS",
  "JDK_JAVA_OPTIONS",
  "JAVA_OPTS",
  "JAVA_OPTIONS",
  "JAVA_HOME",
  "CLASSPATH",
  "MAVEN_OPTS",
  "MAVEN_ARGS",
  "GRADLE_OPTS",
  "SBT_OPTS",
  "ANT_OPTS",
  "DOTNET_STARTUP_HOOKS",
  "DOTNET_ADDITIONAL_DEPS",
  "COR_ENABLE_PROFILING",
  "COR_PROFILER",
  "COR_PROFILER_PATH",
  "PHPRC",
  "PHP_INI_SCAN_DIR",
  "TCLLIBPATH",
  // Go, Rust and the C toolchain a native module build runs.
  "GOFLAGS",
  "GOENV",
  "GOTOOLCHAIN",
  "GOPROXY",
  "GOSUMDB",
  "GONOSUMDB",
  "GONOSUMCHECK",
  "GOINSECURE",
  "RUSTC",
  "RUSTC_WRAPPER",
  "RUSTC_WORKSPACE_WRAPPER",
  "RUSTDOC",
  "CC",
  "CXX",
  "CPP",
  "LD",
  "AR",
  "AS",
  "MAKEFLAGS",
  "MFLAGS",
  "MAKEFILES",
  "OPENSSL_CONF",
  "OPENSSL_ENGINES",
  "OPENSSL_MODULES",
  // Programs other programs launch.
  "EDITOR",
  "VISUAL",
  "PAGER",
  "MANPAGER",
  "BROWSER",
  "LESSOPEN",
  "LESSCLOSE",
  "SSH_ASKPASS",
  "SSH_ASKPASS_REQUIRE",
  "SSH_AUTH_SOCK",
  "SUDO_ASKPASS",
  // Where the GitHub CLI sends the job's token.
  "GH_HOST",
  "GH_ENTERPRISE_TOKEN",
  "GITHUB_API_URL",
]);

/**
 * Whole namespaces: the dynamic loaders, interpreters whose every variable is configuration, git
 * (`GIT_CONFIG_KEY_0=core.sshCommand` is a command), npm's config (`npm_config_script_shell`),
 * the runner's own variables (GitHub refuses repository secrets named `GITHUB_*` for the same
 * reason), and penv's own.
 *
 * Every package manager's configuration namespace, too: an index or registry URL
 * (`PIP_INDEX_URL`, `UV_DEFAULT_INDEX`, `YARN_NPM_REGISTRY_SERVER`, `BUNDLE_MIRROR__*`,
 * `CARGO_REGISTRIES_*`) points the job's next install at a server the secret's writer runs, and
 * that server's package runs code in the job, which holds `id-token: write`.
 */
const RESERVED_PREFIXES = [
  "LD_",
  "DYLD_",
  "BASH_",
  "MALLOC_",
  "PYTHON",
  "PERL",
  "GIT_",
  "NPM_CONFIG_",
  "CORECLR_",
  "LUA_PATH",
  "LUA_CPATH",
  "LUA_INIT",
  "R_PROFILE",
  "R_ENVIRON",
  "CARGO_",
  "RUSTUP_",
  "PIP_",
  "PIPX_",
  "UV_",
  "POETRY_",
  "CONDA_",
  "YARN_",
  "PNPM_",
  "BUNDLE_",
  "GEM_",
  "COMPOSER_",
  "NUGET_",
  "GITHUB_",
  "RUNNER_",
  "ACTIONS_",
  "INPUT_",
  "STATE_",
  "PENV_",
];

const VARIABLE_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Why this variable may not be set from a delivered value, or null when it may. Exported so the
 * test pins the list, and so a refusal names the variable, never the value.
 */
export function reservedReason(variable) {
  if (!VARIABLE_RE.test(variable)) return "is not a usable environment variable name";
  const upper = variable.toUpperCase();
  if (RESERVED_NAMES.has(upper) || RESERVED_PREFIXES.some((p) => upper.startsWith(p))) {
    return "would change how your command runs, so no delivered value may set it";
  }
  return null;
}

/** `NAME=path/name` per line, blank lines and `#` comments ignored. */
export function parseFileMap(input) {
  const entries = [];
  for (const line of (input ?? "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const split = trimmed.indexOf("=");
    if (split <= 0) {
      throw new Error(`\`files\` needs NAME=path/name on every line. Got: ${trimmed}`);
    }
    const variable = trimmed.slice(0, split).trim();
    const address = trimmed.slice(split + 1).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(variable)) {
      throw new Error(`${variable} is not a usable environment variable name.`);
    }
    if (!address) throw new Error(`${variable} in \`files\` names no address.`);
    entries.push({ variable, address });
  }
  return entries;
}

/** `{path, name}` → the `path/name` string `files` entries are written as. */
export function addressOf(parameter) {
  return parameter.path ? `${parameter.path}/${parameter.name}` : parameter.name;
}

/**
 * Decide every variable this delivery will set, refusing anything ambiguous.
 *
 * `files` entries are resolved first because they are the explicit ones: a customer naming
 * `KUBECONFIG` has said what they want, and a derived name is what has to give way — by failing,
 * not by being overwritten.
 */
export function planVariables(parameters, fileEntries) {
  const byAddress = new Map(parameters.map((p) => [addressOf(p), p]));
  const plan = new Map();

  for (const entry of fileEntries) {
    const parameter = byAddress.get(entry.address);
    if (!parameter) {
      throw new Error(
        `\`files\` names ${entry.address}, which this identity cannot read. Check the address, or the identity's project and environment.`,
      );
    }
    if (plan.has(entry.variable)) {
      throw new Error(`\`files\` sets ${entry.variable} twice.`);
    }
    const reserved = reservedReason(entry.variable);
    if (reserved) {
      throw new Error(
        `penv-cloud: \`files\` sets ${entry.variable}, which ${reserved}. Pick another variable name in \`files\`.`,
      );
    }
    plan.set(entry.variable, { parameter, mode: "file" });
  }

  const asFile = new Set(fileEntries.map((e) => e.address));
  for (const parameter of parameters) {
    if (asFile.has(addressOf(parameter))) continue;
    const variable = envNameFor(parameter.path, parameter.name);
    const reserved = reservedReason(variable);
    if (reserved) {
      // Refused, never skipped: a build that quietly ran without a value it expected is how a
      // wrong deploy happens, and a skipped name would hide that someone wrote it.
      throw new Error(
        `penv-cloud: ${addressOf(parameter)} maps to ${variable}, which ${reserved}. Rename the parameter, or remove it from this identity's environment.`,
      );
    }
    const taken = plan.get(variable);
    if (taken) {
      throw new Error(
        `${addressOf(parameter)} and ${addressOf(taken.parameter)} both map to ${variable}. Rename one, or point \`files\` at it.`,
      );
    }
    plan.set(variable, { parameter, mode: "value" });
  }
  return plan;
}
