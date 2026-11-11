# penv-run

Run a command with penv-cloud secrets in its environment, and nowhere else.

```yaml
permissions:
  id-token: write

steps:
  - uses: penvhq/penv-run@<full-commit-sha>
    with:
      audience: ${{ vars.PENV_ORG_ID }}
      run: npm run deploy
```

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `audience` | yes | | The penv-cloud org id. Also the OIDC audience. |
| `run` | yes | | The command to run. It receives the secrets; no other step does. |
| `api-origin` | no | `https://penv.cloud` | The penv-cloud API origin. |
| `files` | no | | One `NAME=path/name` per line, for tools that cannot read an environment variable. The value is written to a 0600 file under `$RUNNER_TEMP`, `NAME` is set to that path, and the file is removed before the step ends. Use only where a file is required. |

## Pin by full commit SHA

This action runs in your CI with your OIDC token. Tags move; a commit SHA does not. Pin the full 40-character SHA, never a tag or branch, and review the diff when you repin.

It has no npm dependencies and uses no third-party actions. It reads no repository secrets. It does not protect against a malicious step in the same job, and revocation at job end is best effort: the server's short TTL bounds a delivered credential.

Docs: https://penv.cloud/docs/guides/github-actions
