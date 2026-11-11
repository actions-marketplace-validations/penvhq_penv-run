import * as api from "./api.mjs";
import { revokePost } from "./revoke.mjs";

/** Entry only. It sets no exit code: revocation is best effort and never fails a job. */
await revokePost({
  env: process.env,
  api,
  emit: (line) => process.stdout.write(`${line}\n`),
  warn: (message) => process.stdout.write(`::warning::${message}\n`),
});
