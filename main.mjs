import { spawn } from "node:child_process";
import { constants } from "node:os";
import * as api from "./api.mjs";
import { deliver } from "./deliver.mjs";

/** Entry only. Everything worth testing lives in `deliver.mjs`. */
function spawnChild(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    child.on("error", reject);
    // A signalled child has no exit code. 128+signal is what a shell reports, so the job fails.
    child.on("close", (code, signal) =>
      resolve(signal ? 128 + (constants.signals[signal] ?? 1) : (code ?? 1)),
    );
  });
}

try {
  process.exitCode = await deliver({
    env: process.env,
    api,
    emit: (line) => process.stdout.write(`${line}\n`),
    warn: (message) => process.stdout.write(`::warning::${message}\n`),
    spawnChild,
  });
} catch (error) {
  process.stdout.write(`::error::${error.message}\n`);
  process.exitCode = 1;
}
