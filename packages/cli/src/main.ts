/**
 * The `tg-secret` / `tg-secret-cli` command (started by bin.ts):
 *   tg-secret <phone> [options]        the secret chat console
 *   tg-secret auth <phone> [options]   sign the number in and exit
 */
import { runAuth } from "./auth.js";
import { runConsole } from "./console.js";
import { c } from "./terminal.js";
import { TooManyAttemptsError } from "tg-secret-core";

const argv = process.argv.slice(2);
const run = argv[0] === "auth" ? runAuth(argv.slice(1)) : runConsole(argv);

run.then(
  () => process.exit(0),
  (e: unknown) => {
    const message = e instanceof Error ? e.message : String(e);
    console.error(c.red(e instanceof TooManyAttemptsError ? `${message}. Exiting.` : message));
    process.exit(1);
  },
);
