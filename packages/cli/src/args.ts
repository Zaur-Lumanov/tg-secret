import { listAccounts, normalizePhone } from "tg-secret-core";
import { c, type Terminal } from "./terminal.js";

export interface CliArgs {
  phone?: string;
  /** local password for an already encrypted account */
  password?: string;
  /** overrides the default data directory */
  dataDir?: string;
  debug: boolean;
}

/**
 * Parses `<phone> [--debug] [--data-dir <dir>] [--password <pw>]` (`--opt=value` works too).
 * The password is scrubbed from process.argv right away (best effort: the OS may
 * still show the original command line to other processes).
 */
export function parseArgs(argv: string[] = process.argv.slice(2)): CliArgs {
  const args: CliArgs = { debug: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--debug") {
      args.debug = true;
    } else if (a.startsWith("--password=")) {
      args.password = a.slice("--password=".length);
    } else if (a === "--password") {
      if (i + 1 >= argv.length) throw new Error("--password: missing value");
      args.password = argv[++i];
    } else if (a.startsWith("--data-dir=")) {
      args.dataDir = a.slice("--data-dir=".length);
    } else if (a === "--data-dir") {
      if (i + 1 >= argv.length) throw new Error("--data-dir: missing value");
      args.dataDir = argv[++i];
    } else if (a.startsWith("--")) {
      throw new Error(`Unknown argument ${a}`);
    } else if (args.phone === undefined) {
      args.phone = a;
    } else {
      throw new Error(`Unexpected argument ${a}`);
    }
  }
  if (args.password === "") throw new Error("--password: empty password");
  if (args.dataDir === "") throw new Error("--data-dir: empty path");
  scrubPassword();
  return args;
}

function scrubPassword(): void {
  for (let i = 0; i < process.argv.length; i++) {
    if (process.argv[i].startsWith("--password=")) process.argv[i] = "--password=***";
    else if (process.argv[i] === "--password" && i + 1 < process.argv.length) process.argv[++i] = "***";
  }
}

/**
 * With --password the command line (and so the password) is on screen: clear the screen
 * and the scrollback before anything else is shown.
 */
export function hidePasswordCommand(term: Terminal, args: CliArgs): void {
  if (args.password !== undefined) term.clearScreen();
}

/** Shown once the session is ready: the password may still sit in the shell history. */
export const PASSWORD_ARG_WARNING = [
  c.yellow("⚠ The local password was passed as a command-line argument."),
  c.yellow("  It may remain in the shell history (PowerShell, cmd, bash) and was visible in the console until it was cleared."),
  c.yellow("  We recommend changing it with /passwd."),
];

/** The phone number from the arguments; without one lists known accounts and asks. Throws if invalid. */
export async function phoneFromArgs(term: Terminal, dataDir: string, args: CliArgs, usage: string): Promise<string> {
  if (args.phone) return "+" + normalizePhone(args.phone);

  const known = listAccounts(dataDir);
  term.log(c.dim(`Usage: ${usage}`));
  if (known.length) {
    term.log(
      "Signed-in numbers:",
      ...known.map((a) => `  ${a.phone}${a.state === "legacy" ? c.yellow("  (not encrypted)") : ""}`),
    );
  }
  return "+" + normalizePhone(await term.ask("Phone number: "));
}
