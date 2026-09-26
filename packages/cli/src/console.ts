/** `tg-secret <phone>` — the secret chat console; signs the number in first if needed. */
import { hidePasswordCommand, parseArgs, PASSWORD_ARG_WARNING, phoneFromArgs } from "./args.js";
import { debugLogger } from "./debug.js";
import { offerAccountsMove } from "./moveAccounts.js";
import { installProcessGuards } from "./processGuards.js";
import { Repl } from "./repl.js";
import { c, Terminal } from "./terminal.js";
import { TerminalPrompts } from "./terminalPrompts.js";
import { resolveDataDir, TgSecret } from "tg-secret-core";

export async function runConsole(argv: string[]): Promise<void> {
  const args = parseArgs(argv); // bad arguments end the process before anything is asked
  const debug = debugLogger(args.debug);
  installProcessGuards(debug);
  const term = new Terminal();
  hidePasswordCommand(term, args);
  const dataDir = resolveDataDir({ dataDir: args.dataDir });
  await offerAccountsMove(term, dataDir);
  const phone = await phoneFromArgs(term, dataDir, args, "tg-secret +79991234567");

  const session = await TgSecret.open({ phone, dataDir, prompts: new TerminalPrompts(term), password: args.password, debug });
  let warnAboutPassword = args.password !== undefined;

  // Each iteration is one unlocked session; /lock tears it down completely and asks for the password again.
  for (;;) {
    term.log(c.green(`Signed in: ${session.name} (${session.phone})`));
    if (warnAboutPassword) term.log(...PASSWORD_ARG_WARNING);
    warnAboutPassword = false;
    for (const ch of session.chats.list().filter((ch) => ch.state === "requested")) {
      term.log(c.magenta(`★ Pending request from ${ch.peerName} — /accept ${ch.id}`));
    }

    const result = await new Repl(term, session).run();
    if (result === "quit") break;

    await session.lock();
    term.clearScreen();
    term.log(c.bold(`🔒 Session locked (${session.phone}).`));
    // the command-line password only unlocks the first session; now it is asked again
    await session.unlock();
  }
  await session.close();
  term.close();
}
