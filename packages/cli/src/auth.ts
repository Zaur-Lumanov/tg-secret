/** `tg-secret auth <phone>` — signs a number in without starting the chat console. */
import { hidePasswordCommand, parseArgs, PASSWORD_ARG_WARNING, phoneFromArgs } from "./args.js";
import { debugLogger } from "./debug.js";
import { offerAccountsMove } from "./moveAccounts.js";
import { installProcessGuards } from "./processGuards.js";
import { c, Terminal } from "./terminal.js";
import { TerminalPrompts } from "./terminalPrompts.js";
import { resolveDataDir, TgSecret } from "tg-secret-core";

export async function runAuth(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const debug = debugLogger(args.debug);
  installProcessGuards(debug);
  const term = new Terminal();
  hidePasswordCommand(term, args);
  const dataDir = resolveDataDir({ dataDir: args.dataDir });
  await offerAccountsMove(term, dataDir);
  const phone = await phoneFromArgs(term, dataDir, args, "tg-secret auth +79991234567");

  const session = await TgSecret.open({ phone, dataDir, prompts: new TerminalPrompts(term), password: args.password, debug });
  term.log(c.green(`✔ ${session.phone} is signed in as ${session.name}. Start the console with: tg-secret ${session.phone}`));
  if (args.password !== undefined) {
    term.log(...PASSWORD_ARG_WARNING.slice(0, 2), c.yellow(`  We recommend changing the password: tg-secret ${session.phone}, then /passwd.`));
  }
  await session.close();
  term.close();
}
