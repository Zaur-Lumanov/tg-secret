import type { ChoiceQuestion, ConfirmQuestion, NoticeLevel, Prompts, Question } from "tg-secret-core";
import { c, type Terminal } from "./terminal.js";

const STYLE: Record<NoticeLevel, (s: string) => string> = {
  title: c.bold,
  info: (s) => s,
  hint: c.dim,
  action: c.cyan,
  success: c.green,
  warning: c.yellow,
  error: c.red,
};

/** The core's questions, asked in the terminal. */
export class TerminalPrompts implements Prompts {
  constructor(private readonly term: Terminal) {}

  notice(level: NoticeLevel, ...lines: string[]): void {
    this.term.out(...lines.map(STYLE[level]));
  }

  text(q: Question): Promise<string> {
    return this.term.ask(`${q.message}: `);
  }

  secret(q: Question): Promise<string> {
    return this.term.askHidden(`${q.message}: `);
  }

  async confirm(q: ConfirmQuestion): Promise<boolean> {
    const answer = await this.term.ask(c.yellow(`${q.message} ${q.default ? "(Y/n)" : "(y/N)"} `));
    return answer === "" ? q.default : /^(y|yes)$/i.test(answer);
  }

  async choose<T>(q: ChoiceQuestion<T>): Promise<T> {
    const def = Math.max(0, q.options.findIndex((o) => o.value === q.default)) + 1;
    for (;;) {
      this.term.out(c.bold(`${q.message}:`), ...q.options.map((o, i) => `  ${i + 1}) ${o.label}`));
      const answer = (await this.term.ask(`Choice [${def}]: `)) || String(def);
      const option = q.options[Number(answer) - 1];
      if (option) return option.value;
      this.term.out(c.red("No such option"));
    }
  }
}
