import readline from "node:readline";

export const c = {
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  cyan: (s: string) => `\x1b[36m${s}\x1b[0m`,
  magenta: (s: string) => `\x1b[35m${s}\x1b[0m`,
};

interface ReadlineInternals {
  _writeToOutput(s: string): void;
  history: string[];
  line: string;
}

/**
 * One readline instance for everything: prompts during login and the REPL.
 * `print` writes above the input line without destroying what the user is typing.
 */
export class Terminal {
  readonly rl: readline.Interface;
  /** prompt of the hidden question being answered, if any */
  private hiddenPrompt?: string;
  private asking = 0;

  constructor(
    private readonly input: NodeJS.ReadableStream = process.stdin,
    private readonly output: NodeJS.WritableStream = process.stdout,
  ) {
    this.rl = readline.createInterface({ input, output, terminal: true });
    // Hidden input: readline echoes through _writeToOutput — either the typed characters,
    // or the whole "prompt + line" when it redraws the line (backspace, cursor keys).
    const rl = this.rl as unknown as ReadlineInternals;
    const original = rl._writeToOutput.bind(this.rl);
    rl._writeToOutput = (s: string) => {
      const prompt = this.hiddenPrompt;
      if (prompt === undefined || /[\r\n]/.test(s)) return original(s);
      if (s.startsWith(prompt)) return original(prompt + "*".repeat([...rl.line].length));
      original("*".repeat([...s].length));
    };
  }

  /** True while a question (e.g. a password) is being answered. */
  get isAsking(): boolean {
    return this.asking > 0;
  }

  /** What is currently typed in the input line (not yet submitted). */
  get currentLine(): string {
    return (this.rl as unknown as ReadlineInternals).line;
  }

  ask(question: string, trim = true): Promise<string> {
    this.asking++;
    return new Promise<string>((resolve) =>
      this.rl.question(question, (a) => {
        this.asking--;
        resolve(trim ? a.trim() : a);
      }),
    );
  }

  /**
   * Input is echoed as asterisks, returned untrimmed (spaces are part of a password)
   * and kept out of the readline history, so the up arrow can't bring it back.
   */
  async askHidden(question: string): Promise<string> {
    this.hiddenPrompt = question;
    let answer: string | undefined;
    try {
      answer = await this.ask(question, false);
      return answer;
    } finally {
      this.hiddenPrompt = undefined;
      const history = (this.rl as unknown as ReadlineInternals).history;
      if (answer && history[0] === answer) history.shift();
    }
  }

  /** Clears the screen and the scrollback, so nothing from the session remains visible. */
  clearScreen(): void {
    this.output.write("\x1b[2J\x1b[3J\x1b[H");
  }

  setPrompt(prompt: string): void {
    this.rl.setPrompt(prompt);
  }

  prompt(): void {
    this.rl.prompt(true);
  }

  /** Set by the REPL while it runs: output then goes above the input line. */
  replActive = false;

  /** Output that works both before the REPL starts and while it runs. */
  out(...lines: string[]): void {
    if (this.replActive) this.print(...lines);
    else this.log(...lines);
  }

  /** Plain output without re-drawing the REPL prompt (used before the REPL starts). */
  log(...lines: string[]): void {
    for (const l of lines) this.output.write(l + "\n");
  }

  print(...lines: string[]): void {
    readline.clearLine(this.output, 0);
    readline.cursorTo(this.output, 0);
    for (const l of lines) this.output.write(l + "\n");
    this.rl.prompt(true);
  }

  close(): void {
    this.rl.close();
  }
}
