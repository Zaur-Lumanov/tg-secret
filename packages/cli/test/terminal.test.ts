import assert from "node:assert/strict";
import { PassThrough, Writable } from "node:stream";
import { test } from "node:test";
import { isTypingMessage } from "../src/repl.js";
import { Terminal } from "../src/terminal.js";

function fakeTty() {
  const input = new PassThrough();
  let out = "";
  const output = new Writable({
    write(chunk, _enc, cb) {
      out += chunk.toString();
      cb();
    },
  });
  // readline redraws lines based on the terminal width
  Object.assign(output, { columns: 80, isTTY: true });
  return { input, output, text: () => out };
}

/** Readline processes keys asynchronously: feed them one tick apart. */
async function type(input: PassThrough, ...keys: string[]) {
  for (const k of keys) {
    input.write(k);
    await new Promise((r) => setImmediate(r));
  }
}

test("askHidden shows the question, masks input (also after backspace) and keeps it out of history", async () => {
  const tty = fakeTty();
  const term = new Terminal(tty.input, tty.output);

  const first = term.askHidden("New local password: ");
  await type(tty.input, "s", "e", "c", "x", "\x7f", "r", "e", "t", "\r");
  assert.equal(await first, "secret");

  const second = term.askHidden("Repeat the password: ");
  await type(tty.input, "s", "e", "c", "r", "e", "t", "\r");
  assert.equal(await second, "secret");

  const out = tty.text();
  assert.ok(out.includes("New local password: "), "first question visible");
  assert.ok(out.includes("Repeat the password: "), "repeat question visible");
  for (const leaked of ["secret", "secx", "sec"]) assert.ok(!out.includes(leaked), `"${leaked}" must not be echoed`);
  // backspace redraw: prompt followed by exactly the remaining 3 asterisks
  assert.ok(out.includes("New local password: ***"));

  const history = (term.rl as unknown as { history: string[] }).history;
  assert.ok(!history.includes("secret"), "password not in readline history");

  const visible = term.ask("Number: ");
  await type(tty.input, "1", "2", "\r");
  assert.equal(await visible, "12");
  assert.ok(tty.text().includes("12"), "normal questions still echo");
  term.close();
});

test("typing is reported only for message text, not for commands, answers or an empty line", () => {
  assert.equal(isTypingMessage("hel", false), true);
  assert.equal(isTypingMessage("/delete", false), false);
  assert.equal(isTypingMessage("  /clean", false), false);
  assert.equal(isTypingMessage("", false), false); // e.g. right after Enter
  assert.equal(isTypingMessage("y", true), false); // answering "Delete the chat? (y/N)"
});

test("currentLine reflects the input buffer and is empty after Enter", async () => {
  const tty = fakeTty();
  const term = new Terminal(tty.input, tty.output);
  const lines: string[] = [];
  term.rl.on("line", (l) => lines.push(l));
  await type(tty.input, "/", "d");
  assert.equal(term.currentLine, "/d");
  await type(tty.input, "\r");
  assert.equal(term.currentLine, "");
  assert.deepEqual(lines, ["/d"]);
  term.close();
});
