import assert from "node:assert/strict";
import { test } from "node:test";
import { parseArgs } from "../src/args.js";

test("parseArgs: phone, --debug, --data-dir and both --password forms", () => {
  assert.deepEqual(parseArgs(["+79990000000"]), { phone: "+79990000000", debug: false });
  assert.deepEqual(parseArgs(["+7999", "--debug", "--password=a b c"]), { phone: "+7999", password: "a b c", debug: true });
  assert.deepEqual(parseArgs(["--password", "secret", "+7999"]), { phone: "+7999", password: "secret", debug: false });
  assert.deepEqual(parseArgs(["+7999", "--data-dir", "D:\\tg"]), { phone: "+7999", dataDir: "D:\\tg", debug: false });
  assert.deepEqual(parseArgs(["--data-dir=./x", "+7999"]), { phone: "+7999", dataDir: "./x", debug: false });
  assert.throws(() => parseArgs(["+7999", "--data-dir"]), /missing value/);
  assert.throws(() => parseArgs(["+7999", "--password"]), /missing value/);
  assert.throws(() => parseArgs(["+7999", "--verbose"]), /Unknown argument/);
  assert.throws(() => parseArgs(["+7999", "+7888"]), /Unexpected argument/);
});
