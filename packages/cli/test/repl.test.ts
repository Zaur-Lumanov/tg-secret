import assert from "node:assert/strict";
import { test } from "node:test";
import { splitPathArg } from "../src/repl.js";

test("splitPathArg handles quoted paths with spaces and captions", () => {
  assert.deepEqual(splitPathArg(' "C:\\My Photos\\a b.jpg" hello world 👋'), { path: "C:\\My Photos\\a b.jpg", caption: "hello world 👋" });
  assert.deepEqual(splitPathArg(" C:\\a.jpg"), { path: "C:\\a.jpg", caption: "" });
});
